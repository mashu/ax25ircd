//! The radio link: a task that owns the TNC connection, turns bytes into
//! [`Ax25Frame`]s and back, reconnects when the TNC goes away, and paces
//! transmissions so we do not bury the channel.
//!
//! Three link types are supported:
//!   * `tcp`      - KISS over TCP, e.g. Direwolf's port 8001. The normal case.
//!   * `serial`   - KISS over a serial port (feature `serial`).
//!   * `loopback` - an in-process fake radio for development and tests.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

use super::frame::Ax25Frame;
use super::kiss::{self, KissDecoder};

pub trait ReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ReadWrite for T {}

/// How to reach the TNC.
#[derive(Clone, Debug)]
pub enum TncLink {
    Tcp { host: String, port: u16 },
    #[cfg(feature = "serial")]
    Serial { path: String, baud: u32 },
    /// In-process loopback. The far end of the duplex stream is handed to the
    /// test harness (see `TncConfig::loopback`).
    Loopback(Arc<Mutex<Option<DuplexStream>>>),
}

#[derive(Clone, Debug)]
pub struct TncConfig {
    pub link: TncLink,
    /// KISS port number on the TNC (0-15).
    pub kiss_port: u8,
    /// Largest AX.25 frame we will accept or emit.
    pub max_frame: usize,
    /// Minimum gap between transmissions, to leave the channel usable by
    /// others. At 1200 baud a 256 byte frame already occupies ~1.9 s.
    pub tx_pacing: Duration,
    /// Frames queued for transmission before we start dropping.
    pub tx_queue_depth: usize,
    /// KISS TXDELAY parameter, in 10 ms units. `None` leaves the TNC alone.
    pub txdelay: Option<u8>,
    /// KISS persistence and slot time, if we should set them.
    pub persistence: Option<u8>,
    pub slottime: Option<u8>,
}

impl Default for TncConfig {
    fn default() -> Self {
        Self {
            link: TncLink::Tcp {
                host: "127.0.0.1".into(),
                port: 8001,
            },
            kiss_port: 0,
            max_frame: 512,
            tx_pacing: Duration::from_millis(1500),
            tx_queue_depth: 64,
            txdelay: None,
            persistence: None,
            slottime: None,
        }
    }
}

impl TncConfig {
    /// Build a loopback link and return the far end, which behaves like a TNC:
    /// write KISS frames into it to simulate reception, read to see what the
    /// server transmitted.
    pub fn loopback() -> (Self, DuplexStream) {
        let (near, far) = tokio::io::duplex(64 * 1024);
        let cfg = Self {
            link: TncLink::Loopback(Arc::new(Mutex::new(Some(near)))),
            tx_pacing: Duration::from_millis(0),
            ..Default::default()
        };
        (cfg, far)
    }
}

/// Handle used by the rest of the server to transmit.
#[derive(Clone)]
pub struct TncHandle {
    tx: mpsc::Sender<Ax25Frame>,
}

impl TncHandle {
    /// Queue a frame for transmission. Returns false if the transmit queue is
    /// full, which is a normal condition on a congested channel and must be
    /// handled by the caller (usually: drop, count, and tell the user).
    pub fn try_send(&self, frame: Ax25Frame) -> bool {
        match self.tx.try_send(frame) {
            Ok(()) => true,
            Err(e) => {
                warn!("TX queue full, dropping frame: {e}");
                false
            }
        }
    }
}

/// Start the TNC task. Received frames are delivered on the returned channel.
pub fn spawn(config: TncConfig) -> (TncHandle, mpsc::Receiver<Ax25Frame>) {
    let (tx_out, rx_out) = mpsc::channel::<Ax25Frame>(config.tx_queue_depth);
    let (tx_in, rx_in) = mpsc::channel::<Ax25Frame>(256);
    tokio::spawn(run(config, rx_out, tx_in));
    (TncHandle { tx: tx_out }, rx_in)
}

async fn connect(link: &TncLink) -> io::Result<Box<dyn ReadWrite>> {
    match link {
        TncLink::Tcp { host, port } => {
            let stream = TcpStream::connect((host.as_str(), *port)).await?;
            stream.set_nodelay(true).ok();
            Ok(Box::new(stream))
        }
        #[cfg(feature = "serial")]
        TncLink::Serial { path, baud } => {
            use tokio_serial::SerialPortBuilderExt;
            let port = tokio_serial::new(path, *baud).open_native_async()?;
            Ok(Box::new(port))
        }
        TncLink::Loopback(slot) => slot
            .lock()
            .await
            .take()
            .map(|s| Box::new(s) as Box<dyn ReadWrite>)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "loopback already taken")),
    }
}

async fn run(
    config: TncConfig,
    mut tx_queue: mpsc::Receiver<Ax25Frame>,
    rx_sink: mpsc::Sender<Ax25Frame>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        match connect(&config.link).await {
            Ok(link) => {
                info!(?config.link, "TNC connected");
                backoff = Duration::from_secs(1);
                if let Err(e) = pump(&config, link, &mut tx_queue, &rx_sink).await {
                    warn!("TNC link closed: {e}");
                }
            }
            Err(e) => warn!("TNC connect failed: {e}"),
        }
        if matches!(config.link, TncLink::Loopback(_)) {
            // Nothing to reconnect to; the harness is gone.
            return;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

async fn pump(
    config: &TncConfig,
    mut link: Box<dyn ReadWrite>,
    tx_queue: &mut mpsc::Receiver<Ax25Frame>,
    rx_sink: &mpsc::Sender<Ax25Frame>,
) -> io::Result<()> {
    // Push KISS parameters, if configured.
    for (cmd, value) in [
        (kiss::CMD_TXDELAY, config.txdelay),
        (kiss::CMD_PERSISTENCE, config.persistence),
        (kiss::CMD_SLOTTIME, config.slottime),
    ] {
        if let Some(v) = value {
            link.write_all(&kiss::encode(config.kiss_port, cmd, &[v])).await?;
        }
    }

    let mut decoder = KissDecoder::new(config.max_frame);
    let mut buf = vec![0u8; 4096];
    let mut next_tx = tokio::time::Instant::now();

    loop {
        tokio::select! {
            read = link.read(&mut buf) => {
                let n = read?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TNC closed"));
                }
                for kf in decoder.push(&buf[..n]) {
                    if kf.command != kiss::CMD_DATA {
                        continue;
                    }
                    match Ax25Frame::decode(&kf.payload) {
                        Ok(frame) => {
                            debug!(target: "rf::rx", "{}", frame.to_monitor_line());
                            if rx_sink.send(frame).await.is_err() {
                                return Ok(());
                            }
                        }
                        Err(e) => debug!("undecodable AX.25 frame ({} bytes): {e}", kf.payload.len()),
                    }
                }
            }
            Some(frame) = tx_queue.recv() => {
                let now = tokio::time::Instant::now();
                if next_tx > now {
                    tokio::time::sleep_until(next_tx).await;
                }
                let bytes = frame.encode();
                if bytes.len() > config.max_frame {
                    warn!("refusing to transmit oversized frame ({} bytes)", bytes.len());
                    continue;
                }
                debug!(target: "rf::tx", "{}", frame.to_monitor_line());
                link.write_all(&kiss::encode(config.kiss_port, kiss::CMD_DATA, &bytes)).await?;
                link.flush().await?;
                next_tx = tokio::time::Instant::now() + config.tx_pacing;
            }
            else => return Ok(()),
        }
    }
}
