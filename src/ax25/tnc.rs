//! The radio link: a task that owns the TNC connection, turns bytes into
//! [`Ax25Frame`]s and back, reconnects when the TNC goes away, and paces
//! transmissions so we do not bury the channel.
//!
//! Three link types are supported:
//!   * `tcp`      - KISS over TCP, e.g. Direwolf's port 8001. The normal case.
//!   * `serial`   - KISS over a serial port (feature `serial`).
//!   * `loopback` - an in-process fake radio for development and tests.

use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

use super::airtime::{AirtimeConfig, AirtimeShared, Governor, TxDecision};
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
    /// KISS persistence and slot time, if we should set them.
    pub persistence: Option<u8>,
    pub slottime: Option<u8>,
    /// Duty-cycle and airtime limits. This is what keeps a QRP transmitter
    /// alive and the channel usable; see [`super::airtime`].
    pub airtime: AirtimeConfig,
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
            persistence: None,
            slottime: None,
            airtime: AirtimeConfig::default(),
        }
    }
}

impl TncConfig {
    /// Everything the TNC task needs, derived from the parsed configuration.
    ///
    /// One constructor, used by the server and by the tests alike. When these
    /// were two pieces of code the test harness quietly stopped passing
    /// `[radio.duty]` through, so the airtime governor was disabled in every
    /// integration test while the unit tests said it worked.
    ///
    /// `link` is a parameter rather than derived here because choosing it is
    /// the one part that differs: the server resolves `radio.tnc.kind`, and a
    /// test substitutes a loopback whose far end it keeps.
    pub fn from_config(config: &crate::config::Config, link: TncLink) -> Self {
        let section = &config.radio.tnc;
        Self {
            link,
            kiss_port: section.kiss_port,
            // paclen is the *information* field. A full AX.25 header with
            // eight digipeaters is 58 octets on top of it; +32 silently
            // discarded long-path frames we were perfectly able to decode.
            max_frame: config.radio.paclen + 64,
            tx_pacing: Duration::from_millis(section.tx_pacing_ms),
            tx_queue_depth: 64,
            persistence: section.persistence,
            slottime: section.slottime,
            airtime: config.radio.duty.to_airtime(),
        }
    }

    /// Build a loopback link and return the far end, which behaves like a TNC:
    /// write KISS frames into it to simulate reception, read to see what the
    /// server transmitted.
    ///
    /// The link only. Pair it with [`TncConfig::from_config`] to get a TNC
    /// configured exactly as the server would configure it.
    pub fn loopback_link() -> (TncLink, DuplexStream) {
        let (near, far) = tokio::io::duplex(64 * 1024);
        (TncLink::Loopback(Arc::new(Mutex::new(Some(near)))), far)
    }
}

/// Handle used by the rest of the server to transmit.
#[derive(Clone)]
pub struct TncHandle {
    tx: mpsc::Sender<Ax25Frame>,
    /// Station identification only. Kept separate from `tx` because an ID is
    /// not ordinary traffic: it is the one transmission a station is
    /// *required* to make, so it must not sit behind a backlog, and it must
    /// still go out when the operator has inhibited everything else — a
    /// station signing off owes the band its callsign.
    priority: mpsc::Sender<Ax25Frame>,
    airtime: Arc<AirtimeShared>,
    /// A copy of the governor's cost model, so the sender can price a frame
    /// before committing to it. The governor itself lives in the TNC task.
    cost: AirtimeConfig,
}

impl TncHandle {
    /// Live airtime counters and the hard transmit inhibit. Shared with the
    /// TNC task; see [`AirtimeShared`].
    pub fn airtime(&self) -> &Arc<AirtimeShared> {
        &self.airtime
    }

    /// Stop transmitting *now*. Frames already queued are discarded rather
    /// than radiated later: an operator who says "off" means off, not
    /// "off once the backlog has drained".
    pub fn set_inhibit(&self, inhibit: bool) {
        self.airtime.inhibit.store(inhibit, Ordering::Relaxed);
    }

    pub fn inhibited(&self) -> bool {
        self.airtime.inhibit.load(Ordering::Relaxed)
    }

    /// Queue a station identification. Jumps the transmit queue and is not
    /// subject to the inhibit or the duty governor: identifying is a legal
    /// obligation, and it is one short frame.
    pub fn try_send_id(&self, frame: Ax25Frame) -> bool {
        match self.priority.try_send(frame) {
            Ok(()) => true,
            Err(e) => {
                warn!("station ID could not be queued: {e}");
                false
            }
        }
    }

    /// Key-down time a frame of this size will cost.
    pub fn airtime_for(&self, octets: usize) -> Duration {
        Governor::new(self.cost.clone()).airtime_for(octets)
    }

    /// Airtime already queued and not yet radiated.
    pub fn queued(&self) -> Duration {
        self.airtime.queued()
    }

    /// Best estimate of how long a frame queued now would wait: the
    /// governor's next free slot plus the existing backlog.
    pub fn eta(&self) -> Duration {
        self.airtime.eta()
    }

    /// Queue a frame for transmission. Returns false if the transmit queue is
    /// full, which is a normal condition on a congested channel and must be
    /// handled by the caller (usually: drop, count, and tell the user).
    ///
    /// The frame's airtime is added to the published backlog here and removed
    /// by the TNC task when the frame is radiated or dropped, so both sides
    /// of the channel keep the figure honest.
    pub fn try_send(&self, frame: Ax25Frame) -> bool {
        let cost = self.airtime_for(frame.encode().len()).as_millis() as u64;
        match self.tx.try_send(frame) {
            Ok(()) => {
                self.airtime.queued_ms.fetch_add(cost, Ordering::Relaxed);
                self.airtime.queued_frames.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(e) => {
                warn!("TX queue full, dropping frame: {e}");
                false
            }
        }
    }
}

/// Subtract a frame's airtime from the published backlog once it has left the
/// queue, whether it was transmitted or dropped. Saturating, because the two
/// sides update independently and a negative backlog is meaningless.
fn release_queued(shared: &AirtimeShared, governor: &Governor, octets: usize) {
    let cost = governor.airtime_for(octets).as_millis() as u64;
    let _ = shared
        .queued_ms
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |q| {
            Some(q.saturating_sub(cost))
        });
    let _ = shared
        .queued_frames
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            Some(n.saturating_sub(1))
        });
}

/// Start the TNC task. Received frames are delivered on the returned channel.
pub fn spawn(config: TncConfig) -> (TncHandle, mpsc::Receiver<Ax25Frame>) {
    let (tx_out, rx_out) = mpsc::channel::<Ax25Frame>(config.tx_queue_depth);
    let (tx_id, rx_id) = mpsc::channel::<Ax25Frame>(4);
    let (tx_in, rx_in) = mpsc::channel::<Ax25Frame>(256);
    let airtime = Arc::new(AirtimeShared::default());
    tokio::spawn(run(config.clone(), rx_out, rx_id, tx_in, airtime.clone()));
    let cost = config.airtime.clone();
    (
        TncHandle {
            tx: tx_out,
            priority: tx_id,
            airtime,
            cost,
        },
        rx_in,
    )
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

/// Everything that survives a reconnect: the frames waiting to go out, the
/// one the pump is holding, and where received frames go.
///
/// Grouped so a link failure cannot lose any of it. The held frame in
/// particular has already reserved airtime in the published backlog, so
/// dropping it would leak that reservation permanently.
struct Link {
    tx_queue: mpsc::Receiver<Ax25Frame>,
    id_queue: mpsc::Receiver<Ax25Frame>,
    rx_sink: mpsc::Sender<Ax25Frame>,
    pending: Option<(Ax25Frame, tokio::time::Instant)>,
}

async fn run(
    config: TncConfig,
    tx_queue: mpsc::Receiver<Ax25Frame>,
    id_queue: mpsc::Receiver<Ax25Frame>,
    rx_sink: mpsc::Sender<Ax25Frame>,
    shared: Arc<AirtimeShared>,
) {
    let mut state = Link {
        tx_queue,
        id_queue,
        rx_sink,
        pending: None,
    };
    // The governor outlives individual TNC connections on purpose: airtime
    // already radiated does not stop counting because Direwolf restarted.
    let mut governor = Governor::new(config.airtime.clone());
    let mut backoff = Duration::from_secs(1);
    loop {
        match connect(&config.link).await {
            Ok(link) => {
                info!(?config.link, "TNC connected");
                backoff = Duration::from_secs(1);
                if let Err(e) = pump(&config, link, &mut state, &mut governor, &shared).await {
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
    state: &mut Link,
    governor: &mut Governor,
    shared: &AirtimeShared,
) -> io::Result<()> {
    let Link {
        tx_queue,
        id_queue,
        rx_sink,
        pending,
    } = state;
    // Push KISS parameters at connect.
    //
    // TXDELAY and TXTAIL come from the airtime config rather than a separate
    // TNC setting: the governor prices every frame with those numbers, so the
    // TNC had better be using the same ones. In 10 ms units, hence the /10.
    let ms_to_kiss = |ms: u128| -> u8 { (ms / 10).min(255) as u8 };
    let mut params: Vec<(u8, u8)> = vec![
        (kiss::CMD_TXDELAY, ms_to_kiss(config.airtime.txdelay.as_millis())),
        (kiss::CMD_TXTAIL, ms_to_kiss(config.airtime.txtail.as_millis())),
        // Half duplex, always. A TNC in full-duplex mode transmits without
        // listening first, which on a shared channel is precisely the
        // behaviour this whole module exists to prevent.
        (kiss::CMD_FULLDUPLEX, 0),
    ];
    for (cmd, value) in [
        (kiss::CMD_PERSISTENCE, config.persistence),
        (kiss::CMD_SLOTTIME, config.slottime),
    ] {
        if let Some(v) = value {
            params.push((cmd, v));
        }
    }
    for (cmd, v) in params {
        link.write_all(&kiss::encode(config.kiss_port, cmd, &[v])).await?;
    }

    let mut decoder = KissDecoder::new(config.max_frame);
    let mut buf = vec![0u8; 4096];
    // Earliest the pacing gate lets us key up again. A fresh connection has
    // not transmitted yet, so the gate starts open.
    let mut next_tx = tokio::time::Instant::now();

    loop {
        // Discard anything queued while the transmitter is inhibited. This is
        // the operator's kill switch: it must take effect on the frames that
        // are already in flight, not just on the next one.
        if shared.tx_blocked() {
            if let Some((frame, _)) = pending.take() {
                release_queued(shared, governor, frame.encode().len());
                shared.dropped_inhibited.fetch_add(1, Ordering::Relaxed);
            }
            while let Ok(frame) = tx_queue.try_recv() {
                release_queued(shared, governor, frame.encode().len());
                shared.dropped_inhibited.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Pick up any live override a control operator has set. Cheap enough
        // to do every time round, and it means `RADIO LIMIT` takes effect on
        // the next frame rather than the next restart.
        governor.set_duty(shared.duty_limit(config.airtime.max_duty));
        let pacing = shared.pacing(config.tx_pacing);

        let far_future = tokio::time::Instant::now() + Duration::from_secs(3600);
        let wake = if pending.is_some() { next_tx } else { far_future };

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
                    if kf.port != config.kiss_port {
                        // Another radio port on the same TNC. Not ours.
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
            Some(frame) = id_queue.recv() => {
                // Identification bypasses the pacing gate, the governor and
                // the operator's inhibit: `RADIO OFF` queues a sign-off ID
                // precisely so the station can put its callsign to the
                // transmissions it has already made, and dropping that would
                // defeat the purpose.
                //
                // It does not bypass the safety interlock. If it is not safe
                // to key up — high SWR, a hot PA, someone on the tower — then
                // it is not safe to key up for an ID either. A licence
                // requires you to identify the transmissions you make, not to
                // make one.
                let bytes = frame.encode();
                if shared.interlock_failed() {
                    warn!("station ID suppressed: the safety interlock is not satisfied");
                } else if bytes.len() <= config.max_frame {
                    write_kiss_bytes(&mut link, config, &frame, &bytes).await?;
                    let now = std::time::Instant::now();
                    let keyed = governor.record(bytes.len(), now);
                    governor.publish_with(shared, now, config.max_frame);
                    next_tx = next_tx.max(tokio::time::Instant::now() + pacing.max(keyed));
                }
            }
            Some(frame) = tx_queue.recv(), if pending.is_none() => {
                *pending = Some((frame, tokio::time::Instant::now()));
            }
            _ = tokio::time::sleep_until(wake), if pending.is_some() => {
                let Some((frame, queued_at)) = pending.take() else {
                    continue;
                };
                if shared.tx_blocked() {
                    release_queued(shared, governor, frame.encode().len());
                    shared.dropped_inhibited.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let bytes = frame.encode();
                if bytes.len() > config.max_frame {
                    warn!("refusing to transmit oversized frame ({} bytes)", bytes.len());
                    release_queued(shared, governor, bytes.len());
                    continue;
                }
                let now = std::time::Instant::now();
                match governor.check(bytes.len(), now) {
                    TxDecision::Send => {
                        write_kiss_bytes(&mut link, config, &frame, &bytes).await?;
                        let keyed = governor.record(bytes.len(), now);
                        release_queued(shared, governor, bytes.len());
                        governor.publish_with(shared, now, config.max_frame);
                        // Pace on whichever is longer: the operator's minimum
                        // gap, or the time this transmission actually occupies
                        // the channel. Without the latter the "gap" would
                        // start while we were still keyed.
                        next_tx = tokio::time::Instant::now() + pacing.max(keyed);
                    }
                    TxDecision::Defer(delay, reason) => {
                        governor.publish_with(shared, now, config.max_frame);
                        let waited = queued_at.elapsed();
                        if waited + delay > config.airtime.max_hold {
                            release_queued(shared, governor, bytes.len());
                            shared.dropped_stale.fetch_add(1, Ordering::Relaxed);
                            warn!(
                                "dropping a frame held {:?} by {} — stale traffic is worse than no traffic",
                                waited,
                                reason.as_str()
                            );
                            continue;
                        }
                        shared.deferred.fetch_add(1, Ordering::Relaxed);
                        debug!("holding a frame for {:?} ({})", delay, reason.as_str());
                        next_tx = tokio::time::Instant::now() + delay;
                        *pending = Some((frame, queued_at));
                    }
                }
            }
            else => return Ok(()),
        }
    }
}

async fn write_kiss_bytes(
    link: &mut Box<dyn ReadWrite>,
    config: &TncConfig,
    frame: &Ax25Frame,
    bytes: &[u8],
) -> io::Result<()> {
    debug!(target: "rf::tx", "{}", frame.to_monitor_line());
    link.write_all(&kiss::encode(config.kiss_port, kiss::CMD_DATA, bytes))
        .await?;
    link.flush().await
}
