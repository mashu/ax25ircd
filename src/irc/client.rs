//! One task per IP client: read lines, hand them to the server actor, write
//! back whatever the actor produces.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::server::state::ClientId;
use crate::server::Event;

/// RFC 1459 line limit, including CRLF.
const MAX_LINE: usize = 512;

#[derive(Clone)]
pub struct ListenerOptions {
    pub ping_interval: Duration,
}

pub async fn listen(
    addr: String,
    events: mpsc::Sender<Event>,
    ids: Arc<AtomicU64>,
    opts: ListenerOptions,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    info!(%addr, "listening for IRC clients");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("accept failed: {e}");
                continue;
            }
        };
        let id = ids.fetch_add(1, Ordering::Relaxed);
        let events = events.clone();
        let opts = opts.clone();
        tokio::spawn(async move {
            let host = peer.ip().to_string();
            if let Err(e) = serve(stream, id, host, events, opts).await {
                debug!(client = id, "connection ended: {e}");
            }
        });
    }
}

async fn serve(
    stream: TcpStream,
    id: ClientId,
    host: String,
    events: mpsc::Sender<Event>,
    opts: ListenerOptions,
) -> std::io::Result<()> {
    stream.set_nodelay(true).ok();
    let (read_half, mut write_half) = stream.into_split();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();
    let pinger = out_tx.clone();

    if events
        .send(Event::Connected {
            id,
            host,
            out: out_tx,
        })
        .await
        .is_err()
    {
        return Ok(());
    }

    // Writer task.
    let writer = tokio::spawn(async move {
        while let Some(line) = out_rx.recv().await {
            let mut buf = line.into_bytes();
            buf.truncate(MAX_LINE - 2);
            buf.extend_from_slice(b"\r\n");
            if write_half.write_all(&buf).await.is_err() {
                break;
            }
        }
        let _ = write_half.shutdown().await;
    });

    let mut reader = BufReader::new(read_half);
    let mut line = Vec::with_capacity(MAX_LINE);
    let mut reason = "Connection closed".to_string();
    let mut idle = tokio::time::interval(opts.ping_interval);
    idle.tick().await;
    let mut awaiting_pong = false;

    loop {
        line.clear();
        tokio::select! {
            read = reader.read_until(b'\n', &mut line) => {
                let n = read?;
                if n == 0 {
                    break;
                }
                if n > MAX_LINE {
                    reason = "Line too long".into();
                    break;
                }
                awaiting_pong = false;
                let text = String::from_utf8_lossy(&line).trim_end_matches(['\r', '\n']).to_string();
                if text.is_empty() {
                    continue;
                }
                if events.send(Event::Line { id, line: text }).await.is_err() {
                    break;
                }
            }
            _ = idle.tick() => {
                if awaiting_pong {
                    reason = "Ping timeout".into();
                    break;
                }
                awaiting_pong = true;
                // Any line from the client clears this, including the PONG.
                if pinger.send("PING :keepalive".to_string()).is_err() {
                    break;
                }
            }
        }
    }

    let _ = events.send(Event::Disconnected { id, reason }).await;
    writer.abort();
    Ok(())
}
