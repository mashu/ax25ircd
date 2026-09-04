//! One task per IP client: read lines, hand them to the server actor, write
//! back whatever the actor produces.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
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
    let (hangup_tx, mut hangup_rx) = oneshot::channel();

    if events
        .send(Event::Connected {
            id,
            host,
            out: out_tx,
            hangup: Some(hangup_tx),
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
    let ping_interval = opts.ping_interval;
    let ping_enabled = ping_interval > Duration::ZERO;
    let mut idle = tokio::time::interval(if ping_enabled {
        ping_interval
    } else {
        Duration::from_secs(3600)
    });
    idle.tick().await;
    let mut awaiting_pong = false;

    loop {
        line.clear();
        tokio::select! {
            read = read_line_capped(&mut reader, &mut line, MAX_LINE) => {
                match read? {
                    LineRead::Eof => break,
                    LineRead::TooLong => {
                        reason = "Line too long".into();
                        break;
                    }
                    LineRead::Line => {
                        awaiting_pong = false;
                        let text = String::from_utf8_lossy(&line)
                            .trim_end_matches(['\r', '\n'])
                            .to_string();
                        if text.is_empty() {
                            continue;
                        }
                        if events.send(Event::Line { id, line: text }).await.is_err() {
                            break;
                        }
                    }
                }
            }
            _ = idle.tick(), if ping_enabled => {
                if awaiting_pong {
                    reason = "Ping timeout".into();
                    break;
                }
                awaiting_pong = true;
                if pinger.send("PING :keepalive".to_string()).is_err() {
                    break;
                }
            }
            _ = &mut hangup_rx => {
                reason = "Dropped".into();
                break;
            }
        }
    }

    let _ = events.send(Event::Disconnected { id, reason }).await;
    writer.abort();
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum LineRead {
    Line,
    Eof,
    TooLong,
}

/// Read one IRC line without ever buffering more than `max` bytes. The length
/// check in the old `read_until` path ran *after* the whole line was in
/// memory, so a pre-auth socket sending gigabytes with no newline was an OOM.
async fn read_line_capped<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<LineRead> {
    line.clear();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(if line.is_empty() {
                LineRead::Eof
            } else {
                LineRead::TooLong
            });
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            let n = pos + 1;
            if line.len().saturating_add(n) > max {
                reader.consume(n);
                return Ok(LineRead::TooLong);
            }
            line.extend_from_slice(&available[..n]);
            reader.consume(n);
            return Ok(LineRead::Line);
        }
        if line.len().saturating_add(available.len()) > max {
            let n = available.len();
            reader.consume(n);
            return Ok(LineRead::TooLong);
        }
        let n = available.len();
        line.extend_from_slice(available);
        reader.consume(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn caps_lines_without_a_newline() {
        let huge = vec![b'A'; 10_000];
        let mut reader = BufReader::new(huge.as_slice());
        let mut line = Vec::new();
        let result = read_line_capped(&mut reader, &mut line, 512)
            .await
            .unwrap();
        assert_eq!(result, LineRead::TooLong);
        assert!(line.len() <= 512);
    }

    #[tokio::test]
    async fn accepts_a_normal_line() {
        let mut reader = BufReader::new(&b"NICK alice\r\n"[..]);
        let mut line = Vec::new();
        assert_eq!(
            read_line_capped(&mut reader, &mut line, 512).await.unwrap(),
            LineRead::Line
        );
        assert_eq!(line, b"NICK alice\r\n");
    }
}
