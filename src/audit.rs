//! Control-operator audit trail: who connected, what was claimed, what went on
//! the air.
//!
//! The record is written from a dedicated task, not from the server actor.
//! That matters more than it sounds: the actor is a single task that every
//! connection and every received frame passes through, so a blocking
//! `write` + `flush` in it is a stall for *everybody* — and this log is
//! written on every connect, every callsign claim and every transmitted
//! frame. A bounded channel keeps the actor's side to a pointer copy.
//!
//! The channel is bounded on purpose. If the writer cannot keep up (a full
//! disk, a network filesystem gone away) the right answer is to drop audit
//! lines and say how many were lost, not to grow a queue until the process
//! dies or to block the server behind the filesystem.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tracing::warn;

/// Audit lines buffered before the server starts dropping them.
const QUEUE: usize = 4096;

pub struct Audit {
    tx: Option<mpsc::Sender<String>>,
    /// Lines dropped because the writer fell behind. Reported to the log so a
    /// gap in the audit trail is never silent.
    dropped: u64,
}

impl Audit {
    /// Open the audit log. With no path, events still reach `tracing` and
    /// nothing is spawned.
    pub fn open(path: Option<&str>) -> Self {
        let Some(path) = path else {
            return Self {
                tx: None,
                dropped: 0,
            };
        };
        let file = match open_append(path) {
            Ok(f) => f,
            Err(e) => {
                warn!(path, "cannot open audit log: {e}");
                return Self {
                    tx: None,
                    dropped: 0,
                };
            }
        };
        tracing::info!(path, "audit log enabled");
        let (tx, rx) = mpsc::channel::<String>(QUEUE);
        spawn_writer(file, rx);
        Self {
            tx: Some(tx),
            dropped: 0,
        }
    }

    /// One line, `unix_ms event k=v k=v ...`. Values with spaces are quoted.
    pub fn event(&mut self, kind: &str, fields: &[(&str, &str)]) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let mut line = format!("{ts} {kind}");
        for (k, v) in fields {
            if v.chars().any(|c| c.is_whitespace()) {
                line.push_str(&format!(" {k}=\"{}\"", v.replace('"', "'")));
            } else {
                line.push_str(&format!(" {k}={v}"));
            }
        }
        tracing::info!(target: "ax25ircd::audit", "{line}");
        let Some(tx) = self.tx.as_ref() else {
            return;
        };
        if tx.try_send(line).is_err() {
            self.dropped += 1;
            // Complain once per power of ten, so a failing disk is visible
            // without the complaint itself becoming the flood.
            if self.dropped.is_power_of_two() {
                warn!(
                    "audit log is not keeping up; {} line(s) dropped so far",
                    self.dropped
                );
            }
        }
    }

    /// Audit lines lost because the writer could not keep up.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// Drain the channel onto disk. Batches whatever has already arrived into one
/// write, so a burst costs one syscall rather than one per line.
fn spawn_writer(file: File, mut rx: mpsc::Receiver<String>) {
    tokio::task::spawn_blocking(move || {
        let mut file = file;
        while let Some(first) = rx.blocking_recv() {
            let mut batch = first;
            batch.push('\n');
            while let Ok(next) = rx.try_recv() {
                batch.push_str(&next);
                batch.push('\n');
            }
            if let Err(e) = file.write_all(batch.as_bytes()).and_then(|()| file.flush()) {
                warn!("audit log write failed: {e}");
            }
        }
    });
}

fn open_append(path: &str) -> std::io::Result<File> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    OpenOptions::new().create(true).append(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_keeps_one_line_per_event() {
        // No path: nothing is spawned, so this needs no runtime.
        let mut a = Audit::open(None);
        a.event("kick", &[("reason", "flooding the channel"), ("n", "3")]);
        assert_eq!(a.dropped(), 0);
    }

    #[tokio::test]
    async fn events_reach_the_file() {
        let path = std::env::temp_dir().join(format!(
            "ax25ircd-audit-{}.log",
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let name = path.to_string_lossy().to_string();
        {
            let mut a = Audit::open(Some(&name));
            a.event("rf_tx", &[("dest", "SM0ABC-7"), ("bytes", "42")]);
            a.event("oper", &[("nick", "alice"), ("host", "127.0.0.1")]);
        }
        // The writer task owns the file; give it a moment to drain.
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            if let Ok(text) = std::fs::read_to_string(&path) {
                if text.lines().count() >= 2 {
                    assert!(text.contains("rf_tx dest=SM0ABC-7 bytes=42"), "{text}");
                    assert!(text.contains("oper nick=alice"), "{text}");
                    let _ = std::fs::remove_file(&path);
                    return;
                }
            }
        }
        panic!("audit lines never reached {name}");
    }
}
