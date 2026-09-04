//! Control-operator audit trail: who connected, what was claimed, what
//! went on the air. Written from the server task (no extra locking).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::warn;

pub struct Audit {
    file: Option<File>,
}

impl Audit {
    pub fn open(path: Option<&str>) -> Self {
        let file = path.and_then(|p| match open_append(p) {
            Ok(f) => {
                tracing::info!(path = p, "audit log enabled");
                Some(f)
            }
            Err(e) => {
                warn!(path = p, "cannot open audit log: {e}");
                None
            }
        });
        Self { file }
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
        if let Some(f) = self.file.as_mut() {
            let _ = writeln!(f, "{line}");
            let _ = f.flush();
        }
    }
}

fn open_append(path: &str) -> std::io::Result<File> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    OpenOptions::new().create(true).append(true).open(path)
}
