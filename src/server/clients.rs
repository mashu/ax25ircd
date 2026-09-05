//! The connected IP clients and the lines going out to them.
//!
//! One rule holds this together: **the server task must never wait on a
//! socket.** It is the single task every connection and every received frame
//! passes through, so a blocking write there is a stall for everybody.
//!
//! That forces the queues to be bounded, which in turn forces a decision about
//! what to do when one fills. The answer is to drop the client: a connection
//! that has stopped reading has already failed, and the alternative — an
//! unbounded queue — trades one broken client for the whole process.

use std::collections::HashMap;

use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use crate::audit::Audit;

use super::state::ClientId;

/// One client's write side.
struct Link {
    out: mpsc::Sender<String>,
    /// Fired by the server when it drops the client (QUIT/KILL/timeout) so the
    /// connection task actually closes the socket, rather than leaving a
    /// zombie that no longer counts toward `max_conns_per_host`.
    hangup: Option<oneshot::Sender<()>>,
}

pub struct Clients {
    links: HashMap<ClientId, Link>,
    audit: Audit,
}

impl Clients {
    pub fn new(audit: Audit) -> Self {
        Self {
            links: HashMap::new(),
            audit,
        }
    }

    pub fn insert(
        &mut self,
        id: ClientId,
        out: mpsc::Sender<String>,
        hangup: Option<oneshot::Sender<()>>,
    ) {
        self.links.insert(id, Link { out, hangup });
    }

    pub fn ids(&self) -> Vec<ClientId> {
        self.links.keys().copied().collect()
    }

    /// Write one line, or drop the client.
    ///
    /// Returns false if the client is gone, so the caller can decide whether
    /// that needs following up. Nothing here blocks.
    pub fn send(&mut self, id: ClientId, line: String) -> bool {
        let full = match self.links.get(&id) {
            Some(link) => match link.out.try_send(line) {
                Ok(()) => return true,
                Err(mpsc::error::TrySendError::Full(_)) => true,
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            },
            None => return false,
        };
        if full {
            let id_s = id.to_string();
            self.audit.event("output_overflow", &[("id", &id_s)]);
            warn!(client = id, "output queue full; dropping the connection");
        }
        self.disconnect(id);
        false
    }

    /// Close the socket. Dropping the output channel stops the writer; firing
    /// `hangup` stops the reader, which makes the connection task emit
    /// `Disconnected` so the user is cleaned up from the top of the event loop.
    ///
    /// Doing it that way rather than cleaning up inline matters: a client
    /// dropped mid-send would otherwise re-enter the send path for every other
    /// member of every shared channel — recursion through the whole userbase,
    /// from inside a write.
    pub fn disconnect(&mut self, id: ClientId) {
        if let Some(link) = self.links.remove(&id) {
            if let Some(h) = link.hangup {
                let _ = h.send(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_whose_queue_fills_is_dropped_not_buffered() {
        let mut clients = Clients::new(Audit::open(None));
        let (tx, _rx) = mpsc::channel(2);
        clients.insert(1, tx, None);

        assert!(clients.send(1, "one".into()));
        assert!(clients.send(1, "two".into()));
        // The queue is full and the reader is not draining it.
        assert!(!clients.send(1, "three".into()));
        assert!(
            clients.ids().is_empty(),
            "the client should have been dropped rather than queued without limit"
        );
        // Sending to a client that is gone is a no-op, not a panic.
        assert!(!clients.send(1, "four".into()));
    }

    #[test]
    fn disconnecting_fires_the_hangup_so_the_socket_closes() {
        let mut clients = Clients::new(Audit::open(None));
        let (tx, _rx) = mpsc::channel(8);
        let (hangup, mut wait) = oneshot::channel();
        clients.insert(7, tx, Some(hangup));
        assert_eq!(clients.ids(), vec![7]);

        clients.disconnect(7);
        assert!(
            wait.try_recv().is_ok(),
            "the reader task needs the hangup or the socket becomes a zombie"
        );
        assert!(clients.ids().is_empty());
        // Idempotent.
        clients.disconnect(7);
    }
}
