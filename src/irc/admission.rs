//! Connection admission that runs at accept time, before TLS.
//!
//! Caps and KLIMEs used to be checked only after `Event::Connected`, which is
//! after the handshake. A flood of TCP connects then spent file descriptors,
//! tasks and CPU without counting toward `max_clients`. This gate reserves a
//! slot as soon as `accept` returns; dropping the slot when the connection
//! task ends.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::irc::message::lower;

fn host_key(host: &str) -> String {
    // Same folding as `accounts::host_ban_key`. Kept here so this module does
    // not depend on `accounts` (that crate-path already uses `irc::message`).
    let trimmed = host.trim().trim_matches(|c| c == '[' || c == ']');
    let lowered = lower(trimmed);
    if let Ok(ip) = lowered.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => v4.to_string(),
            std::net::IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(|v4| v4.to_string())
                .unwrap_or_else(|| v6.to_string()),
        };
    }
    lowered
}

/// Why a socket was refused before IRC framing started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deny {
    Banned,
    Full,
    PerHost,
}

impl Deny {
    pub fn error_line(self, host: &str, max_clients: usize, max_conns_per_host: u32) -> String {
        match self {
            Deny::Banned => "ERROR :Banned from this server".into(),
            Deny::Full => format!("ERROR :Server is full (max {max_clients} clients)"),
            Deny::PerHost => {
                format!("ERROR :Too many connections from {host} (max {max_conns_per_host})")
            }
        }
    }

    pub fn audit_reason(self) -> &'static str {
        match self {
            Deny::Banned => "kline",
            Deny::Full => "max_clients",
            Deny::PerHost => "max_conns_per_host",
        }
    }
}

/// Shared between every IRC listener and the server actor (for KLINE).
pub struct Admission {
    max_clients: usize,
    max_conns_per_host: u32,
    total: AtomicU64,
    per_host: Mutex<HashMap<String, u32>>,
    bans: Mutex<HashSet<String>>,
}

/// A reserved connection slot. Released on drop, including TLS handshake
/// failures and hangups that never reach `Event::Connected`.
pub struct Slot {
    admission: Arc<Admission>,
    host_key: String,
    counted_total: bool,
    counted_host: bool,
}

impl Admission {
    pub fn new(max_clients: usize, max_conns_per_host: u32) -> Arc<Self> {
        Arc::new(Self {
            max_clients,
            max_conns_per_host,
            total: AtomicU64::new(0),
            per_host: Mutex::new(HashMap::new()),
            bans: Mutex::new(HashSet::new()),
        })
    }

    pub fn max_clients(&self) -> usize {
        self.max_clients
    }

    pub fn max_conns_per_host(&self) -> u32 {
        self.max_conns_per_host
    }

    pub fn ban(&self, host: &str) {
        let key = host_key(host);
        if key.is_empty() {
            return;
        }
        self.bans
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key);
    }

    pub fn unban(&self, host: &str) {
        let key = host_key(host);
        self.bans
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&key);
    }

    pub fn load_bans<I, S>(&self, hosts: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut bans = self.bans.lock().unwrap_or_else(|e| e.into_inner());
        bans.clear();
        for host in hosts {
            let key = host_key(host.as_ref());
            if !key.is_empty() {
                bans.insert(key);
            }
        }
    }

    /// Reserve a slot for `host`. The caller must hold the returned [`Slot`]
    /// until the connection task exits.
    pub fn try_acquire(self: &Arc<Self>, host: &str) -> Result<Slot, Deny> {
        let host_key = host_key(host);
        {
            let bans = self.bans.lock().unwrap_or_else(|e| e.into_inner());
            if bans.contains(&host_key) {
                return Err(Deny::Banned);
            }
        }

        let mut counted_total = false;
        if self.max_clients > 0 {
            let n = self.total.fetch_add(1, Ordering::AcqRel) + 1;
            if n > self.max_clients as u64 {
                self.total.fetch_sub(1, Ordering::AcqRel);
                return Err(Deny::Full);
            }
            counted_total = true;
        }

        let mut counted_host = false;
        if self.max_conns_per_host > 0 {
            let mut map = self.per_host.lock().unwrap_or_else(|e| e.into_inner());
            let entry = map.entry(host_key.clone()).or_insert(0);
            if *entry >= self.max_conns_per_host {
                drop(map);
                if counted_total {
                    self.total.fetch_sub(1, Ordering::AcqRel);
                }
                return Err(Deny::PerHost);
            }
            *entry += 1;
            counted_host = true;
        }

        Ok(Slot {
            admission: Arc::clone(self),
            host_key,
            counted_total,
            counted_host,
        })
    }

    fn release(&self, host_key: &str, counted_total: bool, counted_host: bool) {
        if counted_total {
            self.total.fetch_sub(1, Ordering::AcqRel);
        }
        if counted_host {
            let mut map = self.per_host.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(n) = map.get_mut(host_key) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    map.remove(host_key);
                }
            }
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.admission
            .release(&self.host_key, self.counted_total, self.counted_host);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_table_refuses_the_next_socket() {
        let gate = Admission::new(2, 0);
        let a = gate.try_acquire("10.0.0.1").unwrap();
        let b = gate.try_acquire("10.0.0.2").unwrap();
        assert!(matches!(gate.try_acquire("10.0.0.3"), Err(Deny::Full)));
        drop(a);
        assert!(gate.try_acquire("10.0.0.3").is_ok());
        drop(b);
    }

    #[test]
    fn per_host_cap_is_independent_of_the_global_one() {
        let gate = Admission::new(10, 2);
        let _a = gate.try_acquire("203.0.113.9").unwrap();
        let _b = gate.try_acquire("203.0.113.9").unwrap();
        assert!(matches!(
            gate.try_acquire("203.0.113.9"),
            Err(Deny::PerHost)
        ));
        assert!(gate.try_acquire("203.0.113.10").is_ok());
    }

    #[test]
    fn kline_is_checked_before_the_handshake() {
        let gate = Admission::new(10, 8);
        gate.ban("[::ffff:203.0.113.9]");
        assert!(matches!(gate.try_acquire("203.0.113.9"), Err(Deny::Banned)));
        gate.unban("203.0.113.9");
        assert!(gate.try_acquire("203.0.113.9").is_ok());
    }

    #[test]
    fn zero_means_unlimited() {
        let gate = Admission::new(0, 0);
        for i in 0..50 {
            assert!(gate.try_acquire(&format!("10.0.0.{i}")).is_ok());
        }
    }
}
