//! Store-and-forward for stations that are not currently in range.
//!
//! Packet radio is intermittent by nature: a station is on a hilltop for
//! twenty minutes, then in a valley for two hours. Without this, a private
//! message to a station that happens to be out of range is simply lost, which
//! is a poor fit for how people actually use packet.
//!
//! Deliberate limits: the mailbox is bounded per station, bounded in total,
//! and everything expires. A gateway is not a mail server, and a queue that
//! can grow without limit is a queue that will eventually be used as one.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::callsign::Callsign;

#[derive(Clone, Debug)]
pub struct StoredMessage {
    pub from: String,
    pub text: String,
    pub notice: bool,
    /// A policy limit shortened this before it was held, so the station is
    /// told the same thing a live recipient would have been.
    pub truncated: bool,
    pub stored_at: Instant,
}

impl StoredMessage {
    pub fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.stored_at)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    Disabled,
    StationFull,
    GatewayFull,
}

pub struct Mailbox {
    pub enabled: bool,
    per_station: usize,
    total: usize,
    ttl: Duration,
    boxes: HashMap<Callsign, VecDeque<StoredMessage>>,
}

impl Mailbox {
    pub fn new(enabled: bool, per_station: usize, total: usize, ttl: Duration) -> Self {
        Self {
            enabled,
            per_station,
            total,
            ttl,
            boxes: HashMap::new(),
        }
    }

    pub fn store(
        &mut self,
        to: &Callsign,
        message: StoredMessage,
    ) -> Result<usize, StoreError> {
        if !self.enabled || self.per_station == 0 {
            return Err(StoreError::Disabled);
        }
        if self.len() >= self.total {
            return Err(StoreError::GatewayFull);
        }
        let queue = self.boxes.entry(to.clone()).or_default();
        if queue.len() >= self.per_station {
            return Err(StoreError::StationFull);
        }
        queue.push_back(message);
        Ok(queue.len())
    }


    /// Remove and return at most `n` messages, oldest first.
    ///
    /// Held mail is delivered a little at a time rather than all at once. Ten
    /// messages released the instant a station is heard is a minute of
    /// near-continuous transmitting triggered by one short frame — and the
    /// station may be a handheld that has come into range for thirty seconds.
    /// Draining one per exchange lets the station's own activity set the pace.
    pub fn take_some(&mut self, call: &Callsign, n: usize) -> Vec<StoredMessage> {
        let Some(queue) = self.boxes.get_mut(call) else {
            return Vec::new();
        };
        let out: Vec<StoredMessage> = queue.drain(..n.min(queue.len())).collect();
        if queue.is_empty() {
            self.boxes.remove(call);
        }
        out
    }

    pub fn depth(&self, call: &Callsign) -> usize {
        self.boxes.get(call).map(|q| q.len()).unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.boxes.values().map(|q| q.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Stations with mail waiting, and how much.
    pub fn summary(&self) -> Vec<(Callsign, usize)> {
        let mut rows: Vec<(Callsign, usize)> = self
            .boxes
            .iter()
            .filter(|(_, q)| !q.is_empty())
            .map(|(c, q)| (c.clone(), q.len()))
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows
    }

    /// Drop messages older than the TTL. Returns how many were dropped.
    pub fn expire(&mut self, now: Instant) -> usize {
        let ttl = self.ttl;
        let mut dropped = 0;
        for queue in self.boxes.values_mut() {
            let before = queue.len();
            queue.retain(|m| m.age(now) < ttl);
            dropped += before - queue.len();
        }
        self.boxes.retain(|_, q| !q.is_empty());
        dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(text: &str) -> StoredMessage {
        StoredMessage {
            from: "alice".into(),
            text: text.into(),
            notice: false,
            truncated: false,
            stored_at: Instant::now(),
        }
    }

    fn call() -> Callsign {
        "SM0ABC-7".parse().unwrap()
    }

    #[test]
    fn stores_and_delivers_in_order() {
        let mut mb = Mailbox::new(true, 4, 100, Duration::from_secs(3600));
        assert_eq!(mb.store(&call(), msg("one")).unwrap(), 1);
        assert_eq!(mb.store(&call(), msg("two")).unwrap(), 2);
        let taken = mb.take_some(&call(), usize::MAX);
        assert_eq!(
            taken.iter().map(|m| m.text.as_str()).collect::<Vec<_>>(),
            vec!["one", "two"]
        );
        assert!(mb.is_empty());
    }

    #[test]
    fn take_some_drains_a_little_at_a_time() {
        let mut mb = Mailbox::new(true, 8, 100, Duration::from_secs(3600));
        for t in ["a", "b", "c"] {
            mb.store(&call(), msg(t)).unwrap();
        }
        let first = mb.take_some(&call(), 1);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].text, "a");
        assert_eq!(mb.depth(&call()), 2);
        assert_eq!(mb.take_some(&call(), 10).len(), 2);
        assert!(mb.is_empty());
        assert!(mb.take_some(&call(), 1).is_empty());
    }

    #[test]
    fn bounded_per_station_and_overall() {
        let mut mb = Mailbox::new(true, 2, 3, Duration::from_secs(3600));
        mb.store(&call(), msg("a")).unwrap();
        mb.store(&call(), msg("b")).unwrap();
        assert_eq!(mb.store(&call(), msg("c")), Err(StoreError::StationFull));

        let other: Callsign = "SM0XYZ".parse().unwrap();
        mb.store(&other, msg("d")).unwrap();
        assert_eq!(mb.store(&other, msg("e")), Err(StoreError::GatewayFull));
    }

    #[test]
    fn messages_expire() {
        let mut mb = Mailbox::new(true, 4, 100, Duration::from_secs(60));
        mb.store(&call(), msg("old")).unwrap();
        let later = Instant::now() + Duration::from_secs(120);
        assert_eq!(mb.expire(later), 1);
        assert!(mb.take_some(&call(), 10).is_empty());
    }

    #[test]
    fn disabled_mailbox_refuses() {
        let mut mb = Mailbox::new(false, 4, 100, Duration::from_secs(60));
        assert_eq!(mb.store(&call(), msg("x")), Err(StoreError::Disabled));
    }
}
