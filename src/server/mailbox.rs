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

    pub fn store(&mut self, to: &Callsign, message: StoredMessage) -> Result<usize, StoreError> {
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

    /// The oldest message waiting for a station, without removing it.
    ///
    /// Delivery is peek-then-drop rather than take-then-send, because a held
    /// message is the only copy there is: taking it out and then failing to
    /// transmit it would destroy it.
    pub fn peek(&self, call: &Callsign) -> Option<&StoredMessage> {
        self.boxes.get(call).and_then(|q| q.front())
    }

    /// Discard the oldest message for a station, once it has been handed to
    /// the transmitter.
    pub fn drop_front(&mut self, call: &Callsign) -> Option<StoredMessage> {
        let queue = self.boxes.get_mut(call)?;
        let msg = queue.pop_front();
        if queue.is_empty() {
            self.boxes.remove(call);
        }
        msg
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
        let mut taken = Vec::new();
        while let Some(m) = mb.drop_front(&call()) {
            taken.push(m.text);
        }
        assert_eq!(taken, vec!["one", "two"]);
        assert!(mb.is_empty());
    }

    #[test]
    fn peek_does_not_remove_and_drop_front_does() {
        let mut mb = Mailbox::new(true, 4, 100, Duration::from_secs(3600));
        mb.store(&call(), msg("first")).unwrap();
        mb.store(&call(), msg("second")).unwrap();

        assert_eq!(mb.peek(&call()).map(|m| m.text.as_str()), Some("first"));
        assert_eq!(mb.depth(&call()), 2, "peeking must not consume");

        assert_eq!(mb.drop_front(&call()).map(|m| m.text), Some("first".into()));
        assert_eq!(mb.peek(&call()).map(|m| m.text.as_str()), Some("second"));
        mb.drop_front(&call());
        assert!(mb.is_empty());
        assert!(mb.peek(&call()).is_none());
        assert!(mb.drop_front(&call()).is_none());
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
        assert!(mb.peek(&call()).is_none());
    }

    #[test]
    fn disabled_mailbox_refuses() {
        let mut mb = Mailbox::new(false, 4, 100, Duration::from_secs(60));
        assert_eq!(mb.store(&call(), msg("x")), Err(StoreError::Disabled));
    }
}
