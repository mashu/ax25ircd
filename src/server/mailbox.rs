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

    /// Remove and return everything waiting for a station.
    pub fn take(&mut self, call: &Callsign) -> Vec<StoredMessage> {
        self.boxes
            .remove(call)
            .map(|q| q.into_iter().collect())
            .unwrap_or_default()
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
        let taken = mb.take(&call());
        assert_eq!(
            taken.iter().map(|m| m.text.as_str()).collect::<Vec<_>>(),
            vec!["one", "two"]
        );
        assert!(mb.is_empty());
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
        assert!(mb.take(&call()).is_empty());
    }

    #[test]
    fn disabled_mailbox_refuses() {
        let mut mb = Mailbox::new(false, 4, 100, Duration::from_secs(60));
        assert_eq!(mb.store(&call(), msg("x")), Err(StoreError::Disabled));
    }
}
