//! Per-station session state: sequencing, fragmentation, retransmission,
//! duplicate suppression and reassembly.
//!
//! The module is deliberately pure - it never touches the clock or the radio
//! itself, it is driven with an explicit `now` and returns the frames the
//! caller should transmit. That makes the awkward parts (timeouts, retries,
//! reassembly races) testable without a radio or a sleeping test.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use crate::callsign::Callsign;

use super::frame::{flags, AircFrame, Kind, HEADER_LEN};

#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// AX.25 information-field budget in octets (`paclen`). 256 is the AX.25
    /// default; 128 gets through a noisy channel far more often.
    pub paclen: usize,
    pub ack_timeout: Duration,
    pub max_retries: u32,
    pub reassembly_timeout: Duration,
    /// A station we have not heard from in this long is forgotten (and its
    /// IRC-side ghost is removed).
    pub peer_idle_timeout: Duration,
    /// Messages queued per station before we start refusing.
    pub max_queue: usize,
    /// How many recent sequence numbers to remember per station for dedup.
    pub dedup_window: usize,
    /// Stations we will remember at once. Further callsigns are ignored until
    /// an idle peer expires, so a flood of unique sources cannot grow forever.
    pub max_peers: usize,
    /// Incomplete fragmented messages kept per station.
    pub max_reasm: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            paclen: 128,
            ack_timeout: Duration::from_secs(12),
            max_retries: 3,
            reassembly_timeout: Duration::from_secs(60),
            peer_idle_timeout: Duration::from_secs(30 * 60),
            max_queue: 16,
            dedup_window: 64,
            max_peers: 256,
            max_reasm: 4,
        }
    }
}

impl SessionConfig {
    pub fn max_payload(&self) -> usize {
        self.paclen.saturating_sub(HEADER_LEN).max(1)
    }
}

struct Pending {
    frames: Vec<AircFrame>,
    attempts: u32,
    next_retry: Instant,
}

struct Reassembly {
    kind: Kind,
    flags: u8,
    parts: Vec<Option<Vec<u8>>>,
    started: Instant,
}

/// One station heard on the air.
pub struct Peer {
    pub call: Callsign,
    pub channels: HashSet<String>,
    pub first_heard: Instant,
    pub last_heard: Instant,
    /// Set once the station has sent HELLO and passed policy checks.
    pub registered: bool,
    /// Frames dropped for this peer, for `RADIO HEARD`.
    pub dropped: u64,
    pending: Option<Pending>,
    queue: VecDeque<Vec<AircFrame>>,
    seen: VecDeque<u16>,
    reasm: HashMap<u16, Reassembly>,
    /// Channels this station was KICKed from. A following MSG must not
    /// silently rejoin — that made KICK a no-op on RF.
    kicked: HashSet<String>,
}

impl Peer {
    fn new(call: Callsign, now: Instant) -> Self {
        Self {
            call,
            channels: HashSet::new(),
            first_heard: now,
            last_heard: now,
            registered: false,
            dropped: 0,
            pending: None,
            queue: VecDeque::new(),
            seen: VecDeque::new(),
            reasm: HashMap::new(),
            kicked: HashSet::new(),
        }
    }

    pub fn was_kicked_from(&self, channel: &str) -> bool {
        self.kicked.contains(channel)
    }

    pub fn mark_kicked(&mut self, channel: &str) {
        self.kicked.insert(channel.to_string());
        self.channels.remove(channel);
    }

    pub fn clear_kicked(&mut self, channel: &str) {
        self.kicked.remove(channel);
    }

    pub fn queue_depth(&self) -> usize {
        self.queue.len() + usize::from(self.pending.is_some())
    }

    /// True when a reliable message is on the air or waiting for ACK.
    pub fn awaiting_ack(&self) -> bool {
        self.pending.is_some()
    }
}

#[derive(Default)]
pub struct RxOutcome {
    /// A complete message from the station, ready for the bridge.
    pub deliver: Option<AircFrame>,
    /// Frames to put on the air right now (ACKs).
    pub transmit: Vec<AircFrame>,
    /// True if the frame was a duplicate we had already processed.
    pub duplicate: bool,
}

#[derive(Default)]
pub struct TickOutcome {
    pub transmit: Vec<(Callsign, AircFrame)>,
    /// Stations that stopped acknowledging or went quiet; the bridge removes
    /// their IRC presence.
    pub lost: Vec<Callsign>,
}

/// Result of [`Sessions::enqueue`].
pub struct SendOutcome {
    pub frames: Vec<AircFrame>,
    pub accepted: bool,
}

impl SendOutcome {
    fn dropped() -> Self {
        Self {
            frames: Vec::new(),
            accepted: false,
        }
    }
}

pub struct Sessions {
    pub config: SessionConfig,
    peers: HashMap<Callsign, Peer>,
    /// One sequence space for everything this station transmits.
    ///
    /// It has to be shared rather than per destination: a receiver
    /// deduplicates on (source, seq), and it sees our unicast traffic and our
    /// broadcasts as one stream. Per-peer counters would hand out the same
    /// sequence number twice and the second message would be silently
    /// discarded as a duplicate.
    next_seq: u16,
    /// Peers removed by [`Sessions::force_touch`] to make room. The server
    /// turns these into IRC QUITs; without that, the user stays in channels
    /// forever because idle expiry only walks the session table.
    evicted: Vec<Callsign>,
    /// Callsigns a control operator removed with `RADIO KICK`. Independent of
    /// the peer table: `forget` would otherwise let the next MSG recreate them.
    radio_kicked: HashSet<Callsign>,
}

impl Sessions {
    pub fn new(config: SessionConfig) -> Self {
        Self {
            config,
            peers: HashMap::new(),
            next_seq: 1,
            evicted: Vec::new(),
            radio_kicked: HashSet::new(),
        }
    }

    /// Stations dropped from the table to make room for an outgoing message.
    pub fn take_evicted(&mut self) -> Vec<Callsign> {
        std::mem::take(&mut self.evicted)
    }

    /// `RADIO KICK` removes the station and refuses to invent a JOIN from the
    /// next PRIVMSG. HELLO or JOIN lets them back.
    pub fn ban(&mut self, call: &Callsign) {
        self.radio_kicked.insert(call.clone());
    }

    pub fn lift_ban(&mut self, call: &Callsign) {
        self.radio_kicked.remove(call);
    }

    pub fn is_banned(&self, call: &Callsign) -> bool {
        self.radio_kicked.contains(call)
    }

    /// Allocate the next outgoing sequence number. Public because broadcasts
    /// are not addressed to a peer but must share the same space.
    pub fn next_seq(&mut self) -> u16 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        if self.next_seq == 0 {
            self.next_seq = 1;
        }
        seq
    }

    pub fn peer(&self, call: &Callsign) -> Option<&Peer> {
        self.peers.get(call)
    }

    pub fn peer_mut(&mut self, call: &Callsign) -> Option<&mut Peer> {
        self.peers.get_mut(call)
    }

    pub fn peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers.values()
    }

    pub fn touch(&mut self, call: &Callsign, now: Instant) -> Option<&mut Peer> {
        if !self.peers.contains_key(call) && self.peers.len() >= self.config.max_peers {
            return None;
        }
        let peer = self
            .peers
            .entry(call.clone())
            .or_insert_with(|| Peer::new(call.clone(), now));
        peer.last_heard = now;
        Some(peer)
    }

    /// Unlike [`Sessions::touch`], evicts the quietest peer if the table is
    /// full so a legitimate outgoing message is never dropped on the floor.
    pub fn force_touch(&mut self, call: &Callsign, now: Instant) -> &mut Peer {
        if !self.peers.contains_key(call) && self.peers.len() >= self.config.max_peers {
            if let Some(oldest) = self
                .peers
                .iter()
                .min_by_key(|(_, p)| p.last_heard)
                .map(|(c, _)| c.clone())
            {
                self.peers.remove(&oldest);
                self.evicted.push(oldest);
            }
        }
        self.touch(call, now).expect("force_touch made room")
    }

    pub fn forget(&mut self, call: &Callsign) {
        self.peers.remove(call);
    }

    /// Handle a frame received from `src`.
    pub fn on_receive(&mut self, src: &Callsign, frame: AircFrame, now: Instant) -> RxOutcome {
        let cfg = self.config.clone();
        let Some(peer) = self.touch(src, now) else {
            return RxOutcome::default();
        };
        let mut out = RxOutcome::default();

        if frame.kind == Kind::Ack {
            let acked = frame
                .payload
                .get(0..2)
                .map(|b| u16::from_be_bytes([b[0], b[1]]));
            if let (Some(acked), Some(p)) = (acked, peer.pending.as_ref()) {
                if p.frames.first().map(|f| f.seq) == Some(acked) {
                    peer.pending = None;
                    if let Some(next) = peer.queue.pop_front() {
                        out.transmit = start_pending(peer, next, now, &cfg);
                    }
                }
            }
            return out;
        }

        if peer.seen.contains(&frame.seq) {
            out.duplicate = true;
            // A duplicate of an already-delivered message is still ACKed:
            // the usual reason for a repeat is that our ACK was lost.
            // Incomplete fragments are not in `seen` and are not ACKed.
            if frame.wants_ack() {
                out.transmit.push(ack_for(frame.seq));
            }
            return out;
        }

        if frame.frag_total == 1 {
            if frame.wants_ack() {
                out.transmit.push(ack_for(frame.seq));
            }
            remember_seq(peer, frame.seq, cfg.dedup_window);
            out.deliver = Some(frame);
            return out;
        }

        // Fragmented message: stash and wait for the rest. ACK only when the
        // last missing fragment arrives (PROTOCOL.md §5). ACKing fragment 0
        // would let the sender drop the rest of the message.
        if frame.payload.len() > cfg.max_payload() {
            return out;
        }
        if !peer.reasm.contains_key(&frame.seq) && peer.reasm.len() >= cfg.max_reasm {
            if let Some(oldest) = peer
                .reasm
                .iter()
                .min_by_key(|(_, r)| r.started)
                .map(|(s, _)| *s)
            {
                peer.reasm.remove(&oldest);
            }
        }
        let entry = peer.reasm.entry(frame.seq).or_insert_with(|| Reassembly {
            kind: frame.kind,
            flags: frame.flags,
            parts: vec![None; frame.frag_total as usize],
            started: now,
        });
        if entry.parts.len() != frame.frag_total as usize {
            *entry = Reassembly {
                kind: frame.kind,
                flags: frame.flags,
                parts: vec![None; frame.frag_total as usize],
                started: now,
            };
        }
        entry.parts[frame.frag_index as usize] = Some(frame.payload.clone());
        let complete = entry.parts.iter().all(|p| p.is_some());
        if !complete {
            return out;
        }

        let mut payload = Vec::new();
        for part in entry.parts.iter().flatten() {
            payload.extend_from_slice(part);
        }
        let (kind, flg) = (entry.kind, entry.flags);
        peer.reasm.remove(&frame.seq);
        remember_seq(peer, frame.seq, cfg.dedup_window);
        if frame.wants_ack() || flg & flags::ACK_REQ != 0 {
            out.transmit.push(ack_for(frame.seq));
        }
        out.deliver = Some(AircFrame::new(kind, frame.seq, payload).with_flags(flg));
        out
    }

    /// Would a reliable send to `dst` be accepted rather than dropped?
    ///
    /// Held mail uses this so a message is not taken out of the mailbox only
    /// to be refused by a full per-station queue. Unreliable traffic is never
    /// queued, so it is always accepted here.
    pub fn can_accept(&self, dst: &Callsign) -> bool {
        match self.peers.get(dst) {
            Some(peer) if peer.pending.is_some() => peer.queue.len() < self.config.max_queue,
            _ => true,
        }
    }

    /// Queue a message for `dst`, fragmenting as needed. Returns the frames to
    /// transmit immediately (empty if something is already in flight and this
    /// message had to be queued behind it).
    pub fn send(
        &mut self,
        dst: &Callsign,
        kind: Kind,
        payload: Vec<u8>,
        reliable: bool,
        now: Instant,
    ) -> Vec<AircFrame> {
        self.enqueue(dst, kind, payload, reliable, now).frames
    }

    /// As [`Sessions::send`], but says whether the message was accepted.
    ///
    /// Empty frames used to mean both "queued behind something in flight" and
    /// "dropped". Held mail needs the difference: only the latter must leave
    /// the message in the mailbox.
    pub fn enqueue(
        &mut self,
        dst: &Callsign,
        kind: Kind,
        payload: Vec<u8>,
        reliable: bool,
        now: Instant,
    ) -> SendOutcome {
        let cfg = self.config.clone();
        let seq = self.next_seq();
        let peer = self.force_touch(dst, now);
        let chunks: Vec<&[u8]> = if payload.is_empty() {
            vec![&[]]
        } else {
            payload.chunks(cfg.max_payload()).collect()
        };
        if chunks.len() > u8::MAX as usize {
            peer.dropped += 1;
            return SendOutcome::dropped();
        }
        let total = chunks.len() as u8;
        let frames: Vec<AircFrame> = chunks
            .into_iter()
            .enumerate()
            .map(|(i, chunk)| {
                let mut f = AircFrame::new(kind, seq, chunk.to_vec());
                f.frag_index = i as u8;
                f.frag_total = total;
                if reliable {
                    f.flags |= flags::ACK_REQ;
                }
                f
            })
            .collect();

        if !reliable {
            return SendOutcome {
                frames,
                accepted: true,
            };
        }
        if peer.pending.is_some() {
            if peer.queue.len() >= cfg.max_queue {
                peer.dropped += 1;
                return SendOutcome::dropped();
            }
            peer.queue.push_back(frames);
            return SendOutcome {
                frames: Vec::new(),
                accepted: true,
            };
        }
        SendOutcome {
            frames: start_pending(peer, frames, now, &cfg),
            accepted: true,
        }
    }

    /// Drive timers: retransmissions, reassembly expiry, idle stations.
    pub fn tick(&mut self, now: Instant) -> TickOutcome {
        self.tick_retries(now, true)
    }

    /// As [`Sessions::tick`], but when `retry` is false the session does not
    /// retransmit or give up. Used while the transmitter cannot key up —
    /// interlock down *or* `RADIO OFF` — because burning ACK attempts against
    /// a held or purged queue would declare the station lost.
    pub fn tick_retries(&mut self, now: Instant, retry: bool) -> TickOutcome {
        let cfg = self.config.clone();
        let mut out = TickOutcome::default();
        let mut giving_up = Vec::new();

        for (call, peer) in self.peers.iter_mut() {
            peer.reasm
                .retain(|_, r| now.duration_since(r.started) < cfg.reassembly_timeout);

            if now.duration_since(peer.last_heard) > cfg.peer_idle_timeout {
                out.lost.push(call.clone());
                continue;
            }

            if !retry {
                continue;
            }

            let Some(pending) = peer.pending.as_mut() else {
                continue;
            };
            if now < pending.next_retry {
                continue;
            }
            if pending.attempts >= cfg.max_retries {
                giving_up.push(call.clone());
                continue;
            }
            pending.attempts += 1;
            pending.next_retry = now + backoff(&cfg, pending.attempts);
            for f in &pending.frames {
                let mut f = f.clone();
                f.flags |= flags::RETRY;
                out.transmit.push((call.clone(), f));
            }
        }

        for call in giving_up {
            if let Some(peer) = self.peers.get_mut(&call) {
                peer.pending = None;
                peer.dropped += 1;
                if let Some(next) = peer.queue.pop_front() {
                    for f in start_pending(peer, next, now, &cfg) {
                        out.transmit.push((call.clone(), f));
                    }
                } else {
                    // Nothing left to say and the station is not answering.
                    out.lost.push(call.clone());
                }
            }
        }

        for call in &out.lost {
            self.peers.remove(call);
        }
        out
    }
}

fn ack_for(seq: u16) -> AircFrame {
    AircFrame::new(Kind::Ack, seq, seq.to_be_bytes().to_vec())
}

fn start_pending(
    peer: &mut Peer,
    frames: Vec<AircFrame>,
    now: Instant,
    cfg: &SessionConfig,
) -> Vec<AircFrame> {
    peer.pending = Some(Pending {
        frames: frames.clone(),
        attempts: 0,
        next_retry: now + backoff(cfg, 1),
    });
    frames
}

fn backoff(cfg: &SessionConfig, attempt: u32) -> Duration {
    // Linear backoff. Exponential is wrong on a shared half-duplex channel:
    // the usual cause of loss is a collision, and waiting minutes just makes
    // the QSO unusable.
    cfg.ack_timeout * attempt.min(4)
}

fn remember_seq(peer: &mut Peer, seq: u16, window: usize) {
    peer.seen.push_back(seq);
    while peer.seen.len() > window {
        peer.seen.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airc::frame::encode_fields;

    fn call() -> Callsign {
        "SM0ABC-7".parse().unwrap()
    }

    #[test]
    fn fragments_and_reassembles() {
        let cfg = SessionConfig {
            paclen: HEADER_LEN + 4,
            ..Default::default()
        };
        let mut tx = Sessions::new(cfg.clone());
        let mut rx = Sessions::new(cfg);
        let now = Instant::now();

        let frames = tx.send(&call(), Kind::Msg, b"abcdefghij".to_vec(), true, now);
        assert_eq!(frames.len(), 3);

        let mut delivered = None;
        for f in frames {
            let out = rx.on_receive(&call(), f, now);
            if out.deliver.is_some() {
                delivered = out.deliver;
            }
        }
        assert_eq!(delivered.unwrap().payload, b"abcdefghij");
    }

    #[test]
    fn duplicates_are_suppressed_but_still_acked() {
        let mut rx = Sessions::new(SessionConfig::default());
        let now = Instant::now();
        let f = AircFrame::new(Kind::Msg, 9, encode_fields(&["#rf", "hi"]))
            .with_flags(flags::ACK_REQ);

        let first = rx.on_receive(&call(), f.clone(), now);
        assert!(first.deliver.is_some());
        assert_eq!(first.transmit.len(), 1);

        let second = rx.on_receive(&call(), f, now);
        assert!(second.deliver.is_none());
        assert!(second.duplicate);
        assert_eq!(second.transmit.len(), 1, "a repeat means our ACK was lost");
    }

    #[test]
    fn retransmits_then_gives_up() {
        let cfg = SessionConfig {
            ack_timeout: Duration::from_secs(10),
            max_retries: 2,
            ..Default::default()
        };
        let mut s = Sessions::new(cfg);
        let mut now = Instant::now();
        assert_eq!(s.send(&call(), Kind::Msg, b"x".to_vec(), true, now).len(), 1);

        now += Duration::from_secs(11);
        assert_eq!(s.tick(now).transmit.len(), 1);
        now += Duration::from_secs(21);
        assert_eq!(s.tick(now).transmit.len(), 1);
        now += Duration::from_secs(31);
        let out = s.tick(now);
        assert!(out.transmit.is_empty());
        assert_eq!(out.lost, vec![call()]);
    }

    #[test]
    fn a_blocked_transmitter_does_not_burn_retry_attempts() {
        let cfg = SessionConfig {
            ack_timeout: Duration::from_secs(10),
            max_retries: 2,
            ..Default::default()
        };
        let mut s = Sessions::new(cfg);
        let mut now = Instant::now();
        assert_eq!(s.send(&call(), Kind::Msg, b"x".to_vec(), true, now).len(), 1);

        // Well past every retry deadline, but the transmitter cannot key up.
        now += Duration::from_secs(120);
        let out = s.tick_retries(now, false);
        assert!(out.transmit.is_empty());
        assert!(out.lost.is_empty(), "giving up would drop a message still held in the TNC");
        assert!(s.peer(&call()).is_some(), "the session must still be waiting");

        // Once it can transmit, the first retry is still available.
        let out = s.tick_retries(now, true);
        assert_eq!(out.transmit.len(), 1);
        assert!(out.lost.is_empty());
    }

    #[test]
    fn ack_releases_the_queue() {
        let mut s = Sessions::new(SessionConfig::default());
        let now = Instant::now();
        let first = s.send(&call(), Kind::Msg, b"one".to_vec(), true, now);
        let queued = s.send(&call(), Kind::Msg, b"two".to_vec(), true, now);
        assert!(queued.is_empty(), "second message waits for the first ACK");

        let seq = first[0].seq;
        let ack = AircFrame::new(Kind::Ack, seq, seq.to_be_bytes().to_vec());
        let out = s.on_receive(&call(), ack, now);
        assert_eq!(out.transmit.len(), 1);
        assert_eq!(out.transmit[0].payload, b"two");
    }

    #[test]
    fn sequence_numbers_are_not_reused_across_peers() {
        let mut s = Sessions::new(SessionConfig::default());
        let now = Instant::now();
        let other: Callsign = "SM0XYZ".parse().unwrap();
        let a = s.send(&call(), Kind::Msg, b"one".to_vec(), false, now)[0].seq;
        let b = s.send(&other, Kind::Msg, b"two".to_vec(), false, now)[0].seq;
        let c = s.next_seq();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn queue_is_bounded() {
        let cfg = SessionConfig {
            max_queue: 2,
            ..Default::default()
        };
        let mut s = Sessions::new(cfg);
        let now = Instant::now();
        for _ in 0..5 {
            s.send(&call(), Kind::Msg, b"spam".to_vec(), true, now);
        }
        let peer = s.peer(&call()).unwrap();
        assert_eq!(peer.queue_depth(), 3);
        assert_eq!(peer.dropped, 2);
        assert!(
            !s.can_accept(&call()),
            "a full queue must be visible before the next send refuses"
        );
    }

    #[test]
    fn reliable_fragments_are_acked_only_when_complete() {
        let cfg = SessionConfig {
            paclen: HEADER_LEN + 4,
            ..Default::default()
        };
        let mut tx = Sessions::new(cfg.clone());
        let mut rx = Sessions::new(cfg);
        let now = Instant::now();
        let frames = tx.send(&call(), Kind::Msg, b"abcdefghij".to_vec(), true, now);
        assert_eq!(frames.len(), 3);

        let first = rx.on_receive(&call(), frames[0].clone(), now);
        assert!(first.deliver.is_none());
        assert!(
            first.transmit.is_empty(),
            "ACKing fragment 0 lets the sender drop the rest"
        );

        let second = rx.on_receive(&call(), frames[1].clone(), now);
        assert!(second.deliver.is_none());
        assert!(second.transmit.is_empty());

        let last = rx.on_receive(&call(), frames[2].clone(), now);
        assert_eq!(last.deliver.unwrap().payload, b"abcdefghij");
        assert_eq!(last.transmit.len(), 1);
        assert_eq!(last.transmit[0].kind, Kind::Ack);
        assert_eq!(last.transmit[0].payload, frames[0].seq.to_be_bytes());
    }

    #[test]
    fn peer_table_is_bounded() {
        let cfg = SessionConfig {
            max_peers: 2,
            ..Default::default()
        };
        let mut s = Sessions::new(cfg);
        let now = Instant::now();
        let a: Callsign = "SM0AAA-1".parse().unwrap();
        let b: Callsign = "SM0BBB-1".parse().unwrap();
        let c: Callsign = "SM0CCC-1".parse().unwrap();
        assert!(s.touch(&a, now).is_some());
        assert!(s.touch(&b, now).is_some());
        assert!(s.touch(&c, now).is_none(), "a third peer must not grow the table");
        s.force_touch(&c, now);
        assert_eq!(s.peers().count(), 2);
        assert_eq!(
            s.take_evicted().len(),
            1,
            "the quietest station must be reported so IRC can drop the ghost"
        );
    }
}
