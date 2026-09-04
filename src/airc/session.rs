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
        }
    }

    pub fn queue_depth(&self) -> usize {
        self.queue.len() + usize::from(self.pending.is_some())
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
}

impl Sessions {
    pub fn new(config: SessionConfig) -> Self {
        Self {
            config,
            peers: HashMap::new(),
            next_seq: 1,
        }
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

    pub fn touch(&mut self, call: &Callsign, now: Instant) -> &mut Peer {
        let peer = self
            .peers
            .entry(call.clone())
            .or_insert_with(|| Peer::new(call.clone(), now));
        peer.last_heard = now;
        peer
    }

    pub fn forget(&mut self, call: &Callsign) {
        self.peers.remove(call);
    }

    /// Handle a frame received from `src`.
    pub fn on_receive(&mut self, src: &Callsign, frame: AircFrame, now: Instant) -> RxOutcome {
        let cfg = self.config.clone();
        let peer = self.touch(src, now);
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

        // Acknowledge before deduplicating: a repeat usually means our ACK was
        // lost, so it needs another one.
        if frame.wants_ack() {
            out.transmit.push(AircFrame::new(
                Kind::Ack,
                frame.seq,
                frame.seq.to_be_bytes().to_vec(),
            ));
        }

        if peer.seen.contains(&frame.seq) {
            out.duplicate = true;
            return out;
        }

        if frame.frag_total == 1 {
            remember_seq(peer, frame.seq, cfg.dedup_window);
            out.deliver = Some(frame);
            return out;
        }

        // Fragmented message: stash and wait for the rest.
        let entry = peer.reasm.entry(frame.seq).or_insert_with(|| Reassembly {
            kind: frame.kind,
            flags: frame.flags,
            parts: vec![None; frame.frag_total as usize],
            started: now,
        });
        if entry.parts.len() != frame.frag_total as usize {
            // Sequence number reused with a different shape; start over.
            *entry = Reassembly {
                kind: frame.kind,
                flags: frame.flags,
                parts: vec![None; frame.frag_total as usize],
                started: now,
            };
        }
        entry.parts[frame.frag_index as usize] = Some(frame.payload.clone());

        if entry.parts.iter().all(|p| p.is_some()) {
            let mut payload = Vec::new();
            for part in entry.parts.iter().flatten() {
                payload.extend_from_slice(part);
            }
            let (kind, flg) = (entry.kind, entry.flags);
            peer.reasm.remove(&frame.seq);
            remember_seq(peer, frame.seq, cfg.dedup_window);
            out.deliver = Some(AircFrame::new(kind, frame.seq, payload).with_flags(flg));
        }
        out
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
        let cfg = self.config.clone();
        let seq = self.next_seq();
        let peer = self.touch(dst, now);
        let chunks: Vec<&[u8]> = if payload.is_empty() {
            vec![&[]]
        } else {
            payload.chunks(cfg.max_payload()).collect()
        };
        if chunks.len() > u8::MAX as usize {
            peer.dropped += 1;
            return Vec::new();
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
            return frames;
        }
        if peer.pending.is_some() {
            if peer.queue.len() >= cfg.max_queue {
                peer.dropped += 1;
                return Vec::new();
            }
            peer.queue.push_back(frames);
            return Vec::new();
        }
        start_pending(peer, frames, now, &cfg)
    }

    /// Drive timers: retransmissions, reassembly expiry, idle stations.
    pub fn tick(&mut self, now: Instant) -> TickOutcome {
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
    }
}
