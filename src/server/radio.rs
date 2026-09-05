//! Putting something on the air.
//!
//! Every transmission the gateway makes goes through this module, and that is
//! the point: the rules about airtime are only worth anything if there is no
//! second way round them. The invariants it owns are
//!
//! * **Admission.** A message is priced in seconds of key-down time and
//!   checked against the backlog budget for its class *before* the session
//!   layer accepts it — because once that happens an ACK timer is running and
//!   the message costs up to `max_retries` transmissions, not one.
//! * **Identification.** The station knows whether it owes the band a
//!   callsign, and identification is the one thing that outranks the operator
//!   inhibit (though not the safety interlock).
//! * **Fragmentation.** How many frames a payload becomes, and therefore what
//!   it really costs, is known here and nowhere else.
//!
//! The airtime governor itself lives in [`crate::ax25::airtime`], inside the
//! TNC task. This module decides *whether* to hand it something; the governor
//! decides *when* that something is keyed.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, warn};

use crate::airc::{encode_fields, AircFrame, Kind, SessionConfig, Sessions};
use crate::audit::Audit;
use crate::ax25::{AirtimeShared, Ax25Frame, TncHandle};
use crate::callsign::Callsign;
use crate::config::Config;

use super::mailbox::Mailbox;

/// What a frame is *for*, which decides how much of the transmit backlog it
/// may occupy.
///
/// A single FIFO is the wrong shape for a shared, thermally limited channel:
/// a burst of channel chat would fill it and the ACK that would have ended a
/// retry cycle waits behind ten seconds of gossip — costing more airtime than
/// the chat did. Each class may fill only a fraction of the backlog budget,
/// so protocol traffic always has room and conversation is what gets squeezed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TxClass {
    /// Acknowledgements. Cheap, and every one of them prevents a retransmit.
    Ack,
    /// Session control: WELCOME, NAMES replies, errors, PONG.
    Control,
    /// Addressed to one station: private messages and held mail.
    Direct,
    /// Channel conversation. The largest source of traffic and the most
    /// tolerant of being dropped, so it is squeezed first.
    Chat,
}

impl TxClass {
    /// Fraction of the backlog budget this class may occupy.
    fn allowance(self) -> f64 {
        match self {
            TxClass::Ack => 1.0,
            TxClass::Control => 0.85,
            TxClass::Direct => 0.7,
            TxClass::Chat => 0.5,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            TxClass::Ack => "ack",
            TxClass::Control => "control",
            TxClass::Direct => "direct",
            TxClass::Chat => "chat",
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct Stats {
    pub rf_frames_rx: u64,
    pub rf_frames_tx: u64,
    pub rf_frames_dropped: u64,
    /// Frames refused before they were queued, because the backlog for their
    /// class was already full.
    pub rf_frames_refused: u64,
    pub rf_bytes_tx: u64,
    pub ip_connections: u64,
}

/// The station's transmit side.
pub struct Radio {
    config: Arc<Config>,
    audit: Audit,
    tnc: Option<TncHandle>,
    /// Per-station sequencing, ACKs and reassembly.
    pub sessions: Sessions,
    /// Messages held for stations that are out of range.
    pub mailbox: Mailbox,
    pub stats: Stats,
    /// Runtime kill switch (`RADIO OFF`). The control operator must be able to
    /// stop the station radiating immediately, without killing the IRC side.
    pub enabled: bool,
    last_id: Instant,
    /// Set by any transmission, cleared by identifying. An automatically
    /// controlled station must identify the series of transmissions it made,
    /// and must not identify when it has made none — that is just QRM.
    transmitted_since_id: bool,
}

impl Radio {
    pub fn new(config: Arc<Config>, tnc: Option<TncHandle>, audit: Audit) -> Self {
        let sessions = Sessions::new(SessionConfig {
            paclen: config.radio.paclen,
            ack_timeout: Duration::from_secs(config.radio.ack_timeout_secs),
            max_retries: config.radio.max_retries,
            peer_idle_timeout: Duration::from_secs(config.radio.peer_idle_timeout_secs),
            ..Default::default()
        });
        let mailbox = Mailbox::new(
            config.radio.mailbox_enabled,
            config.radio.mailbox_per_station,
            config.radio.mailbox_total,
            Duration::from_secs(config.radio.mailbox_ttl_secs),
        );
        Self {
            enabled: config.radio.enabled && tnc.is_some(),
            config,
            audit,
            tnc,
            sessions,
            mailbox,
            stats: Stats::default(),
            last_id: Instant::now(),
            transmitted_since_id: false,
        }
    }

    /// Live airtime counters and the hard transmit inhibit, if there is a TNC.
    pub fn airtime(&self) -> Option<&Arc<AirtimeShared>> {
        self.tnc.as_ref().map(|t| t.airtime())
    }

    /// Stop transmitting now, discarding whatever is already queued. Unlike
    /// `enabled`, which only stops us queueing more, this reaches the frames
    /// already handed to the TNC task.
    pub fn set_tx_inhibit(&self, inhibit: bool) {
        if let Some(tnc) = self.tnc.as_ref() {
            tnc.set_inhibit(inhibit);
        }
    }

    /// Stations currently heard on the air.
    pub fn peers_heard(&self) -> usize {
        self.sessions.peers().count()
    }

    /// The largest payload one AIRC frame can carry at this paclen.
    pub fn max_payload(&self) -> usize {
        self.sessions.config.max_payload()
    }

    pub fn available(&self) -> bool {
        self.enabled && self.tnc.is_some()
    }

    /// Unreliable one-to-many transmission addressed to the protocol's
    /// destination address. Every station in range hears it once.
    pub fn broadcast(&mut self, kind: Kind, payload: Vec<u8>, class: TxClass) {
        self.broadcast_flagged(kind, payload, class, 0)
    }

    /// Reliable one-to-one transmission with ACK and retry.
    pub fn unicast(
        &mut self,
        dst: &Callsign,
        kind: Kind,
        payload: Vec<u8>,
        reliable: bool,
        class: TxClass,
    ) {
        self.unicast_flagged(dst, kind, payload, reliable, class, 0)
    }

    pub fn transmit_to(&mut self, dst: &Callsign, frame: AircFrame) {
        // A retransmission the session layer has already decided on. It is
        // finishing an exchange that is part-way done, so it is not subject to
        // fresh admission control — dropping it here would leave the peer
        // waiting for something that will never arrive.
        self.transmit_direct(dst, frame, TxClass::Control);
    }

    /// Octets this payload will actually put on the wire once fragmented.
    ///
    /// Fragmentation is not free and the naive estimate hides it: each
    /// fragment carries its own AIRC header *and* a full AX.25 address field,
    /// so a payload one octet over the limit costs a whole extra frame — plus
    /// its TXDELAY and TXTAIL, which the governor prices separately.
    pub fn wire_octets(&self, payload: usize) -> usize {
        // AX.25 addresses (source, destination, up to two digipeaters),
        // control, PID and FCS.
        let per_frame = crate::airc::frame::HEADER_LEN + 7 * (2 + self.config.radio.path.len()) + 4;
        let max = self.sessions.config.max_payload();
        let fragments = payload.div_ceil(max).max(1);
        payload + fragments * per_frame
    }

    /// Airtime the transmit queue may hold before new traffic is refused.
    pub fn backlog_budget(&self) -> Duration {
        Duration::from_secs(self.config.radio.max_queued_airtime_secs)
    }

    /// Is there room in the backlog for `octets` of this class?
    ///
    /// This is the decision point that matters. Refusing here means the sender
    /// finds out immediately and can say something shorter or wait; accepting
    /// and then dropping the frame two minutes later at the transmitter means
    /// the message vanished and nobody knows.
    pub fn backlog_has_room(&self, octets: usize, class: TxClass) -> bool {
        let Some(tnc) = self.tnc.as_ref() else {
            return false;
        };
        let budget = self.backlog_budget().mul_f64(class.allowance());
        tnc.queued() + tnc.airtime_for(octets) <= budget
    }

    /// How long a message queued now would wait before it is on the air.
    pub fn eta(&self) -> Duration {
        self.tnc.as_ref().map(|t| t.eta()).unwrap_or_default()
    }

    pub fn transmit_direct(&mut self, dest: &Callsign, frame: AircFrame, class: TxClass) {
        let (Some(tnc), Some(source)) = (self.tnc.as_ref(), self.config.gateway_callsign()) else {
            return;
        };
        if !self.enabled {
            return;
        }
        let info = frame.encode();
        let ax = match Ax25Frame::ui(source, dest.clone(), &self.config.rf_path(), info) {
            Ok(f) => f,
            Err(e) => {
                warn!("cannot build AX.25 frame: {e}");
                return;
            }
        };
        let len = ax.encode().len();
        if tnc.try_send(ax) {
            self.stats.rf_frames_tx += 1;
            self.stats.rf_bytes_tx += len as u64;
            self.transmitted_since_id = true;
            let kind = format!("{:?}", frame.kind);
            let n = len.to_string();
            let dest_s = dest.to_string();
            self.audit.event(
                "rf_tx",
                &[
                    ("dest", &dest_s),
                    ("kind", &kind),
                    ("bytes", &n),
                    ("class", class.as_str()),
                ],
            );
        } else {
            self.stats.rf_frames_dropped += 1;
        }
    }

    /// Deliver mail held for a station we have just heard from.
    ///
    /// A few at a time, not the whole mailbox. Ten held messages released the
    /// instant a HELLO arrives is a minute of near-continuous transmitting
    /// caused by one short frame from a station that may be in range for
    /// thirty seconds. The rest go out on the next thing we hear from them, so
    /// the station's own activity paces the delivery — which is also the only
    /// evidence we have that it is still listening.
    pub fn flush_mailbox(&mut self, call: &Callsign) {
        let depth = self.mailbox.depth(call);
        if depth == 0 {
            return;
        }
        let batch = self.config.radio.mailbox_flush_batch.max(1);
        let now = Instant::now();
        let nick = call.to_nick();
        let messages = self.mailbox.take_some(call, batch);
        let sent = messages.len();
        for m in messages {
            let age = m.age(now).as_secs().to_string();
            let payload = encode_fields(&[&nick, &m.from, &m.text, &age]);
            let flags = if m.truncated {
                crate::airc::frame::flags::TRUNCATED
            } else {
                0
            };
            self.unicast_flagged(call, Kind::Stored, payload, true, TxClass::Direct, flags);
        }
        let remaining = depth.saturating_sub(sent);
        if remaining > 0 {
            debug!(%call, "{remaining} held message(s) still waiting");
        }
    }

    pub fn maybe_identify(&mut self, now: Instant) {
        if !self.available() {
            return;
        }
        if now.duration_since(self.last_id) < self.config.id_interval() {
            return;
        }
        // Only transmit an ID if we have actually transmitted. Identifying an
        // idle station just adds QRM.
        if self.transmitted_since_id {
            self.send_id();
        }
        self.last_id = now;
    }

    /// Identify now if we have transmitted since the last ID. Called before
    /// the transmitter is taken off the air (shutdown, `RADIO OFF`): an
    /// automatically controlled station must identify at the end of a series
    /// of transmissions, not only every ten minutes.
    pub fn id_if_needed(&mut self) {
        if self.transmitted_since_id && self.available() {
            self.send_id();
        }
    }

    fn send_id(&mut self) {
        let text = format!(
            "{} {}",
            self.config.radio.callsign, self.config.radio.id_text
        );
        let payload = encode_fields(&[&text]);
        let dest: Callsign = "ID".parse().unwrap();
        let seq = self.sessions.next_seq();
        let frame = AircFrame::new(Kind::Id, seq, payload);
        self.transmit_id(&dest, frame);
        self.transmitted_since_id = false;
        self.last_id = Instant::now();
        debug!("station identification transmitted");
    }

    /// Identification goes out on the TNC's priority path, so it is not held
    /// behind a backlog and is not discarded by the transmit inhibit. This is
    /// the one frame the station is obliged to send.
    fn transmit_id(&mut self, dest: &Callsign, frame: AircFrame) {
        let (Some(tnc), Some(source)) = (self.tnc.as_ref(), self.config.gateway_callsign()) else {
            return;
        };
        let ax = match Ax25Frame::ui(source, dest.clone(), &self.config.rf_path(), frame.encode()) {
            Ok(f) => f,
            Err(e) => {
                warn!("cannot build station ID frame: {e}");
                return;
            }
        };
        let len = ax.encode().len();
        if tnc.try_send_id(ax) {
            self.stats.rf_frames_tx += 1;
            self.stats.rf_bytes_tx += len as u64;
            let n = len.to_string();
            self.audit.event("rf_id", &[("bytes", &n)]);
        } else {
            self.stats.rf_frames_dropped += 1;
        }
    }

    pub fn status_line(&self) -> String {
        if !self.config.radio.enabled {
            return "Radio gateway is disabled. This is a plain IRC server; nothing is radiated."
                .into();
        }
        let call = &self.config.radio.callsign;
        if !self.enabled {
            return format!(
                "Radio gateway: transmitter OFF. Station {call}. Nothing is being radiated."
            );
        }
        if self.airtime().map(|a| a.interlock_failed()).unwrap_or(false) {
            return format!(
                "Radio gateway: station {call}, transmitter BLOCKED by the safety interlock. \
                 Nothing is being radiated, including station identification."
            );
        }
        if self.tnc.is_none() {
            return format!("Radio gateway: no TNC. Station {call}. Nothing is being radiated.");
        }
        let duty = self
            .airtime()
            .map(|a| format!(" {:.0}% duty.", a.duty_percent()))
            .unwrap_or_default();
        let cooling = self
            .airtime()
            .map(|a| a.cooling_ms.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(0);
        let cooling = if cooling > 0 {
            format!(" PA cooling for {}s.", cooling / 1000)
        } else {
            String::new()
        };
        format!(
            "Radio gateway: transmitter ON, station {call}, {} RF station(s) heard, {} frames TX / {} RX ({} bytes on air).{duty}{cooling}",
            self.sessions.peers().count(),
            self.stats.rf_frames_tx,
            self.stats.rf_frames_rx,
            self.stats.rf_bytes_tx
        )
    }

    /// As [`Radio::broadcast`], with AIRC frame flags — currently only
    /// [`crate::airc::frame::flags::TRUNCATED`], so a receiving station can
    /// show that it is not seeing the whole message.
    pub fn broadcast_flagged(
        &mut self,
        kind: Kind,
        payload: Vec<u8>,
        class: TxClass,
        flags: u8,
    ) {
        if !self.available() {
            return;
        }
        let seq = self.sessions.next_seq();
        let max = self.sessions.config.max_payload();
        let chunks: Vec<Vec<u8>> = if payload.is_empty() {
            vec![Vec::new()]
        } else {
            payload.chunks(max).map(|c| c.to_vec()).collect()
        };
        if chunks.len() > u8::MAX as usize {
            self.stats.rf_frames_dropped += 1;
            return;
        }
        let total = chunks.len() as u8;
        let dest: Callsign = self
            .config
            .radio
            .destination
            .parse()
            .unwrap_or_else(|_| "AIRC".parse().unwrap());
        for (i, chunk) in chunks.into_iter().enumerate() {
            let mut f = AircFrame::new(kind, seq, chunk).with_flags(flags);
            f.frag_index = i as u8;
            f.frag_total = total;
            self.transmit_direct(&dest, f, class);
        }
    }

    /// As [`Radio::unicast`], with extra AIRC frame flags.
    pub fn unicast_flagged(
        &mut self,
        dst: &Callsign,
        kind: Kind,
        payload: Vec<u8>,
        reliable: bool,
        class: TxClass,
        flags: u8,
    ) {
        if !self.available() {
            return;
        }
        // Admission control happens before the session layer sees the message.
        // Once `Sessions::send` accepts it, an ACK timer is running and the
        // message will be retransmitted up to `max_retries` times — so a
        // message admitted when there is no airtime for it does not cost one
        // transmission, it costs four.
        if !self.backlog_has_room(self.wire_octets(payload.len()), class) {
            self.stats.rf_frames_refused += 1;
            return;
        }
        let now = Instant::now();
        let frames = self.sessions.send(dst, kind, payload, reliable, now);
        for f in frames {
            self.transmit_direct(dst, f.with_flags(flags), class);
        }
    }
}
