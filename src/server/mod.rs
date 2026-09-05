//! The server actor: one task, one state, one ordering of events.

pub mod commands;
pub mod mailbox;
pub mod state;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::accounts::Accounts;
use crate::airc::{encode_fields, AircFrame, Kind, SessionConfig, Sessions};
use crate::audit::Audit;
use crate::ax25::{Ax25Frame, TncHandle};
use crate::callsign::Callsign;
use crate::config::Config;
use crate::irc::message::{lower, Message};
use crate::policy::Policy;

use mailbox::Mailbox;
use state::{ClientId, State, User, UserId};

/// Everything that can happen to the server, from any source.
#[derive(Debug)]
pub enum Event {
    Connected {
        id: ClientId,
        host: String,
        out: mpsc::Sender<String>,
        /// Fired by the server when it drops the user (QUIT/KILL/timeout)
        /// so the connection task actually closes the socket.
        hangup: Option<oneshot::Sender<()>>,
    },
    Line {
        id: ClientId,
        line: String,
    },
    Disconnected {
        id: ClientId,
        reason: String,
    },
    /// Argon2 finished off the event loop.
    AuthFinished {
        id: ClientId,
        kind: AuthKind,
        nick: String,
        result: Result<(), crate::accounts::AccountError>,
        password_hash: Option<String>,
    },
    /// A frame heard on the air.
    Rf(Ax25Frame),
    /// Periodic housekeeping: retransmissions, timeouts, station ID.
    Tick,
    Shutdown,
}

#[derive(Debug, Clone, Copy)]
pub enum AuthKind {
    Identify,
    Register,
    Unregister,
}

struct IpLink {
    out: mpsc::Sender<String>,
    hangup: Option<oneshot::Sender<()>>,
}

/// A thing that happened, in a form that can be rendered either as IRC text or
/// as an on-air AIRC frame. Keeping these separate from the wire formats is
/// what lets one event reach a hardware TNC and an IRC client with the right
/// representation for each.
#[derive(Clone, Debug)]
pub enum Delivery {
    Privmsg {
        from_nick: String,
        from_prefix: String,
        target: String,
        text: String,
        notice: bool,
        /// The text was shortened by a policy limit before transmission. IRC
        /// clients see the ellipsis; RF stations get the protocol's
        /// `TRUNCATED` flag as well, so a station can render it distinctly.
        truncated: bool,
    },
    Join {
        nick: String,
        prefix: String,
        channel: String,
    },
    Part {
        nick: String,
        prefix: String,
        channel: String,
        reason: String,
    },
    Quit {
        nick: String,
        prefix: String,
        reason: String,
    },
    NickChange {
        old_nick: String,
        prefix: String,
        new_nick: String,
    },
    Topic {
        nick: String,
        prefix: String,
        channel: String,
        topic: String,
    },
}

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

pub struct Server {
    pub config: Arc<Config>,
    pub state: State,
    pub policy: Policy,
    pub sessions: Sessions,
    /// Messages held for stations that are out of range.
    pub mailbox: Mailbox,
    pub stats: Stats,
    pub accounts: Accounts,
    pub audit: Audit,
    tnc: Option<TncHandle>,
    outputs: HashMap<ClientId, IpLink>,
    /// Used to run Argon2 off this task. Tests leave it unset and hash inline.
    events: Option<mpsc::Sender<Event>>,
    /// Runtime kill switch for the transmitter (`RADIO OFF`). The control
    /// operator must be able to stop the station radiating, immediately,
    /// without killing the IRC side.
    pub rf_enabled: bool,
    last_id: Instant,
    transmitted_since_id: bool,
    started: SystemTime,
}

impl Server {
    pub fn new(config: Arc<Config>, tnc: Option<TncHandle>) -> Self {
        let sessions = Sessions::new(SessionConfig {
            paclen: config.radio.paclen,
            ack_timeout: Duration::from_secs(config.radio.ack_timeout_secs),
            max_retries: config.radio.max_retries,
            peer_idle_timeout: Duration::from_secs(config.radio.peer_idle_timeout_secs),
            ..Default::default()
        });
        let mut state = State::default();
        for ch in &config.channels {
            let chan = state.ensure_channel(&ch.name, ch.rf);
            chan.configured = true;
            if !ch.topic.is_empty() {
                chan.topic = Some(ch.topic.clone());
                chan.topic_setter = config.server.name.clone();
            }
            chan.operators = ch
                .operators
                .iter()
                .map(|n| lower(n))
                .collect();
        }
        // The configured text length is only an upper bound. What actually
        // decides the airtime is how many AX.25 frames the message becomes,
        // so clamp the text limit to whatever fits in `max_rf_fragments`
        // frames at this paclen. Fragmentation multiplies the airtime *and*
        // the loss rate — a message is only delivered if every fragment
        // arrives, and a retry resends all of them.
        let mut policy_config = config.policy.clone();
        let per_frame = sessions.config.max_payload();
        // Leave room for the AIRC field separators and the target/sender
        // fields that ride along with the text.
        let fragment_cap = per_frame
            .saturating_mul(policy_config.max_rf_fragments.max(1))
            .saturating_sub(48);
        if fragment_cap > 0 && fragment_cap < policy_config.max_rf_text_len {
            info!(
                "capping RF message length to {fragment_cap} characters: \
                 policy.max_rf_fragments = {} at paclen {}",
                policy_config.max_rf_fragments, config.radio.paclen
            );
            policy_config.max_rf_text_len = fragment_cap;
        }
        let policy = Policy::new(policy_config);
        let mailbox = Mailbox::new(
            config.radio.mailbox_enabled,
            config.radio.mailbox_per_station,
            config.radio.mailbox_total,
            Duration::from_secs(config.radio.mailbox_ttl_secs),
        );
        let accounts = match Accounts::load(&config.accounts.file) {
            Ok(a) => a,
            Err(e) => {
                warn!(
                    path = %config.accounts.file,
                    "nick accounts file unreadable ({e}); starting empty"
                );
                Accounts::empty(&config.accounts.file)
            }
        };
        let audit = Audit::open(config.logging.audit_file.as_deref());
        Self {
            rf_enabled: config.radio.enabled && tnc.is_some(),
            config,
            state,
            policy,
            sessions,
            mailbox,
            stats: Stats::default(),
            accounts,
            audit,
            tnc,
            outputs: HashMap::new(),
            events: None,
            last_id: Instant::now(),
            transmitted_since_id: false,
            started: SystemTime::now(),
        }
    }

    pub fn attach_events(&mut self, tx: mpsc::Sender<Event>) {
        self.events = Some(tx);
    }

    pub fn server_name(&self) -> &str {
        &self.config.server.name
    }

    pub fn uptime(&self) -> Duration {
        self.started.elapsed().unwrap_or_default()
    }

    // ---------------------------------------------------------------- events

    pub fn handle(&mut self, event: Event) {
        let now = Instant::now();
        match event {
            Event::Connected {
                id,
                host,
                out,
                hangup,
            } => {
                // Two caps, because the per-host one bounds nothing on its
                // own: an attacker with a hundred source addresses is under it
                // on every one of them.
                let total = self.config.listen.max_clients;
                let per_host = self.config.listen.max_conns_per_host;
                let refuse = if total > 0 && self.state.ip_users() >= total {
                    Some(("max_clients", format!("ERROR :Server is full (max {total} clients)")))
                } else if per_host > 0
                    && self.state.ip_count_from_host(&host) >= per_host as usize
                {
                    Some((
                        "max_conns_per_host",
                        format!("ERROR :Too many connections from {host} (max {per_host})"),
                    ))
                } else {
                    None
                };
                if let Some((reason, message)) = refuse {
                    let _ = out.try_send(message);
                    if let Some(h) = hangup {
                        let _ = h.send(());
                    }
                    self.audit
                        .event("connect_denied", &[("host", &host), ("reason", reason)]);
                    return;
                }
                self.outputs.insert(id, IpLink { out, hangup });
                self.stats.ip_connections += 1;
                let id_s = id.to_string();
                self.audit.event("connect", &[("id", &id_s), ("host", &host)]);
                let user = User::new(UserId::Ip(id), host, now);
                self.state.insert_user(user);
            }
            Event::Line { id, line } => {
                if let Some(msg) = Message::parse(&line) {
                    self.handle_client_message(id, msg);
                }
            }
            Event::Disconnected { id, reason } => {
                let uid = UserId::Ip(id);
                if let Some(u) = self.state.user(&uid) {
                    self.audit.event(
                        "disconnect",
                        &[
                            ("nick", &u.nick),
                            ("host", &u.host),
                            ("reason", &reason),
                        ],
                    );
                }
                self.quit_user(&uid, &reason);
            }
            Event::AuthFinished {
                id,
                kind,
                nick,
                result,
                password_hash,
            } => {
                self.finish_auth(id, kind, nick, result, password_hash);
            }
            Event::Rf(frame) => self.handle_rf_frame(frame, now),
            Event::Tick => self.tick(now),
            Event::Shutdown => self.shutdown(),
        }
    }

    fn tick(&mut self, now: Instant) {
        let outcome = self.sessions.tick(now);
        for (call, frame) in outcome.transmit {
            self.transmit_to(&call, frame);
        }
        for call in outcome.lost {
            let uid = UserId::Rf(call.clone());
            if self.state.user(&uid).is_some() {
                info!(%call, "station timed out");
                self.quit_user(&uid, "Signal lost");
            }
        }
        self.policy.expire(now);
        let dropped = self.mailbox.expire(now);
        if dropped > 0 {
            debug!("{dropped} held messages expired");
        }
        self.maybe_identify(now);
        self.expire_unregistered(now);
        self.expire_unidentified(now);
    }

    /// Drop connections that never finished the NICK/USER handshake. Open
    /// sockets that never register are the cheapest denial of service there
    /// is.
    fn expire_unregistered(&mut self, now: Instant) {
        let limit = Duration::from_secs(self.config.listen.registration_timeout_secs);
        let stale: Vec<UserId> = self
            .state
            .users
            .values()
            .filter(|u| !u.registered && !u.is_rf() && now.duration_since(u.connected_at) > limit)
            .map(|u| u.id.clone())
            .collect();
        for uid in stale {
            if let UserId::Ip(id) = uid {
                self.send_raw(id, "ERROR :Registration timeout".into());
            }
            self.quit_user(&uid, "Registration timeout");
        }
    }

    /// A registered nick that was never IDENTIFY'd is released.
    fn expire_unidentified(&mut self, now: Instant) {
        let stale: Vec<UserId> = self
            .state
            .users
            .values()
            .filter(|u| {
                !u.is_rf()
                    && !u.nick_identified
                    && u.identify_by.map(|d| now >= d).unwrap_or(false)
            })
            .map(|u| u.id.clone())
            .collect();
        for uid in stale {
            let old = self
                .state
                .user(&uid)
                .map(|u| u.nick.clone())
                .unwrap_or_default();
            let guest = format!("Guest{}", match uid {
                UserId::Ip(id) => id,
                UserId::Rf(_) => 0,
            });
            if let Some(u) = self.state.user_mut(&uid) {
                u.identify_by = None;
            }
            if self.state.nick_taken(&guest) {
                self.notice_user(&uid, "This nick is registered. Disconnecting.");
                if let UserId::Ip(id) = uid {
                    self.send_raw(id, "ERROR :Identify timeout on a registered nick".into());
                }
                self.quit_user(&uid, "Identify timeout");
                continue;
            }
            let prefix = self.state.user(&uid).map(|u| u.prefix()).unwrap_or_default();
            let _ = self.state.set_nick(&uid, &guest);
            let d = Delivery::NickChange {
                old_nick: old.clone(),
                prefix,
                new_nick: guest.clone(),
            };
            self.broadcast_peers(&uid, &d, true);
            self.notice_user(
                &uid,
                &format!("{old} is registered. Your nick is now {guest}. IDENTIFY to reclaim it."),
            );
            self.refresh_privileges(&uid);
            self.audit.event(
                "identify_timeout",
                &[("old", &old), ("guest", &guest)],
            );
        }
    }

    fn shutdown(&mut self) {
        // Identify at the end of a transmission series, as required of an
        // automatically controlled station.
        self.id_if_needed();
        for id in self.outputs.keys().copied().collect::<Vec<_>>() {
            self.send_raw(id, "ERROR :Server shutting down".to_string());
        }
    }

    // ------------------------------------------------------------- IP output

    /// Write one line to an IP client.
    ///
    /// The per-client queue is bounded. It has to be: the server task cannot
    /// block on a socket, so a client that stops reading — a laptop that slept,
    /// a deliberately silent connection joined to a busy channel — would
    /// otherwise grow its queue until the process runs out of memory. When the
    /// queue is full the client is disconnected. Losing one slow reader is the
    /// correct trade against losing the server.
    pub fn send_raw(&mut self, id: ClientId, line: String) {
        let full = match self.outputs.get(&id) {
            Some(link) => match link.out.try_send(line) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Full(_)) => true,
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            },
            None => return,
        };
        if full {
            let id_s = id.to_string();
            self.audit
                .event("output_overflow", &[("id", &id_s)]);
            warn!(client = id, "output queue full; dropping the connection");
        }
        // Only drop the link here. Firing `hangup` makes the connection task
        // emit `Disconnected`, which runs `quit_user` from the top of the
        // event loop. Calling it inline instead would re-enter `send_raw` for
        // every other member of every shared channel — recursion through the
        // whole userbase, from inside a send.
        self.drop_ip_link(id);
    }

    /// Close the TCP connection. Dropping the output channel stops the writer;
    /// firing `hangup` stops the reader, so the socket is not left as a zombie
    /// that no longer counts toward `max_conns_per_host`.
    fn drop_ip_link(&mut self, id: ClientId) {
        if let Some(link) = self.outputs.remove(&id) {
            if let Some(h) = link.hangup {
                let _ = h.send(());
            }
        }
    }


    /// Send a numeric reply. RF users never receive numerics: they are pure
    /// airtime with no information a small screen needs.
    pub fn numeric(&mut self, uid: &UserId, code: &str, params: &[&str]) {
        let UserId::Ip(id) = uid else { return };
        let nick = self
            .state
            .user(uid)
            .map(|u| u.nick.clone())
            .unwrap_or_else(|| "*".into());
        let mut p = vec![nick];
        p.extend(params.iter().map(|s| s.to_string()));
        let msg = Message::new(code, p).with_prefix(self.server_name().to_string());
        self.send_raw(*id, msg.to_string());
    }

    pub fn notice_user(&mut self, uid: &UserId, text: &str) {
        match uid {
            UserId::Ip(id) => {
                let nick = self
                    .state
                    .user(uid)
                    .map(|u| u.nick.clone())
                    .unwrap_or_else(|| "*".into());
                let msg = Message::new("NOTICE", vec![nick, text.to_string()])
                    .with_prefix(self.server_name().to_string());
                self.send_raw(*id, msg.to_string());
            }
            UserId::Rf(call) => {
                // A server notice to a station is a courtesy, not a message
                // somebody sent. Keep it to one frame and do not retry it:
                // "your message was shortened" is not worth four transmissions.
                let call = call.clone();
                let text: String = text.chars().take(80).collect();
                let payload = encode_fields(&["*", &text]);
                self.unicast(&call, Kind::Notice, payload, false, TxClass::Control);
            }
        }
    }

    // ------------------------------------------------------------- delivery

    pub fn deliver(&mut self, uid: &UserId, d: &Delivery) {
        match uid.clone() {
            UserId::Ip(id) => {
                if let Some(line) = render_irc(d) {
                    self.send_raw(id, line);
                }
            }
            UserId::Rf(call) => self.deliver_rf(&call, d),
        }
    }

    fn deliver_rf(&mut self, call: &Callsign, d: &Delivery) {
        match d {
            Delivery::Privmsg {
                from_nick,
                target,
                text,
                notice,
                truncated,
                ..
            } => {
                let kind = if *notice { Kind::Notice } else { Kind::Msg };
                let payload = encode_fields(&[target, from_nick, text]);
                let flags = if *truncated {
                    crate::airc::frame::flags::TRUNCATED
                } else {
                    0
                };
                // Channel traffic goes out once as a broadcast; a private
                // message is unicast and acknowledged.
                if target.starts_with('#') || target.starts_with('&') {
                    self.broadcast_flagged(kind, payload, TxClass::Chat, flags);
                } else {
                    self.unicast_flagged(call, kind, payload, true, TxClass::Direct, flags);
                }
            }
            // Presence is off by default and is the lowest-value traffic
            // there is: a transmission to say somebody opened a window.
            Delivery::Join { nick, channel, .. } if self.config.radio.presence_notices => {
                let payload = encode_fields(&[channel, nick, "+"]);
                self.broadcast(Kind::Presence, payload, TxClass::Chat);
            }
            Delivery::Part { nick, channel, .. } if self.config.radio.presence_notices => {
                let payload = encode_fields(&[channel, nick, "-"]);
                self.broadcast(Kind::Presence, payload, TxClass::Chat);
            }
            Delivery::Topic {
                nick,
                channel,
                topic,
                ..
            } => {
                let topic: String = topic.chars().take(64).collect();
                let payload = encode_fields(&[channel, nick, &topic]);
                self.broadcast(Kind::Notice, payload, TxClass::Chat);
            }
            // Quits, nick changes and (by default) presence are not worth the
            // airtime.
            _ => {}
        }
    }

    /// Send to every member of a channel, optionally skipping one user.
    /// Broadcast RF deliveries are deduplicated: a channel message is put on
    /// the air once, not once per listening station.
    pub fn broadcast_channel(&mut self, channel: &str, d: &Delivery, except: Option<&UserId>) {
        self.broadcast_channel_ex(channel, d, except, true);
    }

    /// `allow_rf = false` keeps the event on the wire only. That is the right
    /// choice when the event *came* from the air (every station in range
    /// already heard it) or when policy refused to let it be transmitted.
    pub fn broadcast_channel_ex(
        &mut self,
        channel: &str,
        d: &Delivery,
        except: Option<&UserId>,
        allow_rf: bool,
    ) {
        let members = self.state.members(channel);
        let mut rf_done = false;
        for uid in members {
            if Some(&uid) == except {
                continue;
            }
            if uid.is_rf() {
                if !allow_rf || rf_done {
                    continue;
                }
                rf_done = true;
            }
            self.deliver(&uid, d);
        }
    }

    pub fn broadcast_peers(&mut self, uid: &UserId, d: &Delivery, include_self: bool) {
        let mut targets = self.state.peers_of(uid);
        if include_self {
            targets.push(uid.clone());
        }
        let mut rf_done = false;
        for t in targets {
            if t.is_rf() {
                if rf_done {
                    continue;
                }
                rf_done = true;
            }
            self.deliver(&t, d);
        }
    }

    // ------------------------------------------------------------------- RF

    pub fn rf_available(&self) -> bool {
        self.rf_enabled && self.tnc.is_some()
    }

    /// Live airtime counters from the TNC task, if there is one.
    pub fn airtime(&self) -> Option<&std::sync::Arc<crate::ax25::AirtimeShared>> {
        self.tnc.as_ref().map(|t| t.airtime())
    }

    /// The hard transmit inhibit that the TNC task honours. Unlike
    /// `rf_enabled` (which only stops us *queueing* new frames) this also
    /// discards whatever is already queued.
    pub fn set_tx_inhibit(&self, inhibit: bool) {
        if let Some(tnc) = self.tnc.as_ref() {
            tnc.set_inhibit(inhibit);
        }
    }

    /// Unreliable one-to-many transmission addressed to the protocol's
    /// destination address. Every station in range hears it once.
    pub fn broadcast(&mut self, kind: Kind, payload: Vec<u8>, class: TxClass) {
        self.broadcast_flagged(kind, payload, class, 0)
    }

    /// As [`Server::broadcast`], with AIRC frame flags — currently only
    /// [`crate::airc::frame::flags::TRUNCATED`], so a receiving station can
    /// show that it is not seeing the whole message.
    pub fn broadcast_flagged(
        &mut self,
        kind: Kind,
        payload: Vec<u8>,
        class: TxClass,
        flags: u8,
    ) {
        if !self.rf_available() {
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

    /// As [`Server::unicast`], with extra AIRC frame flags.
    pub fn unicast_flagged(
        &mut self,
        dst: &Callsign,
        kind: Kind,
        payload: Vec<u8>,
        reliable: bool,
        class: TxClass,
        flags: u8,
    ) {
        if !self.rf_available() {
            return;
        }
        // Admission control happens before the session layer sees the message.
        // Once `Sessions::send` accepts it, an ACK timer is running and the
        // message will be retransmitted up to `max_retries` times — so a
        // message admitted when there is no airtime for it does not cost one
        // transmission, it costs four.
        if !self.rf_backlog_has_room(self.wire_octets(payload.len()), class) {
            self.stats.rf_frames_refused += 1;
            return;
        }
        let now = Instant::now();
        let frames = self.sessions.send(dst, kind, payload, reliable, now);
        for f in frames {
            self.transmit_direct(dst, f.with_flags(flags), class);
        }
    }

    fn transmit_to(&mut self, dst: &Callsign, frame: AircFrame) {
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
    fn wire_octets(&self, payload: usize) -> usize {
        // AX.25 addresses (source, destination, up to two digipeaters),
        // control, PID and FCS.
        let per_frame = crate::airc::frame::HEADER_LEN + 7 * (2 + self.config.radio.path.len()) + 4;
        let max = self.sessions.config.max_payload();
        let fragments = payload.div_ceil(max).max(1);
        payload + fragments * per_frame
    }

    /// Airtime the transmit queue may hold before new traffic is refused.
    pub fn rf_backlog_budget(&self) -> Duration {
        Duration::from_secs(self.config.radio.max_queued_airtime_secs)
    }

    /// Is there room in the backlog for `octets` of this class?
    ///
    /// This is the decision point that matters. Refusing here means the sender
    /// finds out immediately and can say something shorter or wait; accepting
    /// and then dropping the frame two minutes later at the transmitter means
    /// the message vanished and nobody knows.
    pub fn rf_backlog_has_room(&self, octets: usize, class: TxClass) -> bool {
        let Some(tnc) = self.tnc.as_ref() else {
            return false;
        };
        let budget = self.rf_backlog_budget().mul_f64(class.allowance());
        tnc.queued() + tnc.airtime_for(octets) <= budget
    }

    /// How long a message queued now would wait before it is on the air.
    pub fn rf_eta(&self) -> Duration {
        self.tnc.as_ref().map(|t| t.eta()).unwrap_or_default()
    }

    pub(crate) fn transmit_direct(&mut self, dest: &Callsign, frame: AircFrame, class: TxClass) {
        let (Some(tnc), Some(source)) = (self.tnc.as_ref(), self.config.gateway_callsign()) else {
            return;
        };
        if !self.rf_enabled {
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
    pub(crate) fn flush_mailbox(&mut self, call: &Callsign) {
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

    fn maybe_identify(&mut self, now: Instant) {
        if !self.rf_available() {
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
    pub(crate) fn id_if_needed(&mut self) {
        if self.transmitted_since_id && self.rf_available() {
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

    // --------------------------------------------------------------- helpers

    pub fn quit_user(&mut self, uid: &UserId, reason: &str) {
        let Some(user) = self.state.user(uid).cloned() else {
            return;
        };
        if user.registered {
            let d = Delivery::Quit {
                nick: user.nick.clone(),
                prefix: user.prefix(),
                reason: reason.to_string(),
            };
            self.broadcast_peers(uid, &d, false);
        }
        let rf_channels: Vec<String> = if user.is_rf() {
            user.channels
                .iter()
                .filter_map(|k| {
                    self.state.channels.get(k).and_then(|c| {
                        if c.rf {
                            Some(c.name.clone())
                        } else {
                            None
                        }
                    })
                })
                .collect()
        } else {
            Vec::new()
        };
        self.state.remove_user(uid);
        if let UserId::Ip(id) = uid {
            self.drop_ip_link(*id);
        }
        if let UserId::Rf(call) = uid {
            self.sessions.forget(call);
        }
        for ch in rf_channels {
            if !self
                .state
                .channel(&ch)
                .map(|c| c.has_rf_members())
                .unwrap_or(true)
            {
                self.notice_rf_audience(
                    &ch,
                    "No RF station remains in this channel. Messages stay on IRC until one joins.",
                );
            }
        }
    }

    pub fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    pub fn find_target(&self, name: &str) -> Option<UserId> {
        self.state.by_nick(name).map(|u| u.id.clone())
    }


    /// May this IP user have a message radiated? RF stations always may:
    /// they are already on the air. An IP user needs RF-TX (OPER, or IDENTIFY
    /// to a nick the operator granted with `RADIO GRANT`).
    pub fn user_may_tx_rf(&self, uid: &UserId) -> bool {
        let Some(user) = self.state.user(uid) else {
            return false;
        };
        user.is_rf() || user.oper || user.rf_tx
    }

    pub fn refresh_rf_tx(&mut self, uid: &UserId) {
        let Some(user) = self.state.user(uid).cloned() else {
            return;
        };
        if user.is_rf() {
            return;
        }
        let granted = user.nick_identified && self.accounts.grants_rf_tx(&user.nick);
        let stored_call = user
            .nick_identified
            .then(|| self.accounts.get(&user.nick).and_then(|a| a.callsign.clone()))
            .flatten();
        if let Some(u) = self.state.user_mut(uid) {
            u.rf_tx = u.oper || granted;
            if u.callsign.is_none() {
                if let Some(c) = stored_call.as_deref().and_then(|s| s.parse().ok()) {
                    u.callsign = Some(c);
                }
            }
        }
    }


    pub fn is_chanop(&self, uid: &UserId, channel: &str) -> bool {
        if self.state.user(uid).map(|u| u.oper).unwrap_or(false) {
            return true;
        }
        self.state
            .channel(channel)
            .and_then(|c| c.members.get(uid).copied())
            .map(|f| f.op)
            .unwrap_or(false)
    }

    pub fn radio_status_line(&self) -> String {
        if !self.config.radio.enabled {
            return "Radio gateway is disabled. This is a plain IRC server; nothing is radiated."
                .into();
        }
        let call = &self.config.radio.callsign;
        if !self.rf_enabled {
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

    pub fn channel_air_line(&self, channel: &str) -> String {
        let Some(chan) = self.state.channel(channel) else {
            return String::new();
        };
        if !chan.rf {
            return format!("{channel} is Internet-only. Nothing here goes on the air.");
        }
        if !self.rf_available() {
            return format!(
                "{channel} is +r (bridged) but the transmitter is OFF. Messages stay on IRC."
            );
        }
        if !chan.has_rf_members() {
            return format!(
                "{channel} is +r, transmitter ON ({}). No RF station is in the channel, so messages stay on IRC until one joins.",
                self.config.radio.callsign
            );
        }
        format!(
            "{channel} is +r, transmitter ON ({}). Messages from users with RF-TX privilege are sent on the air; others stay on IRC.",
            self.config.radio.callsign
        )
    }

    pub fn announce_mode(&mut self, channel: &str, setter: &str, changes: &str, args: &[&str]) {
        let mut params = vec![channel.to_string(), changes.to_string()];
        params.extend(args.iter().map(|s| (*s).to_string()));
        let line = Message::new("MODE", params)
            .with_prefix(setter.to_string())
            .to_string();
        for member in self.state.members(channel) {
            if let UserId::Ip(id) = member {
                self.send_raw(id, line.clone());
            }
        }
    }

    /// Recompute +o/+v on every channel this user is in, and tell IRC clients.
    pub fn refresh_privileges(&mut self, uid: &UserId) {
        self.refresh_rf_tx(uid);
        let channels: Vec<String> = self
            .state
            .user(uid)
            .map(|u| {
                u.channels
                    .iter()
                    .filter_map(|k| self.state.channels.get(k).map(|c| c.name.clone()))
                    .collect()
            })
            .unwrap_or_default();
        let nick = self
            .state
            .user(uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        let server = self.server_name().to_string();
        for ch in channels {
            let Some((old, new)) = self.state.apply_intended_flags(uid, &ch) else {
                continue;
            };
            if old.op != new.op {
                self.announce_mode(
                    &ch,
                    &server,
                    if new.op { "+o" } else { "-o" },
                    &[&nick],
                );
            }
            if old.voice != new.voice {
                self.announce_mode(
                    &ch,
                    &server,
                    if new.voice { "+v" } else { "-v" },
                    &[&nick],
                );
            }
        }
    }

    pub fn notice_rf_join(&mut self, uid: &UserId, channel: &str) {
        self.notice_user(
            uid,
            &format!(
                "{channel} is +rm: bridged to amateur radio. CALLSIGN grants +v \
                 (speak on IRC). Messages go on the air only after a control \
                 operator grants RF-TX to a registered nick (RADIO GRANT) — \
                 everyone else is heard on IRC only."
            ),
        );
        let status = self.radio_status_line();
        self.notice_user(uid, &status);
        let air = self.channel_air_line(channel);
        if !air.is_empty() {
            self.notice_user(uid, &air);
        }
    }

    pub fn notice_rf_audience(&mut self, channel: &str, text: &str) {
        for uid in self.state.members(channel) {
            if !uid.is_rf() {
                self.notice_user(&uid, text);
            }
        }
    }
}

/// Render a delivery as an IRC protocol line.
fn render_irc(d: &Delivery) -> Option<String> {
    let msg = match d {
        Delivery::Privmsg {
            from_prefix,
            target,
            text,
            notice,
            ..
        } => Message::new(
            if *notice { "NOTICE" } else { "PRIVMSG" },
            vec![target.clone(), text.clone()],
        )
        .with_prefix(from_prefix.clone()),
        Delivery::Join {
            prefix, channel, ..
        } => Message::new("JOIN", vec![channel.clone()]).with_prefix(prefix.clone()),
        Delivery::Part {
            prefix,
            channel,
            reason,
            ..
        } => Message::new("PART", vec![channel.clone(), reason.clone()]).with_prefix(prefix.clone()),
        Delivery::Quit { prefix, reason, .. } => {
            Message::new("QUIT", vec![reason.clone()]).with_prefix(prefix.clone())
        }
        Delivery::NickChange {
            prefix, new_nick, ..
        } => Message::new("NICK", vec![new_nick.clone()]).with_prefix(prefix.clone()),
        Delivery::Topic {
            prefix,
            channel,
            topic,
            ..
        } => Message::new("TOPIC", vec![channel.clone(), topic.clone()]).with_prefix(prefix.clone()),
    };
    Some(msg.to_string())
}

/// Run the server event loop until the channel closes.
pub async fn run(mut server: Server, mut events: mpsc::Receiver<Event>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            maybe = events.recv() => match maybe {
                Some(Event::Shutdown) | None => {
                    server.handle(Event::Shutdown);
                    return;
                }
                Some(ev) => server.handle(ev),
            },
            _ = ticker.tick() => server.handle(Event::Tick),
        }
    }
}
