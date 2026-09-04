//! The server actor: one task, one state, one ordering of events.

pub mod commands;
pub mod mailbox;
pub mod state;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::airc::{encode_fields, AircFrame, Kind, SessionConfig, Sessions};
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
        out: mpsc::UnboundedSender<String>,
    },
    Line {
        id: ClientId,
        line: String,
    },
    Disconnected {
        id: ClientId,
        reason: String,
    },
    /// A frame heard on the air.
    Rf(Ax25Frame),
    /// Periodic housekeeping: retransmissions, timeouts, station ID.
    Tick,
    Shutdown,
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

#[derive(Default, Debug, Clone)]
pub struct Stats {
    pub rf_frames_rx: u64,
    pub rf_frames_tx: u64,
    pub rf_frames_dropped: u64,
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
    tnc: Option<TncHandle>,
    outputs: HashMap<ClientId, mpsc::UnboundedSender<String>>,
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
            if !ch.topic.is_empty() {
                chan.topic = Some(ch.topic.clone());
                chan.topic_setter = config.server.name.clone();
            }
        }
        let policy = Policy::new(crate::config::PolicyConfig {
            max_rf_text_len: config.policy.max_rf_text_len,
            rf_msgs_per_min: config.policy.rf_msgs_per_min,
            rf_burst: config.policy.rf_burst,
            ip_to_rf_msgs_per_min: config.policy.ip_to_rf_msgs_per_min,
            block_apparent_ciphertext: config.policy.block_apparent_ciphertext,
            require_callsign_for_rf: config.policy.require_callsign_for_rf,
            deny_callsigns: config.policy.deny_callsigns.clone(),
            allow_callsigns: config.policy.allow_callsigns.clone(),
        });
        let mailbox = Mailbox::new(
            config.radio.mailbox_enabled,
            config.radio.mailbox_per_station,
            config.radio.mailbox_total,
            Duration::from_secs(config.radio.mailbox_ttl_secs),
        );
        Self {
            rf_enabled: config.radio.enabled && tnc.is_some(),
            config,
            state,
            policy,
            sessions,
            mailbox,
            stats: Stats::default(),
            tnc,
            outputs: HashMap::new(),
            last_id: Instant::now(),
            transmitted_since_id: false,
            started: SystemTime::now(),
        }
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
            Event::Connected { id, host, out } => {
                self.outputs.insert(id, out);
                self.stats.ip_connections += 1;
                let user = User::new(UserId::Ip(id), host, now);
                self.state.insert_user(user);
            }
            Event::Line { id, line } => {
                if let Some(msg) = Message::parse(&line) {
                    self.handle_client_message(id, msg);
                }
            }
            Event::Disconnected { id, reason } => {
                self.quit_user(&UserId::Ip(id), &reason);
                self.outputs.remove(&id);
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

    fn shutdown(&mut self) {
        // Identify at the end of a transmission series, as required of an
        // automatically controlled station.
        if self.transmitted_since_id {
            self.send_id();
        }
        for id in self.outputs.keys().copied().collect::<Vec<_>>() {
            self.send_raw(id, format!("ERROR :Server shutting down"));
        }
    }

    // ------------------------------------------------------------- IP output

    pub fn send_raw(&mut self, id: ClientId, line: String) {
        if let Some(out) = self.outputs.get(&id) {
            if out.send(line).is_err() {
                self.outputs.remove(&id);
            }
        }
    }

    pub fn send_to(&mut self, uid: &UserId, msg: Message) {
        if let UserId::Ip(id) = uid {
            self.send_raw(*id, msg.to_string());
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
                let call = call.clone();
                let payload = encode_fields(&["*", text]);
                self.unicast(&call, Kind::Notice, payload, true);
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
                ..
            } => {
                let kind = if *notice { Kind::Notice } else { Kind::Msg };
                let payload = encode_fields(&[target, from_nick, text]);
                // Channel traffic goes out once as a broadcast; a private
                // message is unicast and acknowledged.
                if target.starts_with('#') || target.starts_with('&') {
                    self.broadcast(kind, payload);
                } else {
                    self.unicast(call, kind, payload, true);
                }
            }
            Delivery::Join { nick, channel, .. } if self.config.radio.presence_notices => {
                let payload = encode_fields(&[channel, nick, "+"]);
                self.broadcast(Kind::Presence, payload);
            }
            Delivery::Part { nick, channel, .. } if self.config.radio.presence_notices => {
                let payload = encode_fields(&[channel, nick, "-"]);
                self.broadcast(Kind::Presence, payload);
            }
            Delivery::Topic {
                nick,
                channel,
                topic,
                ..
            } => {
                let payload = encode_fields(&[channel, nick, topic]);
                self.broadcast(Kind::Notice, payload);
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

    /// Unreliable one-to-many transmission addressed to the protocol's
    /// destination address. Every station in range hears it once.
    pub fn broadcast(&mut self, kind: Kind, payload: Vec<u8>) {
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
            let mut f = AircFrame::new(kind, seq, chunk);
            f.frag_index = i as u8;
            f.frag_total = total;
            self.transmit_direct(&dest, f);
        }
    }

    /// Reliable one-to-one transmission with ACK and retry.
    pub fn unicast(&mut self, dst: &Callsign, kind: Kind, payload: Vec<u8>, reliable: bool) {
        if !self.rf_available() {
            return;
        }
        let now = Instant::now();
        let frames = self.sessions.send(dst, kind, payload, reliable, now);
        for f in frames {
            self.transmit_direct(dst, f);
        }
    }

    fn transmit_to(&mut self, dst: &Callsign, frame: AircFrame) {
        self.transmit_direct(dst, frame);
    }

    pub(crate) fn transmit_direct(&mut self, dest: &Callsign, frame: AircFrame) {
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
        } else {
            self.stats.rf_frames_dropped += 1;
        }
    }

    /// Deliver anything that was held for a station we have just heard from.
    /// Held messages are sent reliably, oldest first, and carry their age so
    /// the operator knows they are not fresh.
    pub(crate) fn flush_mailbox(&mut self, call: &Callsign) {
        if self.mailbox.depth(call) == 0 {
            return;
        }
        let now = Instant::now();
        let nick = call.to_nick();
        for m in self.mailbox.take(call) {
            let age = m.age(now).as_secs().to_string();
            let payload = encode_fields(&[&nick, &m.from, &m.text, &age]);
            self.unicast(call, Kind::Stored, payload, true);
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

    fn send_id(&mut self) {
        let text = format!(
            "{} {}",
            self.config.radio.callsign, self.config.radio.id_text
        );
        let payload = encode_fields(&[&text]);
        let dest: Callsign = "ID".parse().unwrap();
        let seq = self.sessions.next_seq();
        let frame = AircFrame::new(Kind::Id, seq, payload);
        self.transmit_direct(&dest, frame);
        self.transmitted_since_id = false;
        self.last_id = Instant::now();
        debug!("station identification transmitted");
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
        self.state.remove_user(uid);
        if let UserId::Rf(call) = uid {
            self.sessions.forget(call);
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

    pub fn is_rf_channel(&self, name: &str) -> bool {
        self.state.channel(name).map(|c| c.rf).unwrap_or(false)
    }

    pub fn channel_key(&self, name: &str) -> String {
        lower(name)
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
