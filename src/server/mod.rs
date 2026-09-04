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
use crate::config::{Config, IpRfTxMode};
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
    out: mpsc::UnboundedSender<String>,
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
        let policy = Policy::new(config.policy.clone());
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
                let cap = self.config.listen.max_conns_per_host;
                if cap > 0 && self.state.ip_count_from_host(&host) >= cap as usize {
                    let _ = out.send(format!(
                        "ERROR :Too many connections from {host} (max {cap})"
                    ));
                    if let Some(h) = hangup {
                        let _ = h.send(());
                    }
                    self.audit.event(
                        "connect_denied",
                        &[("host", &host), ("reason", "max_conns_per_host")],
                    );
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
        if self.transmitted_since_id {
            self.send_id();
        }
        for id in self.outputs.keys().copied().collect::<Vec<_>>() {
            self.send_raw(id, format!("ERROR :Server shutting down"));
        }
    }

    // ------------------------------------------------------------- IP output

    pub fn send_raw(&mut self, id: ClientId, line: String) {
        if let Some(link) = self.outputs.get(&id) {
            if link.out.send(line).is_err() {
                self.drop_ip_link(id);
            }
        }
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
            let kind = format!("{:?}", frame.kind);
            let n = len.to_string();
            let dest_s = dest.to_string();
            self.audit.event(
                "rf_tx",
                &[("dest", &dest_s), ("kind", &kind), ("bytes", &n)],
            );
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

    pub fn is_rf_channel(&self, name: &str) -> bool {
        self.state.channel(name).map(|c| c.rf).unwrap_or(false)
    }

    /// May this IP user have a message radiated? RF stations always may:
    /// they are already on the air. See `policy.ip_rf_tx`.
    pub fn user_may_tx_rf(&self, uid: &UserId) -> bool {
        let Some(user) = self.state.user(uid) else {
            return false;
        };
        if user.is_rf() {
            return true;
        }
        if user.oper {
            return true;
        }
        match self.config.policy.ip_rf_tx {
            IpRfTxMode::Off => false,
            IpRfTxMode::Oper => false,
            IpRfTxMode::Key | IpRfTxMode::Account => user.rf_tx,
            IpRfTxMode::Callsign => user.callsign.is_some(),
        }
    }

    pub fn refresh_rf_tx(&mut self, uid: &UserId) {
        let Some(user) = self.state.user(uid) else {
            return;
        };
        if user.is_rf() {
            return;
        }
        let nick = user.nick.clone();
        let identified = user.nick_identified;
        let listed = self
            .config
            .policy
            .rf_tx_nicks
            .iter()
            .any(|n| lower(n) == lower(&nick));
        let account = identified && (listed || self.accounts.grants_rf_tx(&nick));
        if let Some(u) = self.state.user_mut(uid) {
            if account {
                u.rf_tx = true;
            }
            // OPER and RFKEY set rf_tx directly; do not clear them here.
            if u.oper {
                u.rf_tx = true;
            }
        }
    }

    pub fn channel_key(&self, name: &str) -> String {
        lower(name)
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
        if !self.tnc.is_some() {
            return format!("Radio gateway: no TNC. Station {call}. Nothing is being radiated.");
        }
        format!(
            "Radio gateway: transmitter ON, station {call}, {} RF station(s) heard, {} frames TX / {} RX ({} bytes on air).",
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
                "{channel} is +rm: bridged to amateur radio. Identify with CALLSIGN for +v \
                 (permission to speak here). Messages go on the air only with RF-TX privilege \
                 (IDENTIFY to a granted nick, RFKEY, or OPER) — everyone else is heard on IRC only."
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
