//! The server actor: one task, one state, one ordering of events.

pub mod commands;
pub mod bridge;
pub mod clients;
pub mod mailbox;
pub mod radio;
pub mod state;

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::accounts::Accounts;
use crate::airc::{encode_fields, Kind};
use crate::audit::Audit;
use crate::ax25::{Ax25Frame, TncHandle};
use crate::callsign::Callsign;
use crate::config::Config;
use crate::irc::message::{is_channel_name, lower, Message};
use crate::policy::Policy;

pub use clients::Clients;
pub use radio::{Radio, Stats, TxClass};
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

/// The server actor.
///
/// It owns no radio and no socket of its own: it coordinates subsystems that
/// each own their own data and enforce their own invariants.
///
/// * [`State`] — users, nicks, channels. Who exists and where.
/// * [`Radio`] — everything about putting something on the air, including the
///   airtime budget and the obligation to identify. Nothing else transmits.
/// * [`Policy`] — rate limits and what may be radiated at all.
/// * [`Accounts`] — registered nicknames.
///
/// Keeping them separate is what stops "may this be transmitted?" from being
/// answered in four places with four slightly different answers.
pub struct Server {
    pub config: Arc<Config>,
    pub state: State,
    pub policy: Policy,
    pub radio: Radio,
    pub accounts: Accounts,
    pub audit: Audit,
    clients: Clients,
    /// Used to run Argon2 off this task. Tests leave it unset and hash inline.
    events: Option<mpsc::Sender<Event>>,
    started: SystemTime,
}

impl Server {
    pub fn new(config: Arc<Config>, tnc: Option<TncHandle>) -> Self {
        let audit = Audit::open(config.logging.audit_file.as_deref());
        let radio = Radio::new(config.clone(), tnc, audit.clone());

        let mut state = State::default();
        for ch in &config.channels {
            let chan = state.ensure_channel(&ch.name, ch.rf);
            chan.configured = true;
            if !ch.topic.is_empty() {
                chan.topic = Some(ch.topic.clone());
                chan.topic_setter = config.server.name.clone();
            }
            chan.operators = ch.operators.iter().map(|n| lower(n)).collect();
        }

        // The configured text length is only an upper bound. What actually
        // decides the airtime is how many AX.25 frames the message becomes,
        // so clamp the text limit to whatever fits in `max_rf_fragments`
        // frames at this paclen. Fragmentation multiplies the airtime *and*
        // the loss rate — a message is only delivered if every fragment
        // arrives, and a retry resends all of them.
        let mut policy_config = config.policy.clone();
        // Leave room for the AIRC field separators and the target/sender
        // fields that ride along with the text.
        let fragment_cap = radio
            .max_payload()
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

        Self {
            config,
            state,
            policy: Policy::new(policy_config),
            radio,
            accounts,
            clients: Clients::new(audit.clone()),
            audit,
            events: None,
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
                self.clients.insert(id, out, hangup);
                self.radio.stats.ip_connections += 1;
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
        self.reap_evicted_peers();
    }

    /// [`Sessions::force_touch`] can drop the quietest station to make room.
    /// Idle expiry will not notice — that station is already gone from the
    /// session table — so the IRC-side ghost has to be removed here.
    fn reap_evicted_peers(&mut self) {
        for call in self.radio.sessions.take_evicted() {
            let uid = UserId::Rf(call.clone());
            if self.state.user(&uid).is_some() {
                info!(%call, "peer table full; dropping the quietest station");
                self.quit_user(&uid, "Replaced");
            }
        }
    }

    fn tick(&mut self, now: Instant) {
        // Do not burn ACK retries against a transmitter that cannot key up.
        // The original is held in the TNC until the interlock recovers (or
        // `max_hold`); counting those seconds as failed attempts would mark
        // the station lost while its message was still waiting.
        let outcome = self
            .radio
            .sessions
            .tick_retries(now, self.radio.available() && !self.radio.interlock_down());
        for (call, frame) in outcome.transmit {
            self.radio.transmit_to(&call, frame);
        }
        for call in outcome.lost {
            let uid = UserId::Rf(call.clone());
            if self.state.user(&uid).is_some() {
                info!(%call, "station timed out");
                self.quit_user(&uid, "Signal lost");
            }
        }
        self.policy.expire(now);
        let dropped = self.radio.mailbox.expire(now);
        if dropped > 0 {
            debug!("{dropped} held messages expired");
        }
        self.radio.maybe_identify(now);
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
            let guest = guest_nick(
                match uid {
                    UserId::Ip(id) => id,
                    UserId::Rf(_) => 0,
                },
                self.config.server.max_nick_len,
            );
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
        self.radio.id_if_needed();
        for id in self.clients.ids() {
            self.send_raw(id, "ERROR :Server shutting down".to_string());
        }
    }

    // ------------------------------------------------------------- IP output




    /// Send a numeric reply. RF users never receive numerics: they are pure
    /// airtime with no information a small screen needs.
    /// Write one line to an IP client.
    ///
    /// Delegates to [`Clients`], which owns the bounded-queue rule. Kept here
    /// because it is the primitive every command path uses.
    pub fn send_raw(&mut self, id: ClientId, line: String) {
        self.clients.send(id, line);
    }

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
                self.radio.unicast(&call, Kind::Notice, payload, false, TxClass::Control);
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
                if is_channel_name(target) {
                    self.radio.broadcast_flagged(kind, payload, TxClass::Chat, flags);
                } else {
                    self.radio.unicast_flagged(call, kind, payload, true, TxClass::Direct, flags);
                }
            }
            // Presence is off by default and is the lowest-value traffic
            // there is: a transmission to say somebody opened a window.
            Delivery::Join { nick, channel, .. } if self.config.radio.presence_notices => {
                let payload = encode_fields(&[channel, nick, "+"]);
                self.radio.broadcast(Kind::Presence, payload, TxClass::Chat);
            }
            Delivery::Part { nick, channel, .. } if self.config.radio.presence_notices => {
                let payload = encode_fields(&[channel, nick, "-"]);
                self.radio.broadcast(Kind::Presence, payload, TxClass::Chat);
            }
            Delivery::Topic {
                nick,
                channel,
                topic,
                ..
            } => {
                let topic: String = topic.chars().take(64).collect();
                let payload = encode_fields(&[channel, nick, &topic]);
                self.radio.broadcast(Kind::Notice, payload, TxClass::Chat);
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
            self.clients.disconnect(*id);
        }
        if let UserId::Rf(call) = uid {
            self.radio.sessions.forget(call);
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


    pub fn channel_air_line(&self, channel: &str) -> String {
        let Some(chan) = self.state.channel(channel) else {
            return String::new();
        };
        if !chan.rf {
            return format!("{channel} is Internet-only. Nothing here goes on the air.");
        }
        if !self.radio.available() {
            return format!(
                "{channel} is +r (bridged) but the transmitter is OFF. Messages stay on IRC."
            );
        }
        if self.radio.interlock_down() {
            return format!(
                "{channel} is +r (bridged) but the safety interlock is holding the transmitter. \
                 Messages stay on IRC."
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
        let status = self.radio.status_line();
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

/// The replacement name for a client that has to give up a registered nick.
///
/// `Guest_1`, not `Guest1`: the latter parses as a plausible callsign (letters
/// and a digit), so it would sit in the namespace reserved for RF stations —
/// the server would be handing out a nick it refuses when a client asks for
/// one. The underscore is a legal nickname character and is never legal in a
/// callsign.
///
/// It is also kept within `max_nick_len`, for the same reason: a name the
/// server assigns must be a name the server would accept.
pub fn guest_nick(id: u64, max_nick_len: usize) -> String {
    let full = format!("Guest_{id}");
    if full.len() <= max_nick_len {
        return full;
    }
    // Keep the tail of the number: the low digits are what differ between
    // nearby connection ids, so they are what keeps the name unique.
    let room = max_nick_len.saturating_sub("Guest_".len());
    let digits = id.to_string();
    let tail = &digits[digits.len().saturating_sub(room)..];
    format!("Guest_{tail}")
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
