//! IRC command handling for clients connected over IP.
//!
//! The command set is deliberately small: RFC 1459 minus the parts that only
//! make sense in a linked network (SERVER, SQUIT, services, bans-by-mask).
//! Local extensions:
//!
//! * `CALLSIGN <call>` - claim an amateur callsign (+v on `+r` channels).
//!   Required before an IP user's traffic can be radiated; not authentication.
//! * `RADIO <subcommand>` - transmitter status for everyone; GRANT/REVOKE and
//!   the kill switch for control operators.

use std::time::{Duration, Instant};

use tracing::info;

use crate::accounts::{hash_password, verify_password, AccountError};
use crate::airc::{encode_fields, Kind};
use crate::callsign::Callsign;
use crate::irc::message::{is_channel_name, is_valid_nick, lower, Message};
use crate::irc::numerics as num;
use crate::policy::Verdict;

use super::state::{ClientId, UserId};

/// Text that has passed every gate between an IRC user and the transmitter,
/// and whether a policy limit shortened it on the way.
pub(crate) struct Screened {
    pub text: String,
    pub truncated: bool,
}
use super::{AuthKind, Delivery, Event, Server, TxClass};

impl Server {
    pub fn handle_client_message(&mut self, id: ClientId, msg: Message) {
        let uid = UserId::Ip(id);
        if self.state.user(&uid).is_none() {
            return;
        }
        if let Some(u) = self.state.user_mut(&uid) {
            u.last_active = Instant::now();
        }

        let registered = self.state.user(&uid).map(|u| u.registered).unwrap_or(false);
        let cmd = msg.command.as_str();

        if registered
            && !matches!(cmd, "PONG" | "PING" | "QUIT")
            && !self.policy.ip_cmd_rate_ok(&id.to_string(), Instant::now())
        {
            self.notice_user(&uid, "Slow down: command flood protection.");
            let id_s = id.to_string();
            self.audit.event("flood_cmd", &[("id", &id_s)]);
            return;
        }

        if !registered && !matches!(cmd, "PASS" | "NICK" | "USER" | "QUIT" | "PING" | "PONG" | "CAP")
        {
            self.numeric(&uid, num::ERR_NOTREGISTERED, &["You have not registered"]);
            return;
        }

        match cmd {
            "CAP" => {
                // Minimal IRCv3 handshake: acknowledge nothing, end negotiation.
                if msg.param(0).map(|s| s.eq_ignore_ascii_case("LS")).unwrap_or(false) {
                    let name = self.server_name().to_string();
                    self.send_raw(
                        id,
                        Message::new("CAP", vec!["*".into(), "LS".into(), String::new()])
                            .with_prefix(name)
                            .to_string(),
                    );
                }
            }
            "PASS" => self.cmd_pass(&uid, &msg),
            "NICK" => self.cmd_nick(&uid, &msg),
            "USER" => self.cmd_user(&uid, &msg),
            "QUIT" => {
                let reason = msg.param(0).unwrap_or("Client quit").to_string();
                self.send_raw(id, format!("ERROR :Closing link ({reason})"));
                self.quit_user(&uid, &reason);
            }
            "PING" => {
                let token = msg.param(0).unwrap_or("").to_string();
                let name = self.server_name().to_string();
                self.send_raw(
                    id,
                    Message::new("PONG", vec![name.clone(), token])
                        .with_prefix(name)
                        .to_string(),
                );
            }
            "PONG" => {}
            "JOIN" => self.cmd_join(&uid, &msg),
            "PART" => self.cmd_part(&uid, &msg),
            "PRIVMSG" => self.cmd_privmsg(&uid, &msg, false),
            "NOTICE" => self.cmd_privmsg(&uid, &msg, true),
            "TOPIC" => self.cmd_topic(&uid, &msg),
            "NAMES" => {
                if let Some(chan) = msg.param(0) {
                    let chan = chan.to_string();
                    self.send_names(&uid, &chan);
                }
            }
            "LIST" => self.cmd_list(&uid),
            "WHO" => self.cmd_who(&uid, &msg),
            "WHOIS" => self.cmd_whois(&uid, &msg),
            "MODE" => self.cmd_mode(&uid, &msg),
            "MOTD" => self.send_motd(&uid),
            "LUSERS" => self.send_lusers(&uid),
            "AWAY" => {
                let away = msg.param(0).map(|s| s.to_string()).filter(|s| !s.is_empty());
                if let Some(u) = self.state.user_mut(&uid) {
                    u.away = away;
                }
            }
            "OPER" => self.cmd_oper(&uid, &msg),
            "CALLSIGN" => self.cmd_callsign(&uid, &msg),
            "RADIO" => self.cmd_radio(&uid, &msg),
            "KICK" => self.cmd_kick(&uid, &msg),
            "KILL" => self.cmd_kill(&uid, &msg),
            "REGISTER" => self.cmd_register(&uid, &msg),
            "IDENTIFY" => self.cmd_identify(&uid, &msg),
            "UNREGISTER" => self.cmd_unregister(&uid, &msg),
            other => {
                self.numeric(&uid, num::ERR_UNKNOWNCOMMAND, &[other, "Unknown command"]);
            }
        }
    }

    // ------------------------------------------------------- registration

    fn cmd_pass(&mut self, uid: &UserId, msg: &Message) {
        let Some(given) = msg.param(0) else {
            self.numeric(uid, num::ERR_NEEDMOREPARAMS, &["PASS", "Not enough parameters"]);
            return;
        };
        let ok = self
            .config
            .server
            .password
            .as_ref()
            .map(|p| constant_time_eq(p, given))
            .unwrap_or(true);
        if let Some(u) = self.state.user_mut(uid) {
            u.pass_ok = ok;
        }
    }

    fn cmd_nick(&mut self, uid: &UserId, msg: &Message) {
        let Some(nick) = msg.param(0).map(|s| s.to_string()) else {
            self.numeric(uid, num::ERR_NONICKNAMEGIVEN, &["No nickname given"]);
            return;
        };
        if !is_valid_nick(&nick, self.config.server.max_nick_len) {
            self.numeric(uid, num::ERR_ERRONEUSNICKNAME, &[&nick, "Erroneous nickname"]);
            return;
        }
        // Callsign-shaped nicks belong to RF stations. RFC 1459 casemapping
        // makes `\` the uppercase of `|`, so SM0ABC\7 must be rejected too,
        // as must the AX.25 form SM0ABC-7.
        if Callsign::reserved_from_nick(&nick).is_some() {
            self.numeric(
                uid,
                num::ERR_ERRONEUSNICKNAME,
                &[
                    &nick,
                    "Callsign nicknames are reserved; use CALLSIGN to identify",
                ],
            );
            return;
        }
        if self.state.nick_taken(&nick) {
            self.numeric(uid, num::ERR_NICKNAMEINUSE, &[&nick, "Nickname is already in use"]);
            return;
        }

        let was_registered = self.state.user(uid).map(|u| u.registered).unwrap_or(false);
        let old = self.state.user(uid).map(|u| u.nick.clone()).unwrap_or_default();
        let prefix = self.state.user(uid).map(|u| u.prefix()).unwrap_or_default();
        if !self.state.set_nick(uid, &nick) {
            self.numeric(uid, num::ERR_NICKNAMEINUSE, &[&nick, "Nickname is already in use"]);
            return;
        }
        let claimed = self.accounts.is_registered(&nick);
        let timeout = Duration::from_secs(self.config.accounts.identify_timeout_secs);
        if let Some(u) = self.state.user_mut(uid) {
            u.got_nick = true;
            u.nick_identified = false;
            u.identify_by = if claimed {
                Some(Instant::now() + timeout)
            } else {
                None
            };
        }
        if claimed {
            self.notice_user(
                uid,
                &format!(
                    "This nick is registered. IDENTIFY <password> within {} seconds or it will be released.",
                    self.config.accounts.identify_timeout_secs
                ),
            );
        }

        if was_registered {
            let d = Delivery::NickChange {
                old_nick: old,
                prefix,
                new_nick: nick.clone(),
            };
            self.broadcast_peers(uid, &d, true);
            self.refresh_privileges(uid);
        } else {
            self.try_complete_registration(uid);
        }
    }

    fn cmd_user(&mut self, uid: &UserId, msg: &Message) {
        if self.state.user(uid).map(|u| u.registered).unwrap_or(false) {
            self.numeric(uid, num::ERR_ALREADYREGISTERED, &["You may not reregister"]);
            return;
        }
        if msg.params.len() < 4 {
            self.numeric(uid, num::ERR_NEEDMOREPARAMS, &["USER", "Not enough parameters"]);
            return;
        }
        if let Some(u) = self.state.user_mut(uid) {
            u.username = msg.params[0].chars().take(10).collect();
            u.realname = msg.params[3].clone();
            u.got_user = true;
        }
        self.try_complete_registration(uid);
    }

    fn try_complete_registration(&mut self, uid: &UserId) {
        let Some(user) = self.state.user(uid).cloned() else {
            return;
        };
        if user.registered || !user.got_nick || !user.got_user {
            return;
        }
        if self.config.server.password.is_some() && !user.pass_ok {
            self.numeric(uid, num::ERR_PASSWDMISMATCH, &["Password incorrect"]);
            if let UserId::Ip(id) = uid {
                self.send_raw(*id, "ERROR :Closing link (bad password)".into());
            }
            self.quit_user(uid, "Bad password");
            return;
        }
        if let Some(u) = self.state.user_mut(uid) {
            u.registered = true;
        }
        if let Some(u) = self.state.user(uid) {
            self.audit.event(
                "register",
                &[("nick", &u.nick), ("user", &u.username), ("host", &u.host)],
            );
        }

        let server = self.server_name().to_string();
        let network = self.config.server.network.clone();
        self.numeric(
            uid,
            num::RPL_WELCOME,
            &[&format!(
                "Welcome to the {network} amateur radio IRC network {}",
                user.nick
            )],
        );
        self.numeric(
            uid,
            num::RPL_YOURHOST,
            &[&format!(
                "Your host is {server}, running ax25ircd {}",
                env!("CARGO_PKG_VERSION")
            )],
        );
        self.numeric(uid, num::RPL_CREATED, &["This server was created at startup"]);
        self.numeric(uid, num::RPL_MYINFO, &[&server, "ax25ircd-0.1", "iow", "mnrtkl"]);

        let radio = if self.rf_available() { "ON" } else { "OFF" };
        let isupport = format!(
            "CHANTYPES=#& PREFIX=(ov)@+ NICKLEN={} CHANNELLEN=50 CASEMAPPING=rfc1459 \
             NETWORK={} MAXTARGETS=1 TOPICLEN=200 CHANMODES=k,l,r,mnt RADIO={} RFCALL={}",
            self.config.server.max_nick_len,
            network,
            radio,
            self.config.radio.callsign
        );
        self.numeric(uid, num::RPL_ISUPPORT, &[&isupport, "are supported by this server"]);

        self.send_lusers(uid);
        self.send_motd(uid);

        let status = self.radio_status_line();
        self.notice_user(uid, &status);
        self.notice_user(
            uid,
            "On +r channels CALLSIGN grants +v (speak on IRC). A control operator \
             must RADIO GRANT a registered nick before that nick's messages are \
             radiated. REGISTER/IDENTIFY keep the nick and the grant across restarts.",
        );
        if self.accounts.is_registered(&user.nick) {
            self.notice_user(
                uid,
                &format!(
                    "{} is registered. IDENTIFY <password> within {} seconds.",
                    user.nick, self.config.accounts.identify_timeout_secs
                ),
            );
        }
    }

    fn send_lusers(&mut self, uid: &UserId) {
        let total = self.state.users.len();
        let rf = self.state.users.keys().filter(|u| u.is_rf()).count();
        let text = format!("There are {total} users online, {rf} of them on RF");
        self.numeric(uid, num::RPL_LUSERCLIENT, &[&text]);
        let me = format!("I have {} clients and 0 servers", total - rf);
        self.numeric(uid, num::RPL_LUSERME, &[&me]);
    }

    fn send_motd(&mut self, uid: &UserId) {
        if self.config.server.motd.is_empty() {
            self.numeric(uid, num::ERR_NOMOTD, &["MOTD File is missing"]);
            return;
        }
        let server = self.server_name().to_string();
        self.numeric(uid, num::RPL_MOTDSTART, &[&format!("- {server} Message of the day -")]);
        for line in self.config.server.motd.clone() {
            self.numeric(uid, num::RPL_MOTD, &[&format!("- {line}")]);
        }
        self.numeric(uid, num::RPL_ENDOFMOTD, &["End of /MOTD command"]);
    }

    // ------------------------------------------------------------ channels

    fn cmd_join(&mut self, uid: &UserId, msg: &Message) {
        let Some(list) = msg.param(0).map(|s| s.to_string()) else {
            self.numeric(uid, num::ERR_NEEDMOREPARAMS, &["JOIN", "Not enough parameters"]);
            return;
        };
        if list == "0" {
            for chan in self
                .state
                .user(uid)
                .map(|u| u.channels.iter().cloned().collect::<Vec<_>>())
                .unwrap_or_default()
            {
                let name = self
                    .state
                    .channels
                    .get(&chan)
                    .map(|c| c.name.clone())
                    .unwrap_or(chan);
                self.do_part(uid, &name, "Leaving");
            }
            return;
        }
        let keys: Vec<String> = msg
            .param(1)
            .unwrap_or("")
            .split(',')
            .map(|s| s.to_string())
            .collect();

        for (i, name) in list.split(',').enumerate() {
            let key = keys.get(i).cloned().unwrap_or_default();
            self.do_join(uid, name, &key);
        }
    }

    fn do_join(&mut self, uid: &UserId, name: &str, key: &str) {
        if !is_channel_name(name) {
            self.numeric(uid, num::ERR_NOSUCHCHANNEL, &[name, "No such channel"]);
            return;
        }
        let count = self.state.user(uid).map(|u| u.channels.len()).unwrap_or(0);
        if count >= self.config.server.max_channels_per_user {
            self.numeric(uid, num::ERR_TOOMANYCHANNELS, &[name, "You have joined too many channels"]);
            return;
        }
        if let Some(chan) = self.state.channel(name) {
            if let Some(k) = &chan.key {
                if k != key {
                    self.numeric(uid, num::ERR_BADCHANNELKEY, &[name, "Cannot join channel (+k)"]);
                    return;
                }
            }
            if let Some(limit) = chan.limit {
                if chan.members.len() >= limit {
                    self.numeric(uid, num::ERR_CHANNELISFULL, &[name, "Cannot join channel (+l)"]);
                    return;
                }
            }
        } else {
            // Dynamically created channels are never RF-bridged: which
            // channels occupy the air is an operator decision, not a user one.
            self.state.ensure_channel(name, false);
        }

        if self.state.join(uid, name).is_none() {
            return;
        }
        let flags = self
            .state
            .channel(name)
            .and_then(|c| c.members.get(uid).copied())
            .unwrap_or_default();
        let real_name = self
            .state
            .channel(name)
            .map(|c| c.name.clone())
            .unwrap_or_else(|| name.to_string());
        let (nick, prefix) = self
            .state
            .user(uid)
            .map(|u| (u.nick.clone(), u.prefix()))
            .unwrap_or_default();
        let d = Delivery::Join {
            nick: nick.clone(),
            prefix,
            channel: real_name.clone(),
        };
        self.broadcast_channel(&real_name, &d, None);
        let server = self.server_name().to_string();
        if flags.op {
            self.announce_mode(&real_name, &server, "+o", &[&nick]);
        }
        if flags.voice {
            self.announce_mode(&real_name, &server, "+v", &[&nick]);
        }
        self.send_topic(uid, &real_name, false);
        self.send_names(uid, &real_name);
        if self.state.channel(&real_name).map(|c| c.rf).unwrap_or(false) {
            self.notice_rf_join(uid, &real_name);
        }
    }

    fn cmd_part(&mut self, uid: &UserId, msg: &Message) {
        let Some(list) = msg.param(0).map(|s| s.to_string()) else {
            self.numeric(uid, num::ERR_NEEDMOREPARAMS, &["PART", "Not enough parameters"]);
            return;
        };
        let reason = msg.param(1).unwrap_or("Leaving").to_string();
        for name in list.split(',') {
            self.do_part(uid, name, &reason);
        }
    }

    pub(crate) fn do_part(&mut self, uid: &UserId, name: &str, reason: &str) {
        if self.state.channel(name).is_none() {
            self.numeric(uid, num::ERR_NOSUCHCHANNEL, &[name, "No such channel"]);
            return;
        }
        let real_name = self
            .state
            .channel(name)
            .map(|c| c.name.clone())
            .unwrap_or_else(|| name.to_string());
        if !self
            .state
            .channel(name)
            .map(|c| c.members.contains_key(uid))
            .unwrap_or(false)
        {
            self.numeric(uid, num::ERR_NOTONCHANNEL, &[&real_name, "You're not on that channel"]);
            return;
        }
        let (nick, prefix) = self
            .state
            .user(uid)
            .map(|u| (u.nick.clone(), u.prefix()))
            .unwrap_or_default();
        let d = Delivery::Part {
            nick,
            prefix,
            channel: real_name.clone(),
            reason: reason.to_string(),
        };
        self.broadcast_channel(&real_name, &d, None);
        self.state.part(uid, &real_name);
    }

    fn send_topic(&mut self, uid: &UserId, channel: &str, explicit: bool) {
        let Some(chan) = self.state.channel(channel).cloned() else {
            return;
        };
        match chan.topic {
            Some(topic) => {
                self.numeric(uid, num::RPL_TOPIC, &[&chan.name, &topic]);
                if !chan.topic_setter.is_empty() {
                    let time = chan.topic_time.to_string();
                    self.numeric(
                        uid,
                        num::RPL_TOPICWHOTIME,
                        &[&chan.name, &chan.topic_setter, &time],
                    );
                }
            }
            None if explicit => {
                self.numeric(uid, num::RPL_NOTOPIC, &[&chan.name, "No topic is set"])
            }
            None => {}
        }
    }

    pub(crate) fn send_names(&mut self, uid: &UserId, channel: &str) {
        let Some(chan) = self.state.channel(channel).cloned() else {
            self.numeric(uid, num::ERR_NOSUCHCHANNEL, &[channel, "No such channel"]);
            return;
        };
        let names = self.state.names_of(channel);
        // Chunk by *bytes*, not by count: 20 nicks of the default 30-character
        // maximum is 620 bytes, past the 512-byte line limit, and the writer
        // would silently cut the last name in half.
        const BUDGET: usize = 400;
        let mut chunk: Vec<String> = Vec::new();
        let mut used = 0usize;
        for n in names {
            if !chunk.is_empty() && used + n.len() + 1 > BUDGET {
                let joined = chunk.join(" ");
                self.numeric(uid, num::RPL_NAMREPLY, &["=", &chan.name, &joined]);
                chunk.clear();
                used = 0;
            }
            used += n.len() + 1;
            chunk.push(n);
        }
        if !chunk.is_empty() {
            let joined = chunk.join(" ");
            self.numeric(uid, num::RPL_NAMREPLY, &["=", &chan.name, &joined]);
        }
        self.numeric(uid, num::RPL_ENDOFNAMES, &[&chan.name, "End of /NAMES list"]);
    }

    fn cmd_topic(&mut self, uid: &UserId, msg: &Message) {
        let Some(name) = msg.param(0).map(|s| s.to_string()) else {
            self.numeric(uid, num::ERR_NEEDMOREPARAMS, &["TOPIC", "Not enough parameters"]);
            return;
        };
        let Some(chan) = self.state.channel(&name).cloned() else {
            self.numeric(uid, num::ERR_NOSUCHCHANNEL, &[&name, "No such channel"]);
            return;
        };
        let Some(topic) = msg.param(1).map(|s| s.to_string()) else {
            self.send_topic(uid, &name, true);
            return;
        };
        let is_op = chan.members.get(uid).map(|f| f.op).unwrap_or(false);
        let is_oper = self.state.user(uid).map(|u| u.oper).unwrap_or(false);
        if chan.topic_locked && !is_op && !is_oper {
            self.numeric(uid, num::ERR_CHANOPRIVSNEEDED, &[&chan.name, "You're not channel operator"]);
            return;
        }
        let (nick, prefix) = self
            .state
            .user(uid)
            .map(|u| (u.nick.clone(), u.prefix()))
            .unwrap_or_default();
        let now = self.now_unix();
        let topic = crate::policy::sanitize(&topic);
        // A TOPIC that sets the topic to what it already was is a no-op on
        // IRC and would be a transmission on RF. Notice it before deciding.
        let changed = chan.topic.as_deref() != Some(topic.as_str());
        if let Some(c) = self.state.channel_mut(&name) {
            c.topic = Some(topic.clone());
            c.topic_setter = nick.clone();
            c.topic_time = now;
        }
        // Topic changes go through exactly the same gate as chat: RF-TX
        // privilege, callsign, per-sender rate limit, content screening and
        // the airtime backlog. A channel operator retyping the topic is not
        // a reason to key the transmitter.
        let mut allow_rf = changed
            && chan.rf
            && chan.has_rf_members()
            && self.rf_available();
        let air_topic = if allow_rf {
            match self.screen_for_air(uid, &topic) {
                Some(t) => t.text,
                None => {
                    allow_rf = false;
                    topic.clone()
                }
            }
        } else {
            topic.clone()
        };
        let d = Delivery::Topic {
            nick,
            prefix,
            channel: chan.name.clone(),
            topic: air_topic,
        };
        self.broadcast_channel_ex(&chan.name, &d, None, allow_rf);
    }

    fn cmd_list(&mut self, uid: &UserId) {
        self.numeric(uid, num::RPL_LISTSTART, &["Channel", "Users  Name"]);
        let channels: Vec<_> = self
            .state
            .channels
            .values()
            .map(|c| {
                (
                    c.name.clone(),
                    c.members.len(),
                    c.rf,
                    c.topic.clone().unwrap_or_default(),
                )
            })
            .collect();
        for (name, count, rf, topic) in channels {
            let label = if rf {
                format!("[RF] {topic}")
            } else {
                topic
            };
            self.numeric(uid, num::RPL_LIST, &[&name, &count.to_string(), &label]);
        }
        self.numeric(uid, num::RPL_LISTEND, &["End of /LIST"]);
    }

    fn cmd_who(&mut self, uid: &UserId, msg: &Message) {
        let mask = msg.param(0).unwrap_or("*").to_string();
        let server = self.server_name().to_string();
        let members: Vec<_> = if is_channel_name(&mask) {
            self.state
                .members(&mask)
                .into_iter()
                .filter_map(|id| self.state.user(&id).cloned())
                .collect()
        } else {
            self.state.by_nick(&mask).cloned().into_iter().collect()
        };
        for u in members {
            let flags = if u.is_rf() { "H@rf" } else { "H" };
            let real = format!("0 {}", u.realname);
            self.numeric(
                uid,
                num::RPL_WHOREPLY,
                &[&mask, &u.username, &u.host, &server, &u.nick, flags, &real],
            );
        }
        self.numeric(uid, num::RPL_ENDOFWHO, &[&mask, "End of /WHO list"]);
    }

    fn cmd_whois(&mut self, uid: &UserId, msg: &Message) {
        let Some(nick) = msg.param(0).map(|s| s.to_string()) else {
            self.numeric(uid, num::ERR_NONICKNAMEGIVEN, &["No nickname given"]);
            return;
        };
        let Some(target) = self.state.by_nick(&nick).cloned() else {
            self.numeric(uid, num::ERR_NOSUCHNICK, &[&nick, "No such nick"]);
            return;
        };
        let server = self.server_name().to_string();
        self.numeric(
            uid,
            num::RPL_WHOISUSER,
            &[&target.nick, &target.username, &target.host, "*", &target.realname],
        );
        let desc = match &target.callsign {
            Some(c) if target.is_rf() => format!("Radio station {c}, heard via the gateway"),
            Some(c) => format!("Identified as {c} (connected over the Internet)"),
            None => "Not identified with a callsign".to_string(),
        };
        self.numeric(uid, num::RPL_WHOISSERVER, &[&target.nick, &server, &desc]);
        if target.oper {
            self.numeric(uid, num::RPL_WHOISOPERATOR, &[&target.nick, "is a control operator"]);
        }
        if target.nick_identified {
            self.numeric(
                uid,
                num::RPL_WHOISREGNICK,
                &[&target.nick, "is a registered nick"],
            );
        }
        if target.rf_tx && !target.is_rf() {
            self.numeric(
                uid,
                num::RPL_WHOISOPERATOR,
                &[&target.nick, "has RF-TX privilege (messages may be radiated)"],
            );
        }
        if let (UserId::Rf(call), Some(peer)) = (&target.id, {
            let c = target.id.callsign().cloned();
            c.and_then(|c| self.sessions.peer(&c))
        }) {
            let idle = peer.last_heard.elapsed().as_secs();
            let info = format!(
                "last heard {idle}s ago, {} queued, {} dropped",
                peer.queue_depth(),
                peer.dropped
            );
            self.numeric(uid, num::RPL_WHOISIDLE, &[&call.to_string(), &idle.to_string(), &info]);
        }
        let channels: Vec<String> = target
            .channels
            .iter()
            .filter_map(|k| self.state.channels.get(k).map(|c| c.name.clone()))
            .collect();
        if !channels.is_empty() {
            let joined = channels.join(" ");
            self.numeric(uid, num::RPL_WHOISCHANNELS, &[&target.nick, &joined]);
        }
        if let Some(away) = &target.away {
            self.numeric(uid, num::RPL_AWAY, &[&target.nick, away]);
        }
        self.numeric(uid, num::RPL_ENDOFWHOIS, &[&target.nick, "End of /WHOIS list"]);
    }

    fn cmd_mode(&mut self, uid: &UserId, msg: &Message) {
        let Some(target) = msg.param(0).map(|s| s.to_string()) else {
            self.numeric(uid, num::ERR_NEEDMOREPARAMS, &["MODE", "Not enough parameters"]);
            return;
        };
        if !is_channel_name(&target) {
            let modes = if self.state.user(uid).map(|u| u.oper).unwrap_or(false) {
                if self.state.user(uid).map(|u| u.rf_tx).unwrap_or(false) {
                    "+oR"
                } else {
                    "+o"
                }
            } else if self.state.user(uid).map(|u| u.rf_tx).unwrap_or(false) {
                "+R"
            } else {
                "+i"
            };
            self.numeric(uid, num::RPL_UMODEIS, &[modes]);
            return;
        }
        let Some(chan) = self.state.channel(&target).cloned() else {
            self.numeric(uid, num::ERR_NOSUCHCHANNEL, &[&target, "No such channel"]);
            return;
        };
        let Some(changes) = msg.param(1).map(|s| s.to_string()) else {
            let modes = chan.mode_string();
            self.numeric(uid, num::RPL_CHANNELMODEIS, &[&chan.name, &modes]);
            return;
        };
        let is_op = chan.members.get(uid).map(|f| f.op).unwrap_or(false);
        let is_oper = self.state.user(uid).map(|u| u.oper).unwrap_or(false);
        if !is_op && !is_oper {
            self.numeric(uid, num::ERR_CHANOPRIVSNEEDED, &[&chan.name, "You're not channel operator"]);
            return;
        }
        // `+r` (RF bridging) is reserved to control operators: turning it on
        // decides what gets transmitted under the gateway's licence.
        let mut adding = true;
        let mut arg_index = 2;
        for c in changes.chars() {
            match c {
                '+' => adding = true,
                '-' => adding = false,
                'm' => {
                    if chan.rf && !is_oper {
                        self.numeric(
                            uid,
                            num::ERR_NOPRIVILEGES,
                            &["Only a control operator may change +m on an RF channel"],
                        );
                    } else if let Some(ch) = self.state.channel_mut(&target) {
                        ch.moderated = adding;
                    }
                }
                't' => {
                    if let Some(ch) = self.state.channel_mut(&target) {
                        ch.topic_locked = adding;
                    }
                }
                'r' => {
                    if !is_oper {
                        self.numeric(uid, num::ERR_NOPRIVILEGES, &["Only a control operator may change +r"]);
                    } else if let Some(ch) = self.state.channel_mut(&target) {
                        ch.rf = adding;
                    }
                }
                'k' => {
                    let key = msg.param(arg_index).map(|s| s.to_string());
                    arg_index += 1;
                    if let Some(ch) = self.state.channel_mut(&target) {
                        ch.key = if adding { key } else { None };
                    }
                }
                'l' => {
                    let limit = msg.param(arg_index).and_then(|s| s.parse::<usize>().ok());
                    arg_index += 1;
                    if let Some(ch) = self.state.channel_mut(&target) {
                        ch.limit = if adding { limit } else { None };
                    }
                }
                'o' | 'v' => {
                    let who = msg.param(arg_index).map(|s| s.to_string());
                    arg_index += 1;
                    if c == 'o' && chan.rf && !is_oper {
                        self.numeric(
                            uid,
                            num::ERR_NOPRIVILEGES,
                            &["Only a control operator may grant +o on an RF channel"],
                        );
                        continue;
                    }
                    if let Some(target_id) = who.as_deref().and_then(|n| self.find_target(n)) {
                        if let Some(ch) = self.state.channel_mut(&target) {
                            if let Some(flags) = ch.members.get_mut(&target_id) {
                                if c == 'o' {
                                    flags.op = adding;
                                } else {
                                    flags.voice = adding;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        let prefix = self.state.user(uid).map(|u| u.prefix()).unwrap_or_default();
        let mut params = vec![chan.name.clone(), changes];
        params.extend(msg.params.iter().skip(2).cloned());
        let line = Message::new("MODE", params).with_prefix(prefix).to_string();
        for member in self.state.members(&chan.name) {
            if let UserId::Ip(id) = member {
                self.send_raw(id, line.clone());
            }
        }
    }

    fn cmd_oper(&mut self, uid: &UserId, msg: &Message) {
        let (Some(name), Some(pass)) = (msg.param(0), msg.param(1)) else {
            self.numeric(uid, num::ERR_NEEDMOREPARAMS, &["OPER", "Not enough parameters"]);
            return;
        };
        if !self.auth_rate_ok(uid) {
            return;
        }
        // Compare every configured oper, and compare the password in constant
        // time. `==` on a secret leaks its length and its first differing byte
        // through timing, and OPER is the command that hands out control of a
        // transmitter.
        let mut ok = false;
        for o in &self.config.opers {
            if constant_time_eq(&o.name, name) && constant_time_eq(&o.password, pass) {
                ok = true;
            }
        }
        if ok {
            if let Some(u) = self.state.user_mut(uid) {
                u.oper = true;
            }
            self.numeric(uid, num::RPL_YOUREOPER, &["You are now a control operator"]);
            if let Some(u) = self.state.user(uid) {
                self.audit.event("oper", &[("nick", &u.nick), ("host", &u.host)]);
            }
            self.refresh_privileges(uid);
        } else {
            self.numeric(uid, num::ERR_PASSWDMISMATCH, &["Password incorrect"]);
            if let Some(u) = self.state.user(uid) {
                self.audit.event("oper_fail", &[("nick", &u.nick), ("host", &u.host)]);
            }
        }
    }

    /// The key an airtime rate limiter should count against.
    ///
    /// Never the nickname: `/nick` is free and instantaneous, so a nick-keyed
    /// bucket is a rate limit a user resets by typing one command. The host
    /// survives nick changes, and reconnecting to get a fresh one is already
    /// capped by `listen.max_conns_per_host`.
    fn rate_key(&self, uid: &UserId) -> String {
        match self.state.user(uid) {
            Some(u) if u.is_rf() => u
                .callsign
                .as_ref()
                .map(|c| c.to_string())
                .unwrap_or_else(|| u.nick.clone()),
            Some(u) => format!("ip:{}", u.host),
            None => "unknown".into(),
        }
    }

    // ------------------------------------------------------------ messaging

    fn cmd_privmsg(&mut self, uid: &UserId, msg: &Message, notice: bool) {
        let Some(target) = msg.param(0).map(|s| s.to_string()) else {
            self.numeric(uid, num::ERR_NOSUCHNICK, &["*", "No recipient given"]);
            return;
        };
        let Some(text) = msg.param(1).map(|s| s.to_string()) else {
            self.numeric(uid, num::ERR_NOTEXTTOSEND, &["No text to send"]);
            return;
        };
        if text.is_empty() {
            self.numeric(uid, num::ERR_NOTEXTTOSEND, &["No text to send"]);
            return;
        }
        let Some(sender) = self.state.user(uid).cloned() else {
            return;
        };

        if is_channel_name(&target) {
            let Some(chan) = self.state.channel(&target).cloned() else {
                self.numeric(uid, num::ERR_NOSUCHCHANNEL, &[&target, "No such channel"]);
                return;
            };
            let member = chan.members.get(uid).copied();
            if member.is_none() {
                self.numeric(uid, num::ERR_CANNOTSENDTOCHAN, &[&chan.name, "Cannot send to channel"]);
                return;
            }
            if chan.moderated && !member.map(|f| f.op || f.voice).unwrap_or(false) {
                self.numeric(uid, num::ERR_CANNOTSENDTOCHAN, &[&chan.name, "Channel is moderated (+m); identify with CALLSIGN for +v"]);
                return;
            }

            if chan.rf {
                let key = format!("{}:{}", self.rate_key(uid), chan.name);
                if !self.policy.rf_channel_rate_ok(&key, Instant::now()) {
                    self.notice_user(
                        uid,
                        "Flood protection: too many messages on the RF channel. Slow down.",
                    );
                    self.audit.event(
                        "flood_rf",
                        &[("nick", &sender.nick), ("channel", &chan.name)],
                    );
                    return;
                }
            }

            let mut allow_rf = chan.rf && chan.has_rf_members() && self.rf_available();
            let mut text = text;
            let mut truncated = false;
            if allow_rf {
                match self.screen_for_air(uid, &text) {
                    Some(s) => {
                        text = s.text;
                        truncated = s.truncated;
                    }
                    None => allow_rf = false,
                }
            } else if chan.rf {
                let why = self.channel_air_line(&chan.name);
                if !why.is_empty() {
                    self.notice_user(uid, &why);
                }
            }
            let d = Delivery::Privmsg {
                from_nick: sender.nick.clone(),
                from_prefix: sender.prefix(),
                target: chan.name.clone(),
                text,
                notice,
                truncated,
            };
            self.broadcast_channel_ex(&chan.name, &d, Some(uid), allow_rf);
            if allow_rf && self.config.radio.notice_air_relay && !notice {
                // Say "queued", not "relayed". On a duty-limited channel the
                // two are different, sometimes by a minute, and a sender who
                // is told the truth will not repeat themselves — which is the
                // cheapest airtime saving available.
                let eta = self.rf_eta();
                let when = if eta.as_secs() < 2 {
                    "going out now".to_string()
                } else {
                    format!("about {}s of queue ahead of it", eta.as_secs())
                };
                self.notice_user(
                    uid,
                    &format!(
                        "Queued for RF ({}), {when}. {} station(s) on frequency.",
                        self.config.radio.callsign,
                        self.sessions.peers().count()
                    ),
                );
            }
            return;
        }

        let Some(target_id) = self.find_target(&target) else {
            self.offer_mailbox(uid, &sender.nick, &target, &text, notice);
            return;
        };
        let mut text = text;
        let mut truncated = false;
        if target_id.is_rf() {
            match self.screen_for_air(uid, &text) {
                Some(s) => {
                    text = s.text;
                    truncated = s.truncated;
                }
                None => return,
            }
        }
        if let Some(away) = self.state.user(&target_id).and_then(|u| u.away.clone()) {
            self.numeric(uid, num::RPL_AWAY, &[&target, &away]);
        }
        let d = Delivery::Privmsg {
            from_nick: sender.nick.clone(),
            from_prefix: sender.prefix(),
            target: target.clone(),
            text,
            notice,
            truncated,
        };
        self.deliver(&target_id, &d);
    }

    /// A message to a station that is not currently in range. If it names a
    /// plausible callsign and the mailbox is enabled, hold it; otherwise this
    /// is an ordinary "no such nick".
    fn offer_mailbox(
        &mut self,
        uid: &UserId,
        from: &str,
        target: &str,
        text: &str,
        notice: bool,
    ) {
        let call = crate::callsign::Callsign::from_nick(target)
            .ok()
            .filter(|c| c.looks_like_amateur_call());
        let Some(call) = call else {
            self.numeric(uid, num::ERR_NOSUCHNICK, &[target, "No such nick/channel"]);
            return;
        };
        if !self.mailbox.enabled || !self.config.radio.enabled {
            self.numeric(uid, num::ERR_NOSUCHNICK, &[target, "No such nick/channel"]);
            return;
        }
        let Some(screened) = self.screen_for_air(uid, text) else {
            return;
        };
        let message = crate::server::mailbox::StoredMessage {
            from: from.to_string(),
            text: screened.text,
            truncated: screened.truncated,
            notice,
            stored_at: Instant::now(),
        };
        match self.mailbox.store(&call, message) {
            Ok(depth) => {
                let hours = self.config.radio.mailbox_ttl_secs / 3600;
                self.notice_user(
                    uid,
                    &format!(
                        "{call} is not on frequency. Held for delivery when the station is \
                         next heard ({depth} waiting, dropped after {hours}h)."
                    ),
                );
            }
            Err(e) => {
                let reason = match e {
                    crate::server::mailbox::StoreError::Disabled => "the mailbox is disabled",
                    crate::server::mailbox::StoreError::StationFull => {
                        "that station already has as much mail as it can hold"
                    }
                    crate::server::mailbox::StoreError::GatewayFull => {
                        "the gateway mailbox is full"
                    }
                };
                self.notice_user(uid, &format!("Not held for {call}: {reason}."));
            }
        }
    }

    /// Common gate for anything an IP user wants to put on the air. Returns
    /// the text to transmit, or `None` if it must not be transmitted (the
    /// user has already been told why).
    ///
    /// Every refusal below happens *before* the message is committed to the
    /// radio queue, and every one of them says something to the sender. The
    /// alternative — accept it, queue it, and let the transmitter drop it two
    /// minutes later — is the worst of both worlds: the sender believes it
    /// went out, and the airtime was reserved for nothing.
    fn screen_for_air(&mut self, uid: &UserId, text: &str) -> Option<Screened> {
        if !self.rf_available() {
            self.notice_user(uid, "The transmitter is off; your message stayed on the wire.");
            return None;
        }
        if !self.user_may_tx_rf(uid) {
            self.notice_user(
                uid,
                "Not relayed to RF: you do not have RF-TX privilege. \
                 Register this nick, then ask a control operator to RADIO GRANT it. \
                 CALLSIGN is also required. Until then your messages stay on IRC.",
            );
            return None;
        }
        let identified = self.state.user(uid).and_then(|u| u.callsign.clone());
        if identified.is_none() {
            self.notice_user(
                uid,
                "Not relayed to RF: identify with CALLSIGN <yourcall> first. \
                 Everything transmitted here is third-party traffic under the \
                 gateway licensee's responsibility.",
            );
            return None;
        }
        if let Some(call) = &identified {
            if !self.policy.station_allowed(call) {
                self.notice_user(uid, "Not relayed to RF: your callsign is not permitted on this gateway.");
                return None;
            }
        }
        if !self.policy.ip_rate_ok(&self.rate_key(uid), Instant::now()) {
            // Quote the actual link speed. "1200 bits per second" was
            // hardcoded, which is wrong on every HF gateway.
            let baud = self.config.radio.duty.baud;
            self.notice_user(
                uid,
                &format!(
                    "Not relayed to RF: you are sending faster than the channel can carry. \
                     Slow down; the radio side is {baud} bits per second."
                ),
            );
            return None;
        }
        let mut truncated = false;
        let screened = match self.policy.screen_outbound(text) {
            Verdict::Allow(t) => t,
            Verdict::Truncated(t) => {
                truncated = true;
                self.notice_user(
                    uid,
                    &format!(
                        "Your message was shortened to {} characters before transmission. \
                         The radio side carries sentences, not paragraphs.",
                        self.policy.config.max_rf_text_len
                    ),
                );
                t
            }
            Verdict::Deny(reason) => {
                self.notice_user(uid, reason);
                return None;
            }
        };

        // Last gate, and the one that protects the transmitter: is there room
        // in the airtime backlog? Checked here rather than at the transmitter
        // because from here we can still tell the sender. The payload also
        // carries the channel name and the sender's nick, so allow for those.
        let octets = self.wire_octets(screened.len() + 40);
        if !self.rf_backlog_has_room(octets, TxClass::Chat) {
            let queued = self.rf_eta().as_secs();
            self.notice_user(
                uid,
                &format!(
                    "Not put on the air: the transmit queue is {queued}s deep and the duty-cycle \
                     limit will not clear it in time. Your message was delivered on IRC. \
                     Try again shortly — or say it shorter."
                ),
            );
            self.stats.rf_frames_refused += 1;
            self.audit.event("rf_backlog_refused", &[("octets", &octets.to_string())]);
            return None;
        }
        Some(Screened {
            text: screened,
            truncated,
        })
    }

    // ------------------------------------------------------------ extensions

    fn cmd_callsign(&mut self, uid: &UserId, msg: &Message) {
        let Some(arg) = msg.param(0) else {
            let current = self
                .state
                .user(uid)
                .and_then(|u| u.callsign.clone())
                .map(|c| c.to_string())
                .unwrap_or_else(|| "none".into());
            self.notice_user(uid, &format!("Your callsign is set to: {current}"));
            return;
        };
        let Ok(call) = arg.parse::<crate::callsign::Callsign>() else {
            self.notice_user(uid, "That is not a valid callsign.");
            return;
        };
        if call.require_amateur().is_err() {
            self.notice_user(uid, "That does not look like an amateur callsign.");
            return;
        }
        if !self.policy.station_allowed(&call) {
            self.notice_user(uid, "That callsign is not permitted on this gateway.");
            return;
        }
        // Anyone can type any callsign. We record the claim, show it to
        // everyone, and log it; we do not pretend it is authentication.
        if let Some(u) = self.state.user_mut(uid) {
            u.callsign = Some(call.clone());
        }
        if self.state.user(uid).map(|u| u.nick_identified).unwrap_or(false) {
            if let Some(nick) = self.state.user(uid).map(|u| u.nick.clone()) {
                let _ = self.accounts.set_callsign(&nick, &call.to_string());
            }
        }
        info!(?uid, %call, "IP user claimed a callsign");
        if let Some(u) = self.state.user(uid) {
            self.audit.event(
                "callsign",
                &[("nick", &u.nick), ("call", &call.to_string()), ("host", &u.host)],
            );
        }
        self.notice_user(
            uid,
            &format!(
                "Callsign recorded as {call}. This is an unverified claim and is logged \
                 as such. You are responsible for your own transmissions."
            ),
        );
        self.refresh_privileges(uid);
    }

    fn cmd_radio(&mut self, uid: &UserId, msg: &Message) {
        let sub = msg.param(0).unwrap_or("STATUS").to_ascii_uppercase();
        let oper = self.state.user(uid).map(|u| u.oper).unwrap_or(false);
        if matches!(sub.as_str(), "STATUS") {
            let status = self.radio_status_line();
            self.notice_user(uid, &status);
            if oper {
                let s = self.stats.clone();
                let up = self.uptime().as_secs();
                self.notice_user(
                    uid,
                    &format!(
                        "up {}h{:02}m; frames rx {} tx {} refused {} dropped {} ({} bytes); \
                         stations {}; mail {}",
                        up / 3600,
                        (up % 3600) / 60,
                        s.rf_frames_rx,
                        s.rf_frames_tx,
                        s.rf_frames_refused,
                        s.rf_frames_dropped,
                        s.rf_bytes_tx,
                        self.sessions.peers().count(),
                        self.mailbox.len()
                    ),
                );
                if let Some(a) = self.airtime() {
                    let summary = a.summary();
                    self.notice_user(uid, &summary);
                }
            }
            return;
        }
        if !oper {
            self.numeric(uid, num::ERR_NOPRIVILEGES, &["Permission denied"]);
            return;
        }
        match sub.as_str() {
            "OFF" => {
                // Identify before going quiet: an automatically controlled
                // station has to sign off the series of transmissions it made.
                self.id_if_needed();
                self.rf_enabled = false;
                // Hard inhibit: discard whatever is already queued in the TNC
                // task instead of radiating it after the operator said stop.
                self.set_tx_inhibit(true);
                info!("transmitter disabled by control operator");
                self.notice_user(
                    uid,
                    "Transmitter disabled and the transmit queue purged. The IRC side keeps running.",
                );
                self.audit.event("radio_off", &[]);
                let line = self.radio_status_line();
                for ch in self
                    .state
                    .channels
                    .values()
                    .filter(|c| c.rf)
                    .map(|c| c.name.clone())
                    .collect::<Vec<_>>()
                {
                    self.notice_rf_audience(&ch, &line);
                }
            }
            "ON" => {
                if self.config.radio.enabled {
                    self.set_tx_inhibit(false);
                    self.rf_enabled = true;
                    self.notice_user(uid, "Transmitter enabled.");
                    self.audit.event("radio_on", &[]);
                    let line = self.radio_status_line();
                    for ch in self
                        .state
                        .channels
                        .values()
                        .filter(|c| c.rf)
                        .map(|c| c.name.clone())
                        .collect::<Vec<_>>()
                    {
                        self.notice_rf_audience(&ch, &line);
                    }
                } else {
                    self.notice_user(uid, "Radio support is disabled in the configuration.");
                }
            }
            "ID" => {
                self.force_id();
                self.notice_user(uid, "Station identification transmitted.");
            }
            "HEARD" => {
                let mut rows: Vec<String> = self
                    .sessions
                    .peers()
                    .map(|p| {
                        format!(
                            "{} last heard {}s ago, {} channels, {} queued, {} dropped",
                            p.call,
                            p.last_heard.elapsed().as_secs(),
                            p.channels.len(),
                            p.queue_depth(),
                            p.dropped
                        )
                    })
                    .collect();
                rows.sort();
                if rows.is_empty() {
                    self.notice_user(uid, "No stations heard.");
                }
                for r in rows {
                    self.notice_user(uid, &r);
                }
            }
            "DUTY" => {
                match self.airtime() {
                    Some(a) => {
                        let summary = a.summary();
                        self.notice_user(uid, &summary);
                        let d = &self.config.radio.duty;
                        if d.enabled {
                            self.notice_user(
                                uid,
                                &format!(
                                    "limits: {}% of {}s, max {}s continuous then {}s cooldown, \
                                     {}s per rolling hour, frames dropped after {}s held \
                                     (baud {}, txdelay {}ms, txtail {}ms)",
                                    d.max_duty_percent,
                                    d.window_secs,
                                    d.max_continuous_secs,
                                    d.cooldown_secs,
                                    d.hourly_airtime_secs,
                                    d.max_hold_secs,
                                    d.baud,
                                    d.txdelay_ms,
                                    d.txtail_ms,
                                ),
                            );
                        } else {
                            self.notice_user(
                                uid,
                                "The airtime governor is DISABLED in the configuration. \
                                 Nothing is protecting the finals or the channel.",
                            );
                        }
                    }
                    None => self.notice_user(uid, "No TNC; there is no airtime to report."),
                }
            }
            "QUEUE" => {
                // Everything that has been accepted but not yet radiated, in
                // the three places it can be waiting.
                match self.airtime() {
                    Some(a) => {
                        self.notice_user(
                            uid,
                            &format!(
                                "transmit queue: {} frame(s), {:.1}s of airtime, \
                                 next slot in {:.1}s (budget {}s)",
                                a.queued_frame_count(),
                                a.queued().as_secs_f64(),
                                Duration::from_millis(
                                    a.next_slot_ms.load(std::sync::atomic::Ordering::Relaxed)
                                )
                                .as_secs_f64(),
                                self.rf_backlog_budget().as_secs(),
                            ),
                        );
                    }
                    None => self.notice_user(uid, "No TNC; nothing can be queued."),
                }
                let mut waiting: Vec<String> = self
                    .sessions
                    .peers()
                    .filter(|p| p.queue_depth() > 0)
                    .map(|p| {
                        format!(
                            "  {}: {} message(s) awaiting acknowledgement, {} dropped",
                            p.call,
                            p.queue_depth(),
                            p.dropped
                        )
                    })
                    .collect();
                waiting.sort();
                if waiting.is_empty() {
                    self.notice_user(uid, "No per-station messages in flight.");
                } else {
                    self.notice_user(uid, "Per-station (reliable, awaiting ACK):");
                    for w in waiting {
                        self.notice_user(uid, &w);
                    }
                }
                let held = self.mailbox.len();
                self.notice_user(
                    uid,
                    &format!(
                        "Held for stations out of range: {held} message(s). \
                         Refused for backlog since start: {}. Dropped at the transmitter: {}.",
                        self.stats.rf_frames_refused, self.stats.rf_frames_dropped
                    ),
                );
            }
            "LIMIT" => {
                let what = msg.param(1).unwrap_or("").to_ascii_uppercase();
                let value = msg.param(2);
                let Some(a) = self.airtime().cloned() else {
                    self.notice_user(uid, "No TNC; there is nothing to limit.");
                    return;
                };
                match (what.as_str(), value) {
                    ("DUTY", Some(v)) => {
                        let asked: Option<u32> = if v.eq_ignore_ascii_case("off") {
                            None
                        } else {
                            match v.parse() {
                                Ok(p) => Some(p),
                                Err(_) => {
                                    self.notice_user(uid, "Usage: RADIO LIMIT DUTY <1-50|off>");
                                    return;
                                }
                            }
                        };
                        let applied = a.set_duty_override(asked);
                        let text = match applied {
                            Some(p) if Some(p) != asked => format!(
                                "Duty cycle limited to {p}% — the ceiling is {p}%, \
                                 whatever was asked for.",
                            ),
                            Some(p) => format!("Duty cycle limited to {p}% until further notice."),
                            None => "Duty override cleared; the configured limit applies.".into(),
                        };
                        self.notice_user(uid, &text);
                        self.audit.event(
                            "radio_limit_duty",
                            &[("percent", &applied.map(|p| p.to_string()).unwrap_or("off".into()))],
                        );
                    }
                    ("PACING", Some(v)) => {
                        let ms: Option<u64> = if v.eq_ignore_ascii_case("off") {
                            None
                        } else {
                            match v.parse() {
                                Ok(m) => Some(m),
                                Err(_) => {
                                    self.notice_user(
                                        uid,
                                        "Usage: RADIO LIMIT PACING <milliseconds|off>",
                                    );
                                    return;
                                }
                            }
                        };
                        a.set_pacing_override(ms);
                        let text = match ms {
                            Some(m) => format!(
                                "Minimum gap between transmissions set to {m}ms. \
                                 This slows the station down; it cannot speed it past the \
                                 duty-cycle limit."
                            ),
                            None => "Pacing override cleared; the configured gap applies.".into(),
                        };
                        self.notice_user(uid, &text);
                        self.audit.event(
                            "radio_limit_pacing",
                            &[("ms", &ms.map(|m| m.to_string()).unwrap_or("off".into()))],
                        );
                    }
                    _ => self.notice_user(
                        uid,
                        "RADIO LIMIT DUTY <1-50|off> | RADIO LIMIT PACING <ms|off>. \
                         Both take effect on the next frame and are not saved to the \
                         configuration file.",
                    ),
                }
            }
            "MAIL" => {
                let rows = self.mailbox.summary();
                if rows.is_empty() {
                    self.notice_user(uid, "No messages held.");
                }
                for (call, depth) in rows {
                    self.notice_user(uid, &format!("{call}: {depth} message(s) held"));
                }
            }
            "KICK" => {
                let Some(call) = msg.param(1).and_then(|c| c.parse().ok()) else {
                    self.notice_user(uid, "Usage: RADIO KICK <callsign>");
                    return;
                };
                let target = UserId::Rf(call);
                self.quit_user(&target, "Removed by control operator");
                self.notice_user(uid, "Station removed.");
            }
            "GRANT" => {
                let Some(nick) = msg.param(1).map(|s| s.to_string()) else {
                    self.notice_user(uid, "Usage: RADIO GRANT <nick>");
                    return;
                };
                self.grant_rf_tx(uid, &nick, true);
            }
            "REVOKE" => {
                let Some(nick) = msg.param(1).map(|s| s.to_string()) else {
                    self.notice_user(uid, "Usage: RADIO REVOKE <nick>");
                    return;
                };
                self.grant_rf_tx(uid, &nick, false);
            }
            _ => self.notice_user(
                uid,
                "RADIO STATUS | DUTY | QUEUE | LIMIT | ON | OFF | ID | HEARD | MAIL | \
                 KICK <callsign> | GRANT <nick> | REVOKE <nick>",
            ),
        }
    }

    fn cmd_kick(&mut self, uid: &UserId, msg: &Message) {
        let Some(channel) = msg.param(0).map(|s| s.to_string()) else {
            self.numeric(uid, num::ERR_NEEDMOREPARAMS, &["KICK", "Not enough parameters"]);
            return;
        };
        let Some(who) = msg.param(1).map(|s| s.to_string()) else {
            self.numeric(uid, num::ERR_NEEDMOREPARAMS, &["KICK", "Not enough parameters"]);
            return;
        };
        let reason = msg.param(2).unwrap_or("Kicked").to_string();
        let Some(chan) = self.state.channel(&channel).cloned() else {
            self.numeric(uid, num::ERR_NOSUCHCHANNEL, &[&channel, "No such channel"]);
            return;
        };
        if !self.is_chanop(uid, &chan.name) {
            self.numeric(uid, num::ERR_CHANOPRIVSNEEDED, &[&chan.name, "You're not channel operator"]);
            return;
        }
        let Some(target) = self.find_target(&who) else {
            self.numeric(uid, num::ERR_NOSUCHNICK, &[&who, "No such nick"]);
            return;
        };
        if !chan.members.contains_key(&target) {
            self.numeric(uid, num::ERR_USERNOTINCHANNEL, &[&who, &chan.name, "They aren't on that channel"]);
            return;
        }
        let kicker = self.state.user(uid).map(|u| u.prefix()).unwrap_or_default();
        let line = Message::new("KICK", vec![chan.name.clone(), who.clone(), reason.clone()])
            .with_prefix(kicker)
            .to_string();
        for member in self.state.members(&chan.name) {
            if let UserId::Ip(id) = member {
                self.send_raw(id, line.clone());
            }
        }
        self.state.part(&target, &chan.name);
        self.audit.event("kick", &[("channel", &chan.name), ("nick", &who), ("reason", &reason)]);
        if let UserId::Rf(call) = &target {
            if let Some(peer) = self.sessions.peer_mut(call) {
                peer.channels.remove(&chan.name);
            }
        }
    }

    fn cmd_kill(&mut self, uid: &UserId, msg: &Message) {
        if !self.state.user(uid).map(|u| u.oper).unwrap_or(false) {
            self.numeric(uid, num::ERR_NOPRIVILEGES, &["Permission denied"]);
            return;
        }
        let Some(who) = msg.param(0).map(|s| s.to_string()) else {
            self.numeric(uid, num::ERR_NEEDMOREPARAMS, &["KILL", "Not enough parameters"]);
            return;
        };
        let reason = msg.param(1).unwrap_or("Killed").to_string();
        let Some(target) = self.find_target(&who) else {
            self.numeric(uid, num::ERR_NOSUCHNICK, &[&who, "No such nick"]);
            return;
        };
        self.audit.event("kill", &[("nick", &who), ("reason", &reason)]);
        if let UserId::Ip(id) = target {
            self.send_raw(id, format!("ERROR :Killed ({reason})"));
        }
        self.quit_user(&target, &format!("Killed ({reason})"));
    }

    fn cmd_register(&mut self, uid: &UserId, msg: &Message) {
        let Some(password) = msg.param(0) else {
            self.numeric(uid, num::ERR_NEEDMOREPARAMS, &["REGISTER", "Not enough parameters"]);
            return;
        };
        if !self.auth_rate_ok(uid) {
            return;
        }
        let Some(user) = self.state.user(uid).cloned() else {
            return;
        };
        if Callsign::reserved_from_nick(&user.nick).is_some() {
            self.notice_user(uid, "Callsign nicks cannot be registered; they belong to RF stations.");
            return;
        }
        if password.len() < self.config.accounts.min_password_len {
            self.notice_account_error(uid, AccountError::TooShort);
            return;
        }
        if password.len() > 128 {
            self.notice_account_error(uid, AccountError::TooLong);
            return;
        }
        if !user.nick_identified && self.accounts.is_registered(&user.nick) {
            self.notice_account_error(uid, AccountError::Taken);
            return;
        }
        let password = password.to_string();
        self.run_argon2(uid, AuthKind::Register, user.nick, move || {
            hash_password(&password).map(Some)
        });
    }

    fn cmd_identify(&mut self, uid: &UserId, msg: &Message) {
        let Some(password) = msg.param(0) else {
            self.numeric(uid, num::ERR_NEEDMOREPARAMS, &["IDENTIFY", "Not enough parameters"]);
            return;
        };
        if !self.auth_rate_ok(uid) {
            return;
        }
        let Some(user) = self.state.user(uid).cloned() else {
            return;
        };
        let Some(hash) = self.accounts.hash_for(&user.nick) else {
            self.notice_account_error(uid, AccountError::NotRegistered);
            return;
        };
        let password = password.to_string();
        self.run_argon2(uid, AuthKind::Identify, user.nick, move || {
            verify_password(&password, &hash).map(|()| None)
        });
    }

    fn cmd_unregister(&mut self, uid: &UserId, msg: &Message) {
        let Some(password) = msg.param(0) else {
            self.numeric(uid, num::ERR_NEEDMOREPARAMS, &["UNREGISTER", "Not enough parameters"]);
            return;
        };
        if !self.auth_rate_ok(uid) {
            return;
        }
        let Some(user) = self.state.user(uid).cloned() else {
            return;
        };
        let Some(hash) = self.accounts.hash_for(&user.nick) else {
            self.notice_account_error(uid, AccountError::NotRegistered);
            return;
        };
        let password = password.to_string();
        self.run_argon2(uid, AuthKind::Unregister, user.nick, move || {
            verify_password(&password, &hash).map(|()| None)
        });
    }

    fn auth_rate_ok(&mut self, uid: &UserId) -> bool {
        let host = self
            .state
            .user(uid)
            .map(|u| u.host.clone())
            .unwrap_or_default();
        if !self.policy.identify_rate_ok(&host, Instant::now()) {
            self.notice_user(
                uid,
                "Slow down: too many password attempts from your host.",
            );
            self.audit.event("auth_throttle", &[("host", &host)]);
            return false;
        }
        true
    }

    /// Hash or verify off the event loop when a sender is attached; tests
    /// without one still run inline so they stay deterministic.
    fn run_argon2<F>(&mut self, uid: &UserId, kind: AuthKind, nick: String, work: F)
    where
        F: FnOnce() -> Result<Option<String>, AccountError> + Send + 'static,
    {
        let UserId::Ip(id) = *uid else {
            return;
        };
        if let Some(tx) = self.events.clone() {
            tokio::spawn(async move {
                let outcome = tokio::task::spawn_blocking(work)
                    .await
                    .unwrap_or(Err(AccountError::Hash));
                let (result, password_hash) = match outcome {
                    Ok(hash) => (Ok(()), hash),
                    Err(e) => (Err(e), None),
                };
                let _ = tx
                    .send(Event::AuthFinished {
                        id,
                        kind,
                        nick,
                        result,
                        password_hash,
                    })
                    .await;
            });
            return;
        }
        let (result, password_hash) = match work() {
            Ok(hash) => (Ok(()), hash),
            Err(e) => (Err(e), None),
        };
        self.finish_auth(id, kind, nick, result, password_hash);
    }

    pub(crate) fn finish_auth(
        &mut self,
        id: ClientId,
        kind: AuthKind,
        nick: String,
        result: Result<(), AccountError>,
        password_hash: Option<String>,
    ) {
        let uid = UserId::Ip(id);
        let Some(user) = self.state.user(&uid).cloned() else {
            return;
        };
        if lower(&user.nick) != lower(&nick) {
            self.notice_user(&uid, "Nick changed during password check; try again.");
            return;
        }
        if let Err(e) = result {
            self.notice_account_error(&uid, e);
            return;
        }
        match kind {
            AuthKind::Identify => {
                if let Some(u) = self.state.user_mut(&uid) {
                    u.nick_identified = true;
                    u.identify_by = None;
                }
                self.notice_user(&uid, "Password accepted. You own this nick for this session.");
                self.audit.event("identify", &[("nick", &user.nick), ("host", &user.host)]);
                self.refresh_privileges(&uid);
            }
            AuthKind::Register => {
                let Some(hash) = password_hash else {
                    self.notice_account_error(&uid, AccountError::Hash);
                    return;
                };
                if user.nick_identified && self.accounts.is_registered(&user.nick) {
                    if let Err(e) = self.accounts.set_password_hash(&user.nick, hash) {
                        self.notice_account_error(&uid, e);
                        return;
                    }
                    self.notice_user(&uid, "Password updated.");
                    return;
                }
                if let Err(e) = self.accounts.insert_hashed(&user.nick, hash) {
                    self.notice_account_error(&uid, e);
                    return;
                }
                if let Some(u) = self.state.user_mut(&uid) {
                    u.nick_identified = true;
                    u.identify_by = None;
                }
                if let Some(c) = user.callsign.as_ref() {
                    let _ = self.accounts.set_callsign(&user.nick, &c.to_string());
                }
                self.notice_user(
                    &uid,
                    "Nick registered. The password is stored as an Argon2id hash, not recoverable. IDENTIFY on next connect.",
                );
                self.audit.event("nick_register", &[("nick", &user.nick), ("host", &user.host)]);
                self.refresh_privileges(&uid);
            }
            AuthKind::Unregister => {
                match self.accounts.drop_nick(&user.nick) {
                    Ok(()) => {
                        if let Some(u) = self.state.user_mut(&uid) {
                            u.nick_identified = false;
                            u.rf_tx = u.oper;
                        }
                        self.notice_user(&uid, "Nick unregistered.");
                        self.audit.event("nick_drop", &[("nick", &user.nick)]);
                        self.refresh_privileges(&uid);
                    }
                    Err(e) => self.notice_account_error(&uid, e),
                }
            }
        }
    }

    fn grant_rf_tx(&mut self, oper: &UserId, nick: &str, grant: bool) {
        if !self.accounts.is_registered(nick) {
            self.notice_user(
                oper,
                &format!("{nick} is not registered. They must REGISTER first; the grant is stored in the nick file and restored on IDENTIFY."),
            );
            return;
        }
        if let Err(e) = self.accounts.set_rf_tx(nick, grant) {
            self.notice_account_error(oper, e);
            return;
        }
        if let Some(target) = self.find_target(nick) {
            self.refresh_privileges(&target);
            self.notice_user(
                &target,
                if grant {
                    "A control operator granted you RF-TX. After CALLSIGN, your messages in +r channels may be radiated."
                } else {
                    "RF-TX revoked. Your messages stay on IRC."
                },
            );
        }
        let verb = if grant { "granted" } else { "revoked" };
        self.notice_user(
            oper,
            &format!("RF-TX {verb} for {nick} and stored in the nick file."),
        );
        self.audit.event(
            if grant { "rf_tx_grant" } else { "rf_tx_revoke" },
            &[("nick", nick)],
        );
    }

    fn notice_account_error(&mut self, uid: &UserId, e: AccountError) {
        let text = match e {
            AccountError::TooShort => format!(
                "Password too short (minimum {} characters).",
                self.config.accounts.min_password_len
            ),
            AccountError::TooLong => "Password too long.".into(),
            AccountError::Hash => "Could not hash the password.".into(),
            AccountError::Io => "Could not write the nick database.".into(),
            AccountError::Taken => "That nick is already registered. IDENTIFY to claim it.".into(),
            AccountError::BadPassword => "Password incorrect.".into(),
            AccountError::NotRegistered => "That nick is not registered. REGISTER <password> first.".into(),
        };
        self.notice_user(uid, &text);
    }

    fn force_id(&mut self) {
        let text = format!(
            "{} {}",
            self.config.radio.callsign, self.config.radio.id_text
        );
        self.broadcast(Kind::Id, encode_fields(&[&text]), TxClass::Control);
    }

    pub(crate) fn channel_display_name(&self, name: &str) -> String {
        self.state
            .channels
            .get(&lower(name))
            .map(|c| c.name.clone())
            .unwrap_or_else(|| name.to_string())
    }
}

/// Byte comparison that does not return early.
///
/// Lengths are still distinguishable (they always are, over a network), but
/// the content comparison is uniform, so an attacker cannot walk a password
/// out one byte at a time.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff = (a.len() ^ b.len()) as u8;
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn constant_time_eq_agrees_with_plain_equality() {
        assert!(constant_time_eq("hunter2x", "hunter2x"));
        assert!(!constant_time_eq("hunter2x", "hunter2y"));
        assert!(!constant_time_eq("hunter2x", "hunter2xx"));
        assert!(!constant_time_eq("", "x"));
        assert!(constant_time_eq("", ""));
    }
}
