//! IRC command handling for clients connected over IP.
//!
//! The command set is deliberately small: RFC 1459 minus the parts that only
//! make sense in a linked network (SERVER, SQUIT, services, bans-by-mask).
//! Two commands are local extensions:
//!
//! * `CALLSIGN <call>` - an IP user identifies with an amateur callsign, which
//!   is what allows their traffic to be relayed to RF.
//! * `RADIO <subcommand>` - the control operator's console.

use std::time::Instant;

use tracing::info;

use crate::airc::{encode_fields, Kind};
use crate::irc::message::{is_channel_name, is_valid_nick, lower, Message};
use crate::irc::numerics as num;
use crate::policy::Verdict;

use super::state::{ClientId, UserId};
use super::{Delivery, Server};

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
            .map(|p| p == given)
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
        // A nick that looks like a callsign mapping is reserved for the real
        // station: SM0ABC|7 may only be used by SM0ABC-7 coming in over RF.
        if let Ok(call) = crate::callsign::Callsign::from_nick(&nick) {
            if call.looks_like_amateur_call() {
                let owned_by_self = self
                    .state
                    .user(uid)
                    .and_then(|u| u.callsign.clone())
                    .map(|c| c == call)
                    .unwrap_or(false);
                if !owned_by_self {
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
            }
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
        if let Some(u) = self.state.user_mut(uid) {
            u.got_nick = true;
        }

        if was_registered {
            let d = Delivery::NickChange {
                old_nick: old,
                prefix,
                new_nick: nick,
            };
            self.broadcast_peers(uid, &d, true);
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

        let isupport = format!(
            "CHANTYPES=#& PREFIX=(ov)@+ NICKLEN={} CHANNELLEN=50 CASEMAPPING=rfc1459 \
             NETWORK={} MAXTARGETS=1 TOPICLEN=200 RFPACLEN={}",
            self.config.server.max_nick_len, network, self.config.radio.paclen
        );
        self.numeric(uid, num::RPL_ISUPPORT, &[&isupport, "are supported by this server"]);

        self.send_lusers(uid);
        self.send_motd(uid);

        if self.config.radio.enabled {
            self.notice_user(
                uid,
                "This server bridges to amateur packet radio. Anything you send to a \
                 channel marked +r is transmitted on the air, in the clear, under the \
                 gateway's licence. Identify with CALLSIGN <yourcall> first.",
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

        if !self.state.join(uid, name) {
            return;
        }
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
            nick,
            prefix,
            channel: real_name.clone(),
        };
        self.broadcast_channel(&real_name, &d, None);
        self.send_topic(uid, &real_name, false);
        self.send_names(uid, &real_name);
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
        // Chunk to stay under the 512 byte line limit.
        for chunk in names.chunks(20) {
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
        if let Some(c) = self.state.channel_mut(&name) {
            c.topic = Some(topic.clone());
            c.topic_setter = nick.clone();
            c.topic_time = now;
        }
        let d = Delivery::Topic {
            nick,
            prefix,
            channel: chan.name.clone(),
            topic,
        };
        self.broadcast_channel(&chan.name, &d, None);
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
                "+o"
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
                    if let Some(ch) = self.state.channel_mut(&target) {
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
        let ok = self
            .config
            .opers
            .iter()
            .any(|o| o.name == name && o.password == pass);
        if ok {
            if let Some(u) = self.state.user_mut(uid) {
                u.oper = true;
            }
            self.numeric(uid, num::RPL_YOUREOPER, &["You are now a control operator"]);
        } else {
            self.numeric(uid, num::ERR_PASSWDMISMATCH, &["Password incorrect"]);
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
                self.numeric(uid, num::ERR_CANNOTSENDTOCHAN, &[&chan.name, "Channel is moderated (+m)"]);
                return;
            }

            let mut allow_rf = chan.rf && chan.has_rf_members() && self.rf_available();
            let mut text = text;
            if allow_rf {
                match self.screen_for_air(uid, &sender.nick, &text) {
                    Some(screened) => text = screened,
                    None => allow_rf = false,
                }
            }
            let d = Delivery::Privmsg {
                from_nick: sender.nick.clone(),
                from_prefix: sender.prefix(),
                target: chan.name.clone(),
                text,
                notice,
            };
            self.broadcast_channel_ex(&chan.name, &d, Some(uid), allow_rf);
            return;
        }

        let Some(target_id) = self.find_target(&target) else {
            self.offer_mailbox(uid, &sender.nick, &target, &text, notice);
            return;
        };
        let mut text = text;
        if target_id.is_rf() {
            match self.screen_for_air(uid, &sender.nick, &text) {
                Some(screened) => text = screened,
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
        let Some(text) = self.screen_for_air(uid, from, text) else {
            return;
        };
        let message = crate::server::mailbox::StoredMessage {
            from: from.to_string(),
            text,
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
    fn screen_for_air(&mut self, uid: &UserId, nick: &str, text: &str) -> Option<String> {
        if !self.rf_available() {
            self.notice_user(uid, "The transmitter is off; your message stayed on the wire.");
            return None;
        }
        let identified = self.state.user(uid).and_then(|u| u.callsign.clone());
        if self.policy.config.require_callsign_for_rf && identified.is_none() {
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
        if !self.policy.ip_rate_ok(nick, Instant::now()) {
            self.notice_user(
                uid,
                "Not relayed to RF: you are sending faster than the channel can carry. \
                 Slow down; the radio side is 1200 bits per second.",
            );
            return None;
        }
        match self.policy.screen_outbound(text) {
            Verdict::Allow(t) => Some(t),
            Verdict::Truncated(t) => {
                self.notice_user(uid, "Your message was shortened before transmission.");
                Some(t)
            }
            Verdict::Deny(reason) => {
                self.notice_user(uid, reason);
                None
            }
        }
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
        info!(?uid, %call, "IP user claimed a callsign");
        self.notice_user(
            uid,
            &format!(
                "Callsign recorded as {call}. This is an unverified claim and is logged \
                 as such. You are responsible for your own transmissions."
            ),
        );
    }

    fn cmd_radio(&mut self, uid: &UserId, msg: &Message) {
        if !self.state.user(uid).map(|u| u.oper).unwrap_or(false) {
            self.numeric(uid, num::ERR_NOPRIVILEGES, &["Permission denied"]);
            return;
        }
        let sub = msg.param(0).unwrap_or("STATUS").to_ascii_uppercase();
        match sub.as_str() {
            "STATUS" => {
                let s = self.stats.clone();
                let lines = vec![
                    format!(
                        "transmitter: {}",
                        if self.rf_available() { "ON" } else { "OFF" }
                    ),
                    format!(
                        "station: {} via {}",
                        self.config.radio.callsign,
                        if self.config.radio.path.is_empty() {
                            "direct".to_string()
                        } else {
                            self.config.radio.path.join(",")
                        }
                    ),
                    format!(
                        "frames rx {} tx {} dropped {} ({} bytes transmitted)",
                        s.rf_frames_rx, s.rf_frames_tx, s.rf_frames_dropped, s.rf_bytes_tx
                    ),
                    format!("stations heard: {}", self.sessions.peers().count()),
                    format!("messages held: {}", self.mailbox.len()),
                ];
                for l in lines {
                    self.notice_user(uid, &l);
                }
            }
            "OFF" => {
                self.rf_enabled = false;
                info!("transmitter disabled by control operator");
                self.notice_user(uid, "Transmitter disabled. The IRC side keeps running.");
            }
            "ON" => {
                if self.config.radio.enabled {
                    self.rf_enabled = true;
                    self.notice_user(uid, "Transmitter enabled.");
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
            _ => self.notice_user(
                uid,
                "RADIO STATUS | ON | OFF | ID | HEARD | MAIL | KICK <callsign>",
            ),
        }
    }

    fn force_id(&mut self) {
        let text = format!(
            "{} {}",
            self.config.radio.callsign, self.config.radio.id_text
        );
        self.broadcast(Kind::Id, encode_fields(&[&text]));
    }

    pub(crate) fn channel_display_name(&self, name: &str) -> String {
        self.state
            .channels
            .get(&lower(name))
            .map(|c| c.name.clone())
            .unwrap_or_else(|| name.to_string())
    }
}
