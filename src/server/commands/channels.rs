//! Channels: joining, leaving, membership, topics and modes.
//!
//! Two channel modes are not the usual IRC fare and are handled with more care
//! than the rest: `+r` marks a channel as bridged to the air, and `+m` decides
//! who may speak on one. Both are control-operator decisions, because they
//! settle what gets transmitted under the gateway licensee's callsign.



use crate::irc::message::{is_channel_name, Message};
use crate::irc::numerics as num;

use super::super::state::UserId;
use super::super::{Delivery, Server};

impl Server {
    pub(super) fn cmd_join(&mut self, uid: &UserId, msg: &Message) {
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

    pub(super) fn do_join(&mut self, uid: &UserId, name: &str, key: &str) {
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

    pub(super) fn cmd_part(&mut self, uid: &UserId, msg: &Message) {
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

    pub(super) fn send_topic(&mut self, uid: &UserId, channel: &str, explicit: bool) {
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

    pub(super) fn cmd_topic(&mut self, uid: &UserId, msg: &Message) {
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
            && self.radio.available();
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

    pub(super) fn cmd_list(&mut self, uid: &UserId) {
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

    pub(super) fn cmd_mode(&mut self, uid: &UserId, msg: &Message) {
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
                                // Record that this was a decision, not a
                                // derivation, so recomputing the derived
                                // flags later does not undo it.
                                if c == 'o' {
                                    flags.op = adding;
                                    flags.op_manual = adding;
                                } else {
                                    flags.voice = adding;
                                    flags.voice_manual = adding;
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

    pub(super) fn cmd_kick(&mut self, uid: &UserId, msg: &Message) {
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
            if let Some(peer) = self.radio.sessions.peer_mut(call) {
                peer.channels.remove(&chan.name);
            }
        }
    }
}
