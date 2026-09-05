//! Read-only questions about who is here: `WHO` and `WHOIS`.
//!
//! For a radio station these also report what the link layer knows — when it
//! was last heard, what is queued for it, what has been dropped — because on a
//! packet channel "is that station still there?" is the question people
//! actually have.

use crate::irc::message::{is_channel_name, Message};
use crate::irc::numerics as num;

use super::super::state::UserId;
use super::super::Server;

impl Server {
    pub(super) fn cmd_who(&mut self, uid: &UserId, msg: &Message) {
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

    pub(super) fn cmd_whois(&mut self, uid: &UserId, msg: &Message) {
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
            &[
                &target.nick,
                &target.username,
                &target.host,
                "*",
                &target.realname,
            ],
        );
        let desc = match &target.callsign {
            Some(c) if target.is_rf() => format!("Radio station {c}, heard via the gateway"),
            Some(c) => format!("Identified as {c} (connected over the Internet)"),
            None => "Not identified with a callsign".to_string(),
        };
        self.numeric(uid, num::RPL_WHOISSERVER, &[&target.nick, &server, &desc]);
        if target.oper {
            self.numeric(
                uid,
                num::RPL_WHOISOPERATOR,
                &[&target.nick, "is a control operator"],
            );
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
                &[
                    &target.nick,
                    "has RF-TX privilege (messages may be radiated)",
                ],
            );
        }
        if let (UserId::Rf(call), Some(peer)) = (&target.id, {
            let c = target.id.callsign().cloned();
            c.and_then(|c| self.radio.sessions.peer(&c))
        }) {
            let idle = peer.last_heard.elapsed().as_secs();
            let info = format!(
                "last heard {idle}s ago, {} queued, {} dropped",
                peer.queue_depth(),
                peer.dropped
            );
            self.numeric(
                uid,
                num::RPL_WHOISIDLE,
                &[&call.to_string(), &idle.to_string(), &info],
            );
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
        self.numeric(
            uid,
            num::RPL_ENDOFWHOIS,
            &[&target.nick, "End of /WHOIS list"],
        );
    }
}
