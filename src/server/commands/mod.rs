//! IRC command handling for clients connected over IP.
//!
//! The command set is deliberately small: RFC 1459 minus the parts that only
//! make sense in a linked network (SERVER, SQUIT, services, bans-by-mask).
//! Local extensions:
//!
//! * `CALLSIGN <call>` — claim an amateur callsign (`+v` on `+r` channels).
//!   Required before an IP user's traffic can be radiated; not authentication.
//! * `RADIO <subcommand>` — transmitter status for everyone; the limits, the
//!   grants and the kill switch for control operators.
//!
//! This module is the dispatcher and the handful of things every command
//! family needs. The families themselves are the submodules.

mod accounts;
mod channels;
mod messaging;
mod operator;
mod queries;
mod registration;

use std::time::Instant;


use crate::irc::message::{lower, Message};
use crate::irc::numerics as num;

use super::state::{ClientId, UserId};

/// Text that has passed every gate between an IRC user and the transmitter,
/// and whether a policy limit shortened it on the way.
pub(crate) struct Screened {
    pub text: String,
    pub truncated: bool,
}
use super::Server;

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







    // ------------------------------------------------------------ channels













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




    // ------------------------------------------------------------ extensions














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
