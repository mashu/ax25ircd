//! IRC command handling for clients connected over IP.
//!
//! The command set is deliberately small: RFC 1459 minus the parts that only
//! make sense in a linked network (SERVER, SQUIT, services, bans-by-mask).
//! Local extensions:
//!
//! * `CALLSIGN <call>` — claim an amateur callsign (`+v` on `+r` channels).
//!   Required before an IP user's traffic can be radiated; not proof of
//!   licence. `REGISTER` binds the claim to the nick so nobody else can take
//!   it.
//! * `RADIO <subcommand>` — transmitter status for everyone; the limits, the
//!   grants and the kill switch for control operators.
//!
//! This module is the dispatcher and the handful of things every command
//! family needs. The families themselves are the submodules.

mod accounts;
mod channels;
mod messaging;
mod misc;
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

/// Commands a listen-only (plaintext, off-box) connection may issue.
///
/// They may watch a channel. They may send the connection `PASS` so a
/// passworded server is still watchable. They may not send text, claim a
/// callsign, IDENTIFY/REGISTER/OPER, or anything that keys or retunes the
/// transmitter.
fn listen_only_command(cmd: &str, msg: &Message) -> bool {
    match cmd {
        "CAP" | "PASS" | "NICK" | "USER" | "QUIT" | "PING" | "PONG" | "JOIN" | "PART" | "NAMES"
        | "LIST" | "WHO" | "WHOIS" | "WHOWAS" | "MOTD" | "LUSERS" | "AWAY" | "RADIO"
        | "VERSION" | "TIME" | "ADMIN" | "INFO" | "HELP" | "STATS" | "LINKS" | "ISON"
        | "USERHOST" => true,
        "MODE" => msg.param(1).is_none(),
        "TOPIC" => msg.param(1).is_none(),
        _ => false,
    }
}

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

        if !registered
            && !matches!(
                cmd,
                "PASS" | "NICK" | "USER" | "QUIT" | "PING" | "PONG" | "CAP"
            )
        {
            self.numeric(&uid, num::ERR_NOTREGISTERED, &["You have not registered"]);
            return;
        }

        let listen_only = self
            .state
            .user(&uid)
            .map(|u| u.listen_only)
            .unwrap_or(false);
        if listen_only && !listen_only_command(cmd, &msg) {
            self.numeric(
                &uid,
                num::ERR_RESTRICTED,
                &[
                    cmd,
                    "This connection is listen-only. Connect with TLS to speak, identify, or control the radio.",
                ],
            );
            return;
        }

        match cmd {
            "CAP" => self.cmd_cap(&uid, &msg),
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
                } else {
                    let chans: Vec<String> = self
                        .state
                        .user(&uid)
                        .map(|u| {
                            u.channels
                                .iter()
                                .filter_map(|k| self.state.channels.get(k).map(|c| c.name.clone()))
                                .collect()
                        })
                        .unwrap_or_default();
                    if chans.is_empty() {
                        self.numeric(&uid, num::RPL_ENDOFNAMES, &["*", "End of /NAMES list"]);
                    } else {
                        for ch in chans {
                            self.send_names(&uid, &ch);
                        }
                    }
                }
            }
            "LIST" => self.cmd_list(&uid),
            "WHO" => self.cmd_who(&uid, &msg),
            "WHOIS" => self.cmd_whois(&uid, &msg),
            "WHOWAS" => self.cmd_whowas(&uid, &msg),
            "ISON" => self.cmd_ison(&uid, &msg),
            "USERHOST" => self.cmd_userhost(&uid, &msg),
            "VERSION" => self.cmd_version(&uid),
            "TIME" => self.cmd_time(&uid),
            "ADMIN" => self.cmd_admin(&uid),
            "INFO" => self.cmd_info(&uid),
            "HELP" => self.cmd_help(&uid, &msg),
            "STATS" => self.cmd_stats(&uid, &msg),
            "LINKS" => self.cmd_links(&uid),
            "INVITE" => self.cmd_invite(&uid, &msg),
            "MODE" => self.cmd_mode(&uid, &msg),
            "MOTD" => self.send_motd(&uid),
            "LUSERS" => self.send_lusers(&uid),
            "AWAY" => {
                let away = msg
                    .param(0)
                    .map(|s| s.to_string())
                    .filter(|s| !s.is_empty());
                if let Some(u) = self.state.user_mut(&uid) {
                    u.away = away.clone();
                }
                if away.is_some() {
                    self.numeric(
                        &uid,
                        num::RPL_NOWAWAY,
                        &["You have been marked as being away"],
                    );
                } else {
                    self.numeric(
                        &uid,
                        num::RPL_UNAWAY,
                        &["You are no longer marked as being away"],
                    );
                }
            }
            "OPER" => self.cmd_oper(&uid, &msg),
            "CALLSIGN" => self.cmd_callsign(&uid, &msg),
            "RADIO" => self.cmd_radio(&uid, &msg),
            "KICK" => self.cmd_kick(&uid, &msg),
            "KILL" => self.cmd_kill(&uid, &msg),
            "ACCOUNTS" => self.cmd_accounts(&uid),
            "DROPNICK" => self.cmd_dropnick(&uid, &msg),
            "UNCLAIM" => self.cmd_unclaim(&uid, &msg),
            "KLINE" => self.cmd_kline(&uid, &msg),
            "UNKLINE" => self.cmd_unkline(&uid, &msg),
            "KLINES" => self.cmd_klines(&uid),
            "PASSWD" => self.cmd_passwd(&uid, &msg),
            "REGISTER" => self.cmd_register(&uid, &msg),
            "IDENTIFY" => self.cmd_identify(&uid, &msg),
            "UNREGISTER" => self.cmd_unregister(&uid, &msg),
            other => {
                self.numeric(&uid, num::ERR_UNKNOWNCOMMAND, &[other, "Unknown command"]);
            }
        }
    }

    // ------------------------------------------------------- registration

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
