//! Control-operator commands: `OPER`, `KILL`, `CALLSIGN` and `RADIO`.
//!
//! `RADIO` is the station's control panel. Status is public; everything that
//! changes what the transmitter does — the kill switch, the live duty and
//! pacing limits, grants, removing a station — needs control-operator
//! privilege, because those are the licensee's decisions.

use std::time::Duration;

use tracing::info;

use crate::irc::message::Message;
use crate::irc::numerics as num;

use super::super::state::UserId;
use super::super::Server;
use super::constant_time_eq;

impl Server {
    pub(super) fn cmd_oper(&mut self, uid: &UserId, msg: &Message) {
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

    pub(super) fn cmd_callsign(&mut self, uid: &UserId, msg: &Message) {
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

    pub(super) fn cmd_radio(&mut self, uid: &UserId, msg: &Message) {
        let sub = msg.param(0).unwrap_or("STATUS").to_ascii_uppercase();
        let oper = self.state.user(uid).map(|u| u.oper).unwrap_or(false);
        if matches!(sub.as_str(), "STATUS") {
            let status = self.radio.status_line();
            self.notice_user(uid, &status);
            if oper {
                let s = self.radio.stats.clone();
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
                        self.radio.sessions.peers().count(),
                        self.radio.mailbox.len()
                    ),
                );
                if let Some(a) = self.radio.airtime() {
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
                self.radio.id_if_needed();
                self.radio.enabled = false;
                // Hard inhibit: discard whatever is already queued in the TNC
                // task instead of radiating it after the operator said stop.
                self.radio.set_tx_inhibit(true);
                info!("transmitter disabled by control operator");
                self.notice_user(
                    uid,
                    "Transmitter disabled and the transmit queue purged. The IRC side keeps running.",
                );
                self.audit.event("radio_off", &[]);
                let line = self.radio.status_line();
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
                    self.radio.set_tx_inhibit(false);
                    self.radio.enabled = true;
                    self.notice_user(uid, "Transmitter enabled.");
                    self.audit.event("radio_on", &[]);
                    let line = self.radio.status_line();
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
                if self.radio.identify_now() {
                    self.notice_user(uid, "Station identification transmitted.");
                } else {
                    self.notice_user(
                        uid,
                        "Station identification was not transmitted. Check RADIO STATUS.",
                    );
                }
            }
            "HEARD" => {
                let mut rows: Vec<String> = self.radio
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
                match self.radio.airtime() {
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
                match self.radio.airtime() {
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
                                self.radio.backlog_budget().as_secs(),
                            ),
                        );
                    }
                    None => self.notice_user(uid, "No TNC; nothing can be queued."),
                }
                let mut waiting: Vec<String> = self.radio
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
                let held = self.radio.mailbox.len();
                self.notice_user(
                    uid,
                    &format!(
                        "Held for stations out of range: {held} message(s). \
                         Refused for backlog since start: {}. Dropped at the transmitter: {}.",
                        self.radio.stats.rf_frames_refused, self.radio.stats.rf_frames_dropped
                    ),
                );
            }
            "LIMIT" => {
                let what = msg.param(1).unwrap_or("").to_ascii_uppercase();
                let value = msg.param(2);
                let Some(a) = self.radio.airtime().cloned() else {
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
                let rows = self.radio.mailbox.summary();
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

    pub(super) fn cmd_kill(&mut self, uid: &UserId, msg: &Message) {
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
}
