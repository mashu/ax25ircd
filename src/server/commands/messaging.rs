//! Messages, and the gate between an IRC user and the transmitter.
//!
//! [`Server::screen_for_air`] is the single place that decides whether
//! something an IP user typed may be radiated. Every refusal happens there,
//! before the message is committed to the radio queue, and every one of them
//! says something to the sender — accepting a message and then dropping it at
//! the transmitter is the worst outcome available, because the sender believes
//! it went out.

use std::time::Instant;


use crate::irc::message::{is_channel_name, Message};
use crate::irc::numerics as num;
use crate::policy::Verdict;

use super::super::state::UserId;
use super::super::{Delivery, Server, TxClass};
use super::Screened;

/// When a screened message would actually reach the air.
///
/// The difference matters for exactly one check. Everything else — privilege,
/// callsign, rate limit, content — applies the same either way.
#[derive(Copy, Clone, Debug)]
enum AirTiming {
    /// Queued for transmission now, so the airtime backlog applies.
    Now,
    /// Held for a station that is not on frequency. It will be transmitted
    /// whenever that station is next heard.
    Held,
}

impl Server {
    pub(super) fn cmd_privmsg(&mut self, uid: &UserId, msg: &Message, notice: bool) {
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

            let mut allow_rf = chan.rf && chan.has_rf_members() && self.radio.available();
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
                let eta = self.radio.eta();
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
                        self.radio.sessions.peers().count()
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
    pub(super) fn offer_mailbox(
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
        if !self.radio.mailbox.enabled || !self.config.radio.enabled {
            self.numeric(uid, num::ERR_NOSUCHNICK, &[target, "No such nick/channel"]);
            return;
        }
        let Some(screened) = self.screen_for_mailbox(uid, text) else {
            return;
        };
        let message = crate::server::mailbox::StoredMessage {
            from: from.to_string(),
            text: screened.text,
            truncated: screened.truncated,
            notice,
            stored_at: Instant::now(),
        };
        match self.radio.mailbox.store(&call, message) {
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
    pub(super) fn screen_for_air(&mut self, uid: &UserId, text: &str) -> Option<Screened> {
        self.screen(uid, text, AirTiming::Now)
    }

    /// As [`Server::screen_for_air`], for a message that will be held until
    /// the station is next heard.
    pub(super) fn screen_for_mailbox(&mut self, uid: &UserId, text: &str) -> Option<Screened> {
        self.screen(uid, text, AirTiming::Held)
    }

    fn screen(&mut self, uid: &UserId, text: &str, timing: AirTiming) -> Option<Screened> {
        if !self.radio.available() {
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
        //
        // It does not apply to a message being held: that will be transmitted
        // whenever the station next appears, which may be hours away, so the
        // backlog as it stands this instant says nothing about it. Refusing on
        // those grounds would mean a momentarily busy channel silently turned
        // off store-and-forward — exactly when it is most wanted.
        if matches!(timing, AirTiming::Held) {
            return Some(Screened {
                text: screened,
                truncated,
            });
        }
        if self.radio.interlock_down() {
            self.notice_user(
                uid,
                "Not put on the air: the safety interlock is holding the transmitter. \
                 Your message stayed on IRC.",
            );
            return None;
        }
        let octets = self.radio.wire_octets(screened.len() + 40);
        if !self.radio.backlog_has_room(octets, TxClass::Chat) {
            let queued = self.radio.eta().as_secs();
            self.notice_user(
                uid,
                &format!(
                    "Not put on the air: the transmit queue is {queued}s deep and the duty-cycle \
                     limit will not clear it in time. Your message was delivered on IRC. \
                     Try again shortly — or say it shorter."
                ),
            );
            self.radio.stats.rf_frames_refused += 1;
            self.audit.event("rf_backlog_refused", &[("octets", &octets.to_string())]);
            return None;
        }
        Some(Screened {
            text: screened,
            truncated,
        })
    }
}
