//! The gateway proper: what happens when a frame arrives from the air.
//!
//! Asymmetry is deliberate. Uplink frames (station -> gateway) are as short as
//! possible because the station is transmitting on battery through a handheld;
//! downlink frames carry the sender's nickname because the receiving station
//! has no other way to know who spoke.
//!
//! * uplink   `MSG [target, text]`
//! * downlink `MSG [target, from, text]`

use std::time::Instant;

use tracing::{debug, info, warn};

use crate::airc::{encode_fields, AircFrame, Kind};
use crate::ax25::{frame::PID_NO_L3, Ax25Frame};
use crate::callsign::Callsign;
use crate::irc::message::is_channel_name;
use crate::policy::{sanitize, Verdict};
use crate::server::state::{User, UserId};
use crate::server::{Delivery, Server};

impl Server {
    pub(crate) fn handle_rf_frame(&mut self, frame: Ax25Frame, now: Instant) {
        self.stats.rf_frames_rx += 1;

        if !frame.is_ui() || frame.pid != Some(PID_NO_L3) {
            debug!(target: "rf::monitor", "{}", frame.to_monitor_line());
            return;
        }
        let src = frame.source.call.clone();

        // Our own transmission coming back through a digipeater.
        if self.config.gateway_callsign().as_ref() == Some(&src) {
            return;
        }

        let airc = match AircFrame::decode(&frame.info) {
            Ok(f) => f,
            Err(_) => {
                // Other traffic shares this channel: APRS, NET/ROM, other
                // people's QSOs. Log it for the operator and leave it alone.
                debug!(target: "rf::monitor", "{}", frame.to_monitor_line());
                return;
            }
        };

        if src.require_amateur().is_err() {
            warn!(%src, "ignoring AIRC frame from an implausible callsign");
            return;
        }
        if !self.policy.station_allowed(&src) {
            debug!(%src, "station not permitted, ignoring");
            return;
        }

        let outcome = self.sessions.on_receive(&src, airc, now);
        for f in outcome.transmit {
            self.transmit_airc(&src, f);
        }
        if let Some(msg) = outcome.deliver {
            self.handle_airc_message(&src, msg, now);
        }
    }

    fn handle_airc_message(&mut self, src: &Callsign, msg: AircFrame, now: Instant) {
        let fields = msg.fields();
        match msg.kind {
            Kind::Hello => {
                let created = self.ensure_rf_user(src);
                let name = self.server_name().to_string();
                let motd = self
                    .config
                    .server
                    .motd
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "welcome".into());
                self.unicast(src, Kind::Welcome, encode_fields(&[&name, &motd]), true);
                if created {
                    info!(%src, "station registered");
                }
                self.flush_mailbox(src);
            }
            Kind::Join => {
                let Some(channel) = fields.first().cloned() else {
                    return;
                };
                if self.ensure_rf_user(src) {
                    self.flush_mailbox(src);
                }
                self.rf_join(src, &channel);
            }
            Kind::Part => {
                let Some(channel) = fields.first().cloned() else {
                    return;
                };
                let uid = UserId::Rf(src.clone());
                let display = self.channel_display_name(&channel);
                if self.state.user(&uid).is_some() {
                    self.rf_part(&uid, &display, fields.get(1).cloned().unwrap_or_default());
                }
                if let Some(peer) = self.sessions.peer_mut(src) {
                    peer.channels.remove(&display);
                }
            }
            Kind::Quit => {
                let uid = UserId::Rf(src.clone());
                let reason = fields.first().cloned().unwrap_or_else(|| "Signed off".into());
                self.quit_user(&uid, &reason);
            }
            Kind::Msg | Kind::Notice => {
                let (Some(target), Some(text)) = (fields.first(), fields.get(1)) else {
                    return;
                };
                self.rf_message(
                    src,
                    &target.clone(),
                    &text.clone(),
                    msg.kind == Kind::Notice,
                    now,
                );
            }
            Kind::Names => {
                let Some(channel) = fields.first().cloned() else {
                    return;
                };
                let display = self.channel_display_name(&channel);
                let names = self.state.names_of(&display).join(",");
                self.unicast(
                    src,
                    Kind::NamesReply,
                    encode_fields(&[&display, &names]),
                    false,
                );
            }
            Kind::Ping => {
                let token = fields.first().cloned().unwrap_or_default();
                self.unicast(src, Kind::Pong, encode_fields(&[&token]), false);
            }
            Kind::Id => {
                info!(target: "rf::monitor", %src, "identification: {}", fields.join(" "));
            }
            // Replies we never expect to receive, and ACKs, which the session
            // layer has already consumed.
            Kind::Ack
            | Kind::Welcome
            | Kind::NamesReply
            | Kind::Pong
            | Kind::Presence
            | Kind::Stored
            | Kind::Error => {}
        }
    }

    /// Create the IRC-side presence for a station heard on the air.
    /// Returns true if the user was newly created.
    fn ensure_rf_user(&mut self, call: &Callsign) -> bool {
        let uid = UserId::Rf(call.clone());
        if self.state.user(&uid).is_some() {
            return false;
        }
        let mut user = User::new(uid.clone(), format!("{call}.ax25"), Instant::now());
        user.username = "rf".into();
        user.realname = format!("{call} via {}", self.config.radio.callsign);
        user.callsign = Some(call.clone());
        user.registered = true;
        self.state.insert_user(user);

        // Nick collisions should not happen (callsign-shaped nicks are
        // reserved) but a station must never be locked out because of one.
        let mut nick = call.to_nick();
        let mut suffix = 1;
        while !self.state.set_nick(&uid, &nick) {
            nick = format!("{}_{suffix}", call.to_nick());
            suffix += 1;
            if suffix > 9 {
                self.state.remove_user(&uid);
                return false;
            }
        }
        self.sessions.touch(call, Instant::now()).registered = true;
        true
    }

    fn rf_join(&mut self, call: &Callsign, channel: &str) {
        let uid = UserId::Rf(call.clone());
        if !is_channel_name(channel) {
            self.unicast(
                call,
                Kind::Error,
                encode_fields(&["403", "no such channel"]),
                true,
            );
            return;
        }
        let display = self.channel_display_name(channel);
        let Some(chan) = self.state.channel(&display).cloned() else {
            self.unicast(
                call,
                Kind::Error,
                encode_fields(&["403", "no such channel"]),
                true,
            );
            return;
        };
        if !chan.rf {
            self.unicast(
                call,
                Kind::Error,
                encode_fields(&["404", "channel is not bridged to RF"]),
                true,
            );
            return;
        }
        if self.state.join(&uid, &display).is_none() {
            return;
        }
        if let Some(peer) = self.sessions.peer_mut(call) {
            peer.channels.insert(display.clone());
        }
        let flags = self
            .state
            .channel(&display)
            .and_then(|c| c.members.get(&uid).copied())
            .unwrap_or_default();
        let (nick, prefix) = self
            .state
            .user(&uid)
            .map(|u| (u.nick.clone(), u.prefix()))
            .unwrap_or_default();
        let d = Delivery::Join {
            nick: nick.clone(),
            prefix,
            channel: display.clone(),
        };
        // Other stations on frequency heard the JOIN themselves.
        self.broadcast_channel_ex(&display, &d, Some(&uid), false);
        if flags.voice {
            let server = self.server_name().to_string();
            self.announce_mode(&display, &server, "+v", &[&nick]);
        }
        if self.state.channel(&display).map(|c| c.has_rf_members()).unwrap_or(false) {
            let call_s = call.to_string();
            self.notice_rf_audience(
                &display,
                &format!("RF station {call_s} is on frequency. Messages from +v users will be radiated."),
            );
        }

        let names = self.state.names_of(&display).join(",");
        let topic = self
            .state
            .channel(&display)
            .and_then(|c| c.topic.clone())
            .unwrap_or_default();
        self.unicast(
            call,
            Kind::NamesReply,
            encode_fields(&[&display, &names, &topic]),
            true,
        );
    }

    fn rf_part(&mut self, uid: &UserId, channel: &str, reason: String) {
        let Some(user) = self.state.user(uid).cloned() else {
            return;
        };
        if !self
            .state
            .channel(channel)
            .map(|c| c.members.contains_key(uid))
            .unwrap_or(false)
        {
            return;
        }
        let d = Delivery::Part {
            nick: user.nick.clone(),
            prefix: user.prefix(),
            channel: channel.to_string(),
            reason: if reason.is_empty() {
                "Leaving".into()
            } else {
                reason
            },
        };
        self.broadcast_channel_ex(channel, &d, Some(uid), false);
        self.state.part(uid, channel);
        if !self
            .state
            .channel(channel)
            .map(|c| c.has_rf_members())
            .unwrap_or(true)
        {
            self.notice_rf_audience(
                channel,
                "No RF station remains in this channel. Messages stay on IRC until one joins.",
            );
        }
    }

    fn rf_message(&mut self, src: &Callsign, target: &str, text: &str, notice: bool, now: Instant) {
        if !self.policy.rf_station_rate_ok(src, now) {
            // Do not answer a flood with more transmissions; just drop it and
            // let the operator see it in the log.
            warn!(%src, "rate limit exceeded, dropping message");
            if let Some(peer) = self.sessions.peer_mut(src) {
                peer.dropped += 1;
            }
            return;
        }
        let text = sanitize(text);
        if text.is_empty() {
            return;
        }
        if self.ensure_rf_user(src) {
            self.flush_mailbox(src);
        }
        let uid = UserId::Rf(src.clone());
        let Some(user) = self.state.user(&uid).cloned() else {
            return;
        };

        if is_channel_name(target) {
            let display = self.channel_display_name(target);
            let Some(chan) = self.state.channel(&display).cloned() else {
                self.unicast(
                    src,
                    Kind::Error,
                    encode_fields(&["403", "no such channel"]),
                    true,
                );
                return;
            };
            if !chan.rf {
                self.unicast(
                    src,
                    Kind::Error,
                    encode_fields(&["404", "channel is not bridged to RF"]),
                    true,
                );
                return;
            }
            // Be forgiving: a lost JOIN must not silently swallow a QSO.
            if !chan.members.contains_key(&uid) {
                self.rf_join(src, &display);
            }
            let d = Delivery::Privmsg {
                from_nick: user.nick.clone(),
                from_prefix: user.prefix(),
                target: display.clone(),
                text,
                notice,
            };
            // Every station in range already heard this transmission. We only
            // repeat it if the operator has enabled store-and-forward for
            // hidden stations, and even then it is one extra transmission.
            let repeat = self.config.radio.repeat_rf_traffic;
            self.broadcast_channel_ex(&display, &d, Some(&uid), repeat);
            return;
        }

        // Private message to a nickname.
        let Some(target_id) = self.find_target(target) else {
            self.unicast(
                src,
                Kind::Error,
                encode_fields(&["401", "no such nick"]),
                true,
            );
            return;
        };
        let text = match self.policy.screen_outbound(&text) {
            Verdict::Allow(t) | Verdict::Truncated(t) => t,
            Verdict::Deny(_) => text,
        };
        let d = Delivery::Privmsg {
            from_nick: user.nick.clone(),
            from_prefix: user.prefix(),
            target: target.to_string(),
            text,
            notice,
        };
        self.deliver(&target_id, &d);
    }

    /// Transmit a single AIRC frame to one station (used for ACKs, which must
    /// not go through the session queue).
    fn transmit_airc(&mut self, dst: &Callsign, frame: AircFrame) {
        self.transmit_direct(dst, frame);
    }
}
