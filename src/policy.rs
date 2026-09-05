//! Policy enforcement for anything that is about to be transmitted.
//!
//! Two very different concerns live here:
//!
//! * **Airtime.** The RF channel is a shared, half-duplex, ~1 kbit/s medium.
//!   Rate limits and length caps are not anti-abuse niceties, they are what
//!   keeps the channel usable at all.
//! * **Legality.** In most jurisdictions amateur transmissions may not use
//!   codes or ciphers intended to obscure their meaning, and the licensee is
//!   responsible for everything their station radiates. We refuse to transmit
//!   text that looks like ciphertext, and we can require that anyone whose
//!   traffic reaches the air has identified with a callsign.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::callsign::Callsign;
use crate::config::PolicyConfig;

/// What to do with a message destined for the air.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow(String),
    /// Allowed, but shortened; the sender is told and the frame is flagged.
    Truncated(String),
    /// Refused, with a reason the user sees.
    Deny(&'static str),
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Distinct keys one limiter will track. A limiter is keyed by host or
/// callsign, so this is generous for real traffic — but it has to be bounded:
/// without a cap, anything that can present an unbounded supply of keys turns
/// the limiter itself into the memory leak it exists to prevent.
const MAX_BUCKETS: usize = 4096;

pub struct RateLimiter {
    per_minute: f64,
    burst: f64,
    buckets: HashMap<String, Bucket>,
}

impl RateLimiter {
    pub fn new(per_minute: u32, burst: u32) -> Self {
        Self {
            per_minute: per_minute as f64,
            burst: burst.max(1) as f64,
            buckets: HashMap::new(),
        }
    }

    pub fn check(&mut self, key: &str, now: Instant) -> bool {
        let burst = self.burst;
        let rate = self.per_minute / 60.0;
        if !self.buckets.contains_key(key) && self.buckets.len() >= MAX_BUCKETS {
            // Drop the least recently used key to make room. Evicting one
            // idle bucket is a smaller mistake than growing without limit,
            // and refusing outright would let a flood lock out real users.
            if let Some(oldest) = self
                .buckets
                .iter()
                .min_by_key(|(_, b)| b.last)
                .map(|(k, _)| k.clone())
            {
                self.buckets.remove(&oldest);
            }
        }
        let bucket = self.buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: burst,
            last: now,
        });
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.last = now;
        bucket.tokens = (bucket.tokens + elapsed * rate).min(burst);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn expire(&mut self, now: Instant, idle: Duration) {
        self.buckets
            .retain(|_, b| now.saturating_duration_since(b.last) < idle);
    }

    #[cfg(test)]
    fn bucket_count(&self) -> usize {
        self.buckets.len()
    }
}

pub struct Policy {
    pub config: PolicyConfig,
    rf_out: RateLimiter,
    ip_to_rf: RateLimiter,
    rf_channel: RateLimiter,
    ip_cmds: RateLimiter,
    identify: RateLimiter,
}

impl Policy {
    pub fn new(config: PolicyConfig) -> Self {
        let rf_out = RateLimiter::new(config.rf_msgs_per_min, config.rf_burst);
        let ip_to_rf = RateLimiter::new(config.ip_to_rf_msgs_per_min, config.rf_burst);
        let rf_channel = RateLimiter::new(config.rf_channel_msgs_per_min, config.rf_channel_burst);
        let ip_cmds = RateLimiter::new(config.ip_cmds_per_min, config.ip_cmd_burst);
        let identify = RateLimiter::new(config.identify_per_min, config.identify_burst);
        Self {
            config,
            rf_out,
            ip_to_rf,
            rf_channel,
            ip_cmds,
            identify,
        }
    }

    /// May this station use the gateway at all?
    pub fn station_allowed(&self, call: &Callsign) -> bool {
        let deny = self
            .config
            .deny_callsigns
            .iter()
            .filter_map(|c| c.parse::<Callsign>().ok())
            .any(|c| c == *call || (c.ssid() == 0 && c.same_station(call)));
        if deny {
            return false;
        }
        if self.config.allow_callsigns.is_empty() {
            return true;
        }
        self.config
            .allow_callsigns
            .iter()
            .filter_map(|c| c.parse::<Callsign>().ok())
            .any(|c| c == *call || (c.ssid() == 0 && c.same_station(call)))
    }

    pub fn rf_station_rate_ok(&mut self, call: &Callsign, now: Instant) -> bool {
        self.rf_out.check(&call.to_string(), now)
    }

    pub fn ip_rate_ok(&mut self, key: &str, now: Instant) -> bool {
        self.ip_to_rf.check(key, now)
    }

    pub fn rf_channel_rate_ok(&mut self, key: &str, now: Instant) -> bool {
        self.rf_channel.check(key, now)
    }

    pub fn ip_cmd_rate_ok(&mut self, key: &str, now: Instant) -> bool {
        self.ip_cmds.check(key, now)
    }

    pub fn identify_rate_ok(&mut self, key: &str, now: Instant) -> bool {
        self.identify.check(key, now)
    }

    /// Check and normalise a message body that is about to be transmitted.
    pub fn screen_outbound(&self, text: &str) -> Verdict {
        let cleaned = sanitize(text);
        if cleaned.trim().is_empty() {
            return Verdict::Deny("message is empty after removing control characters");
        }
        if self.config.block_apparent_ciphertext && looks_like_ciphertext(&cleaned) {
            return Verdict::Deny(
                "refusing to transmit: the message looks like ciphertext or an armoured blob, \
                 and amateur transmissions must not obscure their meaning",
            );
        }
        if cleaned.chars().count() > self.config.max_rf_text_len {
            let short: String = cleaned
                .chars()
                .take(self.config.max_rf_text_len.saturating_sub(1))
                .collect();
            return Verdict::Truncated(format!("{short}\u{2026}"));
        }
        Verdict::Allow(cleaned)
    }

    pub fn expire(&mut self, now: Instant) {
        self.rf_out.expire(now, Duration::from_secs(3600));
        self.ip_to_rf.expire(now, Duration::from_secs(3600));
        self.rf_channel.expire(now, Duration::from_secs(3600));
        self.ip_cmds.expire(now, Duration::from_secs(3600));
        self.identify.expire(now, Duration::from_secs(3600));
    }
}

/// Strip IRC formatting codes and control characters. What goes on the air
/// should be readable by a human with a TNC and a terminal.
pub fn sanitize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            // mIRC colour: ^C[fg[,bg]]
            '\u{3}' => {
                for _ in 0..2 {
                    if chars.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                        chars.next();
                    }
                }
                if chars.peek() == Some(&',') {
                    chars.next();
                    for _ in 0..2 {
                        if chars.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                            chars.next();
                        }
                    }
                }
            }
            // bold, italic, underline, reverse, reset, colour codes
            '\u{2}' | '\u{f}' | '\u{16}' | '\u{1d}' | '\u{1f}' | '\u{4}' => {}
            '\r' | '\n' | '\t' => {
                if !out.ends_with(' ') {
                    out.push(' ');
                }
            }
            c if (c as u32) < 0x20 => {}
            ' ' => {
                if !out.ends_with(' ') {
                    out.push(' ');
                }
            }
            c => out.push(c),
        }
    }
    out.trim().to_string()
}

/// Heuristic detector for "this is not plain language".
///
/// It is deliberately conservative: false positives annoy people, and the rule
/// we are enforcing is about *intent* to obscure, which no heuristic can see.
/// It catches the obvious cases - PGP/base64 blobs and long high-entropy
/// tokens - and leaves judgement to the control operator for the rest.
pub fn looks_like_ciphertext(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    if upper.contains("-----BEGIN") && upper.contains("MESSAGE") {
        return true;
    }
    text.split_whitespace().any(|token| {
        let len = token.chars().count();
        if len < 40 {
            return false;
        }
        let b64ish = token
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
            .count();
        if b64ish * 100 / len < 95 {
            return false;
        }
        let has_lower = token.chars().any(|c| c.is_ascii_lowercase());
        let has_upper = token.chars().any(|c| c.is_ascii_uppercase());
        let has_digit = token.chars().any(|c| c.is_ascii_digit());
        (has_lower && has_upper && has_digit) || shannon_entropy(token) > 4.2
    })
}

fn shannon_entropy(s: &str) -> f64 {
    let mut counts = HashMap::new();
    let mut n = 0f64;
    for c in s.chars() {
        *counts.entry(c).or_insert(0f64) += 1.0;
        n += 1.0;
    }
    -counts
        .values()
        .map(|&c| {
            let p = c / n;
            p * p.log2()
        })
        .sum::<f64>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_formatting() {
        assert_eq!(sanitize("\u{3}04red\u{3} text"), "red text");
        assert_eq!(sanitize("a\u{2}b\u{1f}c"), "abc");
        assert_eq!(sanitize(" line\r\nbreak "), "line break");
    }

    #[test]
    fn ciphertext_detection() {
        assert!(looks_like_ciphertext(
            "U2FsdGVkX1+8xQ2mZ9pKbNvYwErTyUiOpAsDfGhJkLzXcVbNm1234567890AbCdEf"
        ));
        assert!(looks_like_ciphertext("-----BEGIN PGP MESSAGE-----"));
        assert!(!looks_like_ciphertext(
            "good morning from Stockholm, running 5 watts into a j-pole today"
        ));
        assert!(
            !looks_like_ciphertext("http://example.com/some/fairly/long/path/to/a/page.html"),
            "URLs contain slashes and dots but are plain language"
        );
    }

    #[test]
    fn truncation_and_rejection() {
        let p = Policy::new(PolicyConfig {
            max_rf_text_len: 10,
            ..Default::default()
        });
        assert_eq!(p.screen_outbound("short"), Verdict::Allow("short".into()));
        assert!(matches!(
            p.screen_outbound("this one is definitely too long"),
            Verdict::Truncated(_)
        ));
        assert!(matches!(p.screen_outbound("\u{2}\u{f}"), Verdict::Deny(_)));
    }

    #[test]
    fn rate_limiter_refills() {
        let mut rl = RateLimiter::new(60, 2);
        let now = Instant::now();
        assert!(rl.check("a", now));
        assert!(rl.check("a", now));
        assert!(!rl.check("a", now));
        assert!(rl.check("a", now + Duration::from_secs(1)));
    }

    #[test]
    fn bucket_table_is_bounded() {
        let mut rl = RateLimiter::new(60, 2);
        let now = Instant::now();
        for i in 0..(MAX_BUCKETS * 2) {
            rl.check(&format!("host-{i}"), now + Duration::from_millis(i as u64));
        }
        assert!(
            rl.bucket_count() <= MAX_BUCKETS,
            "{} buckets",
            rl.bucket_count()
        );
    }

    #[test]
    fn allow_and_deny_lists() {
        let p = Policy::new(PolicyConfig {
            deny_callsigns: vec!["SM0BAD".into()],
            ..Default::default()
        });
        // SSID 0 in the deny list bans the whole station.
        assert!(!p.station_allowed(&"SM0BAD-7".parse().unwrap()));
        assert!(p.station_allowed(&"SM0ABC".parse().unwrap()));
    }
}
