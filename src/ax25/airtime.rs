//! Transmitter airtime governor: the thing that stands between a busy IRC
//! channel and a cooked power amplifier.
//!
//! Rate limits in [`crate::policy`] are about *fairness* — one station must
//! not monopolise a shared channel. This module is about *the hardware and
//! the band*. They are different problems and they need different limits:
//!
//! * A QRP transceiver such as a QMX has no thermal headroom worth the name.
//!   Its finals are small MOSFETs with no heatsink to speak of; a sustained
//!   high duty cycle is how they die. AX.25 at 300 baud makes this easy to
//!   hit by accident: a 128-octet frame is roughly four seconds of key-down,
//!   so a handful of queued messages is already a minute of transmitting.
//! * Even with a rack-mount amplifier, an automatically controlled station
//!   that transmits 80 % of the time has taken the channel away from
//!   everybody else on it.
//!
//! So the governor works in units of *airtime*, not messages. Every frame is
//! costed before it is keyed:
//!
//! ```text
//!   airtime = txdelay + (octets_on_wire * 8 / baud) + txtail
//! ```
//!
//! and three independent limits are enforced:
//!
//! 1. **Duty cycle** over a sliding window (default: 25 % of ten minutes).
//! 2. **Continuous run length** — after this much unbroken transmitting the
//!    station is forced off the air for a cooldown, so the PA can cool.
//! 3. **Rolling-hour budget** — a hard ceiling on airtime per hour, so a
//!    pathological backlog cannot drip-feed the channel forever.
//!
//! Frames are never silently reordered or corrupted: a frame that cannot be
//! sent yet is deferred, and a frame that has waited longer than `max_hold`
//! is dropped and counted. On a 1 kbit/s channel a two-minute-old chat line
//! is noise, not information.
//!
//! The module is pure: it is driven with an explicit `now` and returns a
//! decision, so every limit above is testable without a radio or a sleep.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Octets AX.25/KISS adds around the frame we hand to the TNC: opening and
/// closing flags plus the 16-bit FCS. Small, but at 300 baud it is 100 ms.
const FRAMING_OCTETS: usize = 4;

/// Two transmissions closer together than this are one continuous run as far
/// as the power amplifier is concerned.
const RUN_GAP: Duration = Duration::from_secs(3);

/// The duty cycle this station will never exceed, whatever the configuration
/// says.
///
/// Amateur HF transceivers are rated on the assumption of a speech duty cycle.
/// A QRP rig with unheatsunk finals has no margin at all, and an automatically
/// controlled station keys up when nobody is in the room. 50 % is the number
/// below which essentially any transceiver survives indefinitely, so it is a
/// ceiling rather than a default: `max_duty_percent` is clamped to it on the
/// way in, and [`AirtimeConfig::check_hardware_safe`] refuses a configuration
/// that would breach it in bursts.
pub const HARD_MAX_DUTY: f64 = 0.5;

#[derive(Clone, Debug)]
pub struct AirtimeConfig {
    /// Off entirely. Only sensible on a loopback or a dummy load.
    pub enabled: bool,
    /// On-air symbol rate: 300 for HF, 1200 for VHF FM packet.
    pub baud: u32,
    /// Keyed-but-not-sending time at the start of a transmission (KISS
    /// TXDELAY) and at the end (TXTAIL). Both are real key-down time.
    pub txdelay: Duration,
    pub txtail: Duration,
    /// Sliding window the duty cycle is measured over.
    pub window: Duration,
    /// Fraction of `window` we may transmit for, 0.0-1.0.
    pub max_duty: f64,
    /// Longest unbroken transmit run before a forced cooldown.
    pub max_continuous: Duration,
    /// How long the transmitter stays off after `max_continuous` is reached.
    pub cooldown: Duration,
    /// Hard airtime ceiling per rolling hour. `Duration::ZERO` disables it.
    pub hourly_budget: Duration,
    /// A frame held longer than this is dropped rather than transmitted late.
    pub max_hold: Duration,
}

impl Default for AirtimeConfig {
    fn default() -> Self {
        // Tuned for a QRP HF station: 300 baud, small finals, shared channel.
        Self {
            enabled: true,
            baud: 300,
            txdelay: Duration::from_millis(400),
            txtail: Duration::from_millis(300),
            window: Duration::from_secs(600),
            max_duty: 0.25,
            max_continuous: Duration::from_secs(30),
            cooldown: Duration::from_secs(60),
            hourly_budget: Duration::from_secs(900),
            max_hold: Duration::from_secs(120),
        }
    }
}

/// What the governor says about a frame that is ready to go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxDecision {
    /// Key up now.
    Send,
    /// Not yet. Ask again after this long. The reason is for the operator log
    /// and for `RADIO DUTY`.
    Defer(Duration, DeferReason),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeferReason {
    /// Duty cycle over the sliding window would be exceeded.
    Duty,
    /// The PA has been keyed for `max_continuous`; it is cooling.
    Cooldown,
    /// The rolling-hour airtime budget is spent.
    HourlyBudget,
}

impl DeferReason {
    pub fn as_str(self) -> &'static str {
        match self {
            DeferReason::Duty => "duty cycle",
            DeferReason::Cooldown => "PA cooldown",
            DeferReason::HourlyBudget => "hourly airtime budget",
        }
    }
}

/// Counters the control operator can read from the IRC side. The TNC task
/// owns the [`Governor`]; this is the part it publishes.
///
/// Plain atomics rather than a lock: the writer is one task, the readers only
/// ever want a recent snapshot, and nothing here is worth blocking the event
/// loop for.
#[derive(Debug)]
pub struct AirtimeShared {
    /// Hard transmit inhibit. `RADIO OFF` sets this, and the TNC task then
    /// discards whatever is already queued instead of radiating it later.
    pub inhibit: AtomicBool,
    /// The external safety interlock is satisfied. Separate from `inhibit` so
    /// the two cannot undo each other: an interlock recovering must not cancel
    /// a control operator's `RADIO OFF`, and an operator saying `RADIO ON`
    /// must not override a failing interlock.
    ///
    /// Defaults to true so a gateway with no interlock configured transmits
    /// normally; [`crate::interlock::spawn`] clears it before the first check.
    pub interlock_ok: AtomicBool,
    /// Airtime in the sliding duty window, and the window length.
    pub window_ms: AtomicU64,
    pub window_span_ms: AtomicU64,
    /// Airtime in the last rolling hour, and the configured budget.
    pub hour_ms: AtomicU64,
    pub hour_budget_ms: AtomicU64,
    /// Length of the current unbroken transmit run.
    pub run_ms: AtomicU64,
    /// Milliseconds until the PA cooldown ends, 0 when not cooling.
    pub cooling_ms: AtomicU64,
    /// Total keyed time since start, for the operator's own records.
    pub total_ms: AtomicU64,
    /// How long before the governor would clear a typical frame. Read by the
    /// server to give a sender an honest estimate instead of a promise.
    pub next_slot_ms: AtomicU64,
    /// Airtime of everything queued for transmission but not yet radiated.
    /// Incremented when a frame is queued and decremented when it leaves,
    /// so it is maintained from both sides.
    pub queued_ms: AtomicU64,
    /// The same backlog counted in frames, which is what an operator asking
    /// "how much is still waiting to go out?" actually wants to know.
    pub queued_frames: AtomicU64,
    /// Control-operator overrides, applied by the TNC task before each
    /// decision. Zero means "use the configured value".
    ///
    /// Runtime knobs rather than a config reload because the situation they
    /// answer to is a live one — the band opened, the finals are hot, someone
    /// else needs the frequency — and restarting the gateway to turn the duty
    /// cycle down drops every station on it.
    pub duty_pct_override: AtomicU64,
    pub pacing_ms_override: AtomicU64,
    /// Frames refused admission because the backlog was already too long.
    pub rejected_backlog: AtomicU64,
    /// Frames held back at least once, and frames given up on.
    pub deferred: AtomicU64,
    pub dropped_stale: AtomicU64,
    pub dropped_inhibited: AtomicU64,
}

impl Default for AirtimeShared {
    fn default() -> Self {
        Self {
            // No interlock configured means nothing is holding the
            // transmitter down; `interlock::spawn` clears this if there is.
            interlock_ok: AtomicBool::new(true),
            inhibit: AtomicBool::new(false),
            window_ms: AtomicU64::new(0),
            window_span_ms: AtomicU64::new(0),
            hour_ms: AtomicU64::new(0),
            hour_budget_ms: AtomicU64::new(0),
            run_ms: AtomicU64::new(0),
            cooling_ms: AtomicU64::new(0),
            total_ms: AtomicU64::new(0),
            next_slot_ms: AtomicU64::new(0),
            queued_ms: AtomicU64::new(0),
            queued_frames: AtomicU64::new(0),
            duty_pct_override: AtomicU64::new(0),
            pacing_ms_override: AtomicU64::new(0),
            rejected_backlog: AtomicU64::new(0),
            deferred: AtomicU64::new(0),
            dropped_stale: AtomicU64::new(0),
            dropped_inhibited: AtomicU64::new(0),
        }
    }
}

impl AirtimeShared {
    /// Nothing may be transmitted: the operator has inhibited the station, or
    /// the external safety interlock is not satisfied. Both block station
    /// identification too — a station that must not transmit must not
    /// transmit, and a licence requires you to identify the transmissions you
    /// make, not to make one.
    pub fn tx_blocked(&self) -> bool {
        self.inhibit.load(Ordering::Relaxed) || !self.interlock_ok.load(Ordering::Relaxed)
    }

    pub fn interlock_failed(&self) -> bool {
        !self.interlock_ok.load(Ordering::Relaxed)
    }

    /// Estimated wait before a frame queued right now reaches the air:
    /// the governor's next free slot plus everything already in the queue.
    pub fn eta(&self) -> Duration {
        Duration::from_millis(
            self.next_slot_ms.load(Ordering::Relaxed) + self.queued_ms.load(Ordering::Relaxed),
        )
    }

    pub fn queued(&self) -> Duration {
        Duration::from_millis(self.queued_ms.load(Ordering::Relaxed))
    }

    pub fn queued_frame_count(&self) -> u64 {
        self.queued_frames.load(Ordering::Relaxed)
    }

    /// Duty target in force right now: the operator's override if they set
    /// one, otherwise the configured value. Always within the hard ceiling.
    pub fn duty_limit(&self, configured: f64) -> f64 {
        match self.duty_pct_override.load(Ordering::Relaxed) {
            0 => configured,
            pct => pct as f64 / 100.0,
        }
        .clamp(0.0, HARD_MAX_DUTY)
    }

    /// Set or clear the duty override. Returns the value actually stored,
    /// which may be lower than asked for: the ceiling is not negotiable.
    pub fn set_duty_override(&self, percent: Option<u32>) -> Option<u32> {
        let stored = match percent {
            None | Some(0) => 0,
            Some(p) => u64::from(p.min((HARD_MAX_DUTY * 100.0) as u32)),
        };
        self.duty_pct_override.store(stored, Ordering::Relaxed);
        (stored > 0).then_some(stored as u32)
    }

    pub fn set_pacing_override(&self, ms: Option<u64>) {
        self.pacing_ms_override
            .store(ms.unwrap_or(0), Ordering::Relaxed);
    }

    pub fn pacing(&self, configured: Duration) -> Duration {
        match self.pacing_ms_override.load(Ordering::Relaxed) {
            0 => configured,
            ms => Duration::from_millis(ms),
        }
    }

    pub fn duty_percent(&self) -> f64 {
        let span = self.window_span_ms.load(Ordering::Relaxed);
        if span == 0 {
            return 0.0;
        }
        self.window_ms.load(Ordering::Relaxed) as f64 * 100.0 / span as f64
    }

    /// One line for `RADIO STATUS` / `RADIO DUTY`.
    pub fn summary(&self) -> String {
        let cooling = self.cooling_ms.load(Ordering::Relaxed);
        let budget = self.hour_budget_ms.load(Ordering::Relaxed);
        let mut s = format!(
            "airtime: {:.1}% duty over the last {}s, {}s keyed in the last hour",
            self.duty_percent(),
            self.window_span_ms.load(Ordering::Relaxed) / 1000,
            self.hour_ms.load(Ordering::Relaxed) / 1000,
        );
        if budget > 0 {
            s.push_str(&format!(" (budget {}s)", budget / 1000));
        }
        s.push_str(&format!(
            "; {} frame(s) / {:.1}s queued ({:.1}s until the next slot); total keyed {}s; \
             {} frames deferred, {} refused as backlog, {} dropped stale, \
             {} dropped while inhibited",
            self.queued_frames.load(Ordering::Relaxed),
            self.queued_ms.load(Ordering::Relaxed) as f64 / 1000.0,
            self.next_slot_ms.load(Ordering::Relaxed) as f64 / 1000.0,
            self.total_ms.load(Ordering::Relaxed) / 1000,
            self.deferred.load(Ordering::Relaxed),
            self.rejected_backlog.load(Ordering::Relaxed),
            self.dropped_stale.load(Ordering::Relaxed),
            self.dropped_inhibited.load(Ordering::Relaxed),
        ));
        if cooling > 0 {
            s.push_str(&format!("; PA cooling for another {}s", cooling / 1000));
        }
        let over = self.duty_pct_override.load(Ordering::Relaxed);
        if over > 0 {
            s.push_str(&format!("; duty overridden to {over}% by a control operator"));
        }
        let pacing = self.pacing_ms_override.load(Ordering::Relaxed);
        if pacing > 0 {
            s.push_str(&format!("; pacing overridden to {pacing}ms"));
        }
        if self.inhibit.load(Ordering::Relaxed) {
            s.push_str("; TRANSMIT INHIBITED by a control operator");
        }
        if self.interlock_failed() {
            s.push_str("; TRANSMIT BLOCKED by the safety interlock");
        }
        s
    }
}

/// One transmission that has already happened.
#[derive(Copy, Clone, Debug)]
struct Burst {
    /// When the transmission ended.
    end: Instant,
    len: Duration,
}

pub struct Governor {
    cfg: AirtimeConfig,
    /// Newest last. Trimmed to whichever of the two windows is longer.
    bursts: VecDeque<Burst>,
    /// End of the most recent transmission, for run and gap detection.
    last_end: Option<Instant>,
    /// Airtime in the current unbroken run.
    run: Duration,
    /// Set when `max_continuous` is reached; nothing is transmitted until then.
    cooling_until: Option<Instant>,
    total: Duration,
}

impl Governor {
    pub fn new(cfg: AirtimeConfig) -> Self {
        Self {
            cfg,
            bursts: VecDeque::new(),
            last_end: None,
            run: Duration::ZERO,
            cooling_until: None,
            total: Duration::ZERO,
        }
    }

    pub fn config(&self) -> &AirtimeConfig {
        &self.cfg
    }

    /// Apply a control operator's live duty override.
    pub fn set_duty(&mut self, duty: f64) {
        self.cfg.max_duty = duty;
    }

    /// Airtime permitted inside one duty window.
    fn allowance(&self) -> Duration {
        self.cfg.window.mul_f64(self.cfg.effective_duty())
    }

    /// How long before a frame of `octets` could be transmitted, without
    /// changing any state.
    ///
    /// [`Governor::check`] has to record that a cooldown started, so it takes
    /// `&mut self` and cannot be used to answer "when could I send this?" for
    /// a message the caller has not committed to yet. Admission control needs
    /// exactly that question, so it gets its own read-only path.
    pub fn time_until_clear(&self, octets: usize, now: Instant) -> Duration {
        if !self.cfg.enabled {
            return Duration::ZERO;
        }
        let mut wait = Duration::ZERO;
        if let Some(until) = self.cooling_until {
            wait = wait.max(until.saturating_duration_since(now));
        }
        let cost = self.airtime_for(octets);
        let run = if self
            .last_end
            .map(|l| now.saturating_duration_since(l) >= RUN_GAP)
            .unwrap_or(true)
        {
            Duration::ZERO
        } else {
            self.run
        };
        if run > Duration::ZERO && run + cost > self.cfg.max_continuous {
            let until = self.last_end.unwrap_or(now) + self.cfg.cooldown;
            wait = wait.max(until.saturating_duration_since(now));
        }
        let allowance = self.allowance();
        if self.airtime_within(now, self.cfg.window) + cost > allowance {
            wait = wait.max(self.retry_delay(now, self.cfg.window, allowance, cost));
        }
        if !self.cfg.hourly_budget.is_zero() {
            let hour = self.cfg.hourly_budget_window();
            if self.airtime_within(now, hour) + cost > self.cfg.hourly_budget {
                wait = wait.max(self.retry_delay(now, hour, self.cfg.hourly_budget, cost));
            }
        }
        wait
    }

    /// Key-down time a frame of `octets` will cost, TXDELAY and TXTAIL
    /// included. This is what the PA actually experiences.
    pub fn airtime_for(&self, octets: usize) -> Duration {
        let baud = self.cfg.baud.max(1) as u64;
        let bits = (octets + FRAMING_OCTETS) as u64 * 8;
        self.cfg.txdelay + Duration::from_micros(bits * 1_000_000 / baud) + self.cfg.txtail
    }

    /// The longest window we have to remember bursts for.
    fn retention(&self) -> Duration {
        self.cfg.window.max(self.cfg.hourly_budget_window())
    }

    fn trim(&mut self, now: Instant) {
        let horizon = self.retention();
        while let Some(front) = self.bursts.front() {
            if now.saturating_duration_since(front.end) > horizon {
                self.bursts.pop_front();
            } else {
                break;
            }
        }
    }

    fn airtime_within(&self, now: Instant, window: Duration) -> Duration {
        self.bursts
            .iter()
            .filter(|b| now.saturating_duration_since(b.end) <= window)
            .map(|b| b.len)
            .sum()
    }

    /// May a frame of `octets` be transmitted right now?
    pub fn check(&mut self, octets: usize, now: Instant) -> TxDecision {
        if !self.cfg.enabled {
            return TxDecision::Send;
        }
        self.trim(now);

        // A run that has already ended releases the cooldown clock.
        if let Some(until) = self.cooling_until {
            if now < until {
                return TxDecision::Defer(until - now, DeferReason::Cooldown);
            }
            self.cooling_until = None;
            self.run = Duration::ZERO;
        }

        // A gap long enough for the finals to recover ends the current run.
        if let Some(last) = self.last_end {
            if now.saturating_duration_since(last) >= RUN_GAP {
                self.run = Duration::ZERO;
            }
        }

        let cost = self.airtime_for(octets);

        // 1. Continuous run. Checked before the others because it is the one
        //    that protects the hardware rather than the band.
        if self.run + cost > self.cfg.max_continuous && self.run > Duration::ZERO {
            let until = self.last_end.unwrap_or(now) + self.cfg.cooldown;
            self.cooling_until = Some(until);
            return TxDecision::Defer(
                until.saturating_duration_since(now).max(Duration::from_millis(1)),
                DeferReason::Cooldown,
            );
        }

        // 2. Duty cycle over the sliding window.
        let allowance = self.allowance();
        let used = self.airtime_within(now, self.cfg.window);
        if used + cost > allowance {
            return TxDecision::Defer(self.retry_delay(now, self.cfg.window, allowance, cost), DeferReason::Duty);
        }

        // 3. Rolling-hour budget.
        let hour = self.cfg.hourly_budget_window();
        if !self.cfg.hourly_budget.is_zero() {
            let used = self.airtime_within(now, hour);
            if used + cost > self.cfg.hourly_budget {
                return TxDecision::Defer(
                    self.retry_delay(now, hour, self.cfg.hourly_budget, cost),
                    DeferReason::HourlyBudget,
                );
            }
        }

        TxDecision::Send
    }

    /// How long until enough old airtime falls out of `window` to make room
    /// for `cost`. Exact rather than a fixed poll interval, so a deferred
    /// frame wakes up once instead of spinning.
    fn retry_delay(&self, now: Instant, window: Duration, allowance: Duration, cost: Duration) -> Duration {
        let mut used = self.airtime_within(now, window);
        // Expire bursts oldest-first until `cost` fits.
        for b in self.bursts.iter() {
            if now.saturating_duration_since(b.end) > window {
                continue;
            }
            if used + cost <= allowance {
                break;
            }
            used = used.saturating_sub(b.len);
            // This burst leaves the window `window` after it ended.
            let leaves = (b.end + window).saturating_duration_since(now);
            if used + cost <= allowance {
                return leaves.max(Duration::from_millis(100));
            }
        }
        // Either the frame can never fit (cost alone exceeds the allowance)
        // or the arithmetic ran out; back off and let `max_hold` decide.
        window.min(Duration::from_secs(30)).max(Duration::from_millis(100))
    }

    /// Record a transmission that has just been made. Returns the key-down
    /// time it cost, which the caller uses to pace the next one.
    pub fn record(&mut self, octets: usize, now: Instant) -> Duration {
        if !self.cfg.enabled {
            // Nothing to account for, and no airtime-derived pacing: an
            // operator who turned the governor off wants the raw `tx_pacing`
            // gap and nothing else.
            return Duration::ZERO;
        }
        let cost = self.airtime_for(octets);
        let end = now + cost;
        if let Some(last) = self.last_end {
            if now.saturating_duration_since(last) >= RUN_GAP {
                self.run = Duration::ZERO;
            }
        }
        self.run += cost;
        self.total += cost;
        self.last_end = Some(end);
        self.bursts.push_back(Burst { end, len: cost });
        self.trim(now);
        if self.cfg.enabled && self.run >= self.cfg.max_continuous {
            self.cooling_until = Some(end + self.cfg.cooldown);
        }
        cost
    }

    /// Publish the current picture for `RADIO STATUS` and for admission
    /// control. `typical` is the frame size used to estimate the next slot.
    pub fn publish_with(&self, shared: &AirtimeShared, now: Instant, typical: usize) {
        shared.next_slot_ms.store(
            self.time_until_clear(typical, now).as_millis() as u64,
            Ordering::Relaxed,
        );
        self.publish(shared, now);
    }

    /// Publish the current picture for `RADIO STATUS`.
    pub fn publish(&self, shared: &AirtimeShared, now: Instant) {
        let hour = self.cfg.hourly_budget_window();
        shared.window_ms.store(
            self.airtime_within(now, self.cfg.window).as_millis() as u64,
            Ordering::Relaxed,
        );
        shared
            .window_span_ms
            .store(self.cfg.window.as_millis() as u64, Ordering::Relaxed);
        shared
            .hour_ms
            .store(self.airtime_within(now, hour).as_millis() as u64, Ordering::Relaxed);
        shared.hour_budget_ms.store(
            self.cfg.hourly_budget.as_millis() as u64,
            Ordering::Relaxed,
        );
        shared.run_ms.store(self.run.as_millis() as u64, Ordering::Relaxed);
        shared.total_ms.store(self.total.as_millis() as u64, Ordering::Relaxed);
        let cooling = self
            .cooling_until
            .map(|u| u.saturating_duration_since(now).as_millis() as u64)
            .unwrap_or(0);
        shared.cooling_ms.store(cooling, Ordering::Relaxed);
    }

    /// Forget everything. Used when the operator re-enables a transmitter
    /// that has been off long enough for the window to be meaningless.
    pub fn reset(&mut self) {
        self.bursts.clear();
        self.last_end = None;
        self.run = Duration::ZERO;
        self.cooling_until = None;
    }
}

impl AirtimeConfig {
    /// The duty target actually used, never above [`HARD_MAX_DUTY`].
    pub fn effective_duty(&self) -> f64 {
        self.max_duty.clamp(0.0, HARD_MAX_DUTY)
    }

    /// The worst instantaneous duty cycle the run/cooldown pair permits.
    ///
    /// The sliding window bounds the *average*; this bounds the *burst*.
    /// A 30 s run followed by a 60 s cooldown is 33 %, whatever the window
    /// average happens to be. Without this, `max_duty_percent = 50` over ten
    /// minutes still allows five unbroken minutes of key-down.
    pub fn burst_duty(&self) -> f64 {
        let run = self.max_continuous.as_secs_f64();
        let rest = self.cooldown.as_secs_f64();
        if run + rest <= 0.0 {
            return 1.0;
        }
        run / (run + rest)
    }

    /// Reject a configuration that could exceed [`HARD_MAX_DUTY`] in bursts.
    ///
    /// Clamping `max_duty` is not enough on its own: the run and cooldown
    /// settings are a second, independent way to keep the transmitter keyed.
    pub fn check_hardware_safe(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.burst_duty() > HARD_MAX_DUTY {
            return Err(format!(
                "max_continuous_secs {} with cooldown_secs {} is a {:.0}% burst duty cycle; \
                 the ceiling is {:.0}%. Raise cooldown_secs to at least {} s, or lower \
                 max_continuous_secs.",
                self.max_continuous.as_secs(),
                self.cooldown.as_secs(),
                self.burst_duty() * 100.0,
                HARD_MAX_DUTY * 100.0,
                self.max_continuous.as_secs(),
            ));
        }
        Ok(())
    }

    /// The rolling-hour budget is measured over an hour by definition, but
    /// keep it in one place so the retention window follows it.
    fn hourly_budget_window(&self) -> Duration {
        if self.hourly_budget.is_zero() {
            Duration::ZERO
        } else {
            Duration::from_secs(3600)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> AirtimeConfig {
        AirtimeConfig {
            baud: 300,
            txdelay: Duration::from_millis(400),
            txtail: Duration::from_millis(300),
            window: Duration::from_secs(600),
            max_duty: 0.25,
            max_continuous: Duration::from_secs(30),
            cooldown: Duration::from_secs(60),
            hourly_budget: Duration::ZERO,
            max_hold: Duration::from_secs(120),
            enabled: true,
        }
    }

    #[test]
    fn airtime_matches_the_back_of_the_envelope() {
        let g = Governor::new(cfg());
        // 128 octets of info plus AX.25 addressing is ~158 octets on the wire.
        // (158 + 4) * 8 / 300 = 4.32 s, plus 0.7 s of TXDELAY/TXTAIL.
        let t = g.airtime_for(158);
        assert!(
            t > Duration::from_millis(4900) && t < Duration::from_millis(5100),
            "{t:?}"
        );
    }

    #[test]
    fn duty_cycle_is_enforced() {
        // Isolate the duty limit: a short window, and a run limit far enough
        // out that it is not what bites first.
        let mut c = cfg();
        c.window = Duration::from_secs(60);
        c.max_continuous = Duration::from_secs(3600);
        let mut g = Governor::new(c);
        let now = Instant::now();
        // 25 % of 60 s is 15 s of allowance. Each frame here is ~1.1 s.
        let mut sent = 0;
        let mut t = now;
        for _ in 0..40 {
            if g.check(10, t) == TxDecision::Send {
                g.record(10, t);
                sent += 1;
            }
            // Space them out so the continuous-run limit is not what bites.
            t += Duration::from_secs(4);
        }
        // Over 160 s of wall clock with a 60 s / 25 % window, we must be well
        // under "send everything" but not stuck at zero.
        assert!(sent > 5 && sent < 40, "sent {sent}");
    }

    #[test]
    fn a_long_run_forces_a_cooldown() {
        let mut g = Governor::new(cfg());
        let mut t = Instant::now();
        // Back-to-back frames with no gap: one continuous run.
        let mut keyed = Duration::ZERO;
        loop {
            match g.check(158, t) {
                TxDecision::Send => {
                    keyed += g.record(158, t);
                    t += Duration::from_millis(5100);
                }
                TxDecision::Defer(_, reason) => {
                    assert_eq!(reason, DeferReason::Cooldown, "keyed {keyed:?}");
                    break;
                }
            }
            assert!(keyed < Duration::from_secs(120), "cooldown never triggered");
        }
        assert!(
            keyed <= Duration::from_secs(35),
            "ran {keyed:?} before cooling, max_continuous is 30 s"
        );
    }

    #[test]
    fn cooldown_expires_and_transmission_resumes() {
        let mut g = Governor::new(cfg());
        let mut t = Instant::now();
        while let TxDecision::Send = g.check(158, t) {
            g.record(158, t);
            t += Duration::from_millis(5100);
        }
        // Well past the cooldown and past the duty window too.
        t += Duration::from_secs(600);
        assert_eq!(g.check(158, t), TxDecision::Send);
    }

    #[test]
    fn hourly_budget_is_a_hard_ceiling() {
        let mut c = cfg();
        c.hourly_budget = Duration::from_secs(20);
        c.max_duty = 1.0;
        c.max_continuous = Duration::from_secs(3600);
        let mut g = Governor::new(c);
        let mut t = Instant::now();
        let mut keyed = Duration::ZERO;
        for _ in 0..100 {
            if let TxDecision::Send = g.check(158, t) {
                keyed += g.record(158, t);
            }
            t += Duration::from_secs(10);
        }
        assert!(
            keyed <= Duration::from_secs(25),
            "hourly budget of 20 s was overrun: {keyed:?}"
        );
    }

    /// The invariant the whole module exists for. Drive the governor as hard
    /// as anything possibly could and measure the duty cycle it actually
    /// permitted, over every window position, not just on average.
    #[test]
    fn duty_never_exceeds_the_hard_ceiling() {
        let mut c = cfg();
        // Ask for far more than the ceiling and check the clamp holds.
        c.max_duty = 0.95;
        c.max_continuous = Duration::from_secs(30);
        c.cooldown = Duration::from_secs(30);
        c.hourly_budget = Duration::ZERO;
        assert!(c.check_hardware_safe().is_ok(), "50/50 is exactly the ceiling");

        let mut g = Governor::new(c);
        let start = Instant::now();
        let mut t = start;
        // Every burst that was actually transmitted, as (start, end).
        let mut keyed: Vec<(Duration, Duration)> = Vec::new();
        // Two hours of a sender that never stops trying.
        while t < start + Duration::from_secs(7200) {
            match g.check(158, t) {
                TxDecision::Send => {
                    let cost = g.record(158, t);
                    keyed.push((t - start, t - start + cost));
                    t += cost;
                }
                TxDecision::Defer(d, _) => t += d.max(Duration::from_millis(100)),
            }
        }

        // Slide a window across the whole run and check every position.
        let window = Duration::from_secs(600);
        for start_s in 0..(7200 - 600) {
            let from = Duration::from_secs(start_s);
            let to = from + window;
            let busy: f64 = keyed
                .iter()
                .map(|(a, b)| {
                    let lo = (*a).max(from);
                    let hi = (*b).min(to);
                    if hi > lo {
                        (hi - lo).as_secs_f64()
                    } else {
                        0.0
                    }
                })
                .sum();
            let duty = busy / window.as_secs_f64();
            assert!(
                duty <= HARD_MAX_DUTY + 0.02,
                "duty {duty:.3} in the window starting at {start_s}s exceeds the {HARD_MAX_DUTY} ceiling"
            );
        }
    }

    #[test]
    fn an_override_can_lower_the_duty_but_never_raise_it_past_the_ceiling() {
        let shared = AirtimeShared::default();
        assert_eq!(shared.duty_limit(0.25), 0.25, "no override, configured value");

        assert_eq!(shared.set_duty_override(Some(10)), Some(10));
        assert_eq!(shared.duty_limit(0.25), 0.10);

        // Asking for more than the ceiling gets the ceiling, not the ask.
        assert_eq!(shared.set_duty_override(Some(90)), Some(50));
        assert_eq!(shared.duty_limit(0.25), HARD_MAX_DUTY);

        assert_eq!(shared.set_duty_override(None), None);
        assert_eq!(shared.duty_limit(0.25), 0.25);
    }

    #[test]
    fn a_cooldown_shorter_than_the_run_is_refused() {
        let mut c = cfg();
        c.max_continuous = Duration::from_secs(60);
        c.cooldown = Duration::from_secs(10);
        // 60 on / 10 off is an 86 % burst duty cycle.
        let err = c.check_hardware_safe().unwrap_err();
        assert!(err.contains("burst duty cycle"), "{err}");
    }

    #[test]
    fn time_until_clear_does_not_mutate() {
        let mut g = Governor::new(cfg());
        let mut t = Instant::now();
        while let TxDecision::Send = g.check(158, t) {
            g.record(158, t);
            t += Duration::from_millis(5100);
        }
        let a = g.time_until_clear(158, t);
        let b = g.time_until_clear(158, t);
        assert_eq!(a, b, "the read-only query changed the governor's state");
        assert!(a > Duration::ZERO, "it should report the cooldown it is in");
    }

    #[test]
    fn disabled_governor_never_defers() {
        let mut c = cfg();
        c.enabled = false;
        let mut g = Governor::new(c);
        let t = Instant::now();
        for _ in 0..100 {
            assert_eq!(g.check(200, t), TxDecision::Send);
            g.record(200, t);
        }
    }

    #[test]
    fn a_gap_ends_the_run() {
        let mut g = Governor::new(cfg());
        let mut t = Instant::now();
        g.check(158, t);
        g.record(158, t);
        // Long silence: the finals cooled, the run restarts.
        t += Duration::from_secs(120);
        assert_eq!(g.check(158, t), TxDecision::Send);
        g.record(158, t);
        assert!(g.run < Duration::from_secs(10));
    }
}
