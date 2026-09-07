//! Deciding *which* frame keys the transmitter next, and *when* it is safe to.
//!
//! [`super::airtime::Governor`] answers "may the finals take this?". It does
//! not answer "which of the eleven things waiting should go, and is the other
//! station in the middle of answering us?". With one transceiver those two
//! questions are the whole of the link:
//!
//! * **One FIFO is the wrong shape.** An ACK behind five chat frames is thirty
//!   seconds late at 300 baud, which is longer than the sender's ACK timeout —
//!   so the cheapest frame on the channel causes the most expensive one to be
//!   sent again. Classes are drained by priority, with ageing so conversation
//!   is squeezed rather than starved.
//! * **Fairness is priced in airtime, not in messages.** A station gets
//!   seconds of key-down per minute from a bucket that refills; spending more
//!   than it earns does not block it, it *deprioritises* it. A busy station
//!   still gets through when nobody else wants the channel, and gets out of
//!   the way when they do. The deficit is bounded so a station can never be
//!   locked out permanently.
//! * **Half duplex means silence is part of the protocol.** After a frame that
//!   asks for an answer, the transmitter is held down for a reply window so we
//!   are listening when the answer arrives instead of keying over it. Hearing
//!   anything clears that window early — the reply came, there is no reason to
//!   keep waiting. Hearing anything also arms a short guard, because a station
//!   that just sent fragment 1 of 3 is about to send fragment 2.
//!
//! The module is pure: driven with an explicit `now`, it returns decisions and
//! never touches the clock or the radio, so every rule above is testable
//! without a transceiver and without sleeping.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// What a frame is for. The discriminant is the base priority: higher wins.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Class {
    /// Channel conversation. The most traffic and the most tolerant of delay.
    Chat = 0,
    /// Addressed to one station: private messages, held mail.
    Direct = 1,
    /// Session control: WELCOME, NAMES replies, PONG, ERROR.
    Control = 2,
    /// Acknowledgements. One short frame that prevents a long retransmission.
    Ack = 3,
    /// Station identification. The one frame we are obliged to send.
    Id = 4,
}

impl Class {
    /// Highest priority first. Iteration order and index order are the same.
    pub const ALL: [Class; 5] = [
        Class::Id,
        Class::Ack,
        Class::Control,
        Class::Direct,
        Class::Chat,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Class::Chat => "chat",
            Class::Direct => "direct",
            Class::Control => "control",
            Class::Ack => "ack",
            Class::Id => "id",
        }
    }
}

const CLASSES: usize = Class::ALL.len();

/// One frame waiting for the transmitter.
#[derive(Debug)]
pub struct Queued<T> {
    pub payload: T,
    pub class: Class,
    /// Whose airtime budget this is spent from. Use the destination callsign
    /// for unicast and one shared key (the channel, say) for broadcasts, so
    /// that "one station monopolises the gateway" and "the gateway monopolises
    /// the channel" are two different limits rather than the same one.
    pub account: String,
    /// Key-down time this frame will cost, from the governor's cost model.
    pub cost: Duration,
    pub queued_at: Instant,
    /// The far end is expected to answer this. Arms the reply window.
    pub expects_reply: bool,
}

#[derive(Clone, Debug)]
pub struct SchedulerConfig {
    /// A frame held longer than this is dropped rather than transmitted late.
    pub max_hold: Duration,
    /// Minimum silence after any transmission.
    pub min_gap: Duration,
    /// Silence held after a frame that asks for an answer, so the answer is
    /// not stepped on. Should cover the far end's TXDELAY, its CSMA backoff
    /// and the airtime of the reply itself.
    pub reply_window: Duration,
    /// Silence held after hearing anything on frequency. The next fragment of
    /// somebody else's message is the most likely thing to arrive next.
    pub rx_guard: Duration,
    /// Waiting this long raises a frame by one whole class. This is what
    /// stops chat starving behind a busy protocol exchange.
    pub aging: Duration,
    /// How far a station that has overspent is pushed down. Just over one
    /// class by default: an unfunded ACK still beats a funded chat line.
    pub unfunded_penalty: f64,
    /// Seconds of key-down granted per second of wall clock, per account.
    /// 0.02 is 1.2 s of airtime a minute — roughly one short frame.
    pub station_rate: f64,
    /// Most airtime an idle account may save up.
    pub station_burst: Duration,
    /// Deficit an account may run, as a multiple of `station_burst`. Bounded
    /// so overspending is a handicap, never a ban.
    pub max_deficit: f64,
    /// Accounts tracked at once. The quietest is evicted beyond this.
    pub max_accounts: usize,
    /// Frames each class may hold, indexed by `class as usize`.
    pub depth: [usize; CLASSES],
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            max_hold: Duration::from_secs(120),
            min_gap: Duration::from_millis(1500),
            // 300 baud: their TXDELAY (0.4 s) + a ~30 octet ACK (0.9 s) +
            // TXTAIL + CSMA slack.
            reply_window: Duration::from_millis(3500),
            rx_guard: Duration::from_millis(600),
            aging: Duration::from_secs(20),
            unfunded_penalty: 1.5,
            station_rate: 0.02,
            station_burst: Duration::from_secs(12),
            max_deficit: 3.0,
            max_accounts: 256,
            // Chat, Direct, Control, Ack, Id — by `class as usize`.
            depth: [16, 16, 8, 32, 2],
        }
    }
}

/// What the scheduler wants the pump to do next.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Poll {
    /// Something is waiting and the channel is ours: call [`Scheduler::pop`].
    Ready,
    /// Something is waiting but it is not safe or not time yet.
    Wait(Duration),
    /// Nothing queued.
    Idle,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

pub struct Scheduler<T> {
    cfg: SchedulerConfig,
    queues: [VecDeque<Queued<T>>; CLASSES],
    buckets: HashMap<String, Bucket>,
    /// Earliest the pacing gate or the governor lets us key again.
    pace_until: Option<Instant>,
    /// Earliest we will key after asking for an answer. Cleared by
    /// [`Scheduler::on_heard`]: the answer arrived, stop waiting for it.
    reply_until: Option<Instant>,
    last_heard: Option<Instant>,
    /// Frames refused because their class queue was full.
    pub refused: u64,
    /// Frames dropped because they waited past `max_hold`.
    pub expired: u64,
}

impl<T> Scheduler<T> {
    pub fn new(cfg: SchedulerConfig) -> Self {
        Self {
            cfg,
            queues: std::array::from_fn(|_| VecDeque::new()),
            buckets: HashMap::new(),
            pace_until: None,
            reply_until: None,
            last_heard: None,
            refused: 0,
            expired: 0,
        }
    }

    pub fn config(&self) -> &SchedulerConfig {
        &self.cfg
    }

    /// Queue a frame. Returns it back if its class is full, so the caller can
    /// tell whoever asked instead of dropping it silently.
    pub fn push(&mut self, item: Queued<T>) -> Result<(), Queued<T>> {
        let i = item.class as usize;
        if self.queues[i].len() >= self.cfg.depth[i] {
            self.refused += 1;
            return Err(item);
        }
        self.queues[i].push_back(item);
        Ok(())
    }

    /// Frames that have waited past `max_hold`. Returned rather than dropped
    /// so the caller can release their reserved airtime and count them.
    ///
    /// On a 300 baud channel a two-minute-old chat line is noise, not
    /// information — but an ACK or an ID never expires: the first ends a retry
    /// cycle whenever it arrives and the second is a legal obligation.
    pub fn expire(&mut self, now: Instant) -> Vec<Queued<T>> {
        let hold = self.cfg.max_hold;
        let mut out = Vec::new();
        for class in [Class::Chat, Class::Direct, Class::Control] {
            let q = &mut self.queues[class as usize];
            let mut keep = VecDeque::with_capacity(q.len());
            while let Some(item) = q.pop_front() {
                if now.saturating_duration_since(item.queued_at) > hold {
                    out.push(item);
                } else {
                    keep.push_back(item);
                }
            }
            *q = keep;
        }
        self.expired += out.len() as u64;
        out
    }

    /// A frame was heard on frequency. Arms the receive guard and, because the
    /// answer we were holding the transmitter for has now arrived, clears the
    /// reply window.
    pub fn on_heard(&mut self, now: Instant) {
        self.last_heard = Some(now);
        self.reply_until = None;
    }

    /// A transmission has just been made. `keyed` is what the governor says it
    /// actually cost; it is debited from the account and paces the next frame.
    pub fn on_keyed(&mut self, now: Instant, account: &str, keyed: Duration, expects_reply: bool) {
        let end = now + keyed;
        self.debit(account, now, keyed);
        self.pace_until = Some(end + self.cfg.min_gap);
        self.reply_until = expects_reply.then(|| end + self.cfg.reply_window);
    }

    /// The governor refused this frame for `delay`. Put it back at the head of
    /// its class — it has not lost its place — and do not ask again until then.
    pub fn requeue(&mut self, item: Queued<T>, now: Instant, delay: Duration) {
        self.pace_until = Some(match self.pace_until {
            Some(t) => t.max(now + delay),
            None => now + delay,
        });
        self.queues[item.class as usize].push_front(item);
    }

    /// Earliest moment the transmitter may key, if something is holding it.
    pub fn blocked_until(&self) -> Option<Instant> {
        let rx = self.last_heard.map(|t| t + self.cfg.rx_guard);
        [self.pace_until, self.reply_until, rx]
            .into_iter()
            .flatten()
            .max()
    }

    pub fn poll(&mut self, now: Instant) -> Poll {
        if self.is_empty() {
            return Poll::Idle;
        }
        match self.blocked_until() {
            Some(t) if t > now => Poll::Wait(t - now),
            _ => Poll::Ready,
        }
    }

    /// The frame that should go next, by class priority, ageing and funding.
    /// Does not check the guards — [`Scheduler::poll`] does that.
    ///
    /// Within a class the first *funded* frame is taken, so a station that has
    /// overspent waits behind the ones that have not — but it keeps its place
    /// rather than losing it, and when nothing else is queued it goes out
    /// immediately. Frames from the same account never overtake each other,
    /// which is what makes a fragmented message still arrive in order.
    pub fn pop(&mut self, now: Instant) -> Option<Queued<T>> {
        let mut best: Option<(usize, usize, f64)> = None;
        for class in Class::ALL {
            let ci = class as usize;
            if self.queues[ci].is_empty() {
                continue;
            }
            let idx = self.queues[ci]
                .iter()
                .position(|i| self.funded(&i.account, i.cost, now))
                .unwrap_or(0);
            let score = self.score(&self.queues[ci][idx], now);
            if best.map(|(_, _, b)| score > b).unwrap_or(true) {
                best = Some((ci, idx, score));
            }
        }
        let (ci, idx, _) = best?;
        self.queues[ci].remove(idx)
    }

    fn score(&self, item: &Queued<T>, now: Instant) -> f64 {
        let mut s = item.class as u8 as f64;
        let aging = self.cfg.aging.as_secs_f64().max(0.001);
        s += now.saturating_duration_since(item.queued_at).as_secs_f64() / aging;
        if !self.funded(&item.account, item.cost, now) {
            s -= self.cfg.unfunded_penalty;
        }
        s
    }

    /// Airtime this account has earned and not yet spent. May be negative:
    /// overspending is a handicap on the next frame, not a refusal of it.
    pub fn tokens(&self, account: &str, now: Instant) -> f64 {
        let burst = self.cfg.station_burst.as_secs_f64();
        match self.buckets.get(account) {
            None => burst,
            Some(b) => {
                let earned =
                    now.saturating_duration_since(b.last).as_secs_f64() * self.cfg.station_rate;
                (b.tokens + earned).min(burst)
            }
        }
    }

    pub fn funded(&self, account: &str, cost: Duration, now: Instant) -> bool {
        self.tokens(account, now) >= cost.as_secs_f64()
    }

    fn debit(&mut self, account: &str, now: Instant, cost: Duration) {
        let burst = self.cfg.station_burst.as_secs_f64();
        let floor = -burst * self.cfg.max_deficit.max(0.0);
        let tokens = self.tokens(account, now);
        if !self.buckets.contains_key(account) && self.buckets.len() >= self.cfg.max_accounts {
            if let Some(oldest) = self
                .buckets
                .iter()
                .min_by_key(|(_, b)| b.last)
                .map(|(k, _)| k.clone())
            {
                self.buckets.remove(&oldest);
            }
        }
        let entry = self.buckets.entry(account.to_string()).or_insert(Bucket {
            tokens: burst,
            last: now,
        });
        entry.tokens = (tokens - cost.as_secs_f64()).max(floor);
        entry.last = now;
    }

    /// Forget accounts that have been idle long enough to be back at full
    /// credit. Keeps the table from being a slow leak on a busy frequency.
    pub fn expire_accounts(&mut self, now: Instant, idle: Duration) {
        self.buckets
            .retain(|_, b| now.saturating_duration_since(b.last) < idle);
    }

    pub fn is_empty(&self) -> bool {
        self.queues.iter().all(|q| q.is_empty())
    }

    pub fn len(&self) -> usize {
        self.queues.iter().map(|q| q.len()).sum()
    }

    /// Frames a class will still accept.
    pub fn room_in(&self, class: Class) -> usize {
        let i = class as usize;
        self.cfg.depth[i].saturating_sub(self.queues[i].len())
    }

    /// Airtime of everything queued: what an operator asking "how far behind
    /// are we?" actually wants, and what admission control should price
    /// against.
    pub fn queued_airtime(&self) -> Duration {
        self.queues
            .iter()
            .flat_map(|q| q.iter())
            .map(|i| i.cost)
            .sum()
    }

    pub fn queued_airtime_in(&self, class: Class) -> Duration {
        self.queues[class as usize].iter().map(|i| i.cost).sum()
    }

    /// Everything still queued, for a shutdown or a `RADIO OFF` that discards
    /// the backlog. Guards and budgets are left alone: the operator turning
    /// the transmitter off does not settle anybody's airtime debt.
    pub fn drain(&mut self) -> Vec<Queued<T>> {
        let mut out = Vec::new();
        for q in self.queues.iter_mut() {
            out.extend(q.drain(..));
        }
        out
    }

    /// Drop every class except `keep`. `RADIO OFF` discards chat but still
    /// owes the band a sign-off identification.
    pub fn drain_except(&mut self, keep: Class) -> Vec<Queued<T>> {
        let mut out = Vec::new();
        for class in Class::ALL {
            if class == keep {
                continue;
            }
            out.extend(self.queues[class as usize].drain(..));
        }
        out
    }

    /// Live pacing override from a control operator. Takes effect on the
    /// next `on_keyed`; a frame already waiting for `pace_until` is not
    /// retroactively hurried.
    pub fn set_min_gap(&mut self, gap: Duration) {
        self.cfg.min_gap = gap;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SchedulerConfig {
        SchedulerConfig {
            min_gap: Duration::from_millis(0),
            rx_guard: Duration::from_millis(600),
            reply_window: Duration::from_secs(4),
            ..Default::default()
        }
    }

    fn item(class: Class, account: &str, at: Instant) -> Queued<&'static str> {
        Queued {
            payload: class.as_str(),
            class,
            account: account.into(),
            cost: Duration::from_secs(1),
            queued_at: at,
            expects_reply: false,
        }
    }

    #[test]
    fn an_ack_overtakes_queued_chat() {
        let mut s = Scheduler::new(cfg());
        let now = Instant::now();
        for _ in 0..3 {
            s.push(item(Class::Chat, "#rf", now)).unwrap();
        }
        s.push(item(Class::Ack, "SM0ABC-7", now)).unwrap();
        assert_eq!(s.poll(now), Poll::Ready);
        assert_eq!(s.pop(now).unwrap().class, Class::Ack);
        assert_eq!(s.pop(now).unwrap().class, Class::Chat);
    }

    #[test]
    fn chat_ages_past_control_rather_than_starving() {
        let mut s = Scheduler::new(cfg());
        let now = Instant::now();
        s.push(item(Class::Chat, "#rf", now)).unwrap();
        // Fresh control traffic outranks a fresh chat line.
        let later = now + Duration::from_secs(5);
        s.push(item(Class::Control, "SM0ABC-7", later)).unwrap();
        assert_eq!(s.pop(later).unwrap().class, Class::Control);

        // Two classes' worth of ageing (20 s each) and it does not.
        s.push(item(
            Class::Control,
            "SM0ABC-7",
            now + Duration::from_secs(50),
        ))
        .unwrap();
        let much_later = now + Duration::from_secs(50);
        assert_eq!(
            s.pop(much_later).unwrap().class,
            Class::Chat,
            "a chat line waited 50 s; nothing may starve behind protocol traffic"
        );
    }

    #[test]
    fn an_overspending_station_is_deprioritised_not_blocked() {
        let mut s = Scheduler::new(SchedulerConfig {
            station_burst: Duration::from_secs(4),
            station_rate: 0.0,
            ..cfg()
        });
        let now = Instant::now();
        // Spend the whole budget.
        s.on_keyed(now, "SM0LOUD", Duration::from_secs(6), false);
        assert!(!s.funded("SM0LOUD", Duration::from_secs(1), now));
        assert!(s.funded("SM0QUIET", Duration::from_secs(1), now));

        s.push(item(Class::Direct, "SM0LOUD", now)).unwrap();
        s.push(item(Class::Direct, "SM0QUIET", now)).unwrap();
        assert_eq!(
            s.pop(now).unwrap().account,
            "SM0QUIET",
            "the funded station goes first"
        );
        assert_eq!(
            s.pop(now).unwrap().account,
            "SM0LOUD",
            "but the overspending one is still sent, not dropped"
        );
    }

    #[test]
    fn the_deficit_is_bounded() {
        let mut s: Scheduler<&str> = Scheduler::new(SchedulerConfig {
            station_burst: Duration::from_secs(4),
            station_rate: 0.0,
            max_deficit: 2.0,
            ..cfg()
        });
        let now = Instant::now();
        for _ in 0..50 {
            s.on_keyed(now, "SM0LOUD", Duration::from_secs(10), false);
        }
        assert!(
            s.tokens("SM0LOUD", now) >= -8.0,
            "a station must be able to earn its way back: {}",
            s.tokens("SM0LOUD", now)
        );
    }

    #[test]
    fn a_bucket_refills() {
        let mut s: Scheduler<&str> = Scheduler::new(SchedulerConfig {
            station_burst: Duration::from_secs(10),
            station_rate: 0.1,
            ..cfg()
        });
        let now = Instant::now();
        s.on_keyed(now, "SM0ABC", Duration::from_secs(10), false);
        assert!(!s.funded("SM0ABC", Duration::from_secs(5), now));
        // 0.1 s of airtime per second: a minute buys six seconds.
        assert!(s.funded(
            "SM0ABC",
            Duration::from_secs(5),
            now + Duration::from_secs(60)
        ));
    }

    #[test]
    fn asking_for_an_answer_holds_the_transmitter_down() {
        let mut s = Scheduler::new(cfg());
        let now = Instant::now();
        s.on_keyed(now, "SM0ABC-7", Duration::from_secs(2), true);
        s.push(item(Class::Chat, "#rf", now)).unwrap();
        // 2 s of key-down plus a 4 s reply window.
        match s.poll(now) {
            Poll::Wait(d) => assert!(d > Duration::from_secs(5), "{d:?}"),
            other => panic!("keyed straight over the answer: {other:?}"),
        }
        // The answer arrives: stop waiting for it.
        let heard = now + Duration::from_secs(3);
        s.on_heard(heard);
        match s.poll(heard + Duration::from_millis(700)) {
            Poll::Ready => {}
            other => panic!("the reply came; the window should be over: {other:?}"),
        }
    }

    #[test]
    fn hearing_a_frame_arms_a_short_guard() {
        let mut s = Scheduler::new(cfg());
        let now = Instant::now();
        s.push(item(Class::Ack, "SM0ABC-7", now)).unwrap();
        s.on_heard(now);
        match s.poll(now) {
            Poll::Wait(d) => assert!(d <= Duration::from_millis(600), "{d:?}"),
            other => panic!("expected the receive guard: {other:?}"),
        }
        assert_eq!(
            s.poll(now + Duration::from_millis(601)),
            Poll::Ready,
            "the guard is short: an ACK must not be late"
        );
    }

    #[test]
    fn a_deferred_frame_keeps_its_place() {
        let mut s = Scheduler::new(cfg());
        let now = Instant::now();
        s.push(item(Class::Control, "SM0ABC-7", now)).unwrap();
        s.push(item(Class::Control, "SM0XYZ-9", now)).unwrap();
        let first = s.pop(now).unwrap();
        assert_eq!(first.account, "SM0ABC-7");
        s.requeue(first, now, Duration::from_secs(30));
        assert_eq!(s.poll(now), Poll::Wait(Duration::from_secs(30)));
        assert_eq!(
            s.pop(now + Duration::from_secs(30)).unwrap().account,
            "SM0ABC-7",
            "the governor's refusal must not cost it its turn"
        );
    }

    #[test]
    fn stale_chat_is_dropped_but_acks_and_ids_are_not() {
        let mut s = Scheduler::new(SchedulerConfig {
            max_hold: Duration::from_secs(60),
            ..cfg()
        });
        let now = Instant::now();
        s.push(item(Class::Chat, "#rf", now)).unwrap();
        s.push(item(Class::Ack, "SM0ABC-7", now)).unwrap();
        s.push(item(Class::Id, "gateway", now)).unwrap();
        let dropped = s.expire(now + Duration::from_secs(90));
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].class, Class::Chat);
        assert_eq!(s.len(), 2, "an ACK is always worth sending late");
    }

    #[test]
    fn a_full_class_hands_the_frame_back() {
        let mut s = Scheduler::new(SchedulerConfig {
            depth: [2, 16, 8, 32, 2],
            ..cfg()
        });
        let now = Instant::now();
        assert!(s.push(item(Class::Chat, "#rf", now)).is_ok());
        assert!(s.push(item(Class::Chat, "#rf", now)).is_ok());
        let back = s.push(item(Class::Chat, "#rf", now));
        assert!(back.is_err(), "the caller has to be told, not guessed at");
        assert_eq!(s.refused, 1);
        assert!(
            s.push(item(Class::Ack, "SM0ABC-7", now)).is_ok(),
            "a full chat queue must never crowd out an ACK"
        );
    }

    #[test]
    fn queued_airtime_is_what_admission_control_prices_against() {
        let mut s = Scheduler::new(cfg());
        let now = Instant::now();
        for _ in 0..4 {
            s.push(item(Class::Chat, "#rf", now)).unwrap();
        }
        assert_eq!(s.queued_airtime(), Duration::from_secs(4));
        assert_eq!(s.queued_airtime_in(Class::Ack), Duration::ZERO);
    }

    #[test]
    fn an_empty_scheduler_is_idle_even_while_guarded() {
        let mut s: Scheduler<&str> = Scheduler::new(cfg());
        let now = Instant::now();
        s.on_keyed(now, "SM0ABC-7", Duration::from_secs(2), true);
        assert_eq!(
            s.poll(now),
            Poll::Idle,
            "nothing to send: the pump should sleep on its inputs, not on a timer"
        );
    }

    #[test]
    fn the_account_table_is_bounded() {
        let mut s: Scheduler<&str> = Scheduler::new(SchedulerConfig {
            max_accounts: 8,
            ..cfg()
        });
        let mut now = Instant::now();
        for i in 0..64 {
            s.on_keyed(
                now,
                &format!("SM0A{i:02}"),
                Duration::from_millis(100),
                false,
            );
            now += Duration::from_millis(10);
        }
        assert!(s.buckets.len() <= 8, "{} accounts", s.buckets.len());
    }
}
