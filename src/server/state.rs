//! In-memory server state.
//!
//! There is exactly one instance of this, owned by a single task. All mutation
//! goes through that task's event loop, so there are no locks anywhere in the
//! hot path and no possibility of two connections observing different orders
//! of the same events.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use crate::callsign::Callsign;
use crate::irc::message::lower;

pub type ClientId = u64;

/// Users come from two very different places, and almost every decision in the
/// server depends on which.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UserId {
    Ip(ClientId),
    Rf(Callsign),
}

impl UserId {
    pub fn is_rf(&self) -> bool {
        matches!(self, UserId::Rf(_))
    }

    pub fn callsign(&self) -> Option<&Callsign> {
        match self {
            UserId::Rf(c) => Some(c),
            UserId::Ip(_) => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct User {
    pub id: UserId,
    pub nick: String,
    pub username: String,
    pub realname: String,
    pub host: String,
    /// Set for RF users, and for IP users who have identified with `CALLSIGN`.
    pub callsign: Option<Callsign>,
    pub registered: bool,
    /// Proven ownership of a REGISTER'd nick (IDENTIFY succeeded).
    pub nick_identified: bool,
    /// If set, this nick is registered by someone else and must be IDENTIFY'd.
    pub identify_by: Option<Instant>,
    pub oper: bool,
    pub away: Option<String>,
    pub channels: HashSet<String>,
    pub connected_at: Instant,
    pub last_active: Instant,
    pub got_nick: bool,
    pub got_user: bool,
    pub pass_ok: bool,
    /// May this IP user have their messages put on the air?
    pub rf_tx: bool,
}

impl User {
    pub fn new(id: UserId, host: String, now: Instant) -> Self {
        Self {
            id,
            nick: "*".into(),
            username: "*".into(),
            realname: String::new(),
            host,
            callsign: None,
            registered: false,
            nick_identified: false,
            identify_by: None,
            oper: false,
            away: None,
            channels: HashSet::new(),
            connected_at: now,
            last_active: now,
            got_nick: false,
            got_user: false,
            pass_ok: false,
            rf_tx: false,
        }
    }

    /// `nick!user@host`, as used in message prefixes.
    pub fn prefix(&self) -> String {
        format!("{}!{}@{}", self.nick, self.username, self.host)
    }

    pub fn is_rf(&self) -> bool {
        self.id.is_rf()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemberFlags {
    pub op: bool,
    pub voice: bool,
    /// Granted explicitly with `MODE`, rather than derived from who the user
    /// is.
    ///
    /// The two have to be told apart. Privileges are recomputed whenever
    /// something changes about a user — OPER, IDENTIFY, CALLSIGN, a RADIO
    /// GRANT — and that recomputation used to overwrite the whole flag set,
    /// so an unrelated IDENTIFY silently took away a `+v` a channel operator
    /// had just given out.
    pub op_manual: bool,
    pub voice_manual: bool,
}

impl MemberFlags {
    pub fn sigil(&self) -> &'static str {
        if self.op {
            "@"
        } else if self.voice {
            "+"
        } else {
            ""
        }
    }
}

#[derive(Clone, Debug)]
pub struct Channel {
    pub name: String,
    /// Declared in the configuration file. Configured channels persist while
    /// empty; channels users create are reaped when the last member leaves.
    pub configured: bool,
    pub topic: Option<String>,
    pub topic_setter: String,
    pub topic_time: u64,
    pub members: HashMap<UserId, MemberFlags>,
    /// Bridged to RF. Rendered as channel mode `+r`.
    pub rf: bool,
    pub moderated: bool,
    pub topic_locked: bool,
    pub key: Option<String>,
    pub limit: Option<usize>,
    /// Lowercased nicks that receive +o after IDENTIFY.
    pub operators: HashSet<String>,
}

impl Channel {
    pub fn new(name: &str, rf: bool) -> Self {
        Self {
            name: name.to_string(),
            configured: false,
            topic: None,
            topic_setter: String::new(),
            topic_time: 0,
            members: HashMap::new(),
            rf,
            // RF channels are +m: only callsign-voiced users (and ops) may speak.
            moderated: rf,
            topic_locked: true,
            key: None,
            limit: None,
            operators: HashSet::new(),
        }
    }

    pub fn mode_string(&self) -> String {
        let mut s = String::from("+n");
        if self.rf {
            s.push('r');
        }
        if self.moderated {
            s.push('m');
        }
        if self.topic_locked {
            s.push('t');
        }
        if self.key.is_some() {
            s.push('k');
        }
        if self.limit.is_some() {
            s.push('l');
        }
        s
    }

    pub fn has_rf_members(&self) -> bool {
        self.members.keys().any(|u| u.is_rf())
    }
}

#[derive(Default)]
pub struct State {
    pub users: HashMap<UserId, User>,
    nicks: HashMap<String, UserId>,
    pub channels: HashMap<String, Channel>,
}

impl State {
    pub fn user(&self, id: &UserId) -> Option<&User> {
        self.users.get(id)
    }

    pub fn user_mut(&mut self, id: &UserId) -> Option<&mut User> {
        self.users.get_mut(id)
    }

    pub fn insert_user(&mut self, user: User) {
        self.users.insert(user.id.clone(), user);
    }

    pub fn by_nick(&self, nick: &str) -> Option<&User> {
        self.nicks
            .get(&lower(nick))
            .and_then(|id| self.users.get(id))
    }

    pub fn nick_taken(&self, nick: &str) -> bool {
        self.nicks.contains_key(&lower(nick))
    }

    /// Claim a nickname for a user, releasing the old one. Returns false if it
    /// is already taken by somebody else.
    pub fn set_nick(&mut self, id: &UserId, nick: &str) -> bool {
        // Claiming a nick for a user that does not exist would leave the
        // registry pointing at nothing: `remove_user` could never clean it up,
        // so the nick would be reserved for the life of the process.
        if !self.users.contains_key(id) {
            return false;
        }
        let key = lower(nick);
        if let Some(owner) = self.nicks.get(&key) {
            if owner != id {
                return false;
            }
        }
        if let Some(user) = self.users.get(id) {
            let old = lower(&user.nick);
            self.nicks.remove(&old);
        }
        self.nicks.insert(key, id.clone());
        if let Some(user) = self.users.get_mut(id) {
            user.nick = nick.to_string();
        }
        true
    }

    pub fn channel(&self, name: &str) -> Option<&Channel> {
        self.channels.get(&lower(name))
    }

    pub fn channel_mut(&mut self, name: &str) -> Option<&mut Channel> {
        self.channels.get_mut(&lower(name))
    }

    pub fn ensure_channel(&mut self, name: &str, rf: bool) -> &mut Channel {
        self.channels
            .entry(lower(name))
            .or_insert_with(|| Channel::new(name, rf))
    }

    pub fn join(&mut self, id: &UserId, channel: &str) -> Option<MemberFlags> {
        // Same reasoning as `set_nick`: a membership entry for a user that
        // does not exist is invisible to `names_of` (which looks the user up)
        // but still counted in `members`, and nothing ever removes it.
        if !self.users.contains_key(id) {
            return None;
        }
        let key = lower(channel);
        let (rf, first, operators) = {
            let chan = self.channels.get(&key)?;
            if chan.members.contains_key(id) {
                return None;
            }
            (chan.rf, chan.members.is_empty(), chan.operators.clone())
        };
        let flags = self.flags_for_parts(id, rf, first, &operators);
        if let Some(chan) = self.channels.get_mut(&key) {
            chan.members.insert(id.clone(), flags);
        }
        if let Some(user) = self.users.get_mut(id) {
            user.channels.insert(key);
        }
        Some(flags)
    }

    pub fn flags_for_parts(
        &self,
        id: &UserId,
        rf: bool,
        first: bool,
        operators: &HashSet<String>,
    ) -> MemberFlags {
        let Some(user) = self.users.get(id) else {
            return MemberFlags::default();
        };
        let configured_op = operators.contains(&lower(&user.nick)) && user.nick_identified;
        if rf {
            MemberFlags {
                op: user.oper || configured_op,
                voice: user.callsign.is_some() || user.oper,
                ..Default::default()
            }
        } else {
            MemberFlags {
                op: (first && !id.is_rf()) || user.oper || configured_op,
                voice: false,
                ..Default::default()
            }
        }
    }

    /// Recompute what a user's membership flags *should* be, and apply the
    /// change. Returns the old and new flags when something moved.
    ///
    /// Anything an operator granted by hand is preserved: this only decides
    /// the derived part.
    pub fn apply_intended_flags(
        &mut self,
        id: &UserId,
        channel: &str,
    ) -> Option<(MemberFlags, MemberFlags)> {
        let key = lower(channel);
        let (old, rf, operators) = {
            let chan = self.channels.get(&key)?;
            let old = *chan.members.get(id)?;
            (old, chan.rf, chan.operators.clone())
        };
        let derived = self.flags_for_parts(id, rf, false, &operators);
        let new = MemberFlags {
            op: derived.op || old.op_manual,
            voice: derived.voice || old.voice_manual,
            op_manual: old.op_manual,
            voice_manual: old.voice_manual,
        };
        if old == new {
            return None;
        }
        if let Some(flags) = self
            .channels
            .get_mut(&key)
            .and_then(|c| c.members.get_mut(id))
        {
            *flags = new;
        }
        Some((old, new))
    }

    /// Connected IP clients, registered or not.
    pub fn ip_users(&self) -> usize {
        self.users.values().filter(|u| !u.is_rf()).count()
    }

    pub fn ip_count_from_host(&self, host: &str) -> usize {
        self.users
            .values()
            .filter(|u| !u.is_rf() && u.host == host)
            .count()
    }

    pub fn part(&mut self, id: &UserId, channel: &str) -> bool {
        let key = lower(channel);
        let Some(chan) = self.channels.get_mut(&key) else {
            return false;
        };
        let was_member = chan.members.remove(id).is_some();
        if let Some(user) = self.users.get_mut(id) {
            user.channels.remove(&key);
        }
        self.reap_channel(&key);
        was_member
    }

    /// Forget a user-created channel once it is empty.
    ///
    /// Channels created with `JOIN` used to live forever. Each user may hold
    /// `max_channels_per_user` of them, so a client that joined twenty
    /// channels, disconnected and reconnected could grow the channel table
    /// without limit — cheap for the attacker, permanent for the server.
    /// Configured channels are exempt: an empty `#rf` still has to exist for
    /// a station to join it.
    fn reap_channel(&mut self, key: &str) {
        let gone = self
            .channels
            .get(key)
            .map(|c| !c.configured && c.members.is_empty())
            .unwrap_or(false);
        if gone {
            self.channels.remove(key);
        }
    }

    /// Remove a user entirely. Returns the channels they were in.
    pub fn remove_user(&mut self, id: &UserId) -> Vec<String> {
        let Some(user) = self.users.remove(id) else {
            return Vec::new();
        };
        self.nicks.remove(&lower(&user.nick));
        let mut names = Vec::new();
        for key in user.channels {
            if let Some(chan) = self.channels.get_mut(&key) {
                chan.members.remove(id);
                names.push(chan.name.clone());
            }
            self.reap_channel(&key);
        }
        names
    }

    pub fn members(&self, channel: &str) -> Vec<UserId> {
        self.channel(channel)
            .map(|c| c.members.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Everyone who shares at least one channel with `id`, excluding `id`.
    pub fn peers_of(&self, id: &UserId) -> Vec<UserId> {
        let mut out: HashSet<UserId> = HashSet::new();
        if let Some(user) = self.users.get(id) {
            for key in &user.channels {
                if let Some(chan) = self.channels.get(key) {
                    out.extend(chan.members.keys().cloned());
                }
            }
        }
        out.remove(id);
        out.into_iter().collect()
    }

    pub fn names_of(&self, channel: &str) -> Vec<String> {
        let Some(chan) = self.channel(channel) else {
            return Vec::new();
        };
        let mut names: Vec<String> = chan
            .members
            .iter()
            .filter_map(|(id, flags)| {
                self.users
                    .get(id)
                    .map(|u| format!("{}{}", flags.sigil(), u.nick))
            })
            .collect();
        names.sort();
        names
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(id: UserId, nick: &str) -> User {
        let mut u = User::new(id, "host".into(), Instant::now());
        u.nick = nick.into();
        u
    }

    #[test]
    fn nick_registry_is_case_insensitive() {
        let mut s = State::default();
        s.insert_user(user(UserId::Ip(1), "*"));
        assert!(s.set_nick(&UserId::Ip(1), "Alice"));
        assert!(s.nick_taken("ALICE"));
        s.insert_user(user(UserId::Ip(2), "*"));
        assert!(!s.set_nick(&UserId::Ip(2), "alice"));
    }

    #[test]
    fn first_ip_user_gets_ops_on_local_not_on_rf() {
        let mut s = State::default();
        let rf = UserId::Rf("SM0ABC".parse().unwrap());
        let mut rf_user = user(rf.clone(), "SM0ABC");
        rf_user.callsign = Some("SM0ABC".parse().unwrap());
        s.insert_user(rf_user);
        s.insert_user(user(UserId::Ip(1), "alice"));
        s.ensure_channel("#rf", true);
        s.ensure_channel("#local", false);

        let rf_flags = s.join(&rf, "#rf").unwrap();
        assert!(!rf_flags.op, "RF stations never get channel ops");
        assert!(rf_flags.voice, "a callsign is voiced on +r");

        let ip_on_rf = s.join(&UserId::Ip(1), "#rf").unwrap();
        assert!(!ip_on_rf.op);
        assert!(!ip_on_rf.voice, "no callsign, no voice");

        s.insert_user(user(UserId::Ip(2), "bob"));
        let local = s.join(&UserId::Ip(2), "#local").unwrap();
        assert!(local.op, "first IP user on a local channel gets ops");
    }

    #[test]
    fn removing_a_user_cleans_channels() {
        let mut s = State::default();
        s.insert_user(user(UserId::Ip(1), "alice"));
        s.set_nick(&UserId::Ip(1), "alice");
        s.ensure_channel("#a", false).configured = true;
        assert!(s.join(&UserId::Ip(1), "#a").is_some());
        assert_eq!(s.remove_user(&UserId::Ip(1)), vec!["#a"]);
        assert!(s.channel("#a").unwrap().members.is_empty());
        assert!(!s.nick_taken("alice"));
    }

    #[test]
    fn a_user_that_does_not_exist_cannot_claim_a_nick_or_a_channel() {
        let mut s = State::default();
        s.ensure_channel("#a", false).configured = true;
        let ghost = UserId::Ip(99);

        assert!(!s.set_nick(&ghost, "phantom"));
        assert!(
            !s.nick_taken("phantom"),
            "the nick registry would point at nobody and never be cleaned up"
        );
        assert!(s.join(&ghost, "#a").is_none());
        assert!(
            s.channel("#a").unwrap().members.is_empty(),
            "a membership with no user is invisible to NAMES but counted in the member list"
        );
    }

    #[test]
    fn a_manual_grant_outlives_a_recomputation() {
        let mut s = State::default();
        s.ensure_channel("#a", false).configured = true;
        s.insert_user(user(UserId::Ip(1), "alice"));
        s.set_nick(&UserId::Ip(1), "alice");
        s.join(&UserId::Ip(1), "#a");

        // An operator hands out +v by hand.
        if let Some(f) = s
            .channels
            .get_mut("#a")
            .and_then(|c| c.members.get_mut(&UserId::Ip(1)))
        {
            f.voice = true;
            f.voice_manual = true;
        }
        // Something unrelated recomputes the derived flags.
        s.apply_intended_flags(&UserId::Ip(1), "#a");
        assert!(
            s.channel("#a").unwrap().members[&UserId::Ip(1)].voice,
            "a recomputation must not undo what an operator granted"
        );
    }

    #[test]
    fn user_created_channels_are_reaped_but_configured_ones_are_not() {
        let mut s = State::default();
        s.ensure_channel("#rf", true).configured = true;
        s.insert_user(user(UserId::Ip(1), "alice"));
        s.ensure_channel("#throwaway", false);
        s.join(&UserId::Ip(1), "#throwaway");
        s.join(&UserId::Ip(1), "#rf");

        s.part(&UserId::Ip(1), "#throwaway");
        assert!(
            s.channel("#throwaway").is_none(),
            "an empty user-created channel must not outlive its last member"
        );

        s.remove_user(&UserId::Ip(1));
        assert!(
            s.channel("#rf").is_some(),
            "a configured channel has to exist for a station to join it"
        );
    }
}
