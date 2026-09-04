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
    pub oper: bool,
    pub away: Option<String>,
    pub channels: HashSet<String>,
    pub connected_at: Instant,
    pub last_active: Instant,
    pub got_nick: bool,
    pub got_user: bool,
    pub pass_ok: bool,
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
            oper: false,
            away: None,
            channels: HashSet::new(),
            connected_at: now,
            last_active: now,
            got_nick: false,
            got_user: false,
            pass_ok: false,
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

#[derive(Clone, Copy, Debug, Default)]
pub struct MemberFlags {
    pub op: bool,
    pub voice: bool,
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
}

impl Channel {
    pub fn new(name: &str, rf: bool) -> Self {
        Self {
            name: name.to_string(),
            topic: None,
            topic_setter: String::new(),
            topic_time: 0,
            members: HashMap::new(),
            rf,
            moderated: false,
            topic_locked: true,
            key: None,
            limit: None,
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
        self.nicks.get(&lower(nick)).and_then(|id| self.users.get(id))
    }

    pub fn nick_taken(&self, nick: &str) -> bool {
        self.nicks.contains_key(&lower(nick))
    }

    /// Claim a nickname for a user, releasing the old one. Returns false if it
    /// is already taken by somebody else.
    pub fn set_nick(&mut self, id: &UserId, nick: &str) -> bool {
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

    pub fn join(&mut self, id: &UserId, channel: &str) -> bool {
        let key = lower(channel);
        let Some(chan) = self.channels.get_mut(&key) else {
            return false;
        };
        if chan.members.contains_key(id) {
            return false;
        }
        let first = chan.members.is_empty();
        chan.members.insert(
            id.clone(),
            MemberFlags {
                // The first IP user in an empty channel gets ops; RF stations
                // never do, because the callsign is unauthenticated.
                op: first && !id.is_rf(),
                voice: false,
            },
        );
        if let Some(user) = self.users.get_mut(id) {
            user.channels.insert(key);
        }
        true
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
        was_member
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
    fn first_ip_user_gets_ops_rf_never_does() {
        let mut s = State::default();
        let rf = UserId::Rf("SM0ABC".parse().unwrap());
        s.insert_user(user(rf.clone(), "SM0ABC"));
        s.insert_user(user(UserId::Ip(1), "alice"));
        s.ensure_channel("#rf", true);

        assert!(s.join(&rf, "#rf"));
        assert!(!s.channel("#rf").unwrap().members[&rf].op);
        assert!(s.join(&UserId::Ip(1), "#rf"));
        assert!(!s.channel("#rf").unwrap().members[&UserId::Ip(1)].op);
    }

    #[test]
    fn removing_a_user_cleans_channels() {
        let mut s = State::default();
        s.insert_user(user(UserId::Ip(1), "alice"));
        s.set_nick(&UserId::Ip(1), "alice");
        s.ensure_channel("#a", false);
        s.join(&UserId::Ip(1), "#a");
        assert_eq!(s.remove_user(&UserId::Ip(1)), vec!["#a"]);
        assert!(s.channel("#a").unwrap().members.is_empty());
        assert!(!s.nick_taken("alice"));
    }
}
