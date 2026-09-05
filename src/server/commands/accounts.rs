//! Registered nicknames: `REGISTER`, `IDENTIFY`, `UNREGISTER`, and the
//! RF-TX grant that rides on them.
//!
//! Password hashing happens on a blocking thread and comes back as an
//! [`Event::AuthFinished`], so the event loop is never held up by Argon2. That
//! makes the result asynchronous with respect to everything else, which is why
//! [`Server::finish_auth`] re-checks that the nickname has not changed in the
//! meantime.

use std::time::Instant;

use crate::accounts::{hash_password, verify_password, AccountError};
use crate::callsign::Callsign;
use crate::irc::message::{lower, Message};
use crate::irc::numerics as num;

use super::super::state::{ClientId, UserId};
use super::super::{AuthKind, Event, Server};

impl Server {
    pub(super) fn cmd_register(&mut self, uid: &UserId, msg: &Message) {
        let Some(password) = msg.param(0) else {
            self.numeric(
                uid,
                num::ERR_NEEDMOREPARAMS,
                &["REGISTER", "Not enough parameters"],
            );
            return;
        };
        if !self.auth_rate_ok(uid) {
            return;
        }
        let Some(user) = self.state.user(uid).cloned() else {
            return;
        };
        if Callsign::reserved_from_nick(&user.nick).is_some() {
            self.notice_user(
                uid,
                "Callsign nicks cannot be registered; they belong to RF stations.",
            );
            return;
        }
        if password.len() < self.config.accounts.min_password_len {
            self.notice_account_error(uid, AccountError::TooShort);
            return;
        }
        if password.len() > 128 {
            self.notice_account_error(uid, AccountError::TooLong);
            return;
        }
        if !user.nick_identified && self.accounts.is_registered(&user.nick) {
            self.notice_account_error(uid, AccountError::Taken);
            return;
        }
        let password = password.to_string();
        self.run_argon2(uid, AuthKind::Register, user.nick, move || {
            hash_password(&password).map(Some)
        });
    }

    pub(super) fn cmd_identify(&mut self, uid: &UserId, msg: &Message) {
        let Some(password) = msg.param(0) else {
            self.numeric(
                uid,
                num::ERR_NEEDMOREPARAMS,
                &["IDENTIFY", "Not enough parameters"],
            );
            return;
        };
        if !self.auth_rate_ok(uid) {
            return;
        }
        let Some(user) = self.state.user(uid).cloned() else {
            return;
        };
        let Some(hash) = self.accounts.hash_for(&user.nick) else {
            self.notice_account_error(uid, AccountError::NotRegistered);
            return;
        };
        let password = password.to_string();
        self.run_argon2(uid, AuthKind::Identify, user.nick, move || {
            verify_password(&password, &hash).map(|()| None)
        });
    }

    pub(super) fn cmd_unregister(&mut self, uid: &UserId, msg: &Message) {
        let Some(password) = msg.param(0) else {
            self.numeric(
                uid,
                num::ERR_NEEDMOREPARAMS,
                &["UNREGISTER", "Not enough parameters"],
            );
            return;
        };
        if !self.auth_rate_ok(uid) {
            return;
        }
        let Some(user) = self.state.user(uid).cloned() else {
            return;
        };
        let Some(hash) = self.accounts.hash_for(&user.nick) else {
            self.notice_account_error(uid, AccountError::NotRegistered);
            return;
        };
        let password = password.to_string();
        self.run_argon2(uid, AuthKind::Unregister, user.nick, move || {
            verify_password(&password, &hash).map(|()| None)
        });
    }

    pub(super) fn auth_rate_ok(&mut self, uid: &UserId) -> bool {
        let host = self
            .state
            .user(uid)
            .map(|u| u.host.clone())
            .unwrap_or_default();
        if !self.policy.identify_rate_ok(&host, Instant::now()) {
            self.notice_user(uid, "Slow down: too many password attempts from your host.");
            self.audit.event("auth_throttle", &[("host", &host)]);
            return false;
        }
        true
    }

    /// Hash or verify off the event loop when a sender is attached; tests
    /// without one still run inline so they stay deterministic.
    pub(super) fn run_argon2<F>(&mut self, uid: &UserId, kind: AuthKind, nick: String, work: F)
    where
        F: FnOnce() -> Result<Option<String>, AccountError> + Send + 'static,
    {
        let UserId::Ip(id) = *uid else {
            return;
        };
        if let Some(tx) = self.events.clone() {
            tokio::spawn(async move {
                let outcome = tokio::task::spawn_blocking(work)
                    .await
                    .unwrap_or(Err(AccountError::Hash));
                let (result, password_hash) = match outcome {
                    Ok(hash) => (Ok(()), hash),
                    Err(e) => (Err(e), None),
                };
                let _ = tx
                    .send(Event::AuthFinished {
                        id,
                        kind,
                        nick,
                        result,
                        password_hash,
                    })
                    .await;
            });
            return;
        }
        let (result, password_hash) = match work() {
            Ok(hash) => (Ok(()), hash),
            Err(e) => (Err(e), None),
        };
        self.finish_auth(id, kind, nick, result, password_hash);
    }

    pub(crate) fn finish_auth(
        &mut self,
        id: ClientId,
        kind: AuthKind,
        nick: String,
        result: Result<(), AccountError>,
        password_hash: Option<String>,
    ) {
        let uid = UserId::Ip(id);
        let Some(user) = self.state.user(&uid).cloned() else {
            return;
        };
        if lower(&user.nick) != lower(&nick) {
            self.notice_user(&uid, "Nick changed during password check; try again.");
            return;
        }
        if let Err(e) = result {
            if kind == AuthKind::Oper {
                self.numeric(&uid, num::ERR_PASSWDMISMATCH, &["Password incorrect"]);
                self.audit
                    .event("oper_fail", &[("nick", &user.nick), ("host", &user.host)]);
                return;
            }
            self.notice_account_error(&uid, e);
            return;
        }
        match kind {
            AuthKind::Identify => {
                if let Some(u) = self.state.user_mut(&uid) {
                    u.nick_identified = true;
                    u.identify_by = None;
                }
                self.notice_user(
                    &uid,
                    "Password accepted. You own this nick for this session.",
                );
                self.audit
                    .event("identify", &[("nick", &user.nick), ("host", &user.host)]);
                self.refresh_privileges(&uid);
            }
            AuthKind::Register => {
                let Some(hash) = password_hash else {
                    self.notice_account_error(&uid, AccountError::Hash);
                    return;
                };
                if user.nick_identified && self.accounts.is_registered(&user.nick) {
                    if let Err(e) = self.accounts.set_password_hash(&user.nick, hash) {
                        self.notice_account_error(&uid, e);
                        return;
                    }
                    self.notice_user(&uid, "Password updated.");
                    return;
                }
                if let Err(e) = self.accounts.insert_hashed(&user.nick, hash) {
                    self.notice_account_error(&uid, e);
                    return;
                }
                if let Some(u) = self.state.user_mut(&uid) {
                    u.nick_identified = true;
                    u.identify_by = None;
                }
                if let Some(c) = user.callsign.as_ref() {
                    match self.accounts.set_callsign(&user.nick, &c.to_string()) {
                        Ok(()) => {
                            self.strip_callsign_claims(
                                c,
                                Some(&uid),
                                &format!("Callsign {c} now belongs to another nick."),
                            );
                            self.notice_user(
                                &uid,
                                &format!(
                                    "Callsign {c} is bound to this nick. Nobody else can claim it."
                                ),
                            );
                        }
                        Err(AccountError::CallsignTaken) => {
                            if let Some(u) = self.state.user_mut(&uid) {
                                u.callsign = None;
                            }
                            self.notice_user(
                                &uid,
                                "Nick registered, but that callsign already belongs to another nick. CALLSIGN something else.",
                            );
                        }
                        Err(e) => self.notice_account_error(&uid, e),
                    }
                }
                self.notice_user(
                    &uid,
                    "Nick registered. The password is stored as an Argon2id hash, not recoverable. IDENTIFY on next connect.",
                );
                self.audit.event(
                    "nick_register",
                    &[("nick", &user.nick), ("host", &user.host)],
                );
                self.refresh_privileges(&uid);
            }
            AuthKind::Unregister => match self.accounts.drop_nick(&user.nick) {
                Ok(()) => {
                    if let Some(u) = self.state.user_mut(&uid) {
                        u.nick_identified = false;
                        u.rf_tx = u.oper;
                    }
                    self.notice_user(&uid, "Nick unregistered.");
                    self.audit.event("nick_drop", &[("nick", &user.nick)]);
                    self.refresh_privileges(&uid);
                }
                Err(e) => self.notice_account_error(&uid, e),
            },
            AuthKind::Oper => self.grant_oper(&uid),
        }
    }

    pub(super) fn grant_rf_tx(&mut self, oper: &UserId, nick: &str, grant: bool) {
        if !self.accounts.is_registered(nick) {
            self.notice_user(
                oper,
                &format!("{nick} is not registered. They must REGISTER first; the grant is stored in the nick file and restored on IDENTIFY."),
            );
            return;
        }
        if let Err(e) = self.accounts.set_rf_tx(nick, grant) {
            self.notice_account_error(oper, e);
            return;
        }
        if let Some(target) = self.find_target(nick) {
            self.refresh_privileges(&target);
            self.notice_user(
                &target,
                if grant {
                    "A control operator granted you RF-TX. After CALLSIGN, your messages in +r channels may be radiated."
                } else {
                    "RF-TX revoked. Your messages stay on IRC."
                },
            );
        }
        let verb = if grant { "granted" } else { "revoked" };
        self.notice_user(
            oper,
            &format!("RF-TX {verb} for {nick} and stored in the nick file."),
        );
        self.audit.event(
            if grant { "rf_tx_grant" } else { "rf_tx_revoke" },
            &[("nick", nick)],
        );
    }

    pub(super) fn notice_account_error(&mut self, uid: &UserId, e: AccountError) {
        let text = match e {
            AccountError::TooShort => format!(
                "Password too short (minimum {} characters).",
                self.config.accounts.min_password_len
            ),
            AccountError::TooLong => "Password too long.".into(),
            AccountError::Hash => "Could not hash the password.".into(),
            AccountError::Io => "Could not write the nick database.".into(),
            AccountError::Taken => "That nick is already registered. IDENTIFY to claim it.".into(),
            AccountError::BadPassword => "Password incorrect.".into(),
            AccountError::NotRegistered => {
                "That nick is not registered. REGISTER <password> first.".into()
            }
            AccountError::CallsignTaken => {
                "That callsign is already registered to another nick.".into()
            }
        };
        self.notice_user(uid, &text);
    }
}
