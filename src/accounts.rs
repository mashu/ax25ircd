//! Registered nicknames. Passwords are stored as Argon2id hashes, never in
//! reversible form. "Encrypted on the server" in the amateur-radio sense:
//! the file is useless without the password, and we cannot recover one.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};

use crate::irc::message::lower;

/// Argon2id at the OWASP baseline: 19 MiB, two passes, one lane.
///
/// The old 4 MiB setting was well under that, and memory is the parameter
/// that actually costs an offline attacker anything. Hashing happens on a
/// blocking thread pool (see `run_argon2`), never on the event loop, so the
/// cost is paid by the one connection doing REGISTER or IDENTIFY.
///
/// Raising this is backward compatible: a PHC hash string carries the
/// parameters it was made with, and verification uses those, so existing
/// entries in the nick file keep working and are re-hashed at the new cost
/// whenever the password is next set.
fn hasher() -> Argon2<'static> {
    let params = Params::new(19 * 1024, 2, 1, None).expect("static Argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NickAccount {
    pub nick: String,
    pub password_hash: String,
    pub created_unix: u64,
    /// Operator-granted right to have this nick's messages put on the air.
    #[serde(default)]
    pub rf_tx: bool,
    /// Last CALLSIGN this nick claimed. Restored on IDENTIFY; it is still a
    /// claim, not proof of licence.
    #[serde(default)]
    pub callsign: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct Store {
    nicks: HashMap<String, NickAccount>,
}

pub struct Accounts {
    path: PathBuf,
    store: Store,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AccountError {
    TooShort,
    TooLong,
    Hash,
    Io,
    Taken,
    BadPassword,
    NotRegistered,
}

impl Accounts {
    pub fn empty(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            store: Store::default(),
        }
    }

    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::empty(path.to_path_buf()));
        }
        let text = std::fs::read_to_string(path)?;
        let store: Store = serde_json::from_str(&text)?;
        Ok(Self {
            path: path.to_path_buf(),
            store,
        })
    }

    pub fn is_registered(&self, nick: &str) -> bool {
        self.store.nicks.contains_key(&lower(nick))
    }

    pub fn get(&self, nick: &str) -> Option<&NickAccount> {
        self.store.nicks.get(&lower(nick))
    }

    /// Insert a nick whose password was already hashed off the event loop.
    pub fn insert_hashed(&mut self, nick: &str, password_hash: String) -> Result<(), AccountError> {
        let key = lower(nick);
        if self.store.nicks.contains_key(&key) {
            return Err(AccountError::Taken);
        }
        let created_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.store.nicks.insert(
            key,
            NickAccount {
                nick: nick.to_string(),
                password_hash,
                created_unix,
                rf_tx: false,
                callsign: None,
            },
        );
        self.save()
    }

    pub fn set_password_hash(&mut self, nick: &str, password_hash: String) -> Result<(), AccountError> {
        let Some(acc) = self.store.nicks.get_mut(&lower(nick)) else {
            return Err(AccountError::NotRegistered);
        };
        acc.password_hash = password_hash;
        self.save()
    }

    pub fn drop_nick(&mut self, nick: &str) -> Result<(), AccountError> {
        if self.store.nicks.remove(&lower(nick)).is_none() {
            return Err(AccountError::NotRegistered);
        }
        self.save()
    }

    pub fn set_rf_tx(&mut self, nick: &str, rf_tx: bool) -> Result<(), AccountError> {
        let Some(acc) = self.store.nicks.get_mut(&lower(nick)) else {
            return Err(AccountError::NotRegistered);
        };
        acc.rf_tx = rf_tx;
        self.save()
    }

    pub fn set_callsign(&mut self, nick: &str, callsign: &str) -> Result<(), AccountError> {
        let Some(acc) = self.store.nicks.get_mut(&lower(nick)) else {
            return Err(AccountError::NotRegistered);
        };
        acc.callsign = Some(callsign.to_string());
        self.save()
    }

    pub fn grants_rf_tx(&self, nick: &str) -> bool {
        self.store
            .nicks
            .get(&lower(nick))
            .map(|a| a.rf_tx)
            .unwrap_or(false)
    }

    pub fn hash_for(&self, nick: &str) -> Option<String> {
        self.store
            .nicks
            .get(&lower(nick))
            .map(|a| a.password_hash.clone())
    }

    fn save(&self) -> Result<(), AccountError> {
        let text = serde_json::to_string_pretty(&self.store).map_err(|_| AccountError::Io)?;
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|_| AccountError::Io)?;
            }
        }
        std::fs::write(&self.path, text).map_err(|_| AccountError::Io)
    }
}

pub(crate) fn hash_password(password: &str) -> Result<String, AccountError> {
    let salt = SaltString::generate(&mut OsRng);
    hasher()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| AccountError::Hash)
}

pub(crate) fn verify_password(password: &str, hash: &str) -> Result<(), AccountError> {
    let parsed = PasswordHash::new(hash).map_err(|_| AccountError::Hash)?;
    hasher()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| AccountError::BadPassword)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("ax25ircd-nicks-{n}.json"))
    }

    /// Exercise the same path the server uses: hash off the event loop,
    /// then hand the finished hash to the store.
    fn add(a: &mut Accounts, nick: &str, password: &str) -> Result<(), AccountError> {
        let hash = hash_password(password)?;
        a.insert_hashed(nick, hash)
    }

    #[test]
    fn register_verify_drop() {
        let path = tmp();
        let mut a = Accounts::empty(&path);
        add(&mut a, "Alice", "secret12").unwrap();
        assert!(a.is_registered("alice"));
        let hash = a.hash_for("ALICE").expect("case-insensitive lookup");
        assert_eq!(verify_password("secret12", &hash), Ok(()));
        assert_eq!(
            verify_password("wrongwrong", &hash),
            Err(AccountError::BadPassword)
        );
        assert_eq!(add(&mut a, "alice", "secret12"), Err(AccountError::Taken));
        a.drop_nick("alice").unwrap();
        assert!(!a.is_registered("alice"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn persists_across_load() {
        let path = tmp();
        let mut a = Accounts::empty(&path);
        add(&mut a, "bob", "hunter2x").unwrap();
        a.set_rf_tx("bob", true).unwrap();
        a.set_callsign("bob", "SM0XYZ").unwrap();
        let b = Accounts::load(&path).unwrap();
        let hash = b.hash_for("bob").unwrap();
        assert_eq!(verify_password("hunter2x", &hash), Ok(()));
        assert!(b.grants_rf_tx("bob"));
        assert_eq!(b.get("bob").and_then(|a| a.callsign.as_deref()), Some("SM0XYZ"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_rehash_of_an_old_entry_still_verifies() {
        // Argon2 parameters live in the PHC string, so raising them must not
        // lock out anybody who registered under the old cost.
        let weak = {
            let params = Params::new(4096, 2, 1, None).unwrap();
            let salt = SaltString::generate(&mut OsRng);
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password(b"legacypass", &salt)
                .unwrap()
                .to_string()
        };
        assert_eq!(verify_password("legacypass", &weak), Ok(()));
        assert_eq!(
            verify_password("wrongpass", &weak),
            Err(AccountError::BadPassword)
        );
    }
}
