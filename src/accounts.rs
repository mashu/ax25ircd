//! Registered nicknames. Passwords are stored as Argon2id hashes, never in
//! reversible form. "Encrypted on the server" in the amateur-radio sense:
//! the file is useless without the password, and we cannot recover one.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};

use crate::irc::message::lower;

/// Modest Argon2id parameters: strong enough to store IRC nick passwords,
/// cheap enough that REGISTER/IDENTIFY does not stall the event loop.
fn hasher() -> Argon2<'static> {
    let params = Params::new(4096, 2, 1, None).expect("static Argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NickAccount {
    pub nick: String,
    pub password_hash: String,
    pub created_unix: u64,
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

    pub fn register(&mut self, nick: &str, password: &str, min_len: usize) -> Result<(), AccountError> {
        if password.len() < min_len {
            return Err(AccountError::TooShort);
        }
        if password.len() > 128 {
            return Err(AccountError::TooLong);
        }
        let key = lower(nick);
        if self.store.nicks.contains_key(&key) {
            return Err(AccountError::Taken);
        }
        let hash = hash_password(password)?;
        let created_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.store.nicks.insert(
            key,
            NickAccount {
                nick: nick.to_string(),
                password_hash: hash,
                created_unix,
            },
        );
        self.save()
    }

    pub fn verify(&self, nick: &str, password: &str) -> Result<(), AccountError> {
        let Some(acc) = self.store.nicks.get(&lower(nick)) else {
            return Err(AccountError::NotRegistered);
        };
        verify_password(password, &acc.password_hash)
    }

    /// Change the password of an already-registered nick (caller has verified).
    pub fn set_password(&mut self, nick: &str, password: &str, min_len: usize) -> Result<(), AccountError> {
        if password.len() < min_len {
            return Err(AccountError::TooShort);
        }
        if password.len() > 128 {
            return Err(AccountError::TooLong);
        }
        let key = lower(nick);
        let Some(acc) = self.store.nicks.get_mut(&key) else {
            return Err(AccountError::NotRegistered);
        };
        acc.password_hash = hash_password(password)?;
        self.save()
    }

    pub fn drop_nick(&mut self, nick: &str) -> Result<(), AccountError> {
        if self.store.nicks.remove(&lower(nick)).is_none() {
            return Err(AccountError::NotRegistered);
        }
        self.save()
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

fn hash_password(password: &str) -> Result<String, AccountError> {
    let salt = SaltString::generate(&mut OsRng);
    hasher()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| AccountError::Hash)
}

fn verify_password(password: &str, hash: &str) -> Result<(), AccountError> {
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

    #[test]
    fn register_verify_drop() {
        let path = tmp();
        let mut a = Accounts::empty(&path);
        assert!(a.register("Alice", "secret12", 8).is_ok());
        assert!(a.is_registered("alice"));
        assert_eq!(a.verify("ALICE", "secret12"), Ok(()));
        assert_eq!(a.verify("alice", "wrongwrong"), Err(AccountError::BadPassword));
        assert_eq!(a.register("alice", "secret12", 8), Err(AccountError::Taken));
        a.drop_nick("alice").unwrap();
        assert!(!a.is_registered("alice"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn persists_across_load() {
        let path = tmp();
        let mut a = Accounts::empty(&path);
        a.register("bob", "hunter2x", 8).unwrap();
        let b = Accounts::load(&path).unwrap();
        assert_eq!(b.verify("bob", "hunter2x"), Ok(()));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_short_passwords() {
        let mut a = Accounts::empty(tmp());
        assert_eq!(a.register("x", "short", 8), Err(AccountError::TooShort));
    }
}
