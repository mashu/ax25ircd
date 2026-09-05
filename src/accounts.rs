//! Registered nicknames. Passwords are stored as Argon2id hashes, never in
//! reversible form. "Encrypted on the server" in the amateur-radio sense:
//! the file is useless without the password, and we cannot recover one.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
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
    /// Hosts refused at connect. Survives restart with the nick file.
    #[serde(default)]
    ip_bans: Vec<String>,
}

pub struct Accounts {
    path: PathBuf,
    store: Store,
    persist_lock: Arc<Mutex<()>>,
    persist_gen: Arc<AtomicU64>,
    async_persist: AtomicBool,
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
    CallsignTaken,
}

impl Accounts {
    pub fn empty(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            store: Store::default(),
            persist_lock: Arc::new(Mutex::new(())),
            persist_gen: Arc::new(AtomicU64::new(0)),
            async_persist: AtomicBool::new(false),
        }
    }

    /// Write the nick file from a background thread so fsync does not stall
    /// the server actor. In-memory updates still happen first; tests leave
    /// this off so they can read the file immediately.
    pub fn enable_async_persist(&self) {
        self.async_persist.store(true, Ordering::Release);
    }

    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::empty(path.to_path_buf()));
        }
        let text = std::fs::read_to_string(path).map_err(|e| {
            anyhow::anyhow!(
                "nick accounts file {} exists but cannot be read ({e}); \
                 refusing to start with an empty store that would overwrite it",
                path.display()
            )
        })?;
        let store: Store = serde_json::from_str(&text).map_err(|e| {
            anyhow::anyhow!(
                "nick accounts file {} is unreadable JSON ({e}); \
                 refusing to start with an empty store that would overwrite it",
                path.display()
            )
        })?;
        Ok(Self {
            path: path.to_path_buf(),
            store,
            persist_lock: Arc::new(Mutex::new(())),
            persist_gen: Arc::new(AtomicU64::new(0)),
            async_persist: AtomicBool::new(false),
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

    pub fn set_password_hash(
        &mut self,
        nick: &str,
        password_hash: String,
    ) -> Result<(), AccountError> {
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
        let key = lower(nick);
        if !self.store.nicks.contains_key(&key) {
            return Err(AccountError::NotRegistered);
        }
        if let Some(owner) = self.owner_of_callsign(callsign) {
            if lower(&owner) != key {
                return Err(AccountError::CallsignTaken);
            }
        }
        let Some(acc) = self.store.nicks.get_mut(&key) else {
            return Err(AccountError::NotRegistered);
        };
        acc.callsign = Some(callsign.to_string());
        self.save()
    }

    /// Which registered nick owns this callsign, if any.
    pub fn owner_of_callsign(&self, callsign: &str) -> Option<String> {
        let want = lower(callsign);
        self.store.nicks.values().find_map(|a| {
            a.callsign
                .as_ref()
                .filter(|c| lower(c) == want)
                .map(|_| a.nick.clone())
        })
    }

    pub fn clear_callsign(&mut self, callsign: &str) -> Result<String, AccountError> {
        let want = lower(callsign);
        let key = self.store.nicks.iter().find_map(|(k, a)| {
            a.callsign
                .as_ref()
                .filter(|c| lower(c) == want)
                .map(|_| k.clone())
        });
        let Some(key) = key else {
            return Err(AccountError::NotRegistered);
        };
        let nick = self.store.nicks[&key].nick.clone();
        if let Some(acc) = self.store.nicks.get_mut(&key) {
            acc.callsign = None;
        }
        self.save()?;
        Ok(nick)
    }

    pub fn list(&self) -> Vec<&NickAccount> {
        let mut v: Vec<_> = self.store.nicks.values().collect();
        v.sort_by(|a, b| lower(&a.nick).cmp(&lower(&b.nick)));
        v
    }

    pub fn ban_ip(&mut self, host: &str) -> Result<bool, AccountError> {
        let key = host_ban_key(host);
        if key.is_empty() {
            return Ok(false);
        }
        if self.store.ip_bans.iter().any(|h| host_ban_key(h) == key) {
            return Ok(false);
        }
        self.store.ip_bans.push(key);
        self.save()?;
        Ok(true)
    }

    pub fn unban_ip(&mut self, host: &str) -> Result<bool, AccountError> {
        let key = host_ban_key(host);
        let before = self.store.ip_bans.len();
        self.store.ip_bans.retain(|h| host_ban_key(h) != key);
        if self.store.ip_bans.len() == before {
            return Ok(false);
        }
        self.save()?;
        Ok(true)
    }

    pub fn is_ip_banned(&self, host: &str) -> bool {
        let key = host_ban_key(host);
        self.store.ip_bans.iter().any(|h| host_ban_key(h) == key)
    }

    pub fn ip_bans(&self) -> &[String] {
        &self.store.ip_bans
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

    /// Write the nick database, atomically.
    ///
    /// `fs::write` truncates first, so a crash, a full disk or a power cut in
    /// the middle leaves a half-written file — and since the whole database is
    /// one JSON document, a half-written file is a *lost* database, not a
    /// damaged one: every registration and every RF-TX grant is gone. Writing
    /// a sibling temp file and renaming makes the replacement atomic, so the
    /// worst case is losing the last change rather than all of them.
    fn save(&self) -> Result<(), AccountError> {
        let text = serde_json::to_string_pretty(&self.store).map_err(|_| AccountError::Io)?;
        let path = self.path.clone();
        if self.async_persist.load(Ordering::Acquire) {
            let gen = self.persist_gen.fetch_add(1, Ordering::AcqRel) + 1;
            let persist_gen = self.persist_gen.clone();
            let persist_lock = self.persist_lock.clone();
            std::thread::spawn(move || {
                let _g = persist_lock.lock().unwrap_or_else(|e| e.into_inner());
                if persist_gen.load(Ordering::Acquire) != gen {
                    return;
                }
                if let Err(e) = write_atomic(&path, &text) {
                    tracing::error!(path = %path.display(), "nick database write failed: {e:?}");
                }
            });
            return Ok(());
        }
        let _g = self.persist_lock.lock().unwrap_or_else(|e| e.into_inner());
        write_atomic(&path, &text)
    }
}

/// True if `s` is an Argon2 PHC string, not a plaintext OPER password.
pub fn is_phc_hash(s: &str) -> bool {
    PasswordHash::new(s).is_ok()
}

fn write_atomic(path: &Path, text: &str) -> Result<(), AccountError> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => {
            std::fs::create_dir_all(p).map_err(|_| AccountError::Io)?;
            p.to_path_buf()
        }
        _ => PathBuf::from("."),
    };
    let temp = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "nicks.json".into())
    ));
    {
        use std::io::Write as _;
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temp)
                .map_err(|_| AccountError::Io)?;
            let mut perms = f.metadata().map_err(|_| AccountError::Io)?.permissions();
            perms.set_mode(0o600);
            f.set_permissions(perms).map_err(|_| AccountError::Io)?;
            f
        };
        #[cfg(not(unix))]
        let mut f = std::fs::File::create(&temp).map_err(|_| AccountError::Io)?;
        f.write_all(text.as_bytes()).map_err(|_| AccountError::Io)?;
        f.sync_all().map_err(|_| AccountError::Io)?;
    }
    std::fs::rename(&temp, path).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        let _ = e;
        AccountError::Io
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)
            .map_err(|_| AccountError::Io)?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(|_| AccountError::Io)?;
    }
    Ok(())
}

/// Compare IRC host strings the way KLINE stores them: lowercase, no IPv6
/// brackets, IPv4-mapped IPv6 folded to IPv4 so `10.0.0.1` matches
/// `[::ffff:10.0.0.1]`.
pub fn host_ban_key(host: &str) -> String {
    let trimmed = host.trim().trim_matches(|c| c == '[' || c == ']');
    let lowered = lower(trimmed);
    if let Ok(ip) = lowered.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => v4.to_string(),
            std::net::IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(|v4| v4.to_string())
                .unwrap_or_else(|| v6.to_string()),
        };
    }
    lowered
}

pub fn hash_password(password: &str) -> Result<String, AccountError> {
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
        assert_eq!(
            b.get("bob").and_then(|a| a.callsign.as_deref()),
            Some("SM0XYZ")
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn saving_replaces_the_file_atomically_and_leaves_no_litter() {
        let path = tmp();
        let mut a = Accounts::empty(&path);
        add(&mut a, "alice", "password1").unwrap();
        add(&mut a, "bob", "password2").unwrap();
        a.set_rf_tx("bob", true).unwrap();

        // The database reloads, and the temp file is not left behind.
        let b = Accounts::load(&path).unwrap();
        assert!(b.is_registered("alice") && b.grants_rf_tx("bob"));
        let temp = path.parent().unwrap().join(format!(
            ".{}.tmp",
            path.file_name().unwrap().to_string_lossy()
        ));
        assert!(!temp.exists(), "a temp file was left behind: {temp:?}");
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
        assert!(is_phc_hash(&weak));
        assert!(!is_phc_hash("operpass1"));
    }

    #[test]
    fn a_corrupt_nick_file_is_not_silently_replaced() {
        let path = tmp();
        std::fs::write(&path, "{").unwrap();
        let err = match Accounts::load(&path) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("corrupt nick file loaded as an empty store"),
        };
        assert!(err.contains("overwrite") || err.contains("JSON"), "{err}");
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn nick_file_is_mode_600() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp();
        let mut a = Accounts::empty(&path);
        add(&mut a, "alice", "password1").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "nick database was {mode:o}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_callsign_belongs_to_one_nick() {
        let path = tmp();
        let mut a = Accounts::empty(&path);
        add(&mut a, "alice", "password1").unwrap();
        add(&mut a, "bob", "password2").unwrap();
        a.set_callsign("alice", "SM0XYZ").unwrap();
        assert_eq!(a.owner_of_callsign("sm0xyz").as_deref(), Some("alice"));
        assert_eq!(
            a.set_callsign("bob", "SM0XYZ"),
            Err(AccountError::CallsignTaken)
        );
        a.set_callsign("alice", "SM0XYZ").unwrap();
        let owner = a.clear_callsign("SM0XYZ").unwrap();
        assert_eq!(owner, "alice");
        a.set_callsign("bob", "SM0XYZ").unwrap();
        assert_eq!(a.owner_of_callsign("SM0XYZ").as_deref(), Some("bob"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ip_bans_persist() {
        let path = tmp();
        let mut a = Accounts::empty(&path);
        assert!(a.ban_ip("203.0.113.9").unwrap());
        assert!(!a.ban_ip("203.0.113.9").unwrap());
        assert!(a.is_ip_banned("[203.0.113.9]"));
        let b = Accounts::load(&path).unwrap();
        assert!(b.is_ip_banned("203.0.113.9"));
        assert_eq!(b.ip_bans(), &["203.0.113.9".to_string()]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ipv4_mapped_bans_match_plain_v4() {
        assert_eq!(host_ban_key("[::ffff:10.0.0.1]"), "10.0.0.1");
        assert_eq!(host_ban_key("::ffff:10.0.0.1"), "10.0.0.1");
        assert_eq!(host_ban_key("10.0.0.1"), "10.0.0.1");
        let path = tmp();
        let mut a = Accounts::empty(&path);
        assert!(a.ban_ip("[::ffff:203.0.113.9]").unwrap());
        assert!(a.is_ip_banned("203.0.113.9"));
        assert!(a.unban_ip("203.0.113.9").unwrap());
        assert!(!a.is_ip_banned("[::ffff:203.0.113.9]"));
        let _ = std::fs::remove_file(path);
    }
}
