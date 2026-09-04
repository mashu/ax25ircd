//! Amateur radio callsign + SSID, the identity used on the RF side.
//!
//! On the air, identity is not a secret: an AX.25 frame carries the source
//! callsign in clear text and anyone can transmit anything. We therefore treat
//! a callsign as a *claim*, not as an authenticated identity. See
//! `docs/design.md`, "Trust model".

use std::fmt;
use std::str::FromStr;

/// A callsign with an SSID (0-15), e.g. `SM0ABC-7`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Callsign {
    base: String,
    ssid: u8,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CallsignError {
    #[error("callsign is empty")]
    Empty,
    #[error("callsign base must be 1-6 characters, got {0}")]
    BaseLength(usize),
    #[error("callsign contains an invalid character: {0:?}")]
    BadChar(char),
    #[error("SSID must be 0-15")]
    BadSsid,
    #[error("callsign has no digit or is otherwise implausible: {0}")]
    Implausible(String),
}

impl Callsign {
    pub fn new(base: &str, ssid: u8) -> Result<Self, CallsignError> {
        let base = base.trim().to_ascii_uppercase();
        if base.is_empty() {
            return Err(CallsignError::Empty);
        }
        if base.len() > 6 {
            return Err(CallsignError::BaseLength(base.len()));
        }
        if let Some(c) = base.chars().find(|c| !c.is_ascii_alphanumeric()) {
            return Err(CallsignError::BadChar(c));
        }
        if ssid > 15 {
            return Err(CallsignError::BadSsid);
        }
        Ok(Self { base, ssid })
    }

    /// A stricter check used before we let a station speak on a bridged
    /// channel: a real callsign has at least one digit and at least one letter.
    /// Service addresses such as `ID`, `BEACON` or `AIRC` deliberately fail it.
    pub fn looks_like_amateur_call(&self) -> bool {
        self.base.len() >= 3
            && self.base.chars().any(|c| c.is_ascii_digit())
            && self.base.chars().any(|c| c.is_ascii_alphabetic())
    }

    pub fn require_amateur(&self) -> Result<(), CallsignError> {
        if self.looks_like_amateur_call() {
            Ok(())
        } else {
            Err(CallsignError::Implausible(self.to_string()))
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn ssid(&self) -> u8 {
        self.ssid
    }

    /// Same operator, any SSID.
    pub fn same_station(&self, other: &Callsign) -> bool {
        self.base == other.base
    }

    /// Nickname used on the IRC side. IRC nicks may not contain `-`, so the
    /// SSID is rendered with a `|`: `SM0ABC-7` -> `SM0ABC|7`.
    pub fn to_nick(&self) -> String {
        if self.ssid == 0 {
            self.base.clone()
        } else {
            format!("{}|{}", self.base, self.ssid)
        }
    }

    /// Inverse of [`Callsign::to_nick`].
    pub fn from_nick(nick: &str) -> Result<Self, CallsignError> {
        match nick.split_once('|') {
            Some((b, s)) => Callsign::new(b, s.parse().map_err(|_| CallsignError::BadSsid)?),
            None => Callsign::new(nick, 0),
        }
    }
}

impl FromStr for Callsign {
    type Err = CallsignError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('-') {
            Some((b, ssid)) => {
                let ssid: u8 = ssid.parse().map_err(|_| CallsignError::BadSsid)?;
                Callsign::new(b, ssid)
            }
            None => Callsign::new(s, 0),
        }
    }
}

impl fmt::Display for Callsign {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.ssid == 0 {
            write!(f, "{}", self.base)
        } else {
            write!(f, "{}-{}", self.base, self.ssid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_with_and_without_ssid() {
        assert_eq!(
            "sm0abc".parse::<Callsign>().unwrap(),
            Callsign::new("SM0ABC", 0).unwrap()
        );
        let c: Callsign = "SM0ABC-7".parse().unwrap();
        assert_eq!(c.ssid(), 7);
        assert_eq!(c.to_string(), "SM0ABC-7");
    }

    #[test]
    fn rejects_bad_input() {
        assert!("".parse::<Callsign>().is_err());
        assert!("TOOLONGCALL".parse::<Callsign>().is_err());
        assert!("SM0ABC-16".parse::<Callsign>().is_err());
        assert!("SM0:ABC".parse::<Callsign>().is_err());
    }

    #[test]
    fn nick_roundtrip() {
        let c: Callsign = "SM0ABC-7".parse().unwrap();
        assert_eq!(c.to_nick(), "SM0ABC|7");
        assert_eq!(Callsign::from_nick("SM0ABC|7").unwrap(), c);
    }

    #[test]
    fn plausibility() {
        assert!("SM0ABC".parse::<Callsign>().unwrap().looks_like_amateur_call());
        assert!(!"ID".parse::<Callsign>().unwrap().looks_like_amateur_call());
        assert!(!"AIRC".parse::<Callsign>().unwrap().looks_like_amateur_call());
    }
}
