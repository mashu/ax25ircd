//! AIRC/1 - the on-air application protocol carried in AX.25 UI frames.
//!
//! Design constraints, in order of importance:
//!
//! 1. **It must be legal.** Nothing here obscures meaning: the payload is
//!    UTF-8 text with a small, fully documented binary header. No compression,
//!    no ciphers. See `docs/regulatory.md`.
//! 2. **It must be small.** At 1200 baud, every byte costs ~8.3 ms of shared
//!    channel time. IRC's wire format ("PRIVMSG #channel :text\r\n" plus a
//!    `nick!user@host` prefix) wastes 40-60 bytes per message; AIRC spends 8.
//! 3. **It must survive loss.** UI frames are unacknowledged datagrams, so the
//!    protocol carries its own sequence numbers, ACKs and fragmentation.
//!
//! Header, 8 octets, big endian:
//!
//! ```text
//! 0      1      2      3      4      5      6      7
//! 'A'    '1'    kind   flags  seq_hi seq_lo fidx   ftot
//! ```
//!
//! `seq` is per sender and wraps. `fidx`/`ftot` are 0-based fragment index and
//! total fragment count (`ftot == 1` for the common case). All fragments of a
//! message share a `seq`.

use super::AircError;

pub const MAGIC: [u8; 2] = *b"A1";
pub const HEADER_LEN: usize = 8;
/// Field separator inside a payload (ASCII unit separator).
pub const FS: u8 = 0x1F;

/// Message types. Values are stable wire constants; never renumber.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Station announces itself and (optionally) requests a session.
    Hello = 0x01,
    /// Gateway accepts a station: `[server_name, motd_line]`.
    Welcome = 0x02,
    /// `[channel]`
    Join = 0x03,
    /// `[channel, reason?]`
    Part = 0x04,
    /// `[target, text]` where target is `#channel` or a nick.
    Msg = 0x05,
    /// `[target, text]` - never auto-replied to, mirrors IRC NOTICE.
    Notice = 0x06,
    /// `[channel]` - request the member list.
    Names = 0x07,
    /// `[channel, comma-separated nicks]`
    NamesReply = 0x08,
    /// `[token]`
    Ping = 0x09,
    /// `[token]`
    Pong = 0x0A,
    /// Payload is the two-octet sequence number being acknowledged.
    Ack = 0x0B,
    /// `[code, text]`
    Error = 0x0C,
    /// Station identification / beacon: `[text]`.
    Id = 0x0D,
    /// `[reason?]`
    Quit = 0x0E,
    /// Someone joined or left a channel the station is in:
    /// `[channel, nick, "+"|"-"]`.
    Presence = 0x0F,
    /// A private message that was held while the station was out of range:
    /// `[target, from, text, age_seconds]`.
    Stored = 0x10,
}

impl TryFrom<u8> for Kind {
    type Error = AircError;

    fn try_from(v: u8) -> Result<Self, AircError> {
        use Kind::*;
        Ok(match v {
            0x01 => Hello,
            0x02 => Welcome,
            0x03 => Join,
            0x04 => Part,
            0x05 => Msg,
            0x06 => Notice,
            0x07 => Names,
            0x08 => NamesReply,
            0x09 => Ping,
            0x0A => Pong,
            0x0B => Ack,
            0x0C => Error,
            0x0D => Id,
            0x0E => Quit,
            0x0F => Presence,
            0x10 => Stored,
            other => return Err(AircError::UnknownKind(other)),
        })
    }
}

pub mod flags {
    /// Sender wants an ACK and will retransmit until it gets one.
    pub const ACK_REQ: u8 = 0x01;
    /// This is a retransmission (informational; helps operators debug).
    pub const RETRY: u8 = 0x02;
    /// The text was truncated by a policy limit before transmission.
    pub const TRUNCATED: u8 = 0x04;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AircFrame {
    pub kind: Kind,
    pub flags: u8,
    pub seq: u16,
    pub frag_index: u8,
    pub frag_total: u8,
    pub payload: Vec<u8>,
}

impl AircFrame {
    pub fn new(kind: Kind, seq: u16, payload: Vec<u8>) -> Self {
        Self {
            kind,
            flags: 0,
            seq,
            frag_index: 0,
            frag_total: 1,
            payload,
        }
    }

    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags |= flags;
        self
    }

    pub fn wants_ack(&self) -> bool {
        self.flags & flags::ACK_REQ != 0
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&MAGIC);
        out.push(self.kind as u8);
        out.push(self.flags);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.push(self.frag_index);
        out.push(self.frag_total);
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, AircError> {
        if buf.len() < HEADER_LEN {
            return Err(AircError::Truncated);
        }
        if buf[0..2] != MAGIC {
            return Err(AircError::NotAirc);
        }
        let frag_total = buf[7];
        let frag_index = buf[6];
        if frag_total == 0 || frag_index >= frag_total {
            return Err(AircError::BadFragment);
        }
        Ok(Self {
            kind: Kind::try_from(buf[2])?,
            flags: buf[3],
            seq: u16::from_be_bytes([buf[4], buf[5]]),
            frag_index,
            frag_total,
            payload: buf[HEADER_LEN..].to_vec(),
        })
    }

    /// Split the payload into `\x1F`-separated UTF-8 fields. Invalid UTF-8 is
    /// replaced rather than rejected: a corrupt frame from the air should
    /// degrade, not kill the session.
    pub fn fields(&self) -> Vec<String> {
        self.payload
            .split(|&b| b == FS)
            .map(|f| String::from_utf8_lossy(f).into_owned())
            .collect()
    }

    pub fn field(&self, i: usize) -> Option<String> {
        self.fields().into_iter().nth(i)
    }
}

/// Join fields with the separator. The separator, CR, LF and NUL inside a
/// field are stripped: they are never legal in a nick, channel or message,
/// and CR/LF would be IRC line injection if the field were later rendered
/// for an IP client.
pub fn encode_fields(fields: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            out.push(FS);
        }
        out.extend(
            f.bytes()
                .filter(|&b| b != FS && b != b'\r' && b != b'\n' && b != 0),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let f = AircFrame::new(Kind::Msg, 0x1234, encode_fields(&["#rf", "hello there"]))
            .with_flags(flags::ACK_REQ);
        let bytes = f.encode();
        assert_eq!(bytes.len(), HEADER_LEN + 3 + 1 + 11);
        let back = AircFrame::decode(&bytes).unwrap();
        assert_eq!(back, f);
        assert_eq!(back.fields(), vec!["#rf", "hello there"]);
        assert!(back.wants_ack());
    }

    #[test]
    fn encode_fields_strips_crlf() {
        let bytes = encode_fields(&["bye\r\nNOTICE alice :x"]);
        assert!(!bytes.contains(&b'\r'));
        assert!(!bytes.contains(&b'\n'));
        assert_eq!(AircFrame::new(Kind::Quit, 1, bytes).fields(), vec!["byeNOTICE alice :x"]);
    }

    #[test]
    fn rejects_foreign_traffic() {
        // An APRS position report must not be mistaken for AIRC.
        assert_eq!(
            AircFrame::decode(b"!5930.00N/01803.00E-").unwrap_err(),
            AircError::NotAirc
        );
        assert_eq!(AircFrame::decode(b"A1").unwrap_err(), AircError::Truncated);
    }

    #[test]
    fn rejects_impossible_fragments() {
        let mut bytes = AircFrame::new(Kind::Msg, 1, vec![]).encode();
        bytes[6] = 3; // index 3 of 1
        assert_eq!(AircFrame::decode(&bytes).unwrap_err(), AircError::BadFragment);
    }
}
