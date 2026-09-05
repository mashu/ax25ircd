//! AX.25 frame encoding/decoding.
//!
//! We only need unnumbered information (UI) frames: the gateway runs its own
//! sequencing and retransmission in the AIRC layer (see `src/airc`), which
//! keeps us independent of whatever connected-mode implementation the far end
//! happens to have and lets a single transmission be received by many
//! stations. Non-UI frames are decoded far enough to be logged and dropped.

use crate::callsign::Callsign;

use super::address::{Address, ADDRESS_LEN};
use super::Ax25Error;

/// Control field for an unnumbered information frame, P/F clear.
pub const CONTROL_UI: u8 = 0x03;
/// Protocol identifier: "no layer 3 protocol".
pub const PID_NO_L3: u8 = 0xF0;
/// Maximum number of digipeaters an AX.25 address field may carry.
pub const MAX_DIGIPEATERS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ax25Frame {
    pub destination: Address,
    pub source: Address,
    pub digipeaters: Vec<Address>,
    pub control: u8,
    pub pid: Option<u8>,
    pub info: Vec<u8>,
}

impl Ax25Frame {
    /// Build a UI frame with the usual `PID 0xF0`.
    pub fn ui(
        source: Callsign,
        destination: Callsign,
        path: &[Callsign],
        info: Vec<u8>,
    ) -> Result<Self, Ax25Error> {
        if path.len() > MAX_DIGIPEATERS {
            return Err(Ax25Error::TooManyDigipeaters);
        }
        Ok(Self {
            // Command frame: destination C bit set, source C bit clear.
            destination: Address::new(destination).with_c_bit(true),
            source: Address::new(source),
            digipeaters: path.iter().cloned().map(Address::new).collect(),
            control: CONTROL_UI,
            pid: Some(PID_NO_L3),
            info,
        })
    }

    pub fn is_ui(&self) -> bool {
        // UI is 0b000P0011; mask out the P/F bit.
        self.control & 0xEF == CONTROL_UI
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(ADDRESS_LEN * (2 + self.digipeaters.len()) + 2 + self.info.len());
        let mut dest = self.destination.clone();
        dest.last = false;
        dest.encode(&mut out);

        let mut src = self.source.clone();
        src.last = self.digipeaters.is_empty();
        src.encode(&mut out);

        for (i, digi) in self.digipeaters.iter().enumerate() {
            let mut d = digi.clone();
            d.last = i + 1 == self.digipeaters.len();
            d.encode(&mut out);
        }

        out.push(self.control);
        if let Some(pid) = self.pid {
            out.push(pid);
        }
        out.extend_from_slice(&self.info);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, Ax25Error> {
        let destination = Address::decode(buf)?;
        if destination.last {
            return Err(Ax25Error::BadAddress);
        }
        let source = Address::decode(&buf[ADDRESS_LEN..])?;
        let mut offset = ADDRESS_LEN * 2;
        let mut digipeaters: Vec<Address> = Vec::new();
        let mut last = source.last;
        while !last {
            if digipeaters.len() >= MAX_DIGIPEATERS {
                return Err(Ax25Error::TooManyDigipeaters);
            }
            let digi = Address::decode(buf.get(offset..).ok_or(Ax25Error::Truncated)?)?;
            last = digi.last;
            digipeaters.push(digi);
            offset += ADDRESS_LEN;
        }

        let control = *buf.get(offset).ok_or(Ax25Error::Truncated)?;
        offset += 1;

        // Only I and UI frames carry a PID octet.
        let is_ui = control & 0xEF == CONTROL_UI;
        let is_i = control & 0x01 == 0;
        let (pid, info) = if is_ui || is_i {
            let pid = *buf.get(offset).ok_or(Ax25Error::Truncated)?;
            offset += 1;
            (Some(pid), buf[offset..].to_vec())
        } else {
            (None, Vec::new())
        };

        // The extension bit is a framing artefact: its value is implied by
        // position, and re-encoding recomputes it. Normalising here makes
        // decode(encode(f)) == f.
        let mut destination = destination;
        let mut source = source;
        destination.last = false;
        source.last = false;
        for d in &mut digipeaters {
            d.last = false;
        }

        Ok(Self {
            destination,
            source,
            digipeaters,
            control,
            pid,
            info,
        })
    }

    /// `SRC>DEST,DIGI1*,DIGI2:payload`, the format used in logs and in the
    /// control-operator monitor. Matches what `direwolf`/`axlisten` print, so
    /// operators can correlate our log with a TNC monitor.
    pub fn to_monitor_line(&self) -> String {
        let mut s = format!("{}>{}", self.source.call, self.destination.call);
        for d in &self.digipeaters {
            s.push(',');
            s.push_str(&d.call.to_string());
            if d.c_bit {
                s.push('*');
            }
        }
        s.push(':');
        for &b in &self.info {
            if (0x20..0x7f).contains(&b) {
                s.push(b as char);
            } else {
                s.push('.');
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_roundtrip_with_path() {
        let f = Ax25Frame::ui(
            "SM0ABC-7".parse().unwrap(),
            "AIRC".parse().unwrap(),
            &["SK0MT-1".parse().unwrap(), "SK0AA-2".parse().unwrap()],
            b"hello".to_vec(),
        )
        .unwrap();
        let bytes = f.encode();
        let back = Ax25Frame::decode(&bytes).unwrap();
        assert_eq!(back, f);
        assert!(back.is_ui());
        assert_eq!(back.digipeaters.len(), 2);
        assert_eq!(back.info, b"hello");
    }

    #[test]
    fn monitor_line() {
        let mut f = Ax25Frame::ui(
            "SM0ABC".parse().unwrap(),
            "AIRC".parse().unwrap(),
            &["SK0MT-1".parse().unwrap()],
            b"hi".to_vec(),
        )
        .unwrap();
        f.digipeaters[0].c_bit = true;
        assert_eq!(f.to_monitor_line(), "SM0ABC>AIRC,SK0MT-1*:hi");
    }

    #[test]
    fn truncated_is_an_error() {
        assert!(Ax25Frame::decode(&[0u8; 5]).is_err());
    }
}
