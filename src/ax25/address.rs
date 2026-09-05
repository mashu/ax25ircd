//! AX.25 v2.2 address field (7 octets per address).
//!
//! ```text
//! octets 0..5 : callsign, ASCII, space padded, shifted left one bit
//! octet  6    : C/H  R R  SSID(4)  E
//!               bit7 = command/response bit (dest) or has-been-repeated (digi)
//!               bit6..5 = reserved, transmitted as 1
//!               bit4..1 = SSID
//!               bit0 = extension bit, 1 on the last address of the field
//! ```

use crate::callsign::Callsign;

use super::Ax25Error;

pub const ADDRESS_LEN: usize = 7;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub call: Callsign,
    /// Command/response bit for source and destination, "has been repeated"
    /// for digipeater entries.
    pub c_bit: bool,
    /// Extension bit: set on the final address of the address field.
    pub last: bool,
}

impl Address {
    pub fn new(call: Callsign) -> Self {
        Self {
            call,
            c_bit: false,
            last: false,
        }
    }

    pub fn with_c_bit(mut self, v: bool) -> Self {
        self.c_bit = v;
        self
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        let base = self.call.base().as_bytes();
        for i in 0..6 {
            let ch = if i < base.len() { base[i] } else { b' ' };
            out.push(ch << 1);
        }
        let mut ssid = 0b0110_0000 | (self.call.ssid() << 1);
        if self.c_bit {
            ssid |= 0b1000_0000;
        }
        if self.last {
            ssid |= 0b0000_0001;
        }
        out.push(ssid);
    }

    pub fn decode(buf: &[u8]) -> Result<Self, Ax25Error> {
        if buf.len() < ADDRESS_LEN {
            return Err(Ax25Error::Truncated);
        }
        let mut base = String::with_capacity(6);
        for &b in &buf[..6] {
            if b & 0x01 != 0 {
                // Low bit must be clear in a shifted callsign character.
                return Err(Ax25Error::BadAddress);
            }
            let ch = (b >> 1) as char;
            if ch == ' ' {
                continue;
            }
            if !ch.is_ascii_alphanumeric() {
                return Err(Ax25Error::BadAddress);
            }
            base.push(ch);
        }
        let ssid_byte = buf[6];
        let ssid = (ssid_byte >> 1) & 0x0F;
        let call = Callsign::new(&base, ssid).map_err(|_| Ax25Error::BadAddress)?;
        Ok(Address {
            call,
            c_bit: ssid_byte & 0b1000_0000 != 0,
            last: ssid_byte & 0x01 != 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let a = Address {
            call: "SM0ABC-7".parse().unwrap(),
            c_bit: true,
            last: true,
        };
        let mut buf = Vec::new();
        a.encode(&mut buf);
        assert_eq!(buf.len(), 7);
        assert_eq!(Address::decode(&buf).unwrap(), a);
    }

    #[test]
    fn short_call_is_space_padded() {
        let a = Address::new("N0X".parse().unwrap());
        let mut buf = Vec::new();
        a.encode(&mut buf);
        assert_eq!(
            &buf[..6],
            &[
                b'N' << 1,
                b'0' << 1,
                b'X' << 1,
                b' ' << 1,
                b' ' << 1,
                b' ' << 1
            ]
        );
        assert_eq!(Address::decode(&buf).unwrap().call.base(), "N0X");
    }
}
