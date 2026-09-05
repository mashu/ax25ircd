//! KISS framing (the de-facto TNC protocol used by Direwolf, TNC-Pi, Mobilinkd
//! and friends).
//!
//! A KISS frame is `FEND <port|command> <payload> FEND` with byte stuffing.

pub const FEND: u8 = 0xC0;
pub const FESC: u8 = 0xDB;
pub const TFEND: u8 = 0xDC;
pub const TFESC: u8 = 0xDD;

/// KISS command nibble.
pub const CMD_DATA: u8 = 0x00;
pub const CMD_TXDELAY: u8 = 0x01;
pub const CMD_PERSISTENCE: u8 = 0x02;
pub const CMD_SLOTTIME: u8 = 0x03;
pub const CMD_TXTAIL: u8 = 0x04;
pub const CMD_FULLDUPLEX: u8 = 0x05;

/// Wrap a payload in a KISS frame for the given TNC port (0-15).
pub fn encode(port: u8, command: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.push(FEND);
    out.push(((port & 0x0F) << 4) | (command & 0x0F));
    for &b in payload {
        match b {
            FEND => out.extend_from_slice(&[FESC, TFEND]),
            FESC => out.extend_from_slice(&[FESC, TFESC]),
            other => out.push(other),
        }
    }
    out.push(FEND);
    out
}

/// One decoded KISS frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KissFrame {
    pub port: u8,
    pub command: u8,
    pub payload: Vec<u8>,
}

/// Incremental decoder: feed it whatever bytes arrive from the socket or
/// serial port, get back complete frames.
#[derive(Default)]
pub struct KissDecoder {
    buf: Vec<u8>,
    in_frame: bool,
    escaped: bool,
    max_frame: usize,
}

impl KissDecoder {
    pub fn new(max_frame: usize) -> Self {
        Self {
            buf: Vec::with_capacity(max_frame.min(1024)),
            in_frame: false,
            escaped: false,
            max_frame,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Vec<KissFrame> {
        let mut frames = Vec::new();
        for &b in bytes {
            match b {
                FEND => {
                    if self.in_frame && !self.buf.is_empty() {
                        if let Some(f) = self.take_frame() {
                            frames.push(f);
                        }
                    }
                    self.buf.clear();
                    self.escaped = false;
                    self.in_frame = true;
                }
                _ if !self.in_frame => {}
                FESC => self.escaped = true,
                other => {
                    let byte = if self.escaped {
                        self.escaped = false;
                        match other {
                            TFEND => FEND,
                            TFESC => FESC,
                            // Invalid escape: drop the frame, resync on FEND.
                            _ => {
                                self.in_frame = false;
                                self.buf.clear();
                                continue;
                            }
                        }
                    } else {
                        other
                    };
                    if self.buf.len() >= self.max_frame {
                        self.in_frame = false;
                        self.buf.clear();
                        continue;
                    }
                    self.buf.push(byte);
                }
            }
        }
        frames
    }

    fn take_frame(&mut self) -> Option<KissFrame> {
        let (first, rest) = self.buf.split_first()?;
        Some(KissFrame {
            port: first >> 4,
            command: first & 0x0F,
            payload: rest.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_stuffing() {
        let payload = vec![0x01, FEND, 0x02, FESC, 0x03];
        let wire = encode(2, CMD_DATA, &payload);
        let mut dec = KissDecoder::new(1024);
        let frames = dec.push(&wire);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].port, 2);
        assert_eq!(frames[0].command, CMD_DATA);
        assert_eq!(frames[0].payload, payload);
    }

    #[test]
    fn handles_split_reads_and_leading_garbage() {
        let wire = encode(0, CMD_DATA, b"hello world");
        let mut dec = KissDecoder::new(1024);
        assert!(dec.push(b"\x11\x22").is_empty());
        assert!(dec.push(&wire[..5]).is_empty());
        let frames = dec.push(&wire[5..]);
        assert_eq!(frames[0].payload, b"hello world");
    }

    #[test]
    fn oversized_frames_are_dropped() {
        let wire = encode(0, CMD_DATA, &[0x41; 100]);
        let mut dec = KissDecoder::new(16);
        assert!(dec.push(&wire).is_empty());
        // Decoder resynchronises on the next good frame.
        let good = encode(0, CMD_DATA, b"ok");
        assert_eq!(dec.push(&good)[0].payload, b"ok");
    }
}
