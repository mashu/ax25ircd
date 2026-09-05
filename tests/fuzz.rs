//! Stress and robustness: feed the parsers what a real channel feeds them.
//!
//! Everything here decodes input the gateway does not control — bytes off the
//! air, lines off a socket. The property being checked is always the same one:
//! *no input causes a panic, a hang, or unbounded memory*, and whatever does
//! decode round-trips faithfully. A packet channel supplies corrupt frames for
//! free, so this is not a hypothetical.
//!
//! The generator is a xorshift PRNG rather than a fuzzing framework: it needs
//! no extra dependency, it is deterministic (a failure reproduces from the
//! printed seed), and it runs in CI in under a second.

use std::time::{Duration, Instant};

use ax25ircd::airc::frame::{AircFrame, Kind};
use ax25ircd::airc::{encode_fields, SessionConfig, Sessions};
use ax25ircd::ax25::kiss::{self, KissDecoder};
use ax25ircd::ax25::{Address, Ax25Frame};
use ax25ircd::callsign::Callsign;
use ax25ircd::irc::message::{is_channel_name, is_valid_nick, lower, Message};
use ax25ircd::policy::{looks_like_ciphertext, sanitize, Policy};
use ax25ircd::config::PolicyConfig;

/// Deterministic, dependency-free noise.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }
}

#[test]
fn ax25_decoding_survives_arbitrary_bytes() {
    let mut rng = Rng::new(0x9E3779B97F4A7C15);
    for i in 0..200_000 {
        let len = rng.below(80);
        let buf = rng.bytes(len);
        // The contract is only that it returns rather than panicking. Anything
        // that does decode must re-encode to something that decodes again.
        if let Ok(frame) = Ax25Frame::decode(&buf) {
            let re = frame.encode();
            assert!(
                Ax25Frame::decode(&re).is_ok(),
                "iteration {i}: a decoded frame did not survive a round trip: {buf:02x?}"
            );
            // The monitor line is what an operator sees; it must be printable.
            let line = frame.to_monitor_line();
            assert!(
                !line.contains('\n') && !line.contains('\r'),
                "iteration {i}: monitor output must stay on one line"
            );
        }
    }
}

#[test]
fn ax25_round_trips_for_every_well_formed_frame() {
    let mut rng = Rng::new(12345);
    for _ in 0..20_000 {
        let digis: Vec<Callsign> = (0..rng.below(3))
            .map(|_| {
                let n = rng.below(10);
                format!("SK{n}MT-{}", rng.below(16)).parse().unwrap()
            })
            .collect();
        let n = rng.below(200);
        let info = rng.bytes(n);
        let frame = Ax25Frame::ui(
            "SM0ABC-7".parse().unwrap(),
            "AIRC".parse().unwrap(),
            &digis,
            info.clone(),
        )
        .unwrap();
        let back = Ax25Frame::decode(&frame.encode()).expect("our own frames must decode");
        assert_eq!(back, frame);
        assert_eq!(back.info, info);
    }
}

#[test]
fn the_address_field_rejects_what_it_cannot_represent() {
    let mut rng = Rng::new(777);
    for _ in 0..100_000 {
        let buf = rng.bytes(7);
        if let Ok(addr) = Address::decode(&buf) {
            let mut out = Vec::new();
            addr.encode(&mut out);
            assert_eq!(
                Address::decode(&out).unwrap(),
                addr,
                "an address must survive its own encoding"
            );
        }
    }
}

#[test]
fn the_kiss_decoder_never_exceeds_its_limit_or_hangs() {
    let mut rng = Rng::new(0xDEADBEEF);
    let mut dec = KissDecoder::new(256);
    for _ in 0..2_000 {
        // A mix of structure and noise: FEND and FESC appear far more often
        // than chance would give them, which is what exercises the escape
        // handling and the resynchronisation.
        let len = rng.below(512);
        let chunk: Vec<u8> = (0..len)
            .map(|_| match rng.below(6) {
                0 => kiss::FEND,
                1 => kiss::FESC,
                2 => kiss::TFEND,
                3 => kiss::TFESC,
                _ => rng.byte(),
            })
            .collect();
        for frame in dec.push(&chunk) {
            assert!(
                frame.payload.len() <= 256,
                "the decoder handed back a frame past its own limit"
            );
        }
    }

    // After all that, it still decodes a good frame.
    let wire = kiss::encode(0, kiss::CMD_DATA, b"still working");
    let mut dec = KissDecoder::new(256);
    assert_eq!(dec.push(&wire)[0].payload, b"still working");
}

#[test]
fn kiss_round_trips_any_payload() {
    let mut rng = Rng::new(24680);
    for _ in 0..20_000 {
        let n = rng.below(200);
        let payload = rng.bytes(n);
        let port = (rng.below(16)) as u8;
        let command = (rng.below(16)) as u8;
        let wire = kiss::encode(port, command, &payload);
        let mut dec = KissDecoder::new(1024);
        let frames = dec.push(&wire);
        assert_eq!(frames.len(), 1, "one frame in, one frame out");
        assert_eq!(frames[0].payload, payload);
        assert_eq!(frames[0].port, port);
        assert_eq!(frames[0].command, command);
    }
}

#[test]
fn airc_decoding_survives_arbitrary_bytes() {
    let mut rng = Rng::new(0xC0FFEE);
    for _ in 0..200_000 {
        let n = rng.below(64);
        let mut buf = rng.bytes(n);
        // Half the time, make it look like AIRC so the header path is reached
        // rather than bailing on the magic.
        if buf.len() >= 2 && rng.below(2) == 0 {
            buf[0] = b'A';
            buf[1] = b'1';
        }
        if let Ok(frame) = AircFrame::decode(&buf) {
            assert!(frame.frag_total > 0 && frame.frag_index < frame.frag_total);
            assert_eq!(
                AircFrame::decode(&frame.encode()).unwrap(),
                frame,
                "a decoded AIRC frame must survive a round trip"
            );
            // Fields are lossy-decoded UTF-8, so this must never panic and
            // never produce a separator that would re-split differently.
            for f in frame.fields() {
                assert!(!f.contains('\u{1f}'));
            }
        }
    }
}

#[test]
fn field_encoding_cannot_smuggle_separators_or_line_breaks() {
    let mut rng = Rng::new(13579);
    for _ in 0..20_000 {
        let (la, lb) = (rng.below(20), rng.below(20));
        let a = String::from_utf8_lossy(&rng.bytes(la)).into_owned();
        let b = String::from_utf8_lossy(&rng.bytes(lb)).into_owned();
        let payload = encode_fields(&[&a, &b]);
        assert!(!payload.contains(&b'\r'));
        assert!(!payload.contains(&b'\n'));
        assert!(!payload.contains(&0));
        let frame = AircFrame::new(Kind::Msg, 1, payload);
        assert!(
            frame.fields().len() <= 2,
            "a field must not be able to split itself into more fields"
        );
    }
}

#[test]
fn the_session_layer_survives_a_hostile_peer() {
    let mut rng = Rng::new(0xABCDEF);
    let cfg = SessionConfig {
        paclen: 64,
        max_peers: 8,
        max_reasm: 2,
        max_queue: 4,
        ..Default::default()
    };
    let mut s = Sessions::new(cfg);
    let calls: Vec<Callsign> = (0..20)
        .map(|i| format!("SM{}ABC-{}", i % 10, i % 16).parse().unwrap())
        .collect();

    let start = Instant::now();
    let mut now = start;
    for i in 0..100_000 {
        let call = &calls[rng.below(calls.len())];
        let kind = match rng.below(8) {
            0 => Kind::Hello,
            1 => Kind::Join,
            2 => Kind::Msg,
            3 => Kind::Ack,
            4 => Kind::Part,
            5 => Kind::Names,
            6 => Kind::Ping,
            _ => Kind::Quit,
        };
        let seq = (rng.next() % 65536) as u16;
        let n = rng.below(80);
        let mut f = AircFrame::new(kind, seq, rng.bytes(n));
        f.flags = rng.byte();
        // Fragment headers are validated on decode; here they are set directly,
        // so cover the legal range and let reassembly deal with the rest.
        f.frag_total = 1 + (rng.below(8)) as u8;
        f.frag_index = (rng.below(f.frag_total as usize)) as u8;
        s.on_receive(call, f, now);

        if i % 500 == 0 {
            now += Duration::from_secs(1);
            s.tick(now);
        }
    }

    assert!(
        s.peers().count() <= 8,
        "the peer table grew past max_peers: a flood of unique callsigns is free to produce"
    );
    for p in s.peers() {
        assert!(p.queue_depth() <= 5, "a peer queue grew past its bound");
    }
}

#[test]
fn irc_parsing_survives_arbitrary_lines() {
    let mut rng = Rng::new(0x5EED);
    for _ in 0..200_000 {
        let n = rng.below(600);
        let raw = rng.bytes(n);
        let line = String::from_utf8_lossy(&raw);
        if let Some(msg) = Message::parse(&line) {
            // A parsed message must serialise to exactly one IRC line, or an
            // RF-originated field becomes an injection into every client.
            let out = msg.to_string();
            assert!(
                !out.contains('\r') && !out.contains('\n') && !out.contains('\0'),
                "serialising produced a line break: {out:?}"
            );
            assert!(!msg.command.is_empty());
        }
        // The helpers are called on the same untrusted input.
        let _ = lower(&line);
        let _ = is_channel_name(&line);
        let _ = is_valid_nick(&line, 30);
    }
}

#[test]
fn message_round_trips_survive_reparsing() {
    let mut rng = Rng::new(0x1234ABCD);
    for _ in 0..20_000 {
        let n = 1 + rng.below(4);
        let params: Vec<String> = (0..n)
            .map(|_| {
                let n = 1 + rng.below(12);
                String::from_utf8_lossy(&rng.bytes(n)).into_owned()
            })
            .collect();
        let msg = Message::new("PRIVMSG", params).with_prefix("nick!user@host");
        let line = msg.to_string();
        let back = Message::parse(&line).expect("our own output must parse");
        assert_eq!(back.command, "PRIVMSG");
        assert_eq!(
            back.params.len().min(1),
            1,
            "at least the target must survive"
        );
    }
}

#[test]
fn the_outbound_screen_never_panics_and_always_bounds_length() {
    let mut rng = Rng::new(0xFEEDFACE);
    let policy = Policy::new(PolicyConfig {
        max_rf_text_len: 40,
        ..Default::default()
    });
    for _ in 0..100_000 {
        let n = rng.below(300);
        let raw = rng.bytes(n);
        let text = String::from_utf8_lossy(&raw).into_owned();
        let cleaned = sanitize(&text);
        assert!(!cleaned.contains('\r') && !cleaned.contains('\n'));
        assert!(
            !cleaned.starts_with(' ') && !cleaned.ends_with(' '),
            "sanitised text is trimmed: {cleaned:?}"
        );
        let _ = looks_like_ciphertext(&text);
        match policy.screen_outbound(&text) {
            ax25ircd::policy::Verdict::Allow(t) => assert!(t.chars().count() <= 40),
            ax25ircd::policy::Verdict::Truncated(t) => assert!(
                t.chars().count() <= 40,
                "a truncated message must respect the cap: {} chars",
                t.chars().count()
            ),
            ax25ircd::policy::Verdict::Deny(_) => {}
        }
    }
}

#[test]
fn callsign_parsing_survives_arbitrary_text() {
    let mut rng = Rng::new(0x0BADC0DE);
    for _ in 0..200_000 {
        let n = rng.below(20);
        let raw = rng.bytes(n);
        let text = String::from_utf8_lossy(&raw).into_owned();
        if let Ok(c) = text.parse::<Callsign>() {
            // Display and FromStr are inverses, and the nick form round trips.
            assert_eq!(c.to_string().parse::<Callsign>().unwrap(), c);
            assert_eq!(Callsign::from_nick(&c.to_nick()).unwrap(), c);
            assert!(c.base().len() <= 6 && c.ssid() <= 15);
        }
        let _ = Callsign::reserved_from_nick(&text);
        let _ = Callsign::from_nick(&text);
    }
}

#[test]
fn a_reserved_callsign_nick_can_never_be_claimed_by_an_ip_user() {
    // Every spelling of a callsign an IRC client could type must be caught,
    // including the RFC 1459 casemapping equivalents.
    let mut rng = Rng::new(0x1CE);
    for _ in 0..50_000 {
        let base = format!(
            "{}{}{}",
            (b'A' + rng.below(26) as u8) as char,
            (b'A' + rng.below(26) as u8) as char,
            rng.below(10)
        );
        let ssid = rng.below(16);
        for spelling in [
            base.to_string(),
            format!("{base}-{ssid}"),
            format!("{base}|{ssid}"),
            format!("{base}\\{ssid}"),
            base.to_lowercase(),
        ] {
            if ssid == 0 && spelling.contains(['-', '|', '\\']) {
                continue;
            }
            assert!(
                Callsign::reserved_from_nick(&spelling).is_some(),
                "{spelling} should be reserved for an RF station"
            );
        }
    }
}
