//! The radio side of the bridge: what the gateway does with each kind of frame
//! it hears, and what it refuses to do.
//!
//! These drive the `Server` directly with decoded AX.25 frames rather than
//! going through the TNC task, so a test can assert on one frame at a time
//! without waiting for pacing or airtime.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ax25ircd::airc::{encode_fields, AircFrame, Kind};
use ax25ircd::ax25::tnc::{self, TncConfig};
use ax25ircd::ax25::Ax25Frame;
use ax25ircd::callsign::Callsign;
use ax25ircd::config::Config;
use ax25ircd::server::state::{ClientId, UserId};
use ax25ircd::server::{Event, Server};
use tokio::sync::mpsc;

const CONFIG: &str = r##"
[server]
name = "rf.test"
motd = ["packet here"]

[listen]
bind = []

[radio]
enabled = true
callsign = "SK0MT-1"
destination = "AIRC"
id_interval_secs = 60
paclen = 128
presence_notices = true

[radio.duty]
enabled = true
baud = 9600
txdelay_ms = 10
txtail_ms = 10
max_duty_percent = 50

[policy]
rf_msgs_per_min = 600
rf_burst = 100
rf_channel_msgs_per_min = 600
rf_channel_burst = 100
ip_cmds_per_min = 6000
ip_cmd_burst = 500

[accounts]
file = "target/test-rf-nicks.json"

[[channels]]
name = "#rf"
topic = "bridged"
rf = true

[[channels]]
name = "#local"

[[opers]]
name = "root"
password = "operpass1"
"##;

struct Rf {
    server: Server,
    rx: Vec<(ClientId, mpsc::Receiver<String>)>,
    seq: u16,
    /// The loopback TNC's far end. Never read, but it has to stay alive:
    /// dropping it closes the fake radio and the gateway decides it has no
    /// transmitter — which quietly turns off the mailbox and every other
    /// path that asks "can we radiate?".
    _far: tokio::io::DuplexStream,
    _rf_rx: mpsc::Receiver<Ax25Frame>,
}

impl Rf {
    fn new() -> Self {
        Self::with(CONFIG)
    }

    fn with(text: &str) -> Self {
        let _ = std::fs::remove_file("target/test-rf-nicks.json");
        let config = Arc::new(Config::from_toml(text).unwrap());
        let (link, far) = TncConfig::loopback_link();
        let (handle, rf_rx) = tnc::spawn(TncConfig::from_config(&config, link));
        Rf {
            server: Server::new(config, Some(handle)),
            rx: Vec::new(),
            seq: 1,
            _far: far,
            _rf_rx: rf_rx,
        }
    }

    fn client(&mut self, id: ClientId, nick: &str) -> ClientId {
        let (out, rx) = mpsc::channel(4096);
        self.server.handle(Event::Connected {
            id,
            host: format!("10.1.{}.{}", id / 256, id % 256),
            out,
            hangup: None,
        });
        self.rx.push((id, rx));
        self.send(id, &format!("NICK {nick}"));
        self.send(id, &format!("USER {nick} 0 * :{nick}"));
        self.drain(id);
        id
    }

    fn send(&mut self, id: ClientId, line: &str) {
        self.server.handle(Event::Line {
            id,
            line: line.to_string(),
        });
    }

    fn drain(&mut self, id: ClientId) -> Vec<String> {
        let mut out = Vec::new();
        for (cid, rx) in self.rx.iter_mut() {
            if *cid == id {
                while let Ok(line) = rx.try_recv() {
                    out.push(line);
                }
            }
        }
        out
    }

    /// A station transmits an AIRC frame addressed to the gateway.
    fn heard(&mut self, from: &str, kind: Kind, fields: &[&str]) {
        self.heard_to(from, "SK0MT-1", kind, fields)
    }

    fn heard_to(&mut self, from: &str, to: &str, kind: Kind, fields: &[&str]) {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1).max(1);
        let airc = AircFrame::new(kind, seq, encode_fields(fields));
        let ax = Ax25Frame::ui(
            from.parse().unwrap(),
            to.parse().unwrap(),
            &[],
            airc.encode(),
        )
        .unwrap();
        self.server.handle(Event::Rf(ax));
    }

    /// A raw frame, for the cases that are not well-formed AIRC.
    fn heard_raw(&mut self, frame: Ax25Frame) {
        self.server.handle(Event::Rf(frame));
    }

    fn station(&self, call: &str) -> Option<UserId> {
        let c: Callsign = call.parse().unwrap();
        let uid = UserId::Rf(c);
        self.server.state.user(&uid).map(|u| u.id.clone())
    }
}

// ------------------------------------------------------------ what gets ignored

#[tokio::test]
async fn frames_that_are_not_ours_are_ignored() {
    let mut rf = Rf::new();
    let a = rf.client(1, "alice");
    rf.send(a, "JOIN #rf");
    rf.drain(a);

    // Not a UI frame.
    let mut not_ui = Ax25Frame::ui(
        "SM0ABC-7".parse().unwrap(),
        "SK0MT-1".parse().unwrap(),
        &[],
        AircFrame::new(Kind::Join, 1, encode_fields(&["#rf"])).encode(),
    )
    .unwrap();
    not_ui.control = 0x00; // an I frame
    rf.heard_raw(not_ui);
    assert!(rf.station("SM0ABC-7").is_none(), "non-UI frames are not AIRC");

    // Right control field, wrong PID.
    let mut wrong_pid = Ax25Frame::ui(
        "SM0ABC-7".parse().unwrap(),
        "SK0MT-1".parse().unwrap(),
        &[],
        AircFrame::new(Kind::Join, 2, encode_fields(&["#rf"])).encode(),
    )
    .unwrap();
    wrong_pid.pid = Some(0xCF); // NET/ROM
    rf.heard_raw(wrong_pid);
    assert!(rf.station("SM0ABC-7").is_none());

    // Our own transmission coming back through a digipeater.
    rf.heard("SK0MT-1", Kind::Join, &["#rf"]);
    assert!(rf.station("SK0MT-1").is_none(), "we do not answer ourselves");

    // Addressed to someone else.
    rf.heard_to("SM0ABC-7", "SK0AA-9", Kind::Join, &["#rf"]);
    assert!(rf.station("SM0ABC-7").is_none());

    // Not AIRC at all: an APRS beacon on the same frequency.
    let aprs = Ax25Frame::ui(
        "SM0ABC-7".parse().unwrap(),
        "SK0MT-1".parse().unwrap(),
        &[],
        b"!5930.00N/01803.00E-".to_vec(),
    )
    .unwrap();
    rf.heard_raw(aprs);
    assert!(rf.station("SM0ABC-7").is_none());

    assert!(rf.drain(a).is_empty(), "none of that should reach IRC");
}

#[tokio::test]
async fn an_implausible_callsign_is_ignored() {
    let mut rf = Rf::new();
    // "NOCALL" has no digit, so it is not a callsign anyone was issued.
    rf.heard("NOCALL", Kind::Hello, &[]);
    assert!(rf.station("NOCALL").is_none());
}

#[tokio::test]
async fn a_denied_station_gets_nothing() {
    let text = CONFIG.replace(
        "[policy]",
        "[policy]\ndeny_callsigns = [\"SM0BAD\"]",
    );
    let mut rf = Rf::with(&text);
    rf.heard("SM0BAD-7", Kind::Hello, &[]);
    assert!(rf.station("SM0BAD-7").is_none(), "the deny list covers every SSID");

    rf.heard("SM0ABC-7", Kind::Hello, &[]);
    assert!(rf.station("SM0ABC-7").is_some());
}

#[tokio::test]
async fn an_allow_list_excludes_everyone_else() {
    let text = CONFIG.replace(
        "[policy]",
        "[policy]\nallow_callsigns = [\"SM0ABC\"]",
    );
    let mut rf = Rf::with(&text);
    rf.heard("SM0XYZ-1", Kind::Hello, &[]);
    assert!(rf.station("SM0XYZ-1").is_none());
    rf.heard("SM0ABC-3", Kind::Hello, &[]);
    assert!(rf.station("SM0ABC-3").is_some());
}

// ------------------------------------------------------------- the frame kinds

#[tokio::test]
async fn hello_registers_a_station() {
    let mut rf = Rf::new();
    rf.heard("SM0ABC-7", Kind::Hello, &["ax25irc-station/1"]);
    assert!(rf.station("SM0ABC-7").is_some());
    let u = rf.server.state.by_nick("SM0ABC|7").expect("nick from callsign");
    assert_eq!(u.username, "rf");
    assert!(u.registered);
    assert_eq!(u.callsign.as_ref().map(|c| c.to_string()), Some("SM0ABC-7".into()));
}

#[tokio::test]
async fn join_part_and_quit_are_visible_on_irc() {
    let mut rf = Rf::new();
    let a = rf.client(1, "alice");
    rf.send(a, "JOIN #rf");
    rf.drain(a);

    rf.heard("SM0ABC-7", Kind::Join, &["#rf"]);
    let lines = rf.drain(a);
    assert!(
        lines.iter().any(|l| l.contains("SM0ABC|7") && l.contains("JOIN #rf")),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("+v")),
        "a callsign is voiced on a bridged channel: {lines:?}"
    );

    rf.heard("SM0ABC-7", Kind::Part, &["#rf", "going qrt"]);
    let lines = rf.drain(a);
    assert!(
        lines.iter().any(|l| l.contains("PART #rf") && l.contains("going qrt")),
        "{lines:?}"
    );

    // Re-join, then quit outright.
    rf.heard("SM0ABC-7", Kind::Join, &["#rf"]);
    rf.drain(a);
    rf.heard("SM0ABC-7", Kind::Quit, &["73 all"]);
    let lines = rf.drain(a);
    assert!(lines.iter().any(|l| l.contains("QUIT") && l.contains("73 all")), "{lines:?}");
    assert!(rf.station("SM0ABC-7").is_none());
}

#[tokio::test]
async fn a_quit_with_no_reason_still_reads_sensibly() {
    let mut rf = Rf::new();
    let a = rf.client(1, "alice");
    rf.send(a, "JOIN #rf");
    rf.heard("SM0ABC-7", Kind::Join, &["#rf"]);
    rf.drain(a);

    rf.heard("SM0ABC-7", Kind::Quit, &[""]);
    assert!(
        rf.drain(a).iter().any(|l| l.contains("Signed off")),
        "an empty reason gets a default rather than an empty QUIT"
    );
}

#[tokio::test]
async fn parting_a_channel_the_station_is_not_in_is_harmless() {
    let mut rf = Rf::new();
    let a = rf.client(1, "alice");
    rf.send(a, "JOIN #rf");
    rf.heard("SM0ABC-7", Kind::Hello, &[]);
    rf.drain(a);

    rf.heard("SM0ABC-7", Kind::Part, &["#rf"]);
    rf.heard("SM0ABC-7", Kind::Part, &["#nowhere"]);
    assert!(rf.station("SM0ABC-7").is_some(), "still on frequency");
}

#[tokio::test]
async fn joining_a_channel_that_is_not_bridged_is_refused() {
    let mut rf = Rf::new();
    rf.heard("SM0ABC-7", Kind::Hello, &[]);
    rf.heard("SM0ABC-7", Kind::Join, &["#local"]);
    let uid = rf.station("SM0ABC-7").unwrap();
    assert!(
        rf.server.state.user(&uid).unwrap().channels.is_empty(),
        "an Internet-only channel is not the station's to join"
    );

    rf.heard("SM0ABC-7", Kind::Join, &["#nosuch"]);
    rf.heard("SM0ABC-7", Kind::Join, &["notachannel"]);
    assert!(rf.server.state.user(&uid).unwrap().channels.is_empty());
}

#[tokio::test]
async fn names_and_ping_need_a_registered_station() {
    let mut rf = Rf::new();
    // Neither should register the station as a side effect.
    rf.heard("SM0ABC-7", Kind::Names, &["#rf"]);
    rf.heard("SM0ABC-7", Kind::Ping, &["token"]);
    assert!(rf.station("SM0ABC-7").is_none());

    rf.heard("SM0ABC-7", Kind::Hello, &[]);
    rf.heard("SM0ABC-7", Kind::Names, &["#rf"]);
    rf.heard("SM0ABC-7", Kind::Ping, &["a-very-long-token-indeed"]);
    assert!(rf.station("SM0ABC-7").is_some());
}

#[tokio::test]
async fn identification_and_replies_from_other_gateways_are_only_logged() {
    let mut rf = Rf::new();
    let a = rf.client(1, "alice");
    rf.send(a, "JOIN #rf");
    rf.drain(a);

    // ID is informational. The rest are downlink kinds we never act on.
    for kind in [
        Kind::Id,
        Kind::Ack,
        Kind::Welcome,
        Kind::NamesReply,
        Kind::Pong,
        Kind::Presence,
        Kind::Stored,
        Kind::Error,
    ] {
        rf.heard("SM0ABC-7", kind, &["something"]);
    }
    assert!(
        rf.drain(a).is_empty(),
        "none of those should produce IRC traffic"
    );
}

// -------------------------------------------------------------------- messaging

#[tokio::test]
async fn a_channel_message_from_rf_reaches_irc() {
    let mut rf = Rf::new();
    let a = rf.client(1, "alice");
    rf.send(a, "JOIN #rf");
    rf.heard("SM0ABC-7", Kind::Join, &["#rf"]);
    rf.drain(a);

    rf.heard("SM0ABC-7", Kind::Msg, &["#rf", "good morning"]);
    let lines = rf.drain(a);
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with(":SM0ABC|7!rf@") && l.contains("PRIVMSG #rf :good morning")),
        "{lines:?}"
    );

    rf.heard("SM0ABC-7", Kind::Notice, &["#rf", "a notice"]);
    assert!(rf.drain(a).iter().any(|l| l.contains("NOTICE #rf :a notice")));
}

#[tokio::test]
async fn a_message_from_a_station_that_never_joined_still_arrives() {
    let mut rf = Rf::new();
    let a = rf.client(1, "alice");
    rf.send(a, "JOIN #rf");
    rf.drain(a);

    // A lost JOIN must not silently swallow a QSO.
    rf.heard("SM0XYZ-9", Kind::Msg, &["#rf", "anyone about?"]);
    let lines = rf.drain(a);
    assert!(lines.iter().any(|l| l.contains("JOIN #rf")), "joined implicitly: {lines:?}");
    assert!(lines.iter().any(|l| l.contains("anyone about?")), "{lines:?}");
}

#[tokio::test]
async fn messages_to_channels_the_station_may_not_use_are_refused() {
    let mut rf = Rf::new();
    let a = rf.client(1, "alice");
    rf.send(a, "JOIN #local");
    rf.heard("SM0ABC-7", Kind::Hello, &[]);
    rf.drain(a);

    rf.heard("SM0ABC-7", Kind::Msg, &["#local", "not allowed here"]);
    rf.heard("SM0ABC-7", Kind::Msg, &["#nosuch", "nowhere"]);
    assert!(
        rf.drain(a).iter().all(|l| !l.contains("not allowed here")),
        "an Internet-only channel does not carry RF traffic"
    );
}

#[tokio::test]
async fn a_private_message_from_rf_reaches_one_irc_user() {
    let mut rf = Rf::new();
    let a = rf.client(1, "alice");
    let b = rf.client(2, "bob");
    rf.heard("SM0ABC-7", Kind::Hello, &[]);
    rf.drain(a);
    rf.drain(b);

    rf.heard("SM0ABC-7", Kind::Msg, &["alice", "meet me on 145.500"]);
    assert!(rf.drain(a).iter().any(|l| l.contains("meet me on 145.500")));
    assert!(rf.drain(b).is_empty(), "not a broadcast");

    // To a nick that does not exist.
    rf.heard("SM0ABC-7", Kind::Msg, &["nobody", "hello?"]);
    assert!(rf.drain(a).is_empty());
}

#[tokio::test]
async fn an_empty_message_is_dropped() {
    let mut rf = Rf::new();
    let a = rf.client(1, "alice");
    rf.send(a, "JOIN #rf");
    rf.heard("SM0ABC-7", Kind::Join, &["#rf"]);
    rf.drain(a);

    // Only control characters: nothing survives sanitising.
    rf.heard("SM0ABC-7", Kind::Msg, &["#rf", "\u{2}\u{f}"]);
    assert!(rf.drain(a).is_empty());
    // A malformed MSG with no text field at all.
    rf.heard("SM0ABC-7", Kind::Msg, &["#rf"]);
    assert!(rf.drain(a).is_empty());
}

#[tokio::test]
async fn a_station_that_floods_is_dropped_not_answered() {
    let text = CONFIG
        .replace("rf_msgs_per_min = 600", "rf_msgs_per_min = 6")
        .replace("rf_burst = 100", "rf_burst = 3");
    let mut rf = Rf::with(&text);
    let a = rf.client(1, "alice");
    rf.send(a, "JOIN #rf");
    rf.heard("SM0ABC-7", Kind::Join, &["#rf"]);
    rf.drain(a);

    for i in 0..20 {
        rf.heard("SM0ABC-7", Kind::Msg, &["#rf", &format!("flood {i}")]);
    }
    let delivered = rf.drain(a).iter().filter(|l| l.contains("flood")).count();
    assert!(
        delivered < 20,
        "the token bucket should have dropped most of that: {delivered} got through"
    );
    let call: Callsign = "SM0ABC-7".parse().unwrap();
    assert!(
        rf.server.sessions.peer(&call).unwrap().dropped > 0,
        "drops should be counted so RADIO HEARD can show them"
    );
}

#[tokio::test]
async fn a_quit_reason_from_the_air_cannot_inject_an_irc_line() {
    let mut rf = Rf::new();
    let a = rf.client(1, "alice");
    rf.send(a, "JOIN #rf");
    rf.heard("SM0ABC-7", Kind::Join, &["#rf"]);
    rf.drain(a);

    // encode_fields strips CR and LF, and the IRC serialiser scrubs them
    // again. Belt and braces, because this is a protocol-injection path into
    // every client in the channel.
    let airc = AircFrame::new(Kind::Quit, 99, b"bye\r\nNOTICE alice :pwned".to_vec());
    let ax = Ax25Frame::ui(
        "SM0ABC-7".parse().unwrap(),
        "SK0MT-1".parse().unwrap(),
        &[],
        airc.encode(),
    )
    .unwrap();
    rf.heard_raw(ax);

    for line in rf.drain(a) {
        assert!(!line.contains('\r') && !line.contains('\n'), "{line:?}");
        assert!(
            !line.starts_with(":rf.test NOTICE alice :pwned"),
            "injected a server notice: {line:?}"
        );
    }
}

// ----------------------------------------------------------------- housekeeping

#[tokio::test]
async fn a_station_that_goes_quiet_is_dropped() {
    let text = CONFIG.replace("id_interval_secs = 60", "id_interval_secs = 60\npeer_idle_timeout_secs = 1");
    let mut rf = Rf::with(&text);
    let a = rf.client(1, "alice");
    rf.send(a, "JOIN #rf");
    rf.heard("SM0ABC-7", Kind::Join, &["#rf"]);
    rf.drain(a);
    assert!(rf.station("SM0ABC-7").is_some());

    std::thread::sleep(Duration::from_millis(1100));
    rf.server.handle(Event::Tick);
    assert!(
        rf.station("SM0ABC-7").is_none(),
        "a station we have not heard from is not on frequency"
    );
    assert!(rf.drain(a).iter().any(|l| l.contains("Signal lost")));
}

#[tokio::test]
async fn an_operator_can_remove_a_station() {
    let mut rf = Rf::new();
    let a = rf.client(1, "alice");
    rf.send(a, "OPER root operpass1");
    rf.send(a, "JOIN #rf");
    rf.heard("SM0ABC-7", Kind::Join, &["#rf"]);
    rf.drain(a);

    rf.send(a, "RADIO KICK SM0ABC-7");
    assert!(rf.drain(a).iter().any(|l| l.contains("Station removed")));
    assert!(rf.station("SM0ABC-7").is_none());

    // And RADIO HEARD reports what is on frequency.
    rf.heard("SM0XYZ-1", Kind::Hello, &[]);
    rf.drain(a);
    rf.send(a, "RADIO HEARD");
    assert!(rf.drain(a).iter().any(|l| l.contains("SM0XYZ-1")));
}

#[tokio::test]
async fn an_operator_can_kick_a_station_from_one_channel() {
    let mut rf = Rf::new();
    let a = rf.client(1, "alice");
    rf.send(a, "OPER root operpass1");
    rf.send(a, "JOIN #rf");
    rf.heard("SM0ABC-7", Kind::Join, &["#rf"]);
    rf.drain(a);

    rf.send(a, "KICK #rf SM0ABC|7 :qrm");
    assert!(rf.drain(a).iter().any(|l| l.contains("KICK #rf SM0ABC|7")));
    assert!(
        rf.station("SM0ABC-7").is_some(),
        "kicked from the channel, still on frequency"
    );
    assert!(!rf
        .server
        .state
        .channel("#rf")
        .unwrap()
        .members
        .contains_key(&UserId::Rf("SM0ABC-7".parse().unwrap())));
}

#[tokio::test]
async fn whois_on_a_station_reports_what_the_radio_side_knows() {
    let mut rf = Rf::new();
    let a = rf.client(1, "alice");
    rf.heard("SM0ABC-7", Kind::Hello, &[]);
    rf.drain(a);

    let lines = {
        rf.send(a, "WHOIS SM0ABC|7");
        rf.drain(a)
    };
    assert!(
        lines.iter().any(|l| l.contains("Radio station SM0ABC-7")),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("last heard")),
        "idle time and queue depth belong in WHOIS for a station: {lines:?}"
    );
}

#[tokio::test]
async fn the_mailbox_holds_and_reports_messages_for_absent_stations() {
    let mut rf = Rf::new();
    let a = rf.client(1, "alice");
    rf.send(a, "OPER root operpass1");
    rf.send(a, "CALLSIGN SM0XYZ");
    rf.drain(a);

    rf.send(a, "PRIVMSG SM0ABC|7 :call me when you are back");
    assert!(rf.drain(a).iter().any(|l| l.contains("Held for delivery")));
    assert_eq!(rf.server.mailbox.len(), 1);

    rf.send(a, "RADIO MAIL");
    assert!(rf.drain(a).iter().any(|l| l.contains("SM0ABC-7")));

    // Held messages expire.
    let much_later = Instant::now() + Duration::from_secs(48 * 3600);
    assert_eq!(rf.server.mailbox.expire(much_later), 1);
    assert!(rf.server.mailbox.is_empty());
}

#[tokio::test]
async fn a_full_mailbox_says_so_rather_than_silently_dropping() {
    // Per-station 1, gateway 2: enough room to reach each limit separately.
    // `store` checks the gateway total first, so a total of 1 would mask the
    // per-station message entirely.
    let text = CONFIG.replace(
        "paclen = 128",
        "paclen = 128\nmailbox_per_station = 1\nmailbox_total = 2",
    );
    let mut rf = Rf::with(&text);
    let a = rf.client(1, "alice");
    rf.send(a, "OPER root operpass1");
    rf.send(a, "CALLSIGN SM0XYZ");
    rf.drain(a);

    rf.send(a, "PRIVMSG SM0ABC|7 :first");
    rf.drain(a);
    rf.send(a, "PRIVMSG SM0ABC|7 :second");
    assert!(rf
        .drain(a)
        .iter()
        .any(|l| l.contains("as much mail as it can hold")));

    // A second station fills the gateway, and a third is refused for that.
    rf.send(a, "PRIVMSG SM0DEF|2 :for someone else");
    rf.drain(a);
    rf.send(a, "PRIVMSG SM0GHI|4 :no room left");
    assert!(rf.drain(a).iter().any(|l| l.contains("gateway mailbox is full")));
}

#[tokio::test]
async fn a_station_appearing_gets_its_held_mail_a_little_at_a_time() {
    let mut rf = Rf::new();
    let a = rf.client(1, "alice");
    rf.send(a, "OPER root operpass1");
    rf.send(a, "CALLSIGN SM0XYZ");
    rf.drain(a);
    for i in 0..4 {
        rf.send(a, &format!("PRIVMSG SM0ABC|7 :held {i}"));
    }
    rf.drain(a);
    assert_eq!(rf.server.mailbox.len(), 4);

    rf.heard("SM0ABC-7", Kind::Hello, &[]);
    assert_eq!(
        rf.server.mailbox.len(),
        3,
        "one message per exchange, not the whole mailbox at once"
    );
}

#[tokio::test]
async fn presence_notices_reach_the_air_only_when_enabled() {
    // The fixture turns them on; check the channel sees joins either way and
    // that the setting is what decides whether they are radiated.
    let mut rf = Rf::new();
    assert!(rf.server.config.radio.presence_notices);
    let a = rf.client(1, "alice");
    rf.send(a, "JOIN #rf");
    rf.heard("SM0ABC-7", Kind::Join, &["#rf"]);
    rf.drain(a);

    let b = rf.client(2, "bob");
    rf.send(b, "JOIN #rf");
    let lines = rf.drain(a);
    assert!(lines.iter().any(|l| l.contains("bob") && l.contains("JOIN #rf")));
}

#[tokio::test]
async fn the_last_station_leaving_is_announced_to_the_irc_side() {
    let mut rf = Rf::new();
    let a = rf.client(1, "alice");
    rf.send(a, "JOIN #rf");
    rf.heard("SM0ABC-7", Kind::Join, &["#rf"]);
    let lines = rf.drain(a);
    assert!(
        lines.iter().any(|l| l.contains("is on frequency")),
        "IRC users should be told when the channel goes live: {lines:?}"
    );

    rf.heard("SM0ABC-7", Kind::Part, &["#rf"]);
    let lines = rf.drain(a);
    assert!(
        lines.iter().any(|l| l.contains("No RF station remains")),
        "and when it stops: {lines:?}"
    );
}
