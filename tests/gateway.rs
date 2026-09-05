//! End-to-end tests: a fake TNC on one side, a fake IRC client on the other,
//! and the real server in between.

use std::sync::Arc;
use std::time::Duration;

use ax25ircd::airc::{encode_fields, AircFrame, Kind};
use ax25ircd::ax25::kiss::{self, KissDecoder};
use ax25ircd::ax25::tnc::{self, TncConfig};
use ax25ircd::ax25::Ax25Frame;
use ax25ircd::callsign::Callsign;
use ax25ircd::config::Config;
use ax25ircd::server::state::ClientId;
use ax25ircd::server::{Event, Server};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

const CONFIG: &str = r##"
[server]
name = "test.gateway"
motd = ["packet radio here"]

[listen]
bind = []

[radio]
enabled = true
callsign = "SK0MT-1"
destination = "AIRC"
id_interval_secs = 60
paclen = 128

[radio.tnc]
kind = "loopback"

[policy]

[accounts]
file = "target/test-nicks.json"
identify_timeout_secs = 60

[[channels]]
name = "#rf"
topic = "gateway channel"
rf = true

[[channels]]
name = "#local"

[[opers]]
name = "root"
password = "operpass1"
"##;

struct Harness {
    server: Server,
    far: DuplexStream,
    rf_rx: mpsc::Receiver<Ax25Frame>,
    client_rx: mpsc::Receiver<String>,
    decoder: KissDecoder,
}

const CLIENT: ClientId = 1;

impl Harness {
    async fn new() -> Self {
        Self::from_toml(CONFIG).await
    }

    async fn from_toml(text: &str) -> Self {
        let config = Arc::new(Config::from_toml(text).unwrap());
        let (mut tnc_cfg, far) = TncConfig::loopback();
        tnc_cfg.max_frame = 512;
        let (handle, rf_rx) = tnc::spawn(tnc_cfg);
        let mut server = Server::new(config, Some(handle));

        let (out, client_rx) = mpsc::channel(1024);
        server.handle(Event::Connected {
            id: CLIENT,
            host: "127.0.0.1".into(),
            out,
            hangup: None,
        });
        let mut h = Self {
            server,
            far,
            rf_rx,
            client_rx,
            decoder: KissDecoder::new(1024),
        };
        h.send("NICK alice");
        h.send("USER alice 0 * :Alice");
        h
    }

    fn send(&mut self, line: &str) {
        self.server.handle(Event::Line {
            id: CLIENT,
            line: line.to_string(),
        });
    }

    fn connect_extra(&mut self, id: ClientId, nick: &str) -> mpsc::Receiver<String> {
        let (out, rx) = mpsc::channel(1024);
        self.server.handle(Event::Connected {
            id,
            host: "127.0.0.2".into(),
            out,
            hangup: None,
        });
        self.server.handle(Event::Line {
            id,
            line: format!("NICK {nick}"),
        });
        self.server.handle(Event::Line {
            id,
            line: format!("USER {nick} 0 * :{nick}"),
        });
        rx
    }

    fn oper_and_callsign(&mut self) {
        self.send("OPER root operpass1");
        self.send("CALLSIGN SM0XYZ");
    }

    fn drain_client(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(line) = self.client_rx.try_recv() {
            out.push(line);
        }
        out
    }

    /// Put a frame on the air as if a station had transmitted it, and let the
    /// server process it.
    async fn station_transmits(&mut self, from: &str, frame: AircFrame) {
        // Stations unicast to the gateway callsign; see PROTOCOL.md §3.1.
        self.transmits_to(from, "SK0MT-1", frame).await
    }

    /// As above, but addressed wherever the caller says. Used to check that
    /// the gateway ignores traffic that is not its business.
    async fn transmits_to(&mut self, from: &str, to: &str, frame: AircFrame) {
        let call: Callsign = from.parse().unwrap();
        let ax = Ax25Frame::ui(call, to.parse().unwrap(), &[], frame.encode()).unwrap();
        let wire = kiss::encode(0, kiss::CMD_DATA, &ax.encode());
        self.far.write_all(&wire).await.unwrap();
        self.far.flush().await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(2), self.rf_rx.recv())
            .await
            .expect("TNC task did not deliver the frame")
            .expect("TNC channel closed");
        self.server.handle(Event::Rf(received));
    }

    /// Acknowledge a frame the gateway sent us.
    async fn ack(&mut self, frame: &AircFrame) {
        self.station_transmits(
            "SM0ABC-7",
            AircFrame::new(Kind::Ack, frame.seq, frame.seq.to_be_bytes().to_vec()),
        )
        .await;
    }

    /// Collect everything the gateway has transmitted so far.
    async fn transmitted(&mut self) -> Vec<(Ax25Frame, AircFrame)> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match tokio::time::timeout(Duration::from_millis(150), self.far.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => {
                    for kf in self.decoder.push(&buf[..n]) {
                        let ax = Ax25Frame::decode(&kf.payload).unwrap();
                        if let Ok(airc) = AircFrame::decode(&ax.info) {
                            out.push((ax, airc));
                        }
                    }
                }
                Ok(Err(e)) => panic!("loopback read failed: {e}"),
            }
        }
        out
    }
}

#[tokio::test]
async fn registration_and_local_channel() {
    let mut h = Harness::new().await;
    let lines = h.drain_client();
    assert!(lines.iter().any(|l| l.contains(" 001 alice")));
    assert!(lines.iter().any(|l| l.contains("packet radio here")));

    h.send("JOIN #local");
    let lines = h.drain_client();
    assert!(lines.iter().any(|l| l.contains("JOIN #local")));
    assert!(lines.iter().any(|l| l.contains(" 366 ")));
}

#[tokio::test]
async fn station_joins_and_appears_on_irc() {
    let mut h = Harness::new().await;
    h.send("JOIN #rf");
    h.drain_client();

    h.station_transmits(
        "SM0ABC-7",
        AircFrame::new(Kind::Join, 1, encode_fields(&["#rf"])),
    )
    .await;

    let lines = h.drain_client();
    assert!(
        lines.iter().any(|l| l.contains("SM0ABC|7") && l.contains("JOIN #rf")),
        "IRC users should see the station join: {lines:?}"
    );

    // The gateway answers with a NAMES reply addressed to the station.
    let tx = h.transmitted().await;
    let reply = tx
        .iter()
        .find(|(_, a)| a.kind == Kind::NamesReply)
        .expect("expected a NAMES reply");
    assert_eq!(reply.0.destination.call.to_string(), "SM0ABC-7");
    assert_eq!(reply.0.source.call.to_string(), "SK0MT-1");
    assert!(reply.1.fields()[1].contains("alice"));
}

#[tokio::test]
async fn message_from_rf_reaches_irc_without_retransmission() {
    let mut h = Harness::new().await;
    h.send("JOIN #rf");
    h.drain_client();
    h.station_transmits(
        "SM0ABC-7",
        AircFrame::new(Kind::Join, 1, encode_fields(&["#rf"])),
    )
    .await;
    h.transmitted().await;
    h.drain_client();

    h.station_transmits(
        "SM0ABC-7",
        AircFrame::new(Kind::Msg, 2, encode_fields(&["#rf", "good morning from the hilltop"])),
    )
    .await;

    let lines = h.drain_client();
    assert!(
        lines
            .iter()
            .any(|l| l.contains("PRIVMSG #rf :good morning from the hilltop")),
        "{lines:?}"
    );

    let tx = h.transmitted().await;
    assert!(
        tx.iter().all(|(_, a)| a.kind != Kind::Msg),
        "a message heard on the air must not be transmitted back onto it"
    );
}

#[tokio::test]
async fn irc_message_needs_a_callsign_before_it_is_transmitted() {
    let mut h = Harness::new().await;
    h.send("JOIN #rf");
    h.station_transmits(
        "SM0ABC-7",
        AircFrame::new(Kind::Join, 1, encode_fields(&["#rf"])),
    )
    .await;
    h.transmitted().await;
    h.drain_client();

    h.send("PRIVMSG #rf :hello radio");
    let lines = h.drain_client();
    assert!(
        lines.iter().any(|l| l.contains(" 404 ") || l.contains("+m")),
        "unidentified users must not speak on #rf: {lines:?}"
    );
    let tx = h.transmitted().await;
    assert!(tx.iter().all(|(_, a)| a.kind != Kind::Msg));

    h.send("CALLSIGN SM0XYZ");
    h.drain_client();
    h.send("PRIVMSG #rf :hello radio");
    let lines = h.drain_client();
    assert!(
        lines.iter().any(|l| l.contains("RF-TX") || l.contains("not have RF-TX")),
        "CALLSIGN alone must not radiate: {lines:?}"
    );
    let tx = h.transmitted().await;
    assert!(tx.iter().all(|(_, a)| a.kind != Kind::Msg));

    h.send("OPER root operpass1");
    h.drain_client();
    h.send("PRIVMSG #rf :hello radio");
    h.drain_client();

    let tx = h.transmitted().await;
    let (ax, airc) = tx
        .iter()
        .find(|(_, a)| a.kind == Kind::Msg)
        .unwrap_or_else(|| panic!("OPER + CALLSIGN should put the message on the air; got {:?}", tx.iter().map(|(_,a)| a.kind).collect::<Vec<_>>()));
    assert_eq!(ax.destination.call.to_string(), "AIRC");
    assert_eq!(airc.fields(), vec!["#rf", "alice", "hello radio"]);
}

#[tokio::test]
async fn ciphertext_is_not_transmitted() {
    let mut h = Harness::new().await;
    h.oper_and_callsign();
    h.send("JOIN #rf");
    h.station_transmits(
        "SM0ABC-7",
        AircFrame::new(Kind::Join, 1, encode_fields(&["#rf"])),
    )
    .await;
    h.transmitted().await;
    h.drain_client();

    let mut bob_rx = h.connect_extra(2, "bob");
    let _ = drain_rx(&mut bob_rx);
    h.server.handle(Event::Line {
        id: 2,
        line: "JOIN #rf".into(),
    });
    let _ = drain_rx(&mut bob_rx);

    h.send("PRIVMSG #rf :U2FsdGVkX1+8xQ2mZ9pKbNvYwErTyUiOpAsDfGhJkLzXcVbNm1234567890AbCdEf");
    let lines = h.drain_client();
    assert!(
        lines.iter().any(|l| l.contains("obscure their meaning")),
        "{lines:?}"
    );
    let tx = h.transmitted().await;
    assert!(tx.iter().all(|(_, a)| a.kind != Kind::Msg));

    let bob_lines = drain_rx(&mut bob_rx);
    assert!(
        bob_lines.iter().any(|l| l.contains("PRIVMSG #rf") && l.contains("U2FsdGVk")),
        "ciphertext must still reach other IRC clients: {bob_lines:?}"
    );
}

fn drain_rx(rx: &mut mpsc::Receiver<String>) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(line) = rx.try_recv() {
        out.push(line);
    }
    out
}

#[tokio::test]
async fn private_message_to_a_station_is_acknowledged_and_retried() {
    let mut h = Harness::new().await;
    h.oper_and_callsign();
    h.station_transmits("SM0ABC-7", AircFrame::new(Kind::Hello, 1, encode_fields(&[""])))
        .await;
    // The welcome is sent reliably, so the station must acknowledge it before
    // anything else can be unicast to it.
    let welcome = h
        .transmitted()
        .await
        .into_iter()
        .find(|(_, a)| a.kind == Kind::Welcome)
        .expect("a station that says HELLO gets a welcome");
    h.ack(&welcome.1).await;
    h.drain_client();

    h.send("PRIVMSG SM0ABC|7 :direct message");
    let tx = h.transmitted().await;
    let (ax, airc) = tx
        .iter()
        .find(|(_, a)| a.kind == Kind::Msg)
        .expect("private messages are unicast to the station");
    assert_eq!(ax.destination.call.to_string(), "SM0ABC-7");
    assert!(airc.wants_ack());
    assert_eq!(airc.fields(), vec!["SM0ABC|7", "alice", "direct message"]);

    // The station acknowledges; nothing more is transmitted.
    h.station_transmits(
        "SM0ABC-7",
        AircFrame::new(Kind::Ack, airc.seq, airc.seq.to_be_bytes().to_vec()),
    )
    .await;
    for _ in 0..3 {
        h.server.handle(Event::Tick);
    }
    let tx = h.transmitted().await;
    assert!(
        tx.iter().all(|(_, a)| a.kind != Kind::Msg),
        "an acknowledged message must not be retransmitted"
    );
}

#[tokio::test]
async fn station_frames_from_implausible_callsigns_are_ignored() {
    let mut h = Harness::new().await;
    h.send("JOIN #rf");
    h.drain_client();

    h.station_transmits("NOCALL", AircFrame::new(Kind::Join, 1, encode_fields(&["#rf"])))
        .await;
    let lines = h.drain_client();
    assert!(lines.iter().all(|l| !l.contains("JOIN #rf")), "{lines:?}");
}

#[tokio::test]
async fn messages_are_held_for_a_station_that_is_out_of_range() {
    let mut h = Harness::new().await;
    h.oper_and_callsign();
    h.drain_client();

    // Nobody by that name is on frequency, but it is a plausible callsign.
    h.send("PRIVMSG SM0ABC|7 :meet on 145.500 at 1900");
    let lines = h.drain_client();
    assert!(
        lines.iter().any(|l| l.contains("Held for delivery")),
        "{lines:?}"
    );
    let tx = h.transmitted().await;
    assert!(
        tx.iter().all(|(_, a)| a.kind != Kind::Stored),
        "nothing should be transmitted to a station we cannot hear"
    );

    // The station appears. The welcome goes first and is acknowledged; the
    // held message follows it out of the per-station queue.
    h.station_transmits("SM0ABC-7", AircFrame::new(Kind::Hello, 1, encode_fields(&[""])))
        .await;
    let welcome = h
        .transmitted()
        .await
        .into_iter()
        .find(|(_, a)| a.kind == Kind::Welcome)
        .expect("a station that says HELLO gets a welcome");
    h.ack(&welcome.1).await;
    let tx = h.transmitted().await;
    let (ax, airc) = tx
        .iter()
        .find(|(_, a)| a.kind == Kind::Stored)
        .expect("held mail should be delivered on first contact");
    assert_eq!(ax.destination.call.to_string(), "SM0ABC-7");
    let fields = airc.fields();
    assert_eq!(fields[0], "SM0ABC|7");
    assert_eq!(fields[1], "alice");
    assert_eq!(fields[2], "meet on 145.500 at 1900");
    assert!(fields[3].parse::<u64>().is_ok(), "age in seconds");
    assert!(airc.wants_ack());
}

#[tokio::test]
async fn unknown_nicknames_that_are_not_callsigns_still_fail_normally() {
    let mut h = Harness::new().await;
    h.send("CALLSIGN SM0XYZ");
    h.drain_client();
    h.send("PRIVMSG nosuchperson :hello");
    let lines = h.drain_client();
    assert!(lines.iter().any(|l| l.contains(" 401 ")), "{lines:?}");
}

#[tokio::test]
async fn callsign_nicks_are_reserved_including_casemapping_and_ax25_form() {
    let mut h = Harness::new().await;
    h.drain_client();
    h.send("NICK SM0ABC|7");
    let lines = h.drain_client();
    assert!(lines.iter().any(|l| l.contains(" 432 ")), "{lines:?}");
    h.send("NICK SM0ABC\\7");
    let lines = h.drain_client();
    assert!(lines.iter().any(|l| l.contains(" 432 ")), "{lines:?}");
    h.send("NICK SM0ABC-7");
    let lines = h.drain_client();
    assert!(lines.iter().any(|l| l.contains(" 432 ")), "{lines:?}");
}

#[tokio::test]
async fn rf_quit_reason_cannot_inject_irc_lines() {
    let mut h = Harness::new().await;
    h.send("JOIN #rf");
    h.station_transmits(
        "SM0ABC-7",
        AircFrame::new(Kind::Join, 1, encode_fields(&["#rf"])),
    )
    .await;
    h.drain_client();

    h.station_transmits(
        "SM0ABC-7",
        AircFrame::new(Kind::Quit, 2, b"gone\r\nNOTICE alice :injected".to_vec()),
    )
    .await;
    let lines = h.drain_client();
    assert!(
        lines.iter().any(|l| l.contains("QUIT")),
        "expected a QUIT: {lines:?}"
    );
    assert!(
        lines
            .iter()
            .all(|l| l.contains("QUIT") || !l.contains("NOTICE alice :injected")),
        "CRLF in a QUIT reason must not become a new IRC command: {lines:?}"
    );
}

#[tokio::test]
async fn callsign_alone_does_not_radiate() {
    let mut h = Harness::new().await;
    h.send("CALLSIGN SM0XYZ");
    h.send("JOIN #rf");
    h.station_transmits(
        "SM0ABC-7",
        AircFrame::new(Kind::Join, 1, encode_fields(&["#rf"])),
    )
    .await;
    h.transmitted().await;
    h.drain_client();

    h.send("PRIVMSG #rf :hello radio");
    let lines = h.drain_client();
    assert!(
        lines.iter().any(|l| l.contains("RF-TX") || l.contains("not have RF-TX")),
        "CALLSIGN alone must not radiate: {lines:?}"
    );
    let tx = h.transmitted().await;
    assert!(
        tx.iter().all(|(_, a)| a.kind != Kind::Msg),
        "ordinary IRC clients must not key the transmitter"
    );
}

#[tokio::test]
async fn grant_requires_a_registered_nick_then_survives_identify() {
    let _ = std::fs::remove_file("target/test-nicks-grant.json");
    let toml = r##"
[server]
name = "test.gateway"
[listen]
bind = []
[radio]
enabled = true
callsign = "SK0MT-1"
destination = "AIRC"
id_interval_secs = 60
[radio.tnc]
kind = "loopback"
[accounts]
file = "target/test-nicks-grant.json"
[[channels]]
name = "#rf"
rf = true
[[opers]]
name = "root"
password = "operpass1"
"##;
    let mut h = Harness::from_toml(toml).await;
    h.send("JOIN #rf");
    h.station_transmits(
        "SM0ABC-7",
        AircFrame::new(Kind::Join, 1, encode_fields(&["#rf"])),
    )
    .await;
    h.transmitted().await;
    h.drain_client();

    let mut oper_rx = h.connect_extra(9, "rootop");
    h.server.handle(Event::Line {
        id: 9,
        line: "OPER root operpass1".into(),
    });
    let _ = drain_rx(&mut oper_rx);
    h.server.handle(Event::Line {
        id: 9,
        line: "RADIO GRANT alice".into(),
    });
    let grant_fail = drain_rx(&mut oper_rx);
    assert!(
        grant_fail.iter().any(|l| l.contains("not registered")),
        "{grant_fail:?}"
    );

    h.send("REGISTER secret12");
    h.drain_client();
    h.server.handle(Event::Line {
        id: 9,
        line: "RADIO GRANT alice".into(),
    });
    let grant_ok = drain_rx(&mut oper_rx);
    assert!(
        grant_ok.iter().any(|l| l.contains("stored in the nick file")),
        "{grant_ok:?}"
    );

    h.send("CALLSIGN SM0XYZ");
    h.drain_client();
    h.send("PRIVMSG #rf :after grant");
    h.drain_client();
    let tx = h.transmitted().await;
    assert!(
        tx.iter().any(|(_, a)| a.kind == Kind::Msg && a.fields().last() == Some(&"after grant".to_string())),
        "{tx:?}"
    );
}




#[tokio::test]
async fn frames_addressed_elsewhere_are_ignored() {
    let mut h = Harness::new().await;
    h.drain_client();

    // Addressed to the AIRC protocol address: a broadcast, not ours to act on.
    h.transmits_to(
        "SM0ABC-7",
        "AIRC",
        AircFrame::new(Kind::Join, 1, encode_fields(&["#rf"])),
    )
    .await;
    // Addressed to a different station's callsign entirely.
    h.transmits_to(
        "SM0XYZ-9",
        "SK0AA-1",
        AircFrame::new(Kind::Join, 2, encode_fields(&["#rf"])),
    )
    .await;

    let lines = h.drain_client();
    assert!(
        !lines.iter().any(|l| l.contains("JOIN")),
        "a frame not addressed to this gateway was acted on: {lines:?}"
    );
    assert!(
        h.transmitted().await.is_empty(),
        "the gateway answered traffic that was not addressed to it"
    );
}

#[tokio::test]
async fn a_second_gateways_downlink_does_not_start_a_loop() {
    let mut h = Harness::new().await;
    h.drain_client();

    // Exactly what another ax25ircd on the same frequency puts on the air:
    // a downlink MSG, [channel, from, text], addressed to AIRC. Read as an
    // uplink it would look like a message from SK0AA-1 to "#rf" saying
    // "bob" — which we would then relay and transmit, and so would they.
    h.transmits_to(
        "SK0AA-1",
        "AIRC",
        AircFrame::new(Kind::Msg, 7, encode_fields(&["#rf", "bob", "hello from the other gateway"])),
    )
    .await;

    assert!(
        h.transmitted().await.is_empty(),
        "we answered another gateway's broadcast; two gateways would key each other forever"
    );
    let lines = h.drain_client();
    assert!(
        !lines.iter().any(|l| l.contains("hello from the other gateway")),
        "another gateway's downlink was relayed to IRC: {lines:?}"
    );
}

#[tokio::test]
async fn radio_off_identifies_and_purges_the_queue() {
    let mut h = Harness::new().await;
    h.oper_and_callsign();
    h.send("JOIN #rf");
    h.station_transmits("SM0ABC-7", AircFrame::new(Kind::Hello, 1, Vec::new()))
        .await;
    h.drain_client();
    let before = h.transmitted().await;
    assert!(
        !before.is_empty(),
        "the HELLO should have been answered on the air, so the station owes an ID"
    );

    h.send("RADIO OFF");
    let sent = h.transmitted().await;
    assert!(
        sent.iter().any(|(_, f)| f.kind == Kind::Id),
        "a station that has transmitted must identify before it goes quiet: {:?}",
        sent.iter().map(|(_, f)| f.kind).collect::<Vec<_>>()
    );

    // Nothing more may reach the air after that.
    h.send("PRIVMSG #rf :this must not be transmitted");
    assert!(
        h.transmitted().await.is_empty(),
        "the transmitter kept radiating after RADIO OFF"
    );
}

#[tokio::test]
async fn names_reply_to_rf_is_bounded() {
    let mut h = Harness::new().await;
    h.drain_client();
    // Fill the channel with IP users so an unbounded NAMES would be huge.
    for i in 0..60u64 {
        let mut rx = h.connect_extra(100 + i, &format!("user{i:02}"));
        h.server.handle(Event::Line {
            id: 100 + i,
            line: "JOIN #rf".into(),
        });
        let _ = drain_rx(&mut rx);
    }
    h.station_transmits("SM0ABC-7", AircFrame::new(Kind::Hello, 1, Vec::new()))
        .await;
    h.ack(&AircFrame::new(Kind::Welcome, 0, Vec::new())).await;
    let _ = h.transmitted().await;

    h.station_transmits(
        "SM0ABC-7",
        AircFrame::new(Kind::Join, 2, encode_fields(&["#rf"])),
    )
    .await;
    let sent = h.transmitted().await;
    for (_, f) in &sent {
        if f.kind == Kind::NamesReply {
            assert!(
                f.payload.len() < 400,
                "a NAMES reply of {} octets is minutes of airtime at 300 baud",
                f.payload.len()
            );
        }
    }
}


#[tokio::test]
async fn the_duty_governor_holds_the_transmitter_back() {
    // A real 300-baud HF station: a tight duty allowance and a short run
    // limit. The gateway must refuse to key up past them however much the
    // IRC side wants to talk.
    let toml = CONFIG.replace(
        "[radio.tnc]\nkind = \"loopback\"",
        "[radio.tnc]\nkind = \"loopback\"\n\n[radio.duty]\nenabled = true\nbaud = 300\nwindow_secs = 600\nmax_duty_percent = 5\nmax_continuous_secs = 10\ncooldown_secs = 300\nhourly_airtime_secs = 60\nmax_hold_secs = 5",
    );
    let mut h = Harness::from_toml(&toml).await;
    h.oper_and_callsign();
    h.send("JOIN #rf");
    h.station_transmits("SM0ABC-7", AircFrame::new(Kind::Hello, 1, Vec::new()))
        .await;
    h.drain_client();
    let _ = h.transmitted().await;

    // Twenty full-length messages. At 300 baud each is seconds of airtime,
    // so the 5 % / 600 s allowance is 30 s: only a handful can go out.
    let body = "x".repeat(150);
    for _ in 0..20 {
        h.send(&format!("PRIVMSG #rf :{body}"));
    }
    let sent = h.transmitted().await;
    let msgs = sent.iter().filter(|(_, a)| a.kind == Kind::Msg).count();
    assert!(
        msgs < 20,
        "the governor let all {msgs} messages straight onto the air"
    );

    // And the operator can see why.
    h.drain_client();
    h.send("RADIO DUTY");
    let lines = h.drain_client();
    assert!(
        lines.iter().any(|l| l.contains("duty")),
        "RADIO DUTY told the operator nothing: {lines:?}"
    );
}

#[tokio::test]
async fn config_rejects_a_duty_budget_that_can_never_pass_a_frame() {
    // 1 % of 60 s is 600 ms; a 128-octet frame at 300 baud is several
    // seconds. Nothing would ever be transmitted, and the operator would be
    // left wondering why. Catch it at startup instead.
    let toml = CONFIG.replace(
        "[radio.tnc]\nkind = \"loopback\"",
        "[radio.tnc]\nkind = \"loopback\"\n\n[radio.duty]\nwindow_secs = 60\nmax_duty_percent = 1",
    );
    let err = Config::from_toml(&toml).unwrap_err().to_string();
    assert!(err.contains("duty"), "{err}");
}
