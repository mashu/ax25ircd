//! The TNC task itself: framing, pacing, the inhibit, and the safety
//! interlock, driven through a loopback link.
//!
//! These are the parts between the server and the radio, and they are the
//! parts a unit test on either side skips.

use std::sync::atomic::Ordering;
use std::time::Duration;

use ax25ircd::ax25::airtime::AirtimeConfig;
use ax25ircd::ax25::kiss::{self, KissDecoder};
use ax25ircd::ax25::tnc::{self, TncConfig};
use ax25ircd::ax25::Ax25Frame;
use ax25ircd::interlock::{self, Check};
use ax25ircd::config::InterlockConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

fn frame(from: &str, info: &[u8]) -> Ax25Frame {
    Ax25Frame::ui(
        from.parse().unwrap(),
        "AIRC".parse().unwrap(),
        &[],
        info.to_vec(),
    )
    .unwrap()
}

/// Read whatever the TNC task has written, decoding KISS.
async fn drain(far: &mut DuplexStream, decoder: &mut KissDecoder) -> Vec<kiss::KissFrame> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_millis(150), far.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => out.extend(decoder.push(&buf[..n])),
            _ => break,
        }
    }
    out
}

fn fast() -> AirtimeConfig {
    AirtimeConfig {
        baud: 9600,
        txdelay: Duration::from_millis(10),
        txtail: Duration::from_millis(10),
        ..AirtimeConfig::default()
    }
}

/// A TNC on a loopback link. The receive channel is handed back with the rest
/// even when a test does not read it: dropping it makes the TNC task stop
/// after the first received frame, which would be a confusing way for an
/// unrelated assertion to fail later.
fn spawn(
    airtime: AirtimeConfig,
    max_frame: usize,
) -> (tnc::TncHandle, DuplexStream, mpsc::Receiver<Ax25Frame>) {
    let (link, far) = TncConfig::loopback_link();
    let (handle, rx) = tnc::spawn(TncConfig {
        link,
        max_frame,
        tx_pacing: Duration::from_millis(0),
        airtime,
        ..TncConfig::default()
    });
    (handle, far, rx)
}

#[tokio::test]
async fn frames_are_transmitted_and_the_backlog_is_released() {
    let (tnc, mut far, _rx) = spawn(fast(), 512);
    let mut dec = KissDecoder::new(1024);
    let _ = drain(&mut far, &mut dec).await; // the parameter frames

    assert!(tnc.try_send(frame("SK0MT-1", b"hello")));
    assert!(
        tnc.queued() > Duration::ZERO,
        "a queued frame should be counted as queued airtime"
    );

    let frames = drain(&mut far, &mut dec).await;
    let data: Vec<_> = frames
        .iter()
        .filter(|f| f.command == kiss::CMD_DATA)
        .collect();
    assert_eq!(data.len(), 1);
    assert_eq!(Ax25Frame::decode(&data[0].payload).unwrap().info, b"hello");

    // Once it is on the air it is no longer queued.
    for _ in 0..20 {
        if tnc.queued() == Duration::ZERO {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(tnc.queued(), Duration::ZERO, "the backlog was not released");
    assert_eq!(tnc.airtime().queued_frame_count(), 0);
}

#[tokio::test]
async fn received_frames_reach_the_server() {
    let (link, mut far) = TncConfig::loopback_link();
    let (_tnc, mut rx) = tnc::spawn(TncConfig {
        link,
        max_frame: 512,
        tx_pacing: Duration::from_millis(0),
        kiss_port: 3,
        airtime: fast(),
        ..TncConfig::default()
    });

    // A frame on our KISS port arrives.
    let ours = frame("SM0ABC-7", b"for us");
    far.write_all(&kiss::encode(3, kiss::CMD_DATA, &ours.encode()))
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("nothing arrived")
        .unwrap();
    assert_eq!(got.info, b"for us");

    // A frame on a different port of the same TNC is another radio.
    let theirs = frame("SM0XYZ-1", b"other port");
    far.write_all(&kiss::encode(5, kiss::CMD_DATA, &theirs.encode()))
        .await
        .unwrap();
    // A non-data frame is not AX.25 either.
    far.write_all(&kiss::encode(3, kiss::CMD_TXDELAY, &[40]))
        .await
        .unwrap();
    // Undecodable bytes on our port.
    far.write_all(&kiss::encode(3, kiss::CMD_DATA, b"\x01\x02"))
        .await
        .unwrap();
    // Then something good again, to prove the stream resynchronised.
    let good = frame("SM0ABC-7", b"still here");
    far.write_all(&kiss::encode(3, kiss::CMD_DATA, &good.encode()))
        .await
        .unwrap();

    let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("the good frame never arrived")
        .unwrap();
    assert_eq!(
        got.info, b"still here",
        "the wrong-port, parameter and undecodable frames should all have been skipped"
    );
}

#[tokio::test]
async fn an_oversized_frame_is_refused_rather_than_transmitted() {
    // max_frame smaller than the frame we hand it.
    let (tnc, mut far, _rx) = spawn(fast(), 40);
    let mut dec = KissDecoder::new(4096);
    let _ = drain(&mut far, &mut dec).await;

    assert!(tnc.try_send(frame("SK0MT-1", &[0x41; 200])));
    let frames = drain(&mut far, &mut dec).await;
    assert!(
        frames.iter().all(|f| f.command != kiss::CMD_DATA),
        "a frame past max_frame must not reach the radio"
    );
    // And the backlog it reserved is given back.
    for _ in 0..20 {
        if tnc.queued() == Duration::ZERO {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        tnc.queued(),
        Duration::ZERO,
        "a refused frame must not leave its airtime reserved forever"
    );
}

#[tokio::test]
async fn the_inhibit_purges_the_queue_but_identification_still_goes_out() {
    let (tnc, mut far, _rx) = spawn(fast(), 512);
    let mut dec = KissDecoder::new(1024);
    let _ = drain(&mut far, &mut dec).await;

    tnc.set_inhibit(true);
    assert!(tnc.inhibited());
    for i in 0..5 {
        tnc.try_send(frame("SK0MT-1", format!("chat {i}").as_bytes()));
    }
    let frames = drain(&mut far, &mut dec).await;
    assert!(
        frames.iter().all(|f| f.command != kiss::CMD_DATA),
        "nothing may be radiated while the transmitter is inhibited"
    );
    assert!(tnc.airtime().dropped_inhibited.load(Ordering::Relaxed) > 0);

    // The sign-off ID is the one exception: RADIO OFF queues it precisely so
    // the station can put its callsign to what it already transmitted.
    assert!(tnc.try_send_id(frame("SK0MT-1", b"SK0MT-1 gateway")));
    let frames = drain(&mut far, &mut dec).await;
    assert_eq!(
        frames
            .iter()
            .filter(|f| f.command == kiss::CMD_DATA)
            .count(),
        1,
        "the sign-off ID must survive the inhibit"
    );

    // Lifting it lets traffic through again.
    tnc.set_inhibit(false);
    tnc.try_send(frame("SK0MT-1", b"back on"));
    let frames = drain(&mut far, &mut dec).await;
    assert!(frames.iter().any(|f| f.command == kiss::CMD_DATA));
}

#[tokio::test]
async fn the_safety_interlock_stops_even_identification() {
    let (tnc, mut far, _rx) = spawn(fast(), 512);
    let mut dec = KissDecoder::new(1024);
    let _ = drain(&mut far, &mut dec).await;

    tnc.airtime().interlock_ok.store(false, Ordering::Relaxed);
    assert!(tnc.airtime().tx_blocked());
    assert!(tnc.airtime().interlock_failed());

    tnc.try_send(frame("SK0MT-1", b"traffic"));
    tnc.try_send_id(frame("SK0MT-1", b"SK0MT-1 gateway"));
    let frames = drain(&mut far, &mut dec).await;
    assert!(
        frames.iter().all(|f| f.command != kiss::CMD_DATA),
        "if it is not safe to key up, it is not safe to key up for an ID either"
    );

    tnc.airtime().interlock_ok.store(true, Ordering::Relaxed);
    tnc.try_send_id(frame("SK0MT-1", b"SK0MT-1 gateway"));
    let frames = drain(&mut far, &mut dec).await;
    assert!(frames.iter().any(|f| f.command == kiss::CMD_DATA));
}

#[tokio::test]
async fn a_full_transmit_queue_refuses_rather_than_blocking() {
    let (link, _far) = TncConfig::loopback_link();
    let (tnc, _rx) = tnc::spawn(TncConfig {
        link,
        max_frame: 512,
        // Slow enough that the queue cannot drain during the test.
        tx_pacing: Duration::from_secs(30),
        tx_queue_depth: 4,
        airtime: fast(),
        ..TncConfig::default()
    });
    let mut refused = 0;
    for i in 0..50 {
        if !tnc.try_send(frame("SK0MT-1", format!("{i}").as_bytes())) {
            refused += 1;
        }
    }
    assert!(
        refused > 0,
        "try_send must report a full queue rather than growing it"
    );
}

#[tokio::test]
async fn a_control_operator_can_slow_the_station_down_at_runtime() {
    let (tnc, _far, _rx) = spawn(fast(), 512);
    let air = tnc.airtime();

    assert_eq!(air.duty_limit(0.25), 0.25);
    assert_eq!(air.set_duty_override(Some(10)), Some(10));
    assert_eq!(air.duty_limit(0.25), 0.10);
    // Never above the ceiling, whatever is asked for.
    assert_eq!(air.set_duty_override(Some(99)), Some(50));
    assert_eq!(air.duty_limit(0.25), 0.5);
    assert_eq!(air.set_duty_override(None), None);
    assert_eq!(air.duty_limit(0.25), 0.25);

    assert_eq!(air.pacing(Duration::from_millis(800)), Duration::from_millis(800));
    air.set_pacing_override(Some(4000));
    assert_eq!(air.pacing(Duration::from_millis(800)), Duration::from_millis(4000));
    air.set_pacing_override(None);
    assert_eq!(air.pacing(Duration::from_millis(800)), Duration::from_millis(800));

    let summary = air.summary();
    assert!(summary.contains("duty") && summary.contains("queued"), "{summary}");
}

#[tokio::test]
async fn a_tnc_that_is_not_there_is_retried_not_fatal() {
    // Nothing is listening on this port.
    let (tnc, _rx) = tnc::spawn(TncConfig {
        link: ax25ircd::ax25::TncLink::Tcp {
            host: "127.0.0.1".into(),
            port: 1,
        },
        airtime: fast(),
        ..TncConfig::default()
    });
    // The handle stays usable and the process stays up; frames queue and are
    // eventually dropped rather than panicking anything.
    for _ in 0..10 {
        tnc.try_send(frame("SK0MT-1", b"into the void"));
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!tnc.inhibited(), "a missing TNC is not an inhibit");
}

// ------------------------------------------------------------------- interlock

fn interlock_cfg(command: &str, args: &[&str]) -> InterlockConfig {
    InterlockConfig {
        command: command.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        interval_secs: 1,
        timeout_secs: 1,
    }
}

#[tokio::test]
async fn the_interlock_poller_tracks_the_command() {
    let dir = std::env::temp_dir().join(format!(
        "ax25ircd-interlock-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let flag = dir.join("swr-ok");

    // "SWR is fine" means the file exists.
    let cfg = interlock_cfg("test", &["-f", flag.to_str().unwrap()]);
    let shared = std::sync::Arc::new(ax25ircd::ax25::AirtimeShared::default());
    interlock::spawn(cfg, shared.clone());

    // It starts blocked: nothing has passed yet.
    assert!(
        shared.interlock_failed(),
        "an interlock that has not run yet must fail closed"
    );

    // Once the check passes, transmitting is permitted.
    std::fs::write(&flag, b"ok").unwrap();
    let mut passed = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if !shared.interlock_failed() {
            passed = true;
            break;
        }
    }
    assert!(passed, "the interlock never recovered");

    // And when it fails again, the transmitter goes down with it.
    std::fs::remove_file(&flag).unwrap();
    let mut blocked = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if shared.interlock_failed() {
            blocked = true;
            break;
        }
    }
    assert!(blocked, "a failing interlock must inhibit the transmitter");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn interlock_failures_are_reported_in_the_command_s_own_words() {
    assert_eq!(interlock::run_once(&interlock_cfg("true", &[])).await, Check::Pass);

    let c = interlock_cfg("sh", &["-c", "echo 'SWR 3.8:1 on 40m' >&2; exit 1"]);
    let check = interlock::run_once(&c).await;
    assert!(!check.is_pass());
    assert!(check.reason().contains("SWR 3.8:1"), "{}", check.reason());

    // Output on stdout is used when stderr is empty.
    let c = interlock_cfg("sh", &["-c", "echo 'PA too hot'; exit 2"]);
    assert!(interlock::run_once(&c).await.reason().contains("PA too hot"));

    // A command that says nothing at all still explains itself.
    let c = interlock_cfg("false", &[]);
    let check = interlock::run_once(&c).await;
    assert!(check.reason().contains("exited"), "{}", check.reason());
    assert_eq!(Check::Pass.reason(), "ok");
}

#[tokio::test]
async fn the_backlog_is_not_leaked_when_the_tnc_link_dies() {
    // A "TNC" that drops the first few connections and then behaves —
    // Direwolf restarting, a flaky USB serial adapter, a network TNC on a bad
    // link. Once it settles, everything queued must drain and the airtime
    // accounting must come back to zero. Anything left is a reservation that
    // was made and never released, and it is permanent: admission control
    // subtracts it from the backlog budget forever.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut attempt = 0u32;
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            attempt += 1;
            if attempt <= 4 {
                // Let the client write, then hang up mid-conversation.
                tokio::time::sleep(Duration::from_millis(40)).await;
                continue;
            }
            // From now on, read everything and stay up.
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while stream.read(&mut buf).await.unwrap_or(0) > 0 {}
            });
        }
    });

    let (tnc, _rx) = tnc::spawn(TncConfig {
        link: ax25ircd::ax25::TncLink::Tcp {
            host: "127.0.0.1".into(),
            port: addr.port(),
        },
        max_frame: 512,
        tx_pacing: Duration::from_millis(0),
        tx_queue_depth: 64,
        airtime: fast(),
        ..TncConfig::default()
    });

    // A burst per cycle, not one frame: the first frame of each connection
    // goes out at once (the pacing gate starts open), so only a burst leaves
    // a frame sitting in the pump's pending slot when the link dies. That is
    // the frame whose reservation can be lost.
    let mut sent = 0;
    for _ in 0..6 {
        for _ in 0..4 {
            if tnc.try_send(frame("SK0MT-1", b"into a dying link")) {
                sent += 1;
            }
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    // Now give it plenty of time on the healthy connection to drain.
    for _ in 0..60 {
        if tnc.queued() == Duration::ZERO && tnc.airtime().queued_frame_count() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!(
        "after the link recovered, {:?} of airtime in {} frame(s) is still counted as \
         queued out of {sent} sent: a frame held when the link dropped never released \
         its reservation",
        tnc.queued(),
        tnc.airtime().queued_frame_count(),
    );
}
