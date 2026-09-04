//! `ax25irc-station` - the client side of the gateway, for an operator with a
//! radio and a TNC.
//!
//! It speaks AIRC/1 (see `docs/PROTOCOL.md`) over KISS and presents a plain
//! line-oriented interface, so it works over ssh, on a Pi with no screen, or
//! piped into anything else.
//!
//! ```sh
//! ax25irc-station --call SM0ABC-7 --gateway SK0MT-1 --channel '#rf'
//! ax25irc-station --call SM0ABC-7 --gateway SK0MT-1 --tnc tcp://192.168.1.10:8001
//! ax25irc-station --call SM0ABC-7 --gateway SK0MT-1 --tnc serial:/dev/ttyUSB0@9600
//! ```
//!
//! Commands: `/join #chan`, `/part #chan`, `/names [#chan]`, `/msg <nick> …`,
//! `/who`, `/ping`, `/quit`. Anything else is sent to the current channel.

use std::time::{Duration, Instant};

use ax25ircd::airc::frame::flags;
use ax25ircd::airc::{encode_fields, AircFrame, Kind, SessionConfig, Sessions};
use ax25ircd::ax25::tnc::{self, TncConfig, TncLink};
use ax25ircd::ax25::Ax25Frame;
use ax25ircd::callsign::Callsign;
use tokio::io::{AsyncBufReadExt, BufReader};

struct Args {
    call: Callsign,
    gateway: Callsign,
    channel: Option<String>,
    link: TncLink,
    paclen: usize,
    path: Vec<Callsign>,
    quiet: bool,
}

fn usage() -> ! {
    eprintln!(
        "usage: ax25irc-station --call <CALL-SSID> --gateway <CALL-SSID> [options]

options:
  --tnc <spec>        tcp://host:port (default tcp://127.0.0.1:8001)
                      serial:/dev/ttyUSB0@9600   (needs --features serial)
  --channel <#chan>   join this channel at startup
  --path <A,B>        digipeater path, at most two hops
  --paclen <n>        AX.25 information field limit (default 128)
  --quiet             do not print protocol chatter
  --help"
    );
    std::process::exit(2)
}

fn parse_args() -> anyhow::Result<Args> {
    let mut call = None;
    let mut gateway = None;
    let mut channel = None;
    let mut tnc_spec = "tcp://127.0.0.1:8001".to_string();
    let mut paclen = 128usize;
    let mut path = Vec::new();
    let mut quiet = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--call" => call = args.next(),
            "--gateway" => gateway = args.next(),
            "--channel" => channel = args.next(),
            "--tnc" => tnc_spec = args.next().unwrap_or(tnc_spec),
            "--paclen" => paclen = args.next().and_then(|v| v.parse().ok()).unwrap_or(paclen),
            "--path" => {
                if let Some(v) = args.next() {
                    for hop in v.split(',').filter(|s| !s.is_empty()) {
                        path.push(hop.parse::<Callsign>()?);
                    }
                }
            }
            "--quiet" => quiet = true,
            "--help" | "-h" => usage(),
            other => {
                eprintln!("unknown argument: {other}");
                usage()
            }
        }
    }

    let (Some(call), Some(gateway)) = (call, gateway) else {
        usage()
    };
    if path.len() > 2 {
        anyhow::bail!("more than two digipeater hops is antisocial");
    }

    let link = if let Some(rest) = tnc_spec.strip_prefix("tcp://") {
        let (host, port) = rest.rsplit_once(':').unwrap_or((rest, "8001"));
        TncLink::Tcp {
            host: host.to_string(),
            port: port.parse()?,
        }
    } else if let Some(rest) = tnc_spec.strip_prefix("serial:") {
        let (device, baud) = rest.split_once('@').unwrap_or((rest, "9600"));
        let _ = (device, baud);
        #[cfg(feature = "serial")]
        {
            TncLink::Serial {
                path: device.to_string(),
                baud: baud.parse()?,
            }
        }
        #[cfg(not(feature = "serial"))]
        {
            anyhow::bail!("this build has no serial support; rebuild with --features serial")
        }
    } else {
        anyhow::bail!("unrecognised --tnc spec: {tnc_spec}");
    };

    Ok(Args {
        call: call.parse()?,
        gateway: gateway.parse()?,
        channel,
        link,
        paclen,
        path,
        quiet,
    })
}

struct Station {
    args: Args,
    tnc: tnc::TncHandle,
    sessions: Sessions,
    current: Option<String>,
}

impl Station {
    /// Queue a message for the gateway. Everything a station sends is unicast
    /// to the gateway, so `reliable` is nearly always the right choice - the
    /// exception is chat, where a stale retransmission is worse than a loss.
    fn send(&mut self, kind: Kind, payload: Vec<u8>, reliable: bool) {
        let now = Instant::now();
        let gateway = self.args.gateway.clone();
        let frames = self.sessions.send(&gateway, kind, payload, reliable, now);
        for f in frames {
            self.transmit(f);
        }
    }

    fn transmit(&mut self, frame: AircFrame) {
        match Ax25Frame::ui(
            self.args.call.clone(),
            self.args.gateway.clone(),
            &self.args.path,
            frame.encode(),
        ) {
            Ok(ax) => {
                if !self.tnc.try_send(ax) {
                    println!("!! transmit queue full, message dropped");
                }
            }
            Err(e) => println!("!! cannot build frame: {e}"),
        }
    }

    fn handle_input(&mut self, line: &str) -> bool {
        let line = line.trim();
        if line.is_empty() {
            return true;
        }
        let (cmd, rest) = match line.split_once(' ') {
            Some((c, r)) => (c, r.trim()),
            None => (line, ""),
        };
        match cmd {
            "/quit" | "/q" => {
                self.send(Kind::Quit, encode_fields(&[rest]), false);
                return false;
            }
            "/join" | "/j" => {
                if rest.is_empty() {
                    println!("usage: /join #channel");
                } else {
                    self.send(Kind::Join, encode_fields(&[rest]), true);
                    self.current = Some(rest.to_string());
                }
            }
            "/part" => {
                let chan = if rest.is_empty() {
                    self.current.clone().unwrap_or_default()
                } else {
                    rest.to_string()
                };
                if !chan.is_empty() {
                    self.send(Kind::Part, encode_fields(&[&chan]), true);
                    if self.current.as_deref() == Some(chan.as_str()) {
                        self.current = None;
                    }
                }
            }
            "/names" | "/who" => {
                let chan = if rest.is_empty() {
                    self.current.clone().unwrap_or_default()
                } else {
                    rest.to_string()
                };
                if chan.is_empty() {
                    println!("join a channel first");
                } else {
                    self.send(Kind::Names, encode_fields(&[&chan]), true);
                }
            }
            "/msg" | "/m" => match rest.split_once(' ') {
                Some((who, text)) if !text.is_empty() => {
                    self.send(Kind::Msg, encode_fields(&[who, text]), true);
                    println!("-> {who}: {text}");
                }
                _ => println!("usage: /msg <nick> <text>"),
            },
            "/ping" => self.send(Kind::Ping, encode_fields(&["s"]), false),
            "/help" => {
                println!("/join #chan  /part  /names  /msg <nick> <text>  /ping  /quit");
            }
            _ if cmd.starts_with('/') => println!("unknown command: {cmd}"),
            _ => {
                let Some(chan) = self.current.clone() else {
                    println!("join a channel first: /join #rf");
                    return true;
                };
                // Chat is sent unreliably: on a broadcast channel a
                // retransmission arriving thirty seconds late is noise.
                self.send(Kind::Msg, encode_fields(&[&chan, line]), false);
            }
        }
        true
    }

    fn handle_rf(&mut self, ax: Ax25Frame) {
        if ax.source.call != self.args.gateway {
            return;
        }
        // Unicast traffic for somebody else on frequency is not ours to read
        // or acknowledge. A protocol address such as AIRC is a broadcast and
        // never looks like an amateur callsign.
        let dest = &ax.destination.call;
        if dest.looks_like_amateur_call() && *dest != self.args.call {
            return;
        }
        let Ok(frame) = AircFrame::decode(&ax.info) else {
            return;
        };
        let now = Instant::now();
        let gateway = self.args.gateway.clone();
        let outcome = self.sessions.on_receive(&gateway, frame, now);
        for f in outcome.transmit {
            self.transmit(f);
        }
        let Some(msg) = outcome.deliver else {
            return;
        };
        let f = msg.fields();
        let stale = if msg.flags & flags::RETRY != 0 { " (repeat)" } else { "" };
        match msg.kind {
            Kind::Msg | Kind::Notice => {
                let (target, from, text) = (
                    f.first().cloned().unwrap_or_default(),
                    f.get(1).cloned().unwrap_or_default(),
                    f.get(2).cloned().unwrap_or_default(),
                );
                if target.starts_with('#') || target.starts_with('&') {
                    println!("{target} <{from}> {text}{stale}");
                } else {
                    println!("*{from}* {text}{stale}");
                }
            }
            Kind::Stored => {
                let from = f.get(1).cloned().unwrap_or_default();
                let text = f.get(2).cloned().unwrap_or_default();
                let age = f
                    .get(3)
                    .and_then(|a| a.parse::<u64>().ok())
                    .map(human_age)
                    .unwrap_or_else(|| "earlier".into());
                println!("*{from}* [held {age}] {text}");
            }
            Kind::Welcome => {
                println!("-- connected to {} : {}", f.first().cloned().unwrap_or_default(), f.get(1).cloned().unwrap_or_default());
            }
            Kind::NamesReply => {
                let chan = f.first().cloned().unwrap_or_default();
                println!("-- {chan} members: {}", f.get(1).cloned().unwrap_or_default());
                if let Some(topic) = f.get(2).filter(|t| !t.is_empty()) {
                    println!("-- {chan} topic: {topic}");
                }
            }
            Kind::Presence => {
                let sign = f.get(2).cloned().unwrap_or_default();
                let verb = if sign == "+" { "joined" } else { "left" };
                println!(
                    "-- {} {verb} {}",
                    f.get(1).cloned().unwrap_or_default(),
                    f.first().cloned().unwrap_or_default()
                );
            }
            Kind::Error => println!("!! {}", f.join(" ")),
            Kind::Pong => {
                if !self.args.quiet {
                    println!("-- pong");
                }
            }
            Kind::Id => {
                if !self.args.quiet {
                    println!("-- {}", f.join(" "));
                }
            }
            _ => {}
        }
    }
}

fn human_age(secs: u64) -> String {
    match secs {
        0..=90 => format!("{secs}s"),
        91..=5400 => format!("{}m", secs / 60),
        _ => format!("{}h", secs / 3600),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = parse_args()?;
    let cfg = TncConfig {
        link: args.link.clone(),
        kiss_port: 0,
        max_frame: args.paclen + 32,
        tx_pacing: Duration::from_millis(800),
        tx_queue_depth: 32,
        txdelay: None,
        persistence: None,
        slottime: None,
    };
    let (tnc, mut rf_rx) = tnc::spawn(cfg);
    let sessions = Sessions::new(SessionConfig {
        paclen: args.paclen,
        ..Default::default()
    });

    println!(
        "-- {} calling gateway {} ; /help for commands",
        args.call, args.gateway
    );
    let channel = args.channel.clone();
    let mut station = Station {
        args,
        tnc,
        sessions,
        current: None,
    };

    station.send(Kind::Hello, encode_fields(&["ax25irc-station/1"]), true);
    if let Some(chan) = channel {
        station.send(Kind::Join, encode_fields(&[&chan]), true);
        station.current = Some(chan);
    }

    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            frame = rf_rx.recv() => match frame {
                Some(ax) => station.handle_rf(ax),
                None => break,
            },
            line = stdin.next_line() => match line {
                Ok(Some(line)) => {
                    if !station.handle_input(&line) {
                        break;
                    }
                }
                Ok(None) | Err(_) => break,
            },
            _ = ticker.tick() => {
                let now = Instant::now();
                let outcome = station.sessions.tick(now);
                for (_, f) in outcome.transmit {
                    station.transmit(f);
                }
                if !outcome.lost.is_empty() {
                    println!("!! the gateway is not answering");
                }
            }
        }
    }

    println!("-- 73");
    Ok(())
}
