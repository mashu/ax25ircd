//! ax25ircd - IRC server with an AX.25 packet radio gateway.
//!
//! Usage: `ax25ircd [--config path] [--check]`

use std::fs::OpenOptions;
use std::sync::atomic::AtomicU64;
use std::sync::Mutex;
use std::sync::Arc;
use std::time::Duration;

use ax25ircd::ax25::tnc::{self, TncConfig, TncLink};
use ax25ircd::config::Config;
use ax25ircd::irc::client::{listen, ListenerOptions};
use ax25ircd::server::{self, Event, Server};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut path = "ax25ircd.toml".to_string();
    let mut check_only = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" | "-c" => path = args.next().unwrap_or(path),
            "--check" => check_only = true,
            "--version" | "-V" => {
                println!("ax25ircd {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--help" | "-h" => {
                print!(
                    "\
ax25ircd {} — IRC server with an AX.25 packet-radio gateway

Usage: ax25ircd [--config path] [--check]

  -c, --config <path>   configuration file (default: ax25ircd.toml)
      --check           validate the configuration and exit
  -V, --version         print version
  -h, --help            this help

QMX on Debian: https://mashu.github.io/ax25ircd/
",
                    env!("CARGO_PKG_VERSION")
                );
                return Ok(());
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    let config = Config::load(&path)?;
    if check_only {
        println!("{path}: configuration is valid");
        return Ok(());
    }

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "ax25ircd=info".into());
    let stdout = tracing_subscriber::fmt::layer();
    if let Some(log_path) = &config.logging.file {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;
        let file_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(Mutex::new(file));
        tracing_subscriber::registry()
            .with(filter)
            .with(stdout)
            .with(file_layer)
            .init();
        info!(path = %log_path, "logging to file");
    } else {
        tracing_subscriber::registry().with(filter).with(stdout).init();
    }

    let config = Arc::new(config);

    // Radio link.
    let (tnc_handle, rf_rx) = if config.radio.enabled {
        let section = &config.radio.tnc;
        let link = match section.kind.as_str() {
            "tcp" => TncLink::Tcp {
                host: section.host.clone(),
                port: section.port,
            },
            #[cfg(feature = "serial")]
            "serial" => TncLink::Serial {
                path: section.device.clone(),
                baud: section.baud,
            },
            #[cfg(not(feature = "serial"))]
            "serial" => {
                anyhow::bail!("this build has no serial support; rebuild with --features serial")
            }
            "loopback" => {
                warn!("TNC kind is 'loopback': nothing will be transmitted");
                TncConfig::loopback().0.link
            }
            other => anyhow::bail!("unknown radio.tnc.kind: {other}"),
        };
        let cfg = TncConfig {
            link,
            kiss_port: section.kiss_port,
            // paclen is the *information* field. A full AX.25 header with
            // eight digipeaters is 58 octets on top of it; +32 silently
            // discarded long-path frames we were perfectly able to decode.
            max_frame: config.radio.paclen + 64,
            tx_pacing: Duration::from_millis(section.tx_pacing_ms),
            tx_queue_depth: 64,
            txdelay: section.txdelay,
            persistence: section.persistence,
            slottime: section.slottime,
            airtime: config.radio.duty.to_airtime(),
        };
        let (handle, rx) = tnc::spawn(cfg);
        info!(
            callsign = %config.radio.callsign,
            "radio gateway enabled; identifying every {} s",
            config.radio.id_interval_secs
        );
        (Some(handle), Some(rx))
    } else {
        info!("radio gateway disabled; running as a plain IRC server");
        (None, None)
    };

    let (events_tx, events_rx) = mpsc::channel::<Event>(1024);
    let mut server = Server::new(config.clone(), tnc_handle);
    server.attach_events(events_tx.clone());

    // Feed received frames into the event loop.
    if let Some(mut rf_rx) = rf_rx {
        let tx = events_tx.clone();
        tokio::spawn(async move {
            while let Some(frame) = rf_rx.recv().await {
                if tx.send(Event::Rf(frame)).await.is_err() {
                    break;
                }
            }
        });
    }

    // IRC listeners.
    let ids = Arc::new(AtomicU64::new(1));
    let opts = ListenerOptions {
        ping_interval: Duration::from_secs(config.listen.ping_interval_secs),
    };
    for addr in &config.listen.bind {
        let addr = addr.clone();
        let tx = events_tx.clone();
        let ids = ids.clone();
        let opts = opts.clone();
        tokio::spawn(async move {
            if let Err(e) = listen(addr.clone(), tx, ids, opts).await {
                error!(%addr, "listener failed: {e}");
            }
        });
    }

    // Shutdown: identify, then stop.
    let shutdown_tx = events_tx.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            info!("shutting down");
            let _ = shutdown_tx.send(Event::Shutdown).await;
        }
    });

    server::run(server, events_rx).await;
    Ok(())
}
