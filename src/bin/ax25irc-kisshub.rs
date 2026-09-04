//! `ax25irc-kisshub` - a virtual radio channel.
//!
//! Every TCP client that connects is treated as a station on the same
//! frequency: a KISS frame from one is delivered to all the others, exactly as
//! a shared half-duplex channel would (minus the collisions, the noise and the
//! fun). It exists so the gateway and the station client can be developed,
//! demonstrated and tested end to end without a radio, a TNC or a licence.
//!
//! ```sh
//! ax25irc-kisshub --bind 127.0.0.1:8001 &
//! ax25ircd -c ax25ircd.toml                     # radio.tnc points at 8001
//! ax25irc-station --call SM0ABC-7 --gateway SK0MT-1 --channel '#rf'
//! ```
//!
//! Frames are re-framed rather than forwarded as raw bytes, so a client that
//! writes half a frame cannot corrupt anyone else's stream.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ax25ircd::ax25::kiss::{self, KissDecoder};
use ax25ircd::ax25::Ax25Frame;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};

type Clients = Arc<Mutex<HashMap<u64, mpsc::UnboundedSender<Vec<u8>>>>>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut bind = "127.0.0.1:8001".to_string();
    let mut monitor = true;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" | "-b" => bind = args.next().unwrap_or(bind),
            "--quiet" => monitor = false,
            "--help" | "-h" => {
                println!("usage: ax25irc-kisshub [--bind 127.0.0.1:8001] [--quiet]");
                return Ok(());
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    let listener = TcpListener::bind(&bind).await?;
    println!("virtual channel listening on {bind}");
    let clients: Clients = Arc::new(Mutex::new(HashMap::new()));
    let ids = AtomicU64::new(1);

    loop {
        let (stream, peer) = listener.accept().await?;
        let id = ids.fetch_add(1, Ordering::Relaxed);
        let clients = clients.clone();
        println!("station {id} on channel ({peer})");

        tokio::spawn(async move {
            let (mut read_half, mut write_half) = stream.into_split();
            let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
            clients.lock().await.insert(id, tx);

            let writer = tokio::spawn(async move {
                while let Some(bytes) = rx.recv().await {
                    if write_half.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
            });

            let mut decoder = KissDecoder::new(2048);
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok(n) = read_half.read(&mut buf).await else {
                    break;
                };
                if n == 0 {
                    break;
                }
                for frame in decoder.push(&buf[..n]) {
                    if frame.command != kiss::CMD_DATA {
                        continue; // TXDELAY and friends are local to a TNC.
                    }
                    if monitor {
                        match Ax25Frame::decode(&frame.payload) {
                            Ok(ax) => println!("{}", ax.to_monitor_line()),
                            Err(_) => println!("[{} bytes, undecodable]", frame.payload.len()),
                        }
                    }
                    let wire = kiss::encode(0, kiss::CMD_DATA, &frame.payload);
                    let mut peers = clients.lock().await;
                    peers.retain(|other, tx| *other == id || tx.send(wire.clone()).is_ok());
                }
            }

            clients.lock().await.remove(&id);
            writer.abort();
            println!("station {id} left the channel");
        });
    }
}
