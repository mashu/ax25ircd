//! `ax25ircd` - an IRC server that is also an AX.25 packet radio gateway.
//!
//! Layering, from the antenna up:
//!
//! ```text
//!   radio  --  KISS TNC  --  ax25::tnc      link, framing, TX pacing
//!                            ax25::frame    AX.25 UI frames, callsign addressing
//!                            airc::frame    AIRC/1 compact application protocol
//!                            airc::session  sequencing, ACKs, fragmentation
//!                            bridge         RF <-> IRC translation and policy
//!                            server         users, channels, event loop
//!                            irc::client    RFC 1459 over TCP
//!   IRC client  --  TCP  ----'
//! ```
//!
//! The two sides never share a lock: everything meets in a single-threaded
//! event loop in [`server::run`].

pub mod airc;
pub mod ax25;
pub mod accounts;
pub mod audit;
pub mod bridge;
pub mod callsign;
pub mod config;
pub mod irc;
pub mod policy;
pub mod server;

pub use callsign::Callsign;
pub use config::Config;
pub use server::{Event, Server};
