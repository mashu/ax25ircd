//! The IRC side: wire format, numerics and the per-client connection task.

pub mod client;
pub mod message;
pub mod numerics;
pub mod tls;

pub use message::Message;
