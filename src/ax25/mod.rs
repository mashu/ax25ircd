//! AX.25 link layer: addresses, frames, KISS framing and the TNC link task.

pub mod address;
pub mod frame;
pub mod kiss;
pub mod tnc;

pub use address::Address;
pub use frame::{Ax25Frame, CONTROL_UI, PID_NO_L3};
pub use tnc::{TncConfig, TncHandle, TncLink};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Ax25Error {
    #[error("frame truncated")]
    Truncated,
    #[error("malformed address field")]
    BadAddress,
    #[error("too many digipeaters")]
    TooManyDigipeaters,
}
