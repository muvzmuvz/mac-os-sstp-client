//! SSTP + PPP protocol engine, kept free of GUI dependencies so it builds
//! and tests in seconds. See the workspace root `README.md` for the overall
//! design (this crate is the protocol/network layer; `sstp-gui`, the parent
//! crate, is the UI and macOS integration).

pub mod chap;
pub mod chap_fsm;
pub mod cmac;
#[cfg(target_os = "macos")]
pub mod connection;
pub mod cp;
pub mod engine;
pub mod http;
pub mod ipcp;
pub mod lcp;
pub mod mppe;
pub mod packet;
pub mod ppp;
pub mod tls;
#[cfg(target_os = "macos")]
pub mod utun;
