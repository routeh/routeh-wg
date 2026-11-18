//! The AmneziaWG plugin's service: one process that keeps every AmneziaWG
//! tunnel the router names, told what to be through the plugin's channel
//! and reporting what it is.
//!
//! A client only: one peer per tunnel, its endpoint an address and port.

pub mod base64;
pub mod config;
pub mod engine;
#[cfg(target_os = "linux")]
pub mod kernel;
pub mod log;
pub mod proto;
pub mod server;
