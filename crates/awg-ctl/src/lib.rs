//! The AmneziaWG plugin's service: one process that keeps every AmneziaWG
//! tunnel the router names, told what to be through the plugin's channel
//! and reporting what it is. The channel, the socket, signals and the log
//! are `routeh-plugin-sdk`'s; here is what the plugin does.
//!
//! A client only: one peer per tunnel, its endpoint an address and port.

pub mod config;
pub mod engine;
#[cfg(target_os = "linux")]
pub mod kernel;
mod plugin;

pub use plugin::Awg;
