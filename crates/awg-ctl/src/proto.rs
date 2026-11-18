//! The channel with the router: one JSON object a line, every message
//! whole. What the plugin sends is at most 64 KiB a line; `desired` has no
//! limit of its own.
//!
//! The router owns this contract; these are its types as the plugin needs
//! them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL: u32 = 1;
/// The longest line the plugin may send.
pub const MAX_LINE: usize = 64 * 1024;

#[derive(Debug, Serialize)]
pub struct Hello {
    pub protocol: u32,
    pub plugin: &'static str,
    pub version: &'static str,
}

/// What the router sends.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Incoming {
    Desired(Desired),
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Desired {
    pub digest: String,
    /// `[plugins.awg]`; this plugin has none.
    #[serde(default)]
    pub settings: Value,
    #[serde(default)]
    pub instances: BTreeMap<String, Instance>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Instance {
    pub kind: String,
    pub device: String,
    pub mark: u32,
    #[serde(default)]
    pub settings: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Starting,
    Connecting,
    Up,
    Down,
    Error,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct State {
    pub digest: Option<String>,
    pub settled: bool,
    pub values: BTreeMap<&'static str, Value>,
    pub instances: BTreeMap<String, InstanceState>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InstanceState {
    pub phase: Phase,
    pub message: String,
    pub peer: Option<String>,
    pub values: BTreeMap<&'static str, Value>,
}

/// One line of the channel, with its newline.
pub fn line<T: Serialize>(tag: &str, body: &T) -> String {
    let mut s = serde_json::to_string(&serde_json::json!({ tag: body })).expect("serializable");
    s.push('\n');
    s
}
