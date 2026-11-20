//! The plugin as the SDK runs it: every `desired` and every tick
//! converged by the engine, what it did written to the system log.

use std::time::{Duration, SystemTime};

use routeh_plugin_sdk::{Desired, Log, Plugin, State};
use serde_json::Value;

use crate::engine::{Engine, Kernel};

/// How often the devices are read again (and repaired): the module sends
/// no events.
pub const TICK: Duration = Duration::from_secs(5);

/// The AmneziaWG plugin over a kernel: the module's netlink in a bundle,
/// a mock in tests.
pub struct Awg<K> {
    engine: Engine<K>,
}

impl<K: Kernel> Awg<K> {
    pub fn new(kernel: K) -> Self {
        Self { engine: Engine::new(kernel) }
    }

    fn flush(&mut self, log: &Log) {
        for (key, text) in self.engine.log.drain(..) {
            match key {
                Some(key) => log.instance(&key).info(text),
                None => log.info(text),
            }
        }
    }
}

impl<K: Kernel> Plugin for Awg<K> {
    const ID: &'static str = "awg";
    /// The plugin's version, set by its build (`ROUTEH_PLUGIN_VERSION`);
    /// the crate's otherwise.
    const VERSION: &'static str = match option_env!("ROUTEH_PLUGIN_VERSION") {
        Some(version) => version,
        None => env!("CARGO_PKG_VERSION"),
    };
    /// The plugin has no settings of its own.
    type Settings = Value;
    /// A tunnel's settings, read by the engine so that one it refuses is
    /// that tunnel's error, not the whole `desired`'s.
    type Instance = Value;

    fn converge(&mut self, desired: &Desired, log: &Log) -> State {
        self.engine.set_desired(desired.clone());
        self.engine.converge();
        self.flush(log);
        self.engine.state(SystemTime::now())
    }

    fn tick(&self) -> Option<Duration> {
        Some(TICK)
    }

    /// Every device of every tunnel is removed: the plugin is stopped.
    fn shutdown(&mut self, log: &Log) {
        self.engine.shutdown();
        self.flush(log);
    }
}
