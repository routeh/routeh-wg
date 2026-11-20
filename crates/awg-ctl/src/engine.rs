//! Converging the module's devices to `desired`, and the `state` of them.
//!
//! Pure over the `Kernel` trait, so it is tested with a mock on any system.
//! `desired` and `state` are the SDK's (`routeh-plugin-sdk`).

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime};

use awg_netlink::{Device, DeviceUpdate, Error, Key, PeerUpdate};
use routeh_plugin_sdk::protocol::base64;
use routeh_plugin_sdk::{Desired, InstanceState, Phase, State};
use serde_json::json;

use crate::config::TunnelConfig;

/// Every device the router names for a tunnel starts so.
/// A device of the module's kind with this prefix that `desired` does not
/// name is the plugin's, left from before, and is removed; nothing else is
/// ever touched.
pub const DEVICE_PREFIX: &str = "tn_";

/// WireGuard's `REJECT_AFTER_TIME`: a session with no handshake for longer
/// carries nothing.
const REJECT_AFTER: u64 = 180;

const ENODEV: i32 = 19;
const EOPNOTSUPP: i32 = 95;

pub trait Kernel {
    /// Whether the module is there; the text says why not.
    fn ready(&mut self) -> Result<(), String>;
    /// Names of the module's devices.
    fn links(&mut self) -> Result<Vec<String>, Error>;
    fn create(&mut self, name: &str) -> Result<(), Error>;
    fn delete(&mut self, name: &str) -> Result<(), Error>;
    fn get(&mut self, name: &str) -> Result<Device, Error>;
    fn set(&mut self, u: &DeviceUpdate) -> Result<(), Error>;
    fn module_version(&mut self) -> Option<String>;
}

#[derive(Default)]
struct Tunnel {
    device: String,
    /// What this process last applied; `None` after a start, when the
    /// device was found as it is.
    applied: Option<TunnelConfig>,
    error: Option<String>,
    ever_up: bool,
    dump: Option<Device>,
}

pub struct Engine<K> {
    kernel: K,
    desired: Option<Desired>,
    tunnels: BTreeMap<String, Tunnel>,
    unavailable: Option<String>,
    /// Lines for the log: the tunnel's key, if any, and the text.
    pub log: Vec<(Option<String>, String)>,
}

impl<K: Kernel> Engine<K> {
    pub fn new(kernel: K) -> Self {
        Self { kernel, desired: None, tunnels: BTreeMap::new(), unavailable: None, log: Vec::new() }
    }

    pub fn kernel(&mut self) -> &mut K {
        &mut self.kernel
    }

    pub fn set_desired(&mut self, d: Desired) {
        self.desired = Some(d);
    }

    fn note(&mut self, key: Option<&str>, text: String) {
        self.log.push((key.map(str::to_owned), text));
    }

    /// Makes the devices what `desired` says. Run on every `desired` and on
    /// every tick: what is already right is not touched, so it repairs a
    /// device removed or changed behind its back and costs a dump when
    /// nothing is wrong.
    pub fn converge(&mut self) {
        let Some(desired) = self.desired.clone() else { return };

        if let Err(why) = self.kernel.ready() {
            if self.unavailable.as_ref() != Some(&why) {
                self.note(None, why.clone());
            }
            self.unavailable = Some(why.clone());
            for key in desired.instances.keys() {
                let t = self.tunnels.entry(key.clone()).or_default();
                t.error = Some(why.clone());
                t.dump = None;
            }
            self.tunnels.retain(|k, _| desired.instances.contains_key(k));
            return;
        }
        if self.unavailable.take().is_some() {
            self.note(None, "the amneziawg module is there".into());
        }

        for (key, inst) in &desired.instances {
            let parsed = if inst.kind != "tunnel" {
                Err(format!("awg serves tunnels, not {:?}", inst.kind))
            } else if !inst.device.starts_with(DEVICE_PREFIX) || inst.device.len() >= 16 {
                Err(format!("{:?} is not a tunnel's device name", inst.device))
            } else {
                TunnelConfig::from_settings(&inst.settings)
            };
            let t = self.tunnels.entry(key.clone()).or_default();
            if t.device != inst.device {
                *t = Tunnel { device: inst.device.clone(), ..Default::default() };
            }
            let result = parsed.and_then(|cfg| {
                let done = apply(&mut self.kernel, &inst.device, inst.mark, &cfg, t.applied.as_ref())?;
                Ok((cfg, done))
            });
            let before = t.error.clone();
            // Nothing sent: the device read to plan is the device. Else (an
            // update, a new device, an error) it is read as it is now.
            let mut unchanged = None;
            match result {
                Ok((cfg, done)) => {
                    if done.made {
                        t.ever_up = false;
                    }
                    t.applied = Some(cfg);
                    t.error = None;
                    unchanged = done.unchanged;
                }
                Err(e) => t.error = Some(e),
            }
            t.dump = unchanged.or_else(|| self.kernel.get(&inst.device).ok());
            let after = t.error.clone();
            if after != before {
                let text = after.unwrap_or_else(|| "configured".into());
                self.note(Some(key), text);
            }
        }

        // Left over: ours by name and kind, named by nothing now.
        let named: BTreeSet<&str> = desired.instances.values().map(|i| i.device.as_str()).collect();
        if let Ok(links) = self.kernel.links() {
            for name in links {
                if name.starts_with(DEVICE_PREFIX) && !named.contains(name.as_str()) {
                    match self.kernel.delete(&name) {
                        Ok(()) => self.note(None, format!("removed {name}, no tunnel names it")),
                        Err(e) => self.note(None, format!("cannot remove {name}: {e}")),
                    }
                }
            }
        }
        self.tunnels.retain(|k, _| desired.instances.contains_key(k));
    }

    pub fn state(&mut self, now: SystemTime) -> State {
        let mut instances = BTreeMap::new();
        let mut up = 0u64;
        if let Some(d) = &self.desired {
            for key in d.instances.keys() {
                let Some(t) = self.tunnels.get_mut(key) else { continue };
                let s = instance_state(t, now);
                if s.phase == Phase::Up {
                    up += 1;
                }
                instances.insert(key.clone(), s);
            }
        }
        let mut state = State {
            // Each desired is converged before the next line is read.
            settled: self.desired.is_some(),
            instances,
            ..State::default()
        };
        state = state.value("tunnels_up", up);
        if let Some(v) = self.kernel.module_version() {
            state = state.value("module_version", v);
        }
        state
    }

    /// Removes every device of every tunnel: the plugin is being stopped.
    pub fn shutdown(&mut self) {
        let devices: Vec<String> = self.tunnels.values().map(|t| t.device.clone()).collect();
        for d in devices {
            match self.kernel.delete(&d) {
                Ok(()) => self.note(None, format!("removed {d}")),
                Err(e) if e.errno() == Some(ENODEV) => {}
                Err(e) => self.note(None, format!("cannot remove {d}: {e}")),
            }
        }
    }
}

fn instance_state(t: &mut Tunnel, now: SystemTime) -> InstanceState {
    let mut values = BTreeMap::new();
    let mut peer_addr = None;
    let mut handshake = None;
    if let Some(d) = &t.dump {
        if let Some(k) = &d.public_key {
            values.insert("public_key".into(), json!(base64::encode(k.as_bytes(), true)));
        }
        values.insert("listen_port".into(), json!(d.listen_port));
        let want = t.applied.as_ref().map(|c| &c.peer_public_key);
        if let Some(p) = d.peers.iter().find(|p| Some(&p.public_key) == want) {
            peer_addr = p.endpoint.map(|e| e.to_string());
            handshake = p.last_handshake;
            if let Some(h) = p.last_handshake {
                values.insert("last_handshake".into(), json!(h.as_secs()));
            }
        }
    }
    let (phase, message) = if let Some(e) = &t.error {
        (Phase::Error, e.clone())
    } else if t.dump.is_none() {
        (Phase::Starting, "making the device".to_owned())
    } else {
        let window = t
            .applied
            .as_ref()
            .map(|c| c.obfuscation.reject_after_time)
            .filter(|r| !r.is_zero())
            .map_or(REJECT_AFTER, |r| r.hi() as u64);
        let since_epoch = now.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
        let fresh = handshake.is_some_and(|h| since_epoch.saturating_sub(h) < Duration::from_secs(window));
        if fresh {
            t.ever_up = true;
            (Phase::Up, String::new())
        } else if t.ever_up {
            (Phase::Down, format!("no handshake for more than {window} s"))
        } else {
            (Phase::Connecting, "waiting for the first handshake".to_owned())
        }
    };
    InstanceState { phase, message, peer: peer_addr, values }
}

/// What `apply` did.
struct Applied {
    /// The device was made (again).
    made: bool,
    /// The device as it is now, when nothing was sent to it: what was read
    /// to plan the update is still true, and is not read again.
    unchanged: Option<Device>,
}

/// Makes `name` what `cfg` says.
fn apply<K: Kernel>(
    k: &mut K,
    name: &str,
    mark: u32,
    cfg: &TunnelConfig,
    applied: Option<&TunnelConfig>,
) -> Result<Applied, String> {
    let found = match k.get(name) {
        Ok(d) => Some(d),
        Err(e) if e.errno() == Some(ENODEV) => None,
        Err(e) if e.errno() == Some(EOPNOTSUPP) => {
            return Err(format!("{name} exists and is not an AmneziaWG device"))
        }
        Err(e) => return Err(format!("reading {name}: {e}")),
    };
    let mut made = false;
    if let Some(d) = &found {
        // A header protection key cannot be taken off a device.
        if d.header_protection_key.is_some() && cfg.header_protection_key.is_none() {
            k.delete(name).map_err(|e| format!("removing {name} to drop its header protection key: {e}"))?;
            made = true;
        }
    } else {
        made = true;
    }
    let dev = if made {
        k.create(name).map_err(|e| match e.errno() {
            Some(17) => format!("{name} exists and is not an AmneziaWG device"),
            _ => format!("making {name}: {e}"),
        })?;
        k.get(name).map_err(|e| format!("reading {name}: {e}"))?
    } else {
        found.unwrap()
    };
    let u = plan(&dev, name, mark, cfg, if made { None } else { applied });
    if is_empty(&u) {
        return Ok(Applied { made, unchanged: Some(dev) });
    }
    k.set(&u).map_err(|e| format!("configuring {name}: {e}"))?;
    Ok(Applied { made, unchanged: None })
}

/// Only what differs, so a session is not broken by an update that changes
/// something else: the peer is changed in place, never replaced, while its
/// key stays.
pub fn plan(dev: &Device, name: &str, mark: u32, cfg: &TunnelConfig, applied: Option<&TunnelConfig>) -> DeviceUpdate {
    let mut u = DeviceUpdate { ifname: name.to_owned(), ..Default::default() };
    if dev.private_key.as_ref() != Some(&cfg.private_key) {
        u.private_key = Some(cfg.private_key.clone());
    }
    u.listen_port = match cfg.listen_port {
        Some(p) if dev.listen_port != p => Some(p),
        // Port 0 makes the module pick one; sent only when this process had
        // set one, or every update would pick another.
        None if applied.is_some_and(|a| a.listen_port.is_some()) => Some(0),
        _ => None,
    };
    if dev.fwmark != mark {
        u.fwmark = Some(mark);
    }
    let key_differs = cfg.header_protection_key.is_some() && dev.header_protection_key != cfg.header_protection_key;
    if key_differs || dev.obfuscation.as_ref() != Some(&cfg.obfuscation) {
        u.obfuscation = Some(cfg.obfuscation.clone());
        if key_differs {
            u.header_protection_key = cfg.header_protection_key.clone();
        }
    }

    let want_ips: BTreeSet<_> = TunnelConfig::allowed_ips().into_iter().collect();
    let current = dev.peers.iter().find(|p| p.public_key == cfg.peer_public_key);
    let mut p = PeerUpdate::new(cfg.peer_public_key.clone());
    let mut touch = false;
    match current {
        None => {
            // A new peer, or the peer's key changed: it replaces the others.
            u.replace_peers = !dev.peers.is_empty();
            p.preshared_key = cfg.preshared_key.clone();
            p.endpoint = Some(cfg.endpoint);
            p.persistent_keepalive = Some(cfg.keepalive);
            p.allowed_ips = want_ips.into_iter().collect();
            touch = true;
        }
        Some(cur) => {
            let want_psk = cfg.preshared_key.clone().unwrap_or(Key::ZERO);
            if cur.preshared_key.clone().unwrap_or(Key::ZERO) != want_psk {
                p.preshared_key = Some(want_psk);
                touch = true;
            }
            // The endpoint in a dump is where the peer was last heard from;
            // a roamed peer is left where it went unless the configured
            // endpoint itself changed.
            let endpoint_changed = match applied {
                Some(a) => a.endpoint != cfg.endpoint,
                None => cur.endpoint != Some(cfg.endpoint),
            };
            if endpoint_changed {
                p.endpoint = Some(cfg.endpoint);
                touch = true;
            }
            if cur.persistent_keepalive != cfg.keepalive {
                p.persistent_keepalive = Some(cfg.keepalive);
                touch = true;
            }
            let have: BTreeSet<_> = cur.allowed_ips.iter().map(|i| i.canonical()).collect();
            if have != want_ips {
                p.replace_allowed_ips = true;
                p.allowed_ips = want_ips.into_iter().collect();
                touch = true;
            }
            for other in dev.peers.iter().filter(|o| o.public_key != cfg.peer_public_key) {
                let mut r = PeerUpdate::new(other.public_key.clone());
                r.remove = true;
                u.peers.push(r);
            }
        }
    }
    if touch {
        u.peers.push(p);
    }
    u
}

fn is_empty(u: &DeviceUpdate) -> bool {
    u.private_key.is_none()
        && u.listen_port.is_none()
        && u.fwmark.is_none()
        && !u.replace_peers
        && u.obfuscation.is_none()
        && u.header_protection_key.is_none()
        && u.peers.is_empty()
}
