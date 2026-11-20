//! A kernel that behaves like the module's netlink interface
//! (`awg-netlink/docs/NETLINK.md`): errnos, defaults of a new device, peers
//! changed in place. Shared by the tests that need no module.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use awg_ctl::engine::Kernel;
use awg_netlink::{Device, DeviceUpdate, Error, Key, Obfuscation, Peer, U16Range};
use routeh_plugin_sdk::protocol::base64;

/// A key of 32 bytes `b`, as `desired` writes it.
pub fn key(b: u8) -> String {
    base64::encode(&[b; 32], true)
}

#[derive(Default)]
pub struct Mock {
    pub no_module: bool,
    pub devices: BTreeMap<String, Device>,
    /// Devices of another kind.
    pub others: BTreeSet<String>,
    pub sets: Vec<DeviceUpdate>,
    pub created: Vec<String>,
    pub deleted: Vec<String>,
    /// How many times a device was read.
    pub gets: usize,
}

pub fn kerr(errno: i32) -> Error {
    Error::Kernel { errno, message: None }
}

pub fn public_of(k: &Key) -> Key {
    let mut b = *k.as_bytes();
    b.reverse();
    Key::new(b)
}

impl Kernel for Mock {
    fn ready(&mut self) -> Result<(), String> {
        if self.no_module {
            Err("the amneziawg module is not loaded".into())
        } else {
            Ok(())
        }
    }
    fn links(&mut self) -> Result<Vec<String>, Error> {
        Ok(self.devices.keys().cloned().collect())
    }
    fn create(&mut self, name: &str) -> Result<(), Error> {
        if self.devices.contains_key(name) || self.others.contains(name) {
            return Err(kerr(17));
        }
        self.created.push(name.into());
        let d = Device { ifname: name.into(), obfuscation: Some(Obfuscation::default()), ..Default::default() };
        self.devices.insert(name.into(), d);
        Ok(())
    }
    fn delete(&mut self, name: &str) -> Result<(), Error> {
        self.deleted.push(name.into());
        self.devices.remove(name).map(|_| ()).ok_or(kerr(19))
    }
    fn get(&mut self, name: &str) -> Result<Device, Error> {
        self.gets += 1;
        if self.others.contains(name) {
            return Err(kerr(95));
        }
        self.devices.get(name).cloned().ok_or(kerr(19))
    }
    fn set(&mut self, u: &DeviceUpdate) -> Result<(), Error> {
        self.sets.push(u.clone());
        let d = self.devices.get_mut(&u.ifname).ok_or(kerr(19))?;
        if let Some(k) = &u.private_key {
            d.public_key = Some(public_of(k));
            d.private_key = Some(k.clone());
        }
        match u.listen_port {
            Some(0) => d.listen_port = 40000 + d.listen_port % 7 + 1,
            Some(p) => d.listen_port = p,
            None => {}
        }
        if let Some(m) = u.fwmark {
            d.fwmark = m;
        }
        if let Some(o) = &u.obfuscation {
            d.obfuscation = Some(o.clone());
        }
        if let Some(k) = &u.header_protection_key {
            d.header_protection_key = Some(k.clone());
        }
        if u.replace_peers {
            d.peers.clear();
        }
        for p in &u.peers {
            if p.remove {
                d.peers.retain(|x| x.public_key != p.public_key);
                continue;
            }
            let pos = match d.peers.iter().position(|x| x.public_key == p.public_key) {
                Some(i) => i,
                None => {
                    d.peers.push(Peer {
                        public_key: p.public_key.clone(),
                        preshared_key: None,
                        endpoint: None,
                        persistent_keepalive: U16Range::ZERO,
                        last_handshake: None,
                        rx_bytes: 0,
                        tx_bytes: 0,
                        allowed_ips: vec![],
                    });
                    d.peers.len() - 1
                }
            };
            let x = &mut d.peers[pos];
            if let Some(k) = &p.preshared_key {
                x.preshared_key = (!k.is_zero()).then(|| k.clone());
            }
            if let Some(e) = p.endpoint {
                x.endpoint = Some(e);
            }
            if let Some(k) = p.persistent_keepalive {
                x.persistent_keepalive = k;
            }
            if p.replace_allowed_ips {
                x.allowed_ips.clear();
            }
            x.allowed_ips.extend(p.allowed_ips.iter().copied());
        }
        Ok(())
    }
    fn module_version(&mut self) -> Option<String> {
        Some("3.1.20261113-02".into())
    }
}
