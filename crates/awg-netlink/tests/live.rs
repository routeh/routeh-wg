//! Against the running kernel. Needs CAP_NET_ADMIN and is run only with
//! `AWG_LIVE=1`: ci.yml on the runner's WireGuard, `cargo xtask qemu-test` on
//! the AmneziaWG module.
//! Each flavor is tested when its family exists.

#![cfg(target_os = "linux")]

use awg_netlink::*;

fn live() -> bool {
    std::env::var_os("AWG_LIVE").is_some()
}

fn client(flavor: Flavor) -> Option<Client> {
    if !live() {
        return None;
    }
    match Client::new(flavor) {
        Ok(c) => Some(c),
        Err(Error::NoFamily(f)) => {
            // AWG_REQUIRE names a family that has to be there.
            if std::env::var("AWG_REQUIRE").is_ok_and(|r| r == f) {
                panic!("no {f} family, and AWG_REQUIRE={f}");
            }
            eprintln!("skipped: no {f} family");
            None
        }
        Err(e) => panic!("{e}"),
    }
}

fn key(b: u8) -> Key {
    let mut k = [b; 32];
    // a valid clamped Curve25519 private key
    k[0] &= 248;
    k[31] = (k[31] & 127) | 64;
    Key::new(k)
}

struct Dev<'a>(&'a mut Client, &'static str);
impl Drop for Dev<'_> {
    fn drop(&mut self) {
        let _ = self.0.delete_link(self.1);
    }
}

fn peer(b: u8, ka: U16Range) -> PeerUpdate {
    let mut p = PeerUpdate::new(Key::new([b; 32]));
    p.endpoint = Some("192.0.2.1:51820".parse().unwrap());
    p.persistent_keepalive = Some(ka);
    p.allowed_ips = vec!["10.0.0.0/8".parse().unwrap(), "fd00::/8".parse().unwrap()];
    p
}

#[test]
fn wireguard_round_trip() {
    let Some(mut c) = client(Flavor::WireGuard) else { return };
    let name = "awgtest0";
    let _ = c.delete_link(name);
    c.create_link(name).unwrap();
    let dev = Dev(&mut c, name);
    let c = &mut *dev.0;

    assert!(c.links().unwrap().iter().any(|l| l.name == name));
    let e = c.create_link(name).unwrap_err();
    assert_eq!(e.errno(), Some(17), "EEXIST: {e}");

    let u = DeviceUpdate {
        ifname: name.into(),
        private_key: Some(key(1)),
        listen_port: Some(51999),
        fwmark: Some(257),
        replace_peers: true,
        peers: vec![peer(2, U16Range::fixed(25))],
        ..Default::default()
    };
    c.set_device(&u).unwrap();
    let d = c.get_device(name).unwrap();
    assert_eq!(d.ifname, name);
    assert_eq!(d.listen_port, 51999);
    assert_eq!(d.fwmark, 257);
    assert_eq!(d.private_key, Some(key(1)));
    assert!(d.obfuscation.is_none());
    assert_eq!(d.peers.len(), 1);
    assert_eq!(d.peers[0].persistent_keepalive, U16Range::fixed(25));
    assert_eq!(d.peers[0].endpoint, Some("192.0.2.1:51820".parse().unwrap()));
    assert_eq!(d.peers[0].allowed_ips.len(), 2);

    // many allowed IPs: a dump over several messages, joined
    let mut big = PeerUpdate::new(Key::new([3; 32]));
    big.allowed_ips = (0..3000u32).map(|n| format!("fd01::{n:x}/128").parse().unwrap()).collect();
    c.set_device(&DeviceUpdate { ifname: name.into(), peers: vec![big], ..Default::default() }).unwrap();
    let d = c.get_device(name).unwrap();
    assert_eq!(d.peers.len(), 2);
    let p3 = d.peers.iter().find(|p| p.public_key == Key::new([3; 32])).unwrap();
    assert_eq!(p3.allowed_ips.len(), 3000);

    // a missing device
    let e = c.get_device("awgnone0").unwrap_err();
    assert_eq!(e.errno(), Some(19), "ENODEV: {e}");
}

#[test]
fn amnezia_round_trip() {
    let Some(mut c) = client(Flavor::Amnezia) else { return };
    let name = "awgtest1";
    let _ = c.delete_link(name);
    c.create_link(name).unwrap();
    let dev = Dev(&mut c, name);
    let c = &mut *dev.0;

    // a new device has the defaults Obfuscation::default() states
    let d = c.get_device(name).unwrap();
    assert_eq!(d.obfuscation.as_ref(), Some(&Obfuscation::default()));

    let mut o = Obfuscation {
        jc: 4,
        jmin: 40,
        jmax: 70,
        s: [15, 18, 20, 23],
        h: [
            U32Range::new(100_000, 200_000).unwrap(),
            U32Range::new(300_000, 400_000).unwrap(),
            U32Range::fixed(500_000),
            U32Range::new(600_000, 700_000).unwrap(),
        ],
        ..Default::default()
    };
    o.i[0] = "<b 0xc0ff><r 16><c><t>".into();
    o.rekey_after_time = U16Range::new(110, 130).unwrap();
    let u = DeviceUpdate {
        ifname: name.into(),
        private_key: Some(key(1)),
        listen_port: Some(51998),
        replace_peers: true,
        obfuscation: Some(o.clone()),
        header_protection_key: Some(Key::new([9; 32])),
        peers: vec![peer(2, U16Range::new(20, 30).unwrap())],
        ..Default::default()
    };
    c.set_device(&u).unwrap();
    let d = c.get_device(name).unwrap();
    assert_eq!(d.obfuscation.as_ref(), Some(&o));
    assert_eq!(d.header_protection_key, Some(Key::new([9; 32])));
    assert_eq!(d.peers[0].persistent_keepalive, U16Range::new(20, 30).unwrap());

    // H swapped between two fields in one message: accepted, since each is
    // checked against the others' new values
    let mut o2 = o.clone();
    o2.h.swap(0, 1);
    c.set_device(&DeviceUpdate { ifname: name.into(), obfuscation: Some(o2.clone()), header_protection_key: Some(Key::new([9; 32])), ..Default::default() }).unwrap();
    assert_eq!(c.get_device(name).unwrap().obfuscation.unwrap().h, o2.h);

    // back to the defaults, whole: everything resets but the key
    // the key stays, so S stays ≥ 12
    let back = Obfuscation { s: [12; 4], ..Default::default() };
    c.set_device(&DeviceUpdate { ifname: name.into(), obfuscation: Some(back.clone()), ..Default::default() }).unwrap();
    let d = c.get_device(name).unwrap();
    assert_eq!(d.obfuscation, Some(back));
    assert!(d.header_protection_key.is_some(), "the key cannot be removed");

    // what the module itself refuses comes back as EINVAL
    let mut raw = DeviceUpdate { ifname: name.into(), ..Default::default() };
    raw.obfuscation = Some(Obfuscation { s: [0; 4], ..Default::default() });
    // validate() passes without a key in the update, the module refuses
    // because the device has one
    let e = c.set_device(&raw).unwrap_err();
    assert_eq!(e.errno(), Some(22), "EINVAL: {e}");
}
