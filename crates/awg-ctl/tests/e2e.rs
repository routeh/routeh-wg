//! A real handshake through the module, run only with `AWG_LIVE=1` where
//! the amneziawg module is loaded (`cargo xtask qemu-test`).
//!
//! The engine makes and configures the client `tn_e2e` from a `desired`, as
//! the router would send it; the test makes a server device `awge2esrv` with
//! awg-netlink directly. Both are on this host, the client's endpoint is
//! the server's port on 127.0.0.1, and both have the same obfuscation,
//! header protection included. The tunnel has to reach `up`.

#![cfg(target_os = "linux")]

use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

use awg_ctl::engine::Engine;
use awg_ctl::kernel::Netlink;
use routeh_plugin_sdk::protocol::base64;
use routeh_plugin_sdk::{Desired, Instance, Phase};
use awg_netlink::{Client, DeviceUpdate, Flavor, Key, Obfuscation, PeerUpdate, U32Range};
use serde_json::json;

fn clamp(mut k: [u8; 32]) -> Key {
    k[0] &= 248;
    k[31] = (k[31] & 127) | 64;
    Key::new(k)
}

fn up(dev: &str) {
    let ok = Command::new("ip").args(["link", "set", dev, "up"]).status().map(|s| s.success()).unwrap_or(false);
    assert!(ok, "ip link set {dev} up");
}

#[test]
fn a_handshake_with_full_obfuscation() {
    if std::env::var_os("AWG_LIVE").is_none() {
        return;
    }
    let mut c = match Client::new(Flavor::Amnezia) {
        Ok(c) => c,
        Err(e) => {
            assert!(std::env::var_os("AWG_REQUIRE").is_none(), "{e}, and AWG_REQUIRE is set");
            eprintln!("skipped: {e}");
            return;
        }
    };
    let srv = "awge2esrv";
    let _ = c.delete_link(srv);
    let _ = c.delete_link("tn_e2e");

    let client_priv = clamp([0x11; 32]);
    let server_priv = clamp([0x22; 32]);
    let hp = Key::new([0x33; 32]);
    let psk = Key::new([0x44; 32]);
    let obf = Obfuscation {
        jc: 3,
        jmin: 40,
        jmax: 90,
        s: [15, 18, 20, 23],
        h: [
            U32Range::new(100_000, 200_000).unwrap(),
            U32Range::new(300_000, 400_000).unwrap(),
            U32Range::new(500_000, 600_000).unwrap(),
            U32Range::new(700_000, 800_000).unwrap(),
        ],
        i: ["<b 0xc0ff><r 16><c><t>".into(), "<rc 8>".into(), String::new(), String::new(), String::new()],
        ..Default::default()
    };

    // The server: listens on 51990, knows the client by its public key.
    c.create_link(srv).unwrap();
    c.set_device(&DeviceUpdate {
        ifname: srv.into(),
        private_key: Some(server_priv.clone()),
        listen_port: Some(51990),
        obfuscation: Some(obf.clone()),
        header_protection_key: Some(hp.clone()),
        ..Default::default()
    })
    .unwrap();
    // Its public key and the client's, from the module.
    let server_pub = c.get_device(srv).unwrap().public_key.unwrap();

    // The client, through the engine, as the router would ask for it.
    let range = |r: U32Range| json!({"lo": r.lo(), "hi": r.hi()});
    let settings = json!({
        "private_key": base64::encode(client_priv.as_bytes(), true),
        "endpoint": "127.0.0.1:51990",
        "peer_public_key": base64::encode(server_pub.as_bytes(), true),
        "preshared_key": base64::encode(psk.as_bytes(), true),
        "keepalive": 5,
        "jc": obf.jc, "jmin": obf.jmin, "jmax": obf.jmax,
        "s1": obf.s[0], "s2": obf.s[1], "s3": obf.s[2], "s4": obf.s[3],
        "h1": range(obf.h[0]), "h2": range(obf.h[1]), "h3": range(obf.h[2]), "h4": range(obf.h[3]),
        "i1": obf.i[0], "i2": obf.i[1],
        "header_protection_key": base64::encode(hp.as_bytes(), true),
    });
    let mut e = Engine::new(Netlink::default());
    e.set_desired(Desired {
        digest: "sha256:e2e".into(),
        settings: json!({}),
        instances: [(
            "e2e".to_owned(),
            Instance { kind: "tunnel".into(), device: "tn_e2e".into(), mark: 0, settings },
        )]
        .into(),
    });
    e.converge();
    let s = e.state(SystemTime::now());
    assert_eq!(s.instances["e2e"].phase, Phase::Connecting, "{:?}", s.instances["e2e"]);
    let client_pub = base64::decode(s.instances["e2e"].values["public_key"].as_str().unwrap()).unwrap();

    let mut p = PeerUpdate::new(Key::new(client_pub.try_into().unwrap()));
    p.preshared_key = Some(psk);
    p.allowed_ips = vec!["10.99.0.2/32".parse().unwrap()];
    c.set_device(&DeviceUpdate { ifname: srv.into(), peers: vec![p], ..Default::default() }).unwrap();

    // netifd's part: the links up. The keepalive starts the handshake.
    up(srv);
    up("tn_e2e");

    let deadline = Instant::now() + Duration::from_secs(20);
    let phase = loop {
        e.converge();
        let s = e.state(SystemTime::now());
        let t = &s.instances["e2e"];
        if t.phase == Phase::Up || Instant::now() > deadline {
            break t.clone();
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    let srv_dev = c.get_device(srv).unwrap();
    e.shutdown();
    let _ = c.delete_link(srv);

    assert_eq!(phase.phase, Phase::Up, "{phase:?}");
    assert_eq!(phase.peer.as_deref(), Some("127.0.0.1:51990"));
    assert!(phase.values.contains_key("last_handshake"));
    // The server heard the client: a handshake and bytes on its side too.
    let sp = &srv_dev.peers[0];
    assert!(sp.last_handshake.is_some(), "server saw no handshake");
    assert!(sp.rx_bytes > 0);
    // A plain WireGuard would not get here: the headers are not 1..4.
    assert_eq!(srv_dev.obfuscation.unwrap().h, obf.h);
}
