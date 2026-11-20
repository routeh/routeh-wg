//! The engine against a kernel that behaves like the module's netlink
//! interface (`support/mock.rs`).

use std::time::{Duration, SystemTime};

use awg_ctl::engine::Engine;
use awg_netlink::{Device, Key, U16Range};
use routeh_plugin_sdk::protocol::base64;
use routeh_plugin_sdk::{Desired, Instance, Phase};
use serde_json::{json, Value};

#[path = "support/mock.rs"]
mod mock;
use mock::{key as k, public_of, Mock};


fn settings() -> Value {
    json!({
        "private_key": k(1),
        "endpoint": "203.0.113.7:51820",
        "peer_public_key": k(2),
        "keepalive": 25,
    })
}

fn desired(digest: &str, tunnels: &[(&str, Value)]) -> Desired {
    Desired {
        digest: digest.into(),
        settings: json!({}),
        instances: tunnels
            .iter()
            .map(|(key, s)| {
                (
                    key.to_string(),
                    Instance { kind: "tunnel".into(), device: format!("tn_{key}"), mark: 257, settings: s.clone() },
                )
            })
            .collect(),
    }
}

fn engine() -> Engine<Mock> {
    Engine::new(Mock::default())
}

fn with(mut v: Value, key: &str, val: Value) -> Value {
    v.as_object_mut().unwrap().insert(key.into(), val);
    v
}

const NOW: u64 = 1_800_000_000;
fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(NOW)
}

#[test]
fn a_new_tunnel_is_made_and_configured_once() {
    let mut e = engine();
    e.set_desired(desired("sha256:a", &[("vpn", settings())]));
    e.converge();
    let m = e.kernel();
    assert_eq!(m.created, ["tn_vpn"]);
    assert_eq!(m.sets.len(), 1);
    let u = &m.sets[0];
    assert_eq!(u.ifname, "tn_vpn");
    assert_eq!(u.private_key, Some(Key::new([1; 32])));
    assert_eq!(u.fwmark, Some(257));
    assert_eq!(u.listen_port, None, "no port: the module picks one");
    assert!(!u.replace_peers);
    assert!(u.obfuscation.is_none(), "a new device already has the defaults");
    let p = &u.peers[0];
    assert_eq!(p.endpoint, Some("203.0.113.7:51820".parse().unwrap()));
    assert_eq!(p.persistent_keepalive, Some(U16Range::fixed(25)));
    let ips: Vec<String> = p.allowed_ips.iter().map(|i| i.to_string()).collect();
    assert_eq!(ips, ["0.0.0.0/0", "::/0"]);

    let s = e.state(now());
    assert!(s.settled);
    let t = &s.instances["vpn"];
    assert_eq!(t.phase, Phase::Connecting);
    assert_eq!(t.peer.as_deref(), Some("203.0.113.7:51820"));
    assert_eq!(t.values["public_key"], json!(base64::encode(public_of(&Key::new([1; 32])).as_bytes(), true)));
    assert!(t.values.contains_key("listen_port"));
    assert!(!t.values.contains_key("last_handshake"));
    assert_eq!(s.values["tunnels_up"], json!(0));
    assert_eq!(s.values["module_version"], json!("3.1.20261113-02"));

    // again: nothing differs, nothing is sent
    e.converge();
    assert_eq!(e.kernel().sets.len(), 1);
}

#[test]
fn obfuscation_changes_without_touching_the_peer() {
    let mut e = engine();
    e.set_desired(desired("a", &[("vpn", settings())]));
    e.converge();
    let s = with(with(with(settings(), "jc", json!(4)), "jmin", json!(40)), "jmax", json!(70));
    e.set_desired(desired("b", &[("vpn", s)]));
    e.converge();
    let u = e.kernel().sets.last().unwrap().clone();
    assert_eq!(u.obfuscation.as_ref().unwrap().jc, 4);
    assert!(u.peers.is_empty() && !u.replace_peers && u.private_key.is_none());
    assert!(u.header_protection_key.is_none());
}

#[test]
fn phases_follow_the_handshake() {
    let mut e = engine();
    e.set_desired(desired("a", &[("vpn", settings())]));
    e.converge();
    let hs = |e: &mut Engine<Mock>, ago: u64| {
        e.kernel().devices.get_mut("tn_vpn").unwrap().peers[0].last_handshake = Some(Duration::from_secs(NOW - ago));
        e.converge();
    };
    hs(&mut e, 10);
    let s = e.state(now());
    assert_eq!(s.instances["vpn"].phase, Phase::Up);
    assert_eq!(s.instances["vpn"].values["last_handshake"], json!(NOW - 10));
    assert_eq!(s.values["tunnels_up"], json!(1));
    hs(&mut e, 200);
    let s = e.state(now());
    assert_eq!(s.instances["vpn"].phase, Phase::Down);
    assert_eq!(s.instances["vpn"].message, "no handshake for more than 180 s");

    // a longer reject time widens the window
    let mut e = engine();
    e.set_desired(desired("a", &[("vpn", with(settings(), "reject_after_time", json!({"lo": 250, "hi": 300})))]));
    e.converge();
    hs(&mut e, 200);
    assert_eq!(e.state(now()).instances["vpn"].phase, Phase::Up);
}

#[test]
fn the_state_does_not_change_by_itself_every_second() {
    let mut e = engine();
    e.set_desired(desired("a", &[("vpn", settings())]));
    e.converge();
    e.kernel().devices.get_mut("tn_vpn").unwrap().peers[0].last_handshake = Some(Duration::from_secs(NOW - 10));
    e.converge();
    let a = e.state(now());
    let b = e.state(now() + Duration::from_secs(30));
    assert_eq!(a, b);
}

#[test]
fn dropping_the_header_protection_key_makes_the_device_again() {
    let mut e = engine();
    let hp = with(with(with(with(with(settings(), "s1", json!(12)), "s2", json!(12)), "s3", json!(12)), "s4", json!(12)), "header_protection_key", json!(k(9)));
    e.set_desired(desired("a", &[("vpn", hp)]));
    e.converge();
    let first = e.kernel().sets[0].clone();
    assert_eq!(first.header_protection_key, Some(Key::new([9; 32])));
    assert_eq!(first.obfuscation.as_ref().unwrap().s, [12; 4], "S goes with the key");

    e.set_desired(desired("b", &[("vpn", settings())]));
    e.converge();
    let m = e.kernel();
    assert_eq!(m.deleted, ["tn_vpn"]);
    assert_eq!(m.created, ["tn_vpn", "tn_vpn"]);
    assert!(m.devices["tn_vpn"].header_protection_key.is_none());
}

#[test]
fn leftovers_are_removed_and_nothing_else() {
    let mut e = engine();
    e.kernel().devices.insert("tn_old".into(), Device { ifname: "tn_old".into(), ..Default::default() });
    e.kernel().devices.insert("awg0".into(), Device { ifname: "awg0".into(), ..Default::default() });
    e.kernel().others.insert("tn_br".into());
    let mut d = desired("a", &[("vpn", settings()), ("br", settings())]);
    e.set_desired(d.clone());
    e.converge();
    let s = e.state(now());
    assert!(!e.kernel().devices.contains_key("tn_old"));
    assert!(e.kernel().devices.contains_key("awg0"), "not ours by name");
    assert_eq!(s.instances["br"].phase, Phase::Error);
    assert!(s.instances["br"].message.contains("not an AmneziaWG device"));
    assert_eq!(s.instances["vpn"].phase, Phase::Connecting, "one tunnel's error stops no other");

    // a tunnel removed from desired takes its device with it
    d.instances.remove("vpn");
    d.digest = "b".into();
    e.set_desired(d);
    e.converge();
    assert!(!e.kernel().devices.contains_key("tn_vpn"));
    assert!(!e.state(now()).instances.contains_key("vpn"));
}

#[test]
fn a_refused_configuration_leaves_the_device_alone() {
    let mut e = engine();
    e.set_desired(desired("a", &[("vpn", settings())]));
    e.converge();
    let bad = with(with(settings(), "jmin", json!(80)), "jmax", json!(70));
    e.set_desired(desired("b", &[("vpn", bad)]));
    e.converge();
    assert_eq!(e.kernel().sets.len(), 1);
    let s = e.state(now());
    assert!(s.settled);
    assert_eq!(s.instances["vpn"].phase, Phase::Error);
    assert_eq!(s.instances["vpn"].message, "Jmin (80) is above Jmax (70)");
    assert!(e.log.iter().any(|(k, t)| k.as_deref() == Some("vpn") && t.contains("Jmin")));
}

#[test]
fn without_the_module_every_tunnel_says_so() {
    let mut e = Engine::new(Mock { no_module: true, ..Default::default() });
    e.set_desired(desired("a", &[("vpn", settings())]));
    e.converge();
    let s = e.state(now());
    assert_eq!(s.instances["vpn"].phase, Phase::Error);
    assert_eq!(s.instances["vpn"].message, "the amneziawg module is not loaded");
    assert!(e.kernel().created.is_empty());
    assert!(!s.values.is_empty());
    // the module appears: the next tick makes the tunnel
    e.kernel().no_module = false;
    e.converge();
    assert_eq!(e.state(now()).instances["vpn"].phase, Phase::Connecting);
}

#[test]
fn after_a_restart_the_device_is_taken_over() {
    let mut e = engine();
    e.set_desired(desired("a", &[("vpn", settings())]));
    e.converge();
    let mut m = std::mem::take(e.kernel());
    m.sets.clear();
    m.created.clear();
    // the peer roamed meanwhile
    m.devices.get_mut("tn_vpn").unwrap().peers[0].endpoint = Some("198.51.100.9:4444".parse().unwrap());

    let mut e = Engine::new(m);
    e.set_desired(desired("a", &[("vpn", settings())]));
    e.converge();
    let m = e.kernel();
    assert!(m.created.is_empty() && m.deleted.is_empty(), "not made again");
    // without memory of what it set, the configured endpoint is set again;
    // nothing else is
    assert_eq!(m.sets.len(), 1);
    let u = &m.sets[0];
    assert!(u.private_key.is_none() && !u.replace_peers && u.obfuscation.is_none());
    assert_eq!(u.peers.len(), 1);
    assert_eq!(u.peers[0].endpoint, Some("203.0.113.7:51820".parse().unwrap()));
    assert!(u.peers[0].allowed_ips.is_empty());
}

#[test]
fn a_roamed_peer_is_left_where_it_went() {
    let mut e = engine();
    e.set_desired(desired("a", &[("vpn", settings())]));
    e.converge();
    e.kernel().devices.get_mut("tn_vpn").unwrap().peers[0].endpoint = Some("198.51.100.9:4444".parse().unwrap());
    e.converge();
    assert_eq!(e.kernel().sets.len(), 1);
    // but a new configured endpoint is set
    e.set_desired(desired("b", &[("vpn", with(settings(), "endpoint", json!("192.0.2.1:51820")))]));
    e.converge();
    assert_eq!(e.kernel().sets.last().unwrap().peers[0].endpoint, Some("192.0.2.1:51820".parse().unwrap()));
}

#[test]
fn another_peer_key_replaces_the_peer() {
    let mut e = engine();
    e.set_desired(desired("a", &[("vpn", settings())]));
    e.converge();
    e.set_desired(desired("b", &[("vpn", with(settings(), "peer_public_key", json!(k(3))))]));
    e.converge();
    let u = e.kernel().sets.last().unwrap().clone();
    assert!(u.replace_peers);
    assert_eq!(e.kernel().devices["tn_vpn"].peers.len(), 1);
    assert_eq!(e.kernel().devices["tn_vpn"].peers[0].public_key, Key::new([3; 32]));
}

#[test]
fn a_port_is_given_back_to_the_module_once() {
    let mut e = engine();
    e.set_desired(desired("a", &[("vpn", with(settings(), "listen_port", json!(51820)))]));
    e.converge();
    assert_eq!(e.kernel().sets[0].listen_port, Some(51820));
    e.set_desired(desired("b", &[("vpn", settings())]));
    e.converge();
    assert_eq!(e.kernel().sets.last().unwrap().listen_port, Some(0));
    let n = e.kernel().sets.len();
    e.converge();
    assert_eq!(e.kernel().sets.len(), n, "the picked port is kept");
}

#[test]
fn preshared_key_set_and_removed() {
    let mut e = engine();
    e.set_desired(desired("a", &[("vpn", with(settings(), "preshared_key", json!(k(5))))]));
    e.converge();
    assert_eq!(e.kernel().devices["tn_vpn"].peers[0].preshared_key, Some(Key::new([5; 32])));
    e.set_desired(desired("b", &[("vpn", settings())]));
    e.converge();
    assert_eq!(e.kernel().sets.last().unwrap().peers[0].preshared_key, Some(Key::ZERO));
    assert_eq!(e.kernel().devices["tn_vpn"].peers[0].preshared_key, None);
}

#[test]
fn a_device_gone_behind_its_back_is_made_again() {
    let mut e = engine();
    e.set_desired(desired("a", &[("vpn", settings())]));
    e.converge();
    e.kernel().devices.remove("tn_vpn");
    e.converge();
    assert_eq!(e.kernel().created.len(), 2);
    assert_eq!(e.state(now()).instances["vpn"].phase, Phase::Connecting);
}

#[test]
fn shutdown_removes_every_device() {
    let mut e = engine();
    e.set_desired(desired("a", &[("vpn", settings()), ("b", settings())]));
    e.converge();
    e.shutdown();
    assert!(e.kernel().devices.is_empty());
}

#[test]
fn a_quiet_tick_reads_each_tunnel_once_and_writes_nothing() {
    let mut e = engine();
    e.set_desired(desired("a", &[("vpn", settings()), ("b", settings())]));
    e.converge();
    let sets = e.kernel().sets.len();
    e.kernel().gets = 0;
    e.converge();
    assert_eq!(e.kernel().gets, 2, "one read a tunnel");
    assert_eq!(e.kernel().sets.len(), sets, "nothing sent");
    // What was read is what the state says.
    assert_eq!(e.state(now()).instances["vpn"].phase, Phase::Connecting);
}
