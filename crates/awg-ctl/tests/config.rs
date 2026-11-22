//! A tunnel's settings as `desired` carries them, read into what the module
//! takes (`src/config.rs`).

use awg_ctl::config::TunnelConfig;
use awg_netlink::{Key, Obfuscation, U16Range, U32Range};
use routeh_plugin_sdk::protocol::base64;
use serde_json::{json, Value};

#[path = "support/mock.rs"]
mod mock;
use mock::key as k;

fn base() -> Value {
    json!({
        "private_key": k(1),
        "endpoint": "203.0.113.7:51820",
        "peer_public_key": k(2),
    })
}

#[test]
fn minimal_is_plain_wireguard() {
    let c = TunnelConfig::from_settings(&base()).unwrap();
    assert_eq!(c.obfuscation, Obfuscation::default());
    // Not written: 25 s. Without traffic WireGuard makes no handshake, and
    // a router sends a tunnel no traffic until a handshake says it is up.
    assert_eq!(c.keepalive, U16Range::fixed(25));
    assert_eq!(c.listen_port, None);
    assert_eq!(c.endpoint.to_string(), "203.0.113.7:51820");

    // As the router writes an IPv6 host_port and a duration in hours.
    let mut v = base();
    v["endpoint"] = json!("[2001:db8::1]:51820");
    v["keepalive"] = json!("2h");
    let c = TunnelConfig::from_settings(&v).unwrap();
    assert_eq!(c.endpoint.to_string(), "[2001:db8::1]:51820");
    assert_eq!(c.keepalive, U16Range::fixed(7200));
}

#[test]
fn every_encoding() {
    let mut v = base();
    let o = v.as_object_mut().unwrap();
    o.insert("keepalive".into(), json!("1m"));
    o.insert("listen_port".into(), json!(51820));
    o.insert("preshared_key".into(), json!(k(3)));
    o.insert("jc".into(), json!(4));
    o.insert("jmin".into(), json!(40));
    o.insert("jmax".into(), json!(70));
    o.insert("h1".into(), json!({"lo": 100, "hi": 200}));
    o.insert("h2".into(), json!("300-400"));
    o.insert("h3".into(), json!(500));
    o.insert("rekey_after_time".into(), json!({"lo": 110, "hi": 130}));
    o.insert("i1".into(), json!("<r 16>"));
    let c = TunnelConfig::from_settings(&v).unwrap();
    assert_eq!(c.keepalive, U16Range::fixed(60));
    assert_eq!(c.listen_port, Some(51820));
    assert_eq!(c.preshared_key, Some(Key::new([3; 32])));
    assert_eq!(c.obfuscation.h[0], U32Range::new(100, 200).unwrap());
    assert_eq!(c.obfuscation.h[1], U32Range::new(300, 400).unwrap());
    assert_eq!(c.obfuscation.h[2], U32Range::fixed(500));
    assert_eq!(c.obfuscation.h[3], U32Range::fixed(4), "unset H keeps the module's default");
    assert_eq!(c.obfuscation.rekey_after_time, U16Range::new(110, 130).unwrap());
}

#[test]
fn refusals_name_the_field() {
    let with = |key: &str, val: Value| {
        let mut v = base();
        v.as_object_mut().unwrap().insert(key.into(), val);
        TunnelConfig::from_settings(&v).unwrap_err()
    };
    assert!(with("endpoint", json!("vpn.example:51820")).contains("names a host"));
    assert!(with("endpoint", json!("203.0.113.7")).contains("not an address and a port"));
    assert!(with("endpoint", json!("[::1]:x")).contains("not an address and a port"));
    assert!(with("private_key", json!("abc")).contains("private_key"));
    assert!(with("peer_public_key", json!(base64::encode(&[1; 31], true))).contains("32 bytes"));
    assert!(with("keepalive", json!("70000s")).contains("65535"));
    assert!(with("keepalive", json!("2d")).contains("not like"));
    assert!(with("h1", json!({"lo": 9, "hi": 3})).contains("backwards"));
    assert!(with("i2", json!("<q>")).contains("I2"));
    assert!(with("mtu", json!(1380)).contains("unknown field"));
    assert!(with("jmin", json!(80)).contains("Jmin (80) is above Jmax (0)"));
    // S below 12 with a header protection key
    let e = with("header_protection_key", json!(k(9)));
    assert!(e.contains("S1 (0) must be at least 12"), "{e}");
}

#[test]
fn a_keepalive_of_zero_is_off() {
    let mut v = base();
    v["keepalive"] = json!("0s");
    assert_eq!(TunnelConfig::from_settings(&v).unwrap().keepalive, U16Range::ZERO);
}
