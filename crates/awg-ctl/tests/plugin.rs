//! The plugin as the router sees it: served by the SDK on a socket, read
//! by the router's own reader against the plugin's manifest, so a value the
//! manifest does not declare, or of another type, is caught here.

use std::collections::BTreeMap;

use awg_ctl::Awg;
use routeh_plugin_sdk::protocol::channel::{self, Instance, Reading};
use routeh_plugin_sdk::protocol::{Manifest, Settings};
use routeh_plugin_sdk::testing::Harness;
use routeh_plugin_sdk::Phase;

#[path = "support/mock.rs"]
mod mock;
use mock::{key, Mock};

/// The manifest as a bundle carries it: the build sets `[modules] kernel`.
fn manifest() -> Manifest {
    let text = include_str!("../../../plugin/manifest.toml")
        .replacen("[modules]\n", "[modules]\nkernel = \"6.12.112~67e205f2-r1\"\n", 1);
    Manifest::parse(&text).expect("plugin/manifest.toml is a manifest the router installs")
}

/// The tunnel `vpn` as the router sends it: its settings checked against
/// the manifest, written back as the document writes them, without the
/// fields of role `address`.
fn tunnel(manifest: &Manifest, extra: &str) -> Instance {
    let text = format!(
        "address = \"10.8.0.2/32\"\nprivate_key = \"{}\"\nendpoint = \"203.0.113.7:51820\"\n\
         peer_public_key = \"{}\"\nkeepalive = \"25s\"\n{extra}",
        key(1),
        key(2)
    );
    let schema = &manifest.tunnel.as_ref().expect("a tunnel kind").settings;
    let checked = schema
        .check(&text.parse().unwrap())
        .expect("settings the manifest takes");
    let mut settings = checked.to_toml();
    settings.remove("address");
    Instance { key: "vpn".into(), device: "tn_vpn".into(), mark: 257, settings }
}

fn value<'a>(values: &'a [(String, Reading)], key: &str) -> Option<&'a Reading> {
    values.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

#[test]
fn the_manifest_is_one_the_router_installs() {
    let m = manifest();
    assert_eq!(m.id.as_str(), "awg");
    assert_eq!(m.modules, ["amneziawg"]);
    assert_eq!(m.service.command, "bin/awg-ctl");
}

#[test]
fn it_says_it_answers_pings_and_answers_them() {
    let manifest = manifest();
    let harness = Harness::start(Awg::new(Mock::default())).unwrap();
    let mut router = harness.connect(&manifest).unwrap();
    assert!(router.hello().unwrap().pings);
    router.ping().unwrap();
    harness.stop().unwrap();
}

#[test]
fn a_tunnel_is_made_and_reported_as_the_manifest_declares() {
    let manifest = manifest();
    let harness = Harness::start(Awg::new(Mock::default())).unwrap();
    let mut router = harness.connect(&manifest).unwrap();
    let hello = router.hello().unwrap();
    assert_eq!(hello.plugin, "awg");

    let vpn = tunnel(&manifest, "jc = 4\njmin = 10\njmax = 50\n");
    let desired = channel::desired(&Settings::default(), &[vpn]);
    router.send(&desired).unwrap();
    let report = router.settled(&desired.digest).unwrap();
    assert!(report.dropped.is_empty(), "undeclared: {:?}", report.dropped);
    let vpn = &report.instances["vpn"];
    assert_eq!(vpn.phase, Phase::Connecting);
    assert!(report.wrong.is_empty(), "of the wrong type: {:?}", report.wrong);
    assert!(matches!(value(&vpn.values, "public_key"), Some(Reading::Text(_))));
    assert!(matches!(value(&vpn.values, "listen_port"), Some(Reading::Count(_))));
    assert_eq!(value(&report.values, "tunnels_up"), Some(&Reading::Count(0)));

    // Settings the module would misuse: that tunnel's error, nothing else.
    let bad = tunnel(&manifest, "jmin = 80\njmax = 70\n");
    let desired = channel::desired(&Settings::default(), &[bad]);
    router.send(&desired).unwrap();
    let report = router.settled(&desired.digest).unwrap();
    assert_eq!(report.instances["vpn"].phase, Phase::Error);
    assert_eq!(report.instances["vpn"].message, "Jmin (80) is above Jmax (70)");
    assert!(harness.log().contains("Jmin (80) is above Jmax (70)"), "logged");

    // Turned off: told no instance, it takes its device away.
    let desired = channel::desired(&Settings::default(), &[]);
    router.send(&desired).unwrap();
    let report = router.settled(&desired.digest).unwrap();
    assert_eq!(report.instances, BTreeMap::new());
    harness.stop().unwrap();
}
