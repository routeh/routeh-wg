//! The channel over a real Unix socket, with a kernel that has no module.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::Ordering;
use std::time::Duration;

use awg_ctl::engine::{Engine, Kernel};
use awg_ctl::log::Log;
use awg_ctl::server::{run, STOP};
use awg_netlink::{Device, DeviceUpdate, Error};
use serde_json::Value;

struct NoModule;
impl Kernel for NoModule {
    fn ready(&mut self) -> Result<(), String> {
        Err("the amneziawg module is not loaded".into())
    }
    fn links(&mut self) -> Result<Vec<String>, Error> {
        Ok(vec![])
    }
    fn create(&mut self, _: &str) -> Result<(), Error> {
        unreachable!()
    }
    fn delete(&mut self, _: &str) -> Result<(), Error> {
        Ok(())
    }
    fn get(&mut self, _: &str) -> Result<Device, Error> {
        unreachable!()
    }
    fn set(&mut self, _: &DeviceUpdate) -> Result<(), Error> {
        unreachable!()
    }
    fn module_version(&mut self) -> Option<String> {
        None
    }
}

fn read(r: &mut BufReader<UnixStream>) -> Value {
    let mut l = String::new();
    r.read_line(&mut l).unwrap();
    serde_json::from_str(&l).unwrap()
}

#[test]
fn hello_state_desired_state() {
    let dir = std::env::temp_dir().join(format!("awg-ctl-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("awg.sock");
    let p = path.clone();
    let server = std::thread::spawn(move || run(&p, Engine::new(NoModule), &Log::open()));

    let mut s = None;
    for _ in 0..100 {
        if let Ok(c) = UnixStream::connect(&path) {
            s = Some(c);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let s = s.expect("server listens");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut w = s.try_clone().unwrap();
    let mut r = BufReader::new(s);

    let hello = read(&mut r);
    assert_eq!(hello["hello"]["protocol"], 1);
    assert_eq!(hello["hello"]["plugin"], "awg");
    let first = read(&mut r);
    assert_eq!(first["state"]["digest"], Value::Null);
    assert_eq!(first["state"]["settled"], false);

    let desired = serde_json::json!({"desired": {"digest": "sha256:x", "settings": {}, "instances": {
        "vpn": {"kind": "tunnel", "device": "tn_vpn", "mark": 257, "settings": {}}}}});
    writeln!(w, "{desired}").unwrap();
    let st = read(&mut r);
    assert_eq!(st["state"]["digest"], "sha256:x");
    assert_eq!(st["state"]["settled"], true);
    assert_eq!(st["state"]["instances"]["vpn"]["phase"], "error");
    assert_eq!(st["state"]["instances"]["vpn"]["message"], "the amneziawg module is not loaded");

    // a second connection gets hello and the current state at once
    let s2 = UnixStream::connect(&path).unwrap();
    s2.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut r2 = BufReader::new(s2);
    read(&mut r2);
    assert_eq!(read(&mut r2)["state"]["digest"], "sha256:x");

    // the socket was renamed into place: no `.new` is left
    assert!(!dir.join("awg.sock.new").exists());

    // a desired of any length is read whole: here one of about 1 MiB
    let many: serde_json::Map<String, Value> = (0..16)
        .map(|n| {
            let i = serde_json::json!({"kind": "tunnel", "device": format!("tn_t{n}"), "mark": 257,
                "settings": {"i1": "x".repeat(64 * 1024)}});
            (format!("t{n}"), i)
        })
        .collect();
    let big = serde_json::json!({"desired": {"digest": "sha256:big", "settings": {}, "instances": many}});
    let line = big.to_string();
    assert!(line.len() > 900 * 1024);
    writeln!(w, "{line}").unwrap();
    let mut got = String::new();
    r.read_line(&mut got).unwrap();
    let st: Value = serde_json::from_str(&got).unwrap();
    assert_eq!(st["state"]["digest"], "sha256:big", "read whole, still connected");

    STOP.store(true, Ordering::Relaxed);
    server.join().unwrap().unwrap();
    assert!(!path.exists(), "the socket is removed when it stops");
    let _ = std::fs::remove_dir_all(&dir);
}
