//! `qemu-test`: the module, awg-netlink and awg-ctl on a real OpenWrt.
//!
//! Here: what the test needs, built for aarch64 (the module for
//! armsr/armv8 of the release, awg-ctl, the test binaries `live` and
//! `e2e`). In `xtask/qemu-test.sh`: the virtual machine.

use std::process::Command;

use crate::cmd::{mkdir, run, OUT};
use crate::docker;
use crate::openwrt::{build_kmod, kmod_dir};

const TARGET: &str = "armsr/armv8";
const RUST: &str = "aarch64-unknown-linux-musl";

pub fn test(release: &str, native: bool) -> Result<(), String> {
    let kmod = kmod_dir(release, TARGET);
    if !std::path::Path::new(&format!("{kmod}/amneziawg.ko")).exists() {
        eprintln!("== {TARGET} on {release}: amneziawg.ko");
        build_kmod(release, TARGET, native)?;
    }
    let bin = format!("{OUT}/test-bin");
    mkdir(&bin)?;
    if !std::path::Path::new(&format!("{OUT}/ctl/{RUST}/awg-ctl")).exists() {
        eprintln!("== awg-ctl {RUST}");
        docker::build_ctl(RUST, native)?;
    }
    std::fs::copy(format!("{OUT}/ctl/{RUST}/awg-ctl"), format!("{bin}/awg-ctl")).map_err(|e| e.to_string())?;

    eprintln!("== test binaries {RUST}");
    let json = docker::cargo(RUST, &["test", "-q", "--no-run", "--workspace", "--message-format=json"], &[], native)?;
    let mut found = 0;
    for line in json.lines() {
        let Ok(m) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        let (Some(exe), Some(name)) = (m["executable"].as_str(), m["target"]["name"].as_str()) else { continue };
        if name == "live" || name == "e2e" {
            std::fs::copy(exe, format!("{bin}/{name}")).map_err(|e| format!("{exe}: {e}"))?;
            found += 1;
        }
    }
    if found != 2 {
        return Err("the test binaries live and e2e were not built".into());
    }
    run(Command::new("sh").args(["xtask/qemu-test.sh", release, &kmod, &bin, &format!("{OUT}/qemu")]))
}
