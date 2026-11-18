//! Releases and targets of OpenWrt, and the module's build with the SDK.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::cmd::{fetch, mkdir, OUT};

const DOWNLOADS: &str = "https://downloads.openwrt.org";

/// One target of one release, as a build needs it.
#[derive(Debug, Clone, Serialize)]
pub struct Target {
    pub openwrt: String,
    pub target: String,
    /// `OPENWRT_ARCH`.
    pub arch: String,
    pub rust: String,
    /// The version of the package `kernel`: `6.12.112~<hash>-r1`.
    pub kernel: String,
    /// The file name of its bundle, `.tar`: the same version, architecture
    /// and kernel are always this name.
    pub bundle: String,
}

impl Target {
    /// `amneziawg.ko` and `meta.json`.
    pub fn kmod_dir(&self) -> String {
        kmod_dir(&self.openwrt, &self.target)
    }
}

#[derive(Deserialize)]
struct Targets {
    targets: Vec<String>,
    rust: BTreeMap<String, String>,
    module_packages: BTreeMap<String, String>,
}

fn targets_toml() -> Result<Targets, String> {
    let s = std::fs::read_to_string("targets.toml").map_err(|e| format!("targets.toml: {e}"))?;
    toml::from_str(&s).map_err(|e| format!("targets.toml: {e}"))
}

pub fn module_packages() -> Result<BTreeMap<String, String>, String> {
    Ok(targets_toml()?.module_packages)
}

/// A release by number, or `stable`. Release candidates and snapshots are
/// not built.
pub fn release(r: &str) -> Result<String, String> {
    if r == "stable" {
        let v: serde_json::Value = serde_json::from_str(&fetch(&format!("{DOWNLOADS}/.versions.json"))?)
            .map_err(|e| format!(".versions.json: {e}"))?;
        return v["stable_version"].as_str().map(str::to_owned).ok_or("no stable_version".into());
    }
    let ok = r.split('.').count() == 3 && r.split('.').all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()));
    if ok {
        Ok(r.to_owned())
    } else {
        Err(format!("{r:?} is not a release like 25.12.6"))
    }
}

pub fn resolve(release: &str, which: &str) -> Result<Vec<Target>, String> {
    let t = targets_toml()?;
    let names: Vec<String> = if which == "all" {
        t.targets.clone()
    } else {
        which.split(',').map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect()
    };
    let mut out = Vec::new();
    for name in names {
        if name.split('/').count() != 2 {
            return Err(format!("{name:?} is not a target like mediatek/filogic"));
        }
        let url = format!("{DOWNLOADS}/releases/{release}/targets/{name}/profiles.json");
        let p: serde_json::Value = serde_json::from_str(&fetch(&url)?).map_err(|e| format!("{url}: {e}"))?;
        let arch = p["arch_packages"].as_str().ok_or(format!("{url}: no arch_packages"))?.to_owned();
        let k = &p["linux_kernel"];
        let kernel = format!(
            "{}~{}-r{}",
            k["version"].as_str().unwrap_or_default(),
            k["vermagic"].as_str().unwrap_or_default(),
            k["release"].as_str().unwrap_or_default()
        );
        let rust = t
            .rust
            .get(&arch)
            .ok_or(format!("{name} is {arch}: add its Rust target to [rust] of targets.toml"))?
            .clone();
        let bundle = crate::bundle::file_name(&arch, &kernel);
        out.push(Target { openwrt: release.to_owned(), target: name, arch, rust, kernel, bundle });
    }
    Ok(out)
}

pub fn kmod_dir(release: &str, target: &str) -> String {
    format!("{OUT}/kmod/{release}/{}", target.replace('/', "-"))
}

/// `amneziawg.ko` and `meta.json` of a release and target, by kmod/build.sh.
pub fn build_kmod(release: &str, target: &str, native: bool) -> Result<(), String> {
    let out = kmod_dir(release, target);
    mkdir(&out)?;
    crate::docker::sdk(release, target, &out, native)
}
