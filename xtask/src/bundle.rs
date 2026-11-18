//! The bundle, in the router's format: a POSIX ustar archive of
//! regular files in the order of their paths (mode 0644, 0755 under `bin/`,
//! owner 0, time 0), then `SHA256SUMS`, then `SHA256SUMS.sig`.
//!
//! ```text
//! bin/awg-ctl
//! build.json            what it was built from and for
//! manifest.toml         plugin/manifest.toml, its [modules] kernel set
//! modules/amneziawg.ko
//! SHA256SUMS            "<sha256>  <path>" of each file above, in order
//! SHA256SUMS.sig        added by `publish`
//! ```
//!
//! `bundle` writes it without the signature; `publish` signs it (keys.rs),
//! and the result is the bytes the router's own packer makes of the same
//! files and key.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use serde_json::json;

use crate::cmd::{mkdir, OUT};
use crate::keys::{self, Secret};
use crate::openwrt::{module_packages, Target};

const SUMS: &str = "SHA256SUMS";
const SIGNATURE: &str = "SHA256SUMS.sig";
const BLOCK: usize = 512;
// The router's limits.
const MAX_FILES: usize = 1024;
const MAX_FILE: usize = 32 << 20;
const MAX_TOTAL: usize = 64 << 20;

pub fn sha256_hex(b: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, b).as_ref().iter().map(|x| format!("{x:02x}")).collect()
}

fn manifest() -> Result<(String, toml::Value), String> {
    let text = std::fs::read_to_string("plugin/manifest.toml").map_err(|e| format!("plugin/manifest.toml: {e}"))?;
    let v: toml::Value = toml::from_str(&text).map_err(|e| format!("plugin/manifest.toml: {e}"))?;
    Ok((text, v))
}

/// `version` of plugin/manifest.toml: `<AWG version>-r<revision>`.
pub fn plugin_version() -> String {
    manifest()
        .ok()
        .and_then(|(_, v)| v.get("version").and_then(|x| x.as_str()).map(str::to_owned))
        .unwrap_or_else(|| crate::cmd::fail("plugin/manifest.toml has no version"))
}

/// The module's version as the plugin's version writes it: `3.1.20261113-02`
/// is `3.1.20261113.2`.
pub fn awg_part(module_version: &str) -> Option<String> {
    let parts: Option<Vec<String>> = module_version
        .split(['.', '-'])
        .map(|p| p.parse::<u64>().ok().map(|n| n.to_string()))
        .collect();
    parts.filter(|p| !p.is_empty()).map(|p| p.join("."))
}

fn check_version(version: &str, module_version: &str) -> Result<(), String> {
    let (awg, rev) = version
        .rsplit_once("-r")
        .filter(|(_, r)| !r.is_empty() && r.bytes().all(|c| c.is_ascii_digit()))
        .ok_or(format!("version {version:?} is not <AWG version>-r<n>"))?;
    let want = awg_part(module_version).ok_or(format!("module version {module_version:?} unreadable"))?;
    if awg != want {
        return Err(format!(
            "version {version} is not of the module it carries: AWG {module_version} is {want}-r{rev}; \
             change `version` in plugin/manifest.toml or the commit in kmod/amneziawg/Makefile"
        ));
    }
    Ok(())
}

/// The manifest with `kernel` set in `[modules]`: the `kernel` package
/// version the modules of this bundle are built for.
fn with_kernel(text: &str, kernel: &str) -> Result<String, String> {
    let v: toml::Value = toml::from_str(text).map_err(|e| e.to_string())?;
    if v.get("modules").and_then(|m| m.get("kernel")).is_some() {
        return Err("plugin/manifest.toml sets [modules] kernel: the build does".into());
    }
    let mut out = String::with_capacity(text.len() + 80);
    let mut done = false;
    for line in text.lines() {
        out.push_str(line);
        out.push('\n');
        if !done && line.trim() == "[modules]" {
            out.push_str(&format!("kernel = \"{kernel}\"\n"));
            done = true;
        }
    }
    if !done {
        return Err("plugin/manifest.toml has no [modules]".into());
    }
    Ok(out)
}

/// ELF `e_machine` of each architecture family.
fn machine_of(arch: &str) -> Option<u16> {
    Some(match arch.split('_').next()? {
        "aarch64" => 183,
        "arm" => 40,
        "x86" | "x86_64" | "i386" => 62,
        "mips" | "mipsel" | "mips64" | "mips64el" => 8,
        _ => return None,
    })
}

fn elf_machine(b: &[u8]) -> Option<u16> {
    if b.len() < 20 || &b[..4] != b"\x7fELF" {
        return None;
    }
    let m = [b[18], b[19]];
    Some(if b[5] == 1 { u16::from_le_bytes(m) } else { u16::from_be_bytes(m) })
}

fn kernel_dir(kernel: &str) -> String {
    // 6.12.112~<hash>-r1 -> 6.12.112-1-<hash>, as OpenWrt names kmods/
    match kernel.split_once('~').and_then(|(v, rest)| rest.rsplit_once("-r").map(|(h, r)| (v, h, r))) {
        Some((v, h, r)) => format!("{v}-{r}-{h}"),
        None => kernel.replace('~', "-"),
    }
}

pub fn file_name(arch: &str, kernel: &str) -> String {
    format!("awg-{}-{arch}-{}.tar", plugin_version(), kernel_dir(kernel))
}

// ---- ustar, as the router's packer writes it ----

fn header(name: &str, kind: u8, size: usize, executable: bool) -> [u8; BLOCK] {
    let mut h = [0u8; BLOCK];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..108].copy_from_slice(if executable { b"0000755\0" } else { b"0000644\0" });
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    h[136..148].copy_from_slice(b"00000000000\0");
    h[156] = kind;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

fn push_data(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(data);
    out.resize(out.len().div_ceil(BLOCK) * BLOCK, 0);
}

fn pax_record(key: &str, value: &str) -> String {
    let body = format!(" {key}={value}\n");
    let mut length = body.len() + 1;
    while format!("{length}{body}").len() != length {
        length += 1;
    }
    format!("{length}{body}")
}

fn write_tar<'a>(files: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> Vec<u8> {
    let mut out = Vec::new();
    for (path, data) in files {
        if path.len() > 100 {
            let record = pax_record("path", path);
            out.extend(header("PaxHeader", b'x', record.len(), false));
            push_data(&mut out, record.as_bytes());
        }
        let short = if path.len() > 100 { &path[..100] } else { path };
        out.extend(header(short, b'0', data.len(), path.starts_with("bin/")));
        push_data(&mut out, data);
    }
    out.extend([0u8; 2 * BLOCK]);
    out
}

fn sums_of(files: &BTreeMap<String, Vec<u8>>) -> String {
    files.iter().map(|(p, b)| format!("{}  {p}\n", sha256_hex(b))).collect()
}

fn tar_of(files: &BTreeMap<String, Vec<u8>>, signature: Option<&str>) -> Vec<u8> {
    let sums = sums_of(files);
    let mut entries: Vec<(&str, &[u8])> = files.iter().map(|(p, b)| (p.as_str(), b.as_slice())).collect();
    entries.push((SUMS, sums.as_bytes()));
    if let Some(s) = signature {
        entries.push((SIGNATURE, s.as_bytes()));
    }
    write_tar(entries)
}

/// The entries of a bundle, as the router's reader takes them: regular files
/// and directories, pax `path` records, safe paths, within its limits.
fn read_tar(path: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut ar = tar::Archive::new(f);
    let mut files = BTreeMap::new();
    let mut total = 0usize;
    for e in ar.entries().map_err(|e| e.to_string())? {
        let mut e = e.map_err(|e| e.to_string())?;
        let p = e.path().map_err(|e| e.to_string())?.to_string_lossy().into_owned();
        let kind = e.header().entry_type();
        let bad_path = p.starts_with('/')
            || p.trim_end_matches('/').split('/').any(|c| c.is_empty() || c == ".." || c == ".")
            || p.chars().any(char::is_control);
        if bad_path {
            return Err(format!("{p:?}: not a path inside the bundle"));
        }
        if kind.is_dir() {
            continue;
        }
        if !kind.is_file() {
            return Err(format!("{p}: not a regular file ({kind:?})"));
        }
        let size = e.size() as usize;
        total += size;
        if size > MAX_FILE || total > MAX_TOTAL || files.len() >= MAX_FILES {
            return Err(format!("{p}: over the bundle's limits (1024 files, 32 MiB a file, 64 MiB in all)"));
        }
        let mut b = Vec::with_capacity(size);
        e.read_to_end(&mut b).map_err(|e| e.to_string())?;
        if files.insert(p.clone(), b).is_some() {
            return Err(format!("{p}: twice"));
        }
    }
    Ok(files)
}

pub fn make(t: &Target) -> Result<PathBuf, String> {
    let (manifest_text, m) = manifest()?;
    let version = plugin_version();
    let read = |p: &str| std::fs::read(p).map_err(|e| format!("{p}: {e} (build it first)"));
    let meta: serde_json::Value =
        serde_json::from_slice(&read(&format!("{}/meta.json", t.kmod_dir()))?).map_err(|e| e.to_string())?;
    let ko = read(&format!("{}/amneziawg.ko", t.kmod_dir()))?;
    let ctl = read(&format!("{OUT}/ctl/{}/awg-ctl", t.rust))?;
    let s = |k: &str| meta[k].as_str().unwrap_or_default().to_owned();

    check_version(&version, &s("module_version"))?;
    if s("kernel_package") != t.kernel {
        return Err(format!("the module is for kernel {}, the release has {}", s("kernel_package"), t.kernel));
    }
    let vermagic = format!("vermagic={}\0", s("vermagic"));
    if !ko.windows(vermagic.len()).any(|w| w == vermagic.as_bytes()) {
        return Err("meta.json's vermagic is not the module's".into());
    }
    let want = machine_of(&t.arch).ok_or(format!("unknown architecture {}", t.arch))?;
    for (what, b) in [("amneziawg.ko", &ko), ("awg-ctl", &ctl)] {
        if elf_machine(b) != Some(want) {
            return Err(format!("{what} is not a binary for {}", t.arch));
        }
    }
    let requires: Vec<&str> = m
        .get("requires")
        .and_then(|r| r.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    let packages = module_packages()?;
    let depends: Vec<String> = s("depends").split(',').filter(|d| !d.is_empty()).map(str::to_owned).collect();
    for d in &depends {
        let p = packages.get(d).ok_or(format!("the module depends on {d}: add its package to [module_packages] of targets.toml"))?;
        if !requires.contains(&p.as_str()) {
            return Err(format!("the module depends on {d} of {p}, which `requires` of plugin/manifest.toml lacks"));
        }
    }

    let build = serde_json::to_vec_pretty(&json!({
        "plugin": m.get("id").and_then(|v| v.as_str()).unwrap_or("awg"),
        "version": version,
        "openwrt": t.openwrt,
        "target": t.target,
        "arch": t.arch,
        "rust": t.rust,
        "kernel_package": t.kernel,
        "vermagic": s("vermagic"),
        "module_build_id": s("build_id"),
        "module_version": s("module_version"),
        "module_depends": depends,
        "upstream": s("upstream"),
        "patches": s("patches"),
    }))
    .unwrap();

    let mut files = BTreeMap::new();
    files.insert("bin/awg-ctl".to_owned(), ctl);
    files.insert("build.json".to_owned(), build);
    files.insert("manifest.toml".to_owned(), with_kernel(&manifest_text, &t.kernel)?.into_bytes());
    files.insert("modules/amneziawg.ko".to_owned(), ko);
    let tar = tar_of(&files, None);

    let dir = format!("{OUT}/bundles");
    mkdir(&dir)?;
    let path = PathBuf::from(format!("{dir}/{}", t.bundle));
    std::fs::write(&path, &tar).map_err(|e| e.to_string())?;
    // For CI and the feed: what the bundle is, without opening it.
    let side = json!({
        "file": t.bundle,
        "sha256": sha256_hex(&tar),
        "size": tar.len(),
        "plugin": "awg",
        "version": version,
        "openwrt": t.openwrt,
        "target": t.target,
        "arch": t.arch,
        "kernel": t.kernel,
        "signed": false,
    });
    let side_path = format!("{dir}/{}.json", t.bundle.trim_end_matches(".tar"));
    std::fs::write(side_path, serde_json::to_vec_pretty(&side).unwrap()).map_err(|e| e.to_string())?;
    Ok(path)
}

/// The bundle signed by `key`: what the router's own packer makes of its
/// files and that key.
pub fn signed(path: &Path, key: &Secret) -> Result<Vec<u8>, String> {
    let mut files = read_tar(path)?;
    let sums = files.remove(SUMS).ok_or("no SHA256SUMS")?;
    files.remove(SIGNATURE);
    if sums != sums_of(&files).into_bytes() {
        return Err("SHA256SUMS is not of the files".into());
    }
    Ok(tar_of(&files, Some(&key.sign(&sums))))
}

/// What a bundle is, from its build.json.
pub struct Info {
    pub plugin: String,
    pub version: String,
    pub arch: String,
    pub kernel: String,
}

/// What the router checks when it opens a bundle, but the signature's key:
/// the archive, `SHA256SUMS` against every file, the manifest's command
/// and modules in it; and of this plugin, that the manifest and build.json
/// agree. A signature line is checked for its form only.
pub fn verify(path: &Path) -> Result<String, String> {
    let (info, signer) = check(path)?;
    let signed = match signer {
        Some(k) => format!("signed by {}", keys::b64(&k)),
        None => "unsigned".into(),
    };
    Ok(format!("ok, {} {} for {} kernel {}, {signed}", info.plugin, info.version, info.arch, info.kernel))
}

/// `verify`'s checks; what the bundle is, and the key of a signature that
/// holds.
pub fn check(path: &Path) -> Result<(Info, Option<[u8; 32]>), String> {
    let mut files = read_tar(path)?;
    let signature = files.remove(SIGNATURE);
    let sums = files.remove(SUMS).ok_or("SHA256SUMS: not in the bundle")?;
    let sums = String::from_utf8(sums).map_err(|_| "SHA256SUMS: not UTF-8")?;
    let mut last: Option<&str> = None;
    let mut listed = BTreeMap::new();
    for (n, line) in sums.lines().enumerate() {
        let (digest, p) = line
            .split_once("  ")
            .filter(|(d, p)| d.len() == 64 && d.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) && !p.is_empty())
            .ok_or(format!("SHA256SUMS: line {} is not `<sha256 in hex>  <path>`", n + 1))?;
        if last.is_some_and(|l| l >= p) {
            return Err(format!("SHA256SUMS: line {} is not in the order of paths", n + 1));
        }
        last = Some(p);
        listed.insert(p, digest);
    }
    for (p, b) in &files {
        match listed.get(p.as_str()) {
            None => return Err(format!("{p}: not in SHA256SUMS")),
            Some(d) if *d != sha256_hex(b) => return Err(format!("{p}: not the digest SHA256SUMS lists")),
            Some(_) => {}
        }
    }
    if let Some(missing) = listed.keys().find(|p| !files.contains_key(**p)) {
        return Err(format!("{missing}: listed in SHA256SUMS but not in the bundle"));
    }
    let signer = match &signature {
        Some(s) => Some(keys::verify(&String::from_utf8_lossy(s), sums.as_bytes()).map_err(|e| format!("SHA256SUMS.sig: {e}"))?),
        None => None,
    };
    let text = std::str::from_utf8(files.get("manifest.toml").ok_or("manifest.toml: not in the bundle")?)
        .map_err(|_| "manifest.toml: not UTF-8")?;
    let m: toml::Value = toml::from_str(text).map_err(|e| format!("manifest.toml: {e}"))?;
    let command = m.get("service").and_then(|s| s.get("command")).and_then(|c| c.as_str()).unwrap_or_default();
    if !files.contains_key(command) {
        return Err(format!("{command}: the service's command is not in the bundle"));
    }
    let modules = m.get("modules");
    for name in modules.and_then(|x| x.get("load")).and_then(|l| l.as_array()).into_iter().flatten() {
        let p = format!("modules/{}.ko", name.as_str().unwrap_or_default());
        if !files.contains_key(&p) {
            return Err(format!("{p}: a module the manifest loads is not in the bundle"));
        }
    }
    let b: serde_json::Value =
        serde_json::from_slice(files.get("build.json").ok_or("build.json: not in the bundle")?).map_err(|e| format!("build.json: {e}"))?;
    let version = m.get("version").and_then(|v| v.as_str()).unwrap_or_default();
    let kernel = modules.and_then(|x| x.get("kernel")).and_then(|k| k.as_str()).unwrap_or_default();
    if b["version"].as_str() != Some(version) || b["kernel_package"].as_str() != Some(kernel) {
        return Err("build.json and manifest.toml disagree on the version or the kernel".into());
    }
    let id = m.get("id").and_then(|v| v.as_str()).unwrap_or_default();
    let info = Info {
        plugin: id.to_owned(),
        version: version.to_owned(),
        arch: b["arch"].as_str().unwrap_or_default().to_owned(),
        kernel: kernel.to_owned(),
    };
    Ok((info, signer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(awg_part("3.1.20261113-02").as_deref(), Some("3.1.20261113.2"));
        assert!(check_version("3.1.20261113.2-r1", "3.1.20261113-02").is_ok());
        assert!(check_version("3.1.20261113.2-r12", "3.1.20261113-02").is_ok());
        assert!(check_version("3.1.20261113.3-r1", "3.1.20261113-02").is_err());
        assert!(check_version("3.1.20261113.2", "3.1.20261113-02").is_err());
        assert!(check_version("3.1.20261113.2-rx", "3.1.20261113-02").is_err());
    }

    #[test]
    fn kernel_dirs() {
        assert_eq!(kernel_dir("6.12.112~67e205f2-r1"), "6.12.112-1-67e205f2");
    }

    #[test]
    fn kernel_goes_into_modules() {
        let m = "id = \"awg\"\n\n[modules]\nload = [\"amneziawg\"]\n\n[service]\ncommand = \"bin/x\"\n";
        let out = with_kernel(m, "6.12.112~ab-r1").unwrap();
        let v: toml::Value = toml::from_str(&out).unwrap();
        assert_eq!(v["modules"]["kernel"].as_str(), Some("6.12.112~ab-r1"));
        assert!(with_kernel(&out, "x").is_err());
        assert!(with_kernel("id = \"awg\"\n", "x").is_err());
    }

    #[test]
    fn tar_is_the_routers() {
        let mut files = BTreeMap::new();
        files.insert("bin/a".to_owned(), b"#!".to_vec());
        files.insert("m".to_owned(), vec![1; 700]);
        let t = tar_of(&files, Some("ed25519 a b\n"));
        // bin/a: header + 1 block; m: header + 2 blocks; SUMS: header + 1; sig: header + 1; end 2
        assert_eq!(t.len(), BLOCK * (2 + 3 + 2 + 2 + 2));
        assert_eq!(&t[100..108], b"0000755\0");
        assert_eq!(&t[2 * BLOCK + 100..2 * BLOCK + 108], b"0000644\0");
        assert_eq!(&t[257..263], b"ustar\0");
    }
}
