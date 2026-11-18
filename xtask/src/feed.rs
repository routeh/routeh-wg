//! The feed, in the router's format: a directory served as it is.
//!
//! ```text
//! index.json        {"feed": 1, "serial", "expires", "plugins": {id: [{version, builds}]}}
//! index.json.sig    "ed25519 <public key> <signature of index.json>"
//! blobs/<sha256>    each signed bundle, by the SHA-256 of its bytes
//! ```
//!
//! `publish` signs bundles into it and the index again; `missing` says
//! which targets of a release it has no build of this version for.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::bundle::{check, sha256_hex, signed};
use crate::keys::{self, Secret};
use crate::openwrt;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    feed: u64,
    serial: u64,
    expires: u64,
    plugins: BTreeMap<String, Vec<Version>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Version {
    version: String,
    builds: Vec<Build>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
struct Build {
    arch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kernel: Option<String>,
    blob: String,
    size: u64,
}

/// Versions as the router orders them:
/// runs of digits as numbers, other runs as text.
fn newer(a: &str, b: &str) -> Ordering {
    fn runs(s: &str) -> Vec<&str> {
        let mut out = Vec::new();
        let mut start = 0;
        let b = s.as_bytes();
        for i in 1..=b.len() {
            if i == b.len() || b[i].is_ascii_digit() != b[i - 1].is_ascii_digit() {
                out.push(&s[start..i]);
                start = i;
            }
        }
        out
    }
    let (ra, rb) = (runs(a), runs(b));
    for (x, y) in ra.iter().zip(&rb) {
        let o = match (x.parse::<u128>(), y.parse::<u128>()) {
            (Ok(x), Ok(y)) => x.cmp(&y),
            _ => x.cmp(y),
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    ra.len().cmp(&rb.len())
}

/// The index of a feed, checked against its signature by `key`; a new
/// one where there is none.
fn read(dir: &Path, key: &Secret) -> Result<Index, String> {
    let (index, sig) = (dir.join("index.json"), dir.join("index.json.sig"));
    if !index.exists() {
        return Ok(Index { feed: 1, serial: 0, expires: 0, plugins: BTreeMap::new() });
    }
    let text = std::fs::read(&index).map_err(|e| format!("{}: {e}", index.display()))?;
    let line = std::fs::read_to_string(&sig).map_err(|e| format!("{}: {e}", sig.display()))?;
    let by = keys::verify(&line, &text).map_err(|e| format!("index.json.sig: {e}"))?;
    if by != key.public() {
        return Err(format!(
            "index.json is signed by {}, not by this key: another key's feed is not written over",
            keys::b64(&by)
        ));
    }
    let i: Index = serde_json::from_slice(&text).map_err(|e| format!("index.json: {e}"))?;
    if i.feed != 1 {
        return Err(format!("index.json: feed format {} is not 1", i.feed));
    }
    Ok(i)
}

/// Signs each bundle into `blobs/`, adds its build to the index (a build of
/// the same version, architecture and kernel is replaced), raises
/// `serial`, sets `expires`, and signs the index. With no bundles, only
/// the index is signed again with a new `expires`.
pub fn publish(dir: &Path, key: &Secret, bundles: &[String], expires_days: u64) -> Result<(), String> {
    let mut index = read(dir, key)?;
    let blobs = dir.join("blobs");
    std::fs::create_dir_all(&blobs).map_err(|e| e.to_string())?;
    for b in bundles {
        let (info, _) = check(Path::new(b)).map_err(|e| format!("{b}: {e}"))?;
        let bytes = signed(Path::new(b), key)?;
        let sha = sha256_hex(&bytes);
        let blob = blobs.join(&sha);
        if !blob.exists() {
            std::fs::write(&blob, &bytes).map_err(|e| format!("{}: {e}", blob.display()))?;
        }
        let build = Build { arch: info.arch.clone(), kernel: Some(info.kernel.clone()), blob: format!("sha256:{sha}"), size: bytes.len() as u64 };
        let versions = index.plugins.entry(info.plugin.clone()).or_default();
        let v = match versions.iter().position(|v| v.version == info.version) {
            Some(i) => &mut versions[i],
            None => {
                versions.push(Version { version: info.version.clone(), builds: Vec::new() });
                versions.last_mut().unwrap()
            }
        };
        v.builds.retain(|x| !(x.arch == build.arch && x.kernel == build.kernel));
        v.builds.push(build);
        v.builds.sort_by(|a, b| (&a.arch, &a.kernel).cmp(&(&b.arch, &b.kernel)));
        versions.sort_by(|a, b| newer(&b.version, &a.version));
        eprintln!("{} {} {} kernel {}: blobs/{sha}", info.plugin, info.version, info.arch, info.kernel);
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    index.serial += 1;
    index.expires = now + expires_days * 86400;
    let mut text = serde_json::to_vec_pretty(&index).unwrap();
    text.push(b'\n');
    std::fs::write(dir.join("index.json"), &text).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("index.json.sig"), key.sign(&text)).map_err(|e| e.to_string())?;
    eprintln!("index.json: serial {}, expires in {expires_days} days", index.serial);
    Ok(())
}

/// The targets of a release that the feed has no build of this plugin's
/// version for, comma-separated (empty when it has every one).
pub fn missing(dir: &Path, release: &str) -> Result<String, String> {
    let index: Option<Index> = match std::fs::read(dir.join("index.json")) {
        Ok(text) => Some(serde_json::from_slice(&text).map_err(|e| format!("index.json: {e}"))?),
        Err(_) => None,
    };
    let version = crate::bundle::plugin_version();
    let builds: Vec<Build> = index
        .iter()
        .flat_map(|i| i.plugins.get("awg").into_iter().flatten())
        .filter(|v| v.version == version)
        .flat_map(|v| v.builds.clone())
        .collect();
    let lacking: Vec<String> = openwrt::resolve(release, "all")?
        .into_iter()
        .filter(|t| !builds.iter().any(|b| b.arch == t.arch && b.kernel.as_deref() == Some(t.kernel.as_str())))
        .map(|t| t.target)
        .collect();
    Ok(lacking.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_order_as_the_router() {
        assert_eq!(newer("3.1.20261113.2-r10", "3.1.20261113.2-r9"), Ordering::Greater);
        assert_eq!(newer("3.1.20261114.1-r1", "3.1.20261113.2-r9"), Ordering::Greater);
        assert_eq!(newer("1.0", "1.0"), Ordering::Equal);
        assert_eq!(newer("1.0", "1.0.1"), Ordering::Less);
    }
}
