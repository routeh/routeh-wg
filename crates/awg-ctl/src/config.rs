//! A tunnel's settings as `desired` carries them, read into what the module
//! takes.
//!
//! Each value as the router writes it into `desired`, as its configuration
//! writes it: `bytes` in canonical base64, a `range` as `"100-200"`, a
//! `duration` as `"25s"`, `"1m"` or `"2h"`, a `host_port` as
//! `"203.0.113.7:51820"` or `"[v6]:port"`. A range is also taken as
//! `{"lo": …, "hi": …}` or a number, a duration as a number of seconds. A
//! key it does not know is an error: the manifest and the service are one
//! bundle.

use std::net::SocketAddr;

use awg_netlink::{AllowedIp, Key, Obfuscation, U16Range, U32Range};
use routeh_plugin_sdk::protocol::base64;
use serde::Deserialize;
use serde_json::Value;

/// What one tunnel is to be, checked against everything the module would
/// refuse or misuse.
#[derive(Debug, Clone, PartialEq)]
pub struct TunnelConfig {
    pub private_key: Key,
    /// `None`: the module picks one.
    pub listen_port: Option<u16>,
    pub endpoint: SocketAddr,
    pub peer_public_key: Key,
    pub preshared_key: Option<Key>,
    /// `ZERO`: off.
    pub keepalive: U16Range,
    pub obfuscation: Obfuscation,
    pub header_protection_key: Option<Key>,
}

impl TunnelConfig {
    /// Everything through the one peer: what reaches the tunnel is decided
    /// by the router's routing, not by WireGuard's allowed IPs.
    pub fn allowed_ips() -> [AllowedIp; 2] {
        ["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()]
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    private_key: String,
    #[serde(default)]
    listen_port: Option<u16>,
    endpoint: String,
    peer_public_key: String,
    #[serde(default)]
    preshared_key: Option<String>,
    #[serde(default)]
    keepalive: Option<Value>,
    #[serde(default)]
    jc: u16,
    #[serde(default)]
    jmin: u16,
    #[serde(default)]
    jmax: u16,
    #[serde(default)]
    s1: u16,
    #[serde(default)]
    s2: u16,
    #[serde(default)]
    s3: u16,
    #[serde(default)]
    s4: u16,
    #[serde(default)]
    h1: Option<Value>,
    #[serde(default)]
    h2: Option<Value>,
    #[serde(default)]
    h3: Option<Value>,
    #[serde(default)]
    h4: Option<Value>,
    #[serde(default)]
    i1: String,
    #[serde(default)]
    i2: String,
    #[serde(default)]
    i3: String,
    #[serde(default)]
    i4: String,
    #[serde(default)]
    i5: String,
    #[serde(default)]
    header_protection_key: Option<String>,
    #[serde(default)]
    content_padding_addition: Option<Value>,
    #[serde(default)]
    rekey_after_time: Option<Value>,
    #[serde(default)]
    rekey_timeout: Option<Value>,
    #[serde(default)]
    reject_after_time: Option<Value>,
    #[serde(default)]
    keepalive_timeout: Option<Value>,
    #[serde(default)]
    max_handshake_attempts: Option<Value>,
    #[serde(default)]
    random_trailers: bool,
    #[serde(default)]
    disable_cookies: bool,
}

impl TunnelConfig {
    pub fn from_settings(v: &Value) -> Result<Self, String> {
        let r: Raw = serde_json::from_value(v.clone()).map_err(|e| e.to_string())?;
        let defaults = Obfuscation::default();
        let h = |v: &Option<Value>, n: usize| -> Result<U32Range, String> {
            match v {
                None => Ok(defaults.h[n]),
                Some(v) => range32(v).map_err(|e| format!("h{}: {e}", n + 1)),
            }
        };
        let r16 = |v: &Option<Value>, name: &str| -> Result<U16Range, String> {
            match v {
                None => Ok(U16Range::ZERO),
                Some(v) => range16(v).map_err(|e| format!("{name}: {e}")),
            }
        };
        let obfuscation = Obfuscation {
            jc: r.jc,
            jmin: r.jmin,
            jmax: r.jmax,
            s: [r.s1, r.s2, r.s3, r.s4],
            h: [h(&r.h1, 0)?, h(&r.h2, 1)?, h(&r.h3, 2)?, h(&r.h4, 3)?],
            i: [r.i1, r.i2, r.i3, r.i4, r.i5],
            content_padding_addition: r16(&r.content_padding_addition, "content_padding_addition")?,
            rekey_after_time: r16(&r.rekey_after_time, "rekey_after_time")?,
            rekey_timeout: r16(&r.rekey_timeout, "rekey_timeout")?,
            reject_after_time: r16(&r.reject_after_time, "reject_after_time")?,
            keepalive_timeout: r16(&r.keepalive_timeout, "keepalive_timeout")?,
            max_handshake_attempts: r16(&r.max_handshake_attempts, "max_handshake_attempts")?,
            random_trailers: r.random_trailers,
            disable_cookies: r.disable_cookies,
        };
        let header_protection_key = r
            .header_protection_key
            .as_deref()
            .map(|s| key(s).map_err(|e| format!("header_protection_key: {e}")))
            .transpose()?;
        obfuscation.validate(header_protection_key.is_some()).map_err(|e| e.to_string())?;

        let keepalive = match &r.keepalive {
            None => U16Range::ZERO,
            Some(v) => U16Range::fixed(seconds(v).map_err(|e| format!("keepalive: {e}"))?),
        };
        Ok(Self {
            private_key: key(&r.private_key).map_err(|e| format!("private_key: {e}"))?,
            listen_port: r.listen_port.filter(|&p| p != 0),
            endpoint: endpoint(&r.endpoint)?,
            peer_public_key: key(&r.peer_public_key).map_err(|e| format!("peer_public_key: {e}"))?,
            preshared_key: r
                .preshared_key
                .as_deref()
                .map(|s| key(s).map_err(|e| format!("preshared_key: {e}")))
                .transpose()?,
            keepalive,
            obfuscation,
            header_protection_key,
        })
    }
}

fn key(s: &str) -> Result<Key, String> {
    // Only the canonical form: padded, no whitespace, unused bits zero.
    let b = base64::decode(s)
        .filter(|b| base64::encode(b, true) == s)
        .ok_or("not base64")?;
    let b: [u8; 32] = b.try_into().map_err(|_| "not 32 bytes")?;
    Ok(Key::new(b))
}

/// A duration as the router writes it: a whole number and `s`, `m` or `h`
/// (`"25s"`, `"1m"`, `"2h"`), or a number of seconds.
fn seconds(v: &Value) -> Result<u16, String> {
    let n = match v {
        Value::Number(n) => n.as_u64().ok_or("not a whole number of seconds")?,
        Value::String(s) => {
            let unit = match s.chars().last() {
                Some('s') => 1,
                Some('m') => 60,
                Some('h') => 3600,
                _ => 0,
            };
            s[..s.len().saturating_sub(1)]
                .parse::<u64>()
                .ok()
                .filter(|_| unit > 0)
                .and_then(|n| n.checked_mul(unit))
                .ok_or_else(|| format!("{s:?} is not like \"25s\", \"1m\" or \"2h\""))?
        }
        _ => return Err("not a duration".into()),
    };
    u16::try_from(n).map_err(|_| format!("{n} s is over 65535 s"))
}

/// An address and a port. The router's type is `host_port`, which takes a
/// name too; this plugin resolves no names, so a name is refused here and
/// the apply fails with this message.
fn endpoint(s: &str) -> Result<std::net::SocketAddr, String> {
    if let Ok(a) = s.parse() {
        return Ok(a);
    }
    let host = s.rsplit_once(':').map_or(s, |(h, _)| h);
    if !host.is_empty() && !host.starts_with('[') && host.parse::<std::net::IpAddr>().is_err() {
        return Err(format!(
            "endpoint {s:?} names a host; AmneziaWG here resolves no names: write its address (203.0.113.7:51820 or [2001:db8::1]:51820)"
        ));
    }
    Err(format!("endpoint {s:?} is not an address and a port"))
}

fn range_parts(v: &Value) -> Result<(u64, u64), String> {
    match v {
        Value::Object(o) => {
            let get = |k: &str| o.get(k).and_then(Value::as_u64).ok_or_else(|| format!("no {k}"));
            Ok((get("lo")?, get("hi")?))
        }
        Value::Number(n) => {
            let n = n.as_u64().ok_or("not a whole number")?;
            Ok((n, n))
        }
        Value::String(s) => match s.split_once('-') {
            Some((a, b)) => Ok((a.parse().map_err(|_| "not lo-hi")?, b.parse().map_err(|_| "not lo-hi")?)),
            None => {
                let n = s.parse().map_err(|_| "not lo-hi")?;
                Ok((n, n))
            }
        },
        _ => Err("not a range".into()),
    }
}

fn range32(v: &Value) -> Result<U32Range, String> {
    let (lo, hi) = range_parts(v)?;
    let lo = u32::try_from(lo).map_err(|_| "too large")?;
    let hi = u32::try_from(hi).map_err(|_| "too large")?;
    U32Range::new(lo, hi).ok_or_else(|| format!("{lo}-{hi} runs backwards"))
}

fn range16(v: &Value) -> Result<U16Range, String> {
    let (lo, hi) = range_parts(v)?;
    let lo = u16::try_from(lo).map_err(|_| "too large")?;
    let hi = u16::try_from(hi).map_err(|_| "too large")?;
    U16Range::new(lo, hi).ok_or_else(|| format!("{lo}-{hi} runs backwards"))
}
