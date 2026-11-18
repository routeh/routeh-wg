//! `WG_CMD_SET_DEVICE` and `WG_CMD_GET_DEVICE`: what is sent and what is read.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::attr::{Attr, Attrs, MessageBuilder};
use crate::template;
use crate::types::*;
use crate::uapi::*;
use crate::Error;

/// Which module a device belongs to. The two share the first attributes
/// and differ in what follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    /// amneziawg-linux-kernel-module: family `amneziawg`, link kind
    /// `amneziawg`.
    Amnezia,
    /// The kernel's WireGuard: family `wireguard`, link kind `wireguard`.
    /// It has no obfuscation, its keepalive is a plain `u16`, and its
    /// strict validation refuses any attribute past `WGDEVICE_A_PEERS`.
    WireGuard,
}

impl Flavor {
    pub fn family_name(self) -> &'static str {
        match self {
            Flavor::Amnezia => "amneziawg",
            Flavor::WireGuard => "wireguard",
        }
    }
    /// `IFLA_INFO_KIND` of its devices (`KBUILD_MODNAME`).
    pub fn link_kind(self) -> &'static str {
        self.family_name()
    }
    fn genl_version(self) -> u8 {
        match self {
            Flavor::Amnezia => 3,
            Flavor::WireGuard => 1,
        }
    }
}

/// Everything AmneziaWG adds to a device, whole.
///
/// It is always sent whole: the module keeps every value it is not sent,
/// so a value left out would stay as an earlier configuration set it.
/// `Default` is what a new device has (`wg_setup`): no junk, no padding,
/// headers 1, 2, 3, 4, no I-packets, the module's timers.
///
/// The header protection key is not here: once set it cannot be taken off
/// a device (there is no way to clear it), so it is a field of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Obfuscation {
    /// Junk packets before each handshake initiation; none while 0 or
    /// while `jmax` is 0.
    pub jc: u16,
    pub jmin: u16,
    pub jmax: u16,
    /// Random bytes before the init, response, cookie and data messages.
    pub s: [u16; 4],
    /// The message types of init, response, cookie and data.
    pub h: [U32Range; 4],
    /// I1–I5 (`template`); "" sends nothing.
    pub i: [String; 5],
    pub content_padding_addition: U16Range,
    pub rekey_after_time: U16Range,
    pub rekey_timeout: U16Range,
    pub reject_after_time: U16Range,
    pub keepalive_timeout: U16Range,
    pub max_handshake_attempts: U16Range,
    pub random_trailers: bool,
    pub disable_cookies: bool,
}

impl Default for Obfuscation {
    fn default() -> Self {
        Self {
            jc: 0,
            jmin: 0,
            jmax: 0,
            s: [0; 4],
            h: [1, 2, 3, 4].map(U32Range::fixed),
            i: Default::default(),
            content_padding_addition: U16Range::ZERO,
            rekey_after_time: U16Range::ZERO,
            rekey_timeout: U16Range::ZERO,
            reject_after_time: U16Range::ZERO,
            keepalive_timeout: U16Range::ZERO,
            max_handshake_attempts: U16Range::ZERO,
            random_trailers: false,
            disable_cookies: false,
        }
    }
}

impl Obfuscation {
    /// Every value the module would refuse, or take and misuse, with the
    /// reason, in one error. `header_protection` says whether the device
    /// will have a header protection key.
    ///
    /// The module itself checks only the overlap of H and the minimum of S;
    /// `jmin > jmax` it takes, and then writes junk past the end of a buffer
    /// of `jmax` bytes (`send.c`, `wg_packet_send_handshake_initiation`).
    pub fn validate(&self, header_protection: bool) -> Result<(), Error> {
        let mut why = Vec::new();
        if self.jmin > self.jmax {
            why.push(format!("Jmin ({}) is above Jmax ({})", self.jmin, self.jmax));
        }
        for (n, h) in self.h.iter().enumerate() {
            if !h.is_ordered() {
                why.push(format!("H{} ({h}) runs backwards", n + 1));
            }
            for (m, g) in self.h.iter().enumerate().skip(n + 1) {
                if h.overlaps(*g) {
                    why.push(format!("H{} ({h}) overlaps H{} ({g})", n + 1, m + 1));
                }
            }
        }
        if header_protection {
            for (n, s) in self.s.iter().enumerate() {
                if *s < HEADER_PROTECTION_NONCE_SIZE {
                    why.push(format!(
                        "S{} ({s}) must be at least {HEADER_PROTECTION_NONCE_SIZE} with a header protection key",
                        n + 1
                    ));
                }
            }
        }
        for (n, t) in self.i.iter().enumerate() {
            if let Err(e) = template::packet_size(t) {
                why.push(format!("I{}: {e}", n + 1));
            }
        }
        for (name, r) in [
            ("content padding addition", self.content_padding_addition),
            ("rekey after time", self.rekey_after_time),
            ("rekey timeout", self.rekey_timeout),
            ("reject after time", self.reject_after_time),
            ("keepalive timeout", self.keepalive_timeout),
            ("max handshake attempts", self.max_handshake_attempts),
        ] {
            if !r.is_ordered() {
                why.push(format!("{name} ({r}) runs backwards"));
            }
        }
        if why.is_empty() {
            Ok(())
        } else {
            Err(Error::Invalid(why.join("; ")))
        }
    }

    fn put(&self, b: &mut MessageBuilder) {
        b.put_u16(WGDEVICE_A_JC, self.jc)
            .put_u16(WGDEVICE_A_JMIN, self.jmin)
            .put_u16(WGDEVICE_A_JMAX, self.jmax);
        for (ty, s) in [WGDEVICE_A_S1, WGDEVICE_A_S2, WGDEVICE_A_S3, WGDEVICE_A_S4].iter().zip(self.s) {
            b.put_u16(*ty, s);
        }
        // All four in one message: each is checked against the others'
        // values of this message, so none is refused for overlapping a
        // value that is being replaced.
        for (ty, h) in [WGDEVICE_A_H1, WGDEVICE_A_H2, WGDEVICE_A_H3, WGDEVICE_A_H4].iter().zip(self.h) {
            b.put_u64(*ty, h.to_raw());
        }
        for (n, t) in self.i.iter().enumerate() {
            b.put_str(WGDEVICE_A_I1 + n as u16, t);
        }
        b.put_u32(WGDEVICE_A_CONTENT_PADDING_ADDITION, self.content_padding_addition.to_raw())
            .put_u32(WGDEVICE_A_REKEY_AFTER_TIME, self.rekey_after_time.to_raw())
            .put_u32(WGDEVICE_A_REKEY_TIMEOUT, self.rekey_timeout.to_raw())
            .put_u32(WGDEVICE_A_REJECT_AFTER_TIME, self.reject_after_time.to_raw())
            .put_u32(WGDEVICE_A_KEEPALIVE_TIMEOUT, self.keepalive_timeout.to_raw())
            .put_u32(WGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS, self.max_handshake_attempts.to_raw())
            .put_u8(WGDEVICE_A_RANDOM_TRAILERS, self.random_trailers as u8)
            .put_u8(WGDEVICE_A_DISABLE_COOKIES, self.disable_cookies as u8);
    }
}

/// What to change on a device. `None` leaves a value as it is.
#[derive(Debug, Clone, Default)]
pub struct DeviceUpdate {
    pub ifname: String,
    pub private_key: Option<Key>,
    pub listen_port: Option<u16>,
    /// The mark of the outer socket. Setting it forgets every peer's cached
    /// source address, even when it is the same mark.
    pub fwmark: Option<u32>,
    /// Remove every peer before adding `peers`.
    pub replace_peers: bool,
    /// AmneziaWG only; sent whole (`Obfuscation`).
    pub obfuscation: Option<Obfuscation>,
    /// AmneziaWG only. Cannot be removed once set: a device that is to
    /// lose it has to be made again.
    pub header_protection_key: Option<Key>,
    pub peers: Vec<PeerUpdate>,
}

#[derive(Debug, Clone)]
pub struct PeerUpdate {
    pub public_key: Key,
    /// `Some(Key::ZERO)` removes it.
    pub preshared_key: Option<Key>,
    pub endpoint: Option<SocketAddr>,
    /// AmneziaWG takes a range; WireGuard a single value (`fixed`).
    /// `ZERO` turns it off.
    pub persistent_keepalive: Option<U16Range>,
    pub replace_allowed_ips: bool,
    pub allowed_ips: Vec<AllowedIp>,
    pub remove: bool,
    /// Change the peer only if it exists; never add it.
    pub update_only: bool,
}

impl PeerUpdate {
    pub fn new(public_key: Key) -> Self {
        Self {
            public_key,
            preshared_key: None,
            endpoint: None,
            persistent_keepalive: None,
            replace_allowed_ips: false,
            allowed_ips: Vec::new(),
            remove: false,
            update_only: false,
        }
    }
}

/// Allowed IPs per piece of a peer: about 40 bytes each, so a piece stays
/// well under the 64 KiB a nested attribute can hold.
const ALLOWED_IPS_PER_PIECE: usize = 512;
/// Room for peers in one message (`WGDEVICE_A_PEERS` is one attribute, its
/// length a u16).
const PEERS_BUDGET: usize = 60 * 1024;

/// The messages of a `WG_CMD_SET_DEVICE`, in order.
///
/// Usually one. Peers that do not fit in one attribute go on in further
/// messages, and a peer with more allowed IPs than fit in one piece is
/// continued in the next piece by its public key alone, as wireguard-tools
/// does. The module applies each message as it comes and nothing is
/// undone when one fails: after an error the device is partly changed,
/// and the caller reads it again.
pub fn set_device_messages(
    family: u16,
    flavor: Flavor,
    u: &DeviceUpdate,
    mut seq: impl FnMut() -> u32,
) -> Result<Vec<Vec<u8>>, Error> {
    check_ifname(&u.ifname)?;
    if flavor == Flavor::WireGuard && (u.obfuscation.is_some() || u.header_protection_key.is_some()) {
        return Err(Error::Invalid("WireGuard has no obfuscation".into()));
    }
    if let Some(o) = &u.obfuscation {
        o.validate(u.header_protection_key.is_some())?;
    } else if u.header_protection_key.is_some() {
        return Err(Error::Invalid(
            "a header protection key needs the obfuscation (S1–S4) in the same update".into(),
        ));
    }

    let mut pieces = Vec::new();
    for p in &u.peers {
        peer_pieces(flavor, p, &mut pieces)?;
    }

    let mut out = Vec::new();
    let mut b = start(family, flavor, &u.ifname, seq());
    if u.replace_peers {
        b.put_u32(WGDEVICE_A_FLAGS, WGDEVICE_F_REPLACE_PEERS);
    }
    if let Some(port) = u.listen_port {
        b.put_u16(WGDEVICE_A_LISTEN_PORT, port);
    }
    if let Some(mark) = u.fwmark {
        b.put_u32(WGDEVICE_A_FWMARK, mark);
    }
    // S1–S4 come before the key in the message, and the module reads them
    // first: so a device can get S ≥ 12 and the key in one message.
    if let Some(o) = &u.obfuscation {
        o.put(&mut b);
    }
    if let Some(k) = &u.header_protection_key {
        b.put(WGDEVICE_A_HEADER_PROTECTION_KEY, k.as_bytes());
    }
    if let Some(k) = &u.private_key {
        b.put(WGDEVICE_A_PRIVATE_KEY, k.as_bytes());
    }

    let mut used = 0;
    let mut open = false;
    for piece in pieces {
        if open && used + piece.len() > PEERS_BUDGET {
            b.end_nest();
            out.push(b.finish());
            b = start(family, flavor, &u.ifname, seq());
            open = false;
            used = 0;
        }
        if !open {
            b.nest(WGDEVICE_A_PEERS);
            open = true;
        }
        b.bytes(&piece);
        used += piece.len();
    }
    if open {
        b.end_nest();
    }
    out.push(b.finish());
    Ok(out)
}

fn start(family: u16, flavor: Flavor, ifname: &str, seq: u32) -> MessageBuilder {
    let mut b = MessageBuilder::new(family, NLM_F_REQUEST | NLM_F_ACK, seq);
    b.genl_header(WG_CMD_SET_DEVICE, flavor.genl_version());
    b.put_str(WGDEVICE_A_IFNAME, ifname);
    b
}

fn check_ifname(name: &str) -> Result<(), Error> {
    if name.is_empty() || name.len() >= IFNAMSIZ || name.contains(['/', '\0']) || name.contains(char::is_whitespace) {
        return Err(Error::Invalid(format!("{name:?} is not a device name")));
    }
    Ok(())
}

/// One peer as the nested attributes it is sent as, each piece a whole
/// entry of `WGDEVICE_A_PEERS`.
fn peer_pieces(flavor: Flavor, p: &PeerUpdate, out: &mut Vec<Vec<u8>>) -> Result<(), Error> {
    let mut flags = 0;
    if p.remove {
        flags |= WGPEER_F_REMOVE_ME;
    }
    if p.replace_allowed_ips {
        flags |= WGPEER_F_REPLACE_ALLOWEDIPS;
    }
    if p.update_only {
        flags |= WGPEER_F_UPDATE_ONLY;
    }
    let chunks: Vec<&[AllowedIp]> = if p.allowed_ips.is_empty() {
        vec![&[]]
    } else {
        p.allowed_ips.chunks(ALLOWED_IPS_PER_PIECE).collect()
    };
    for (n, ips) in chunks.into_iter().enumerate() {
        let mut b = MessageBuilder::attrs();
        b.nest(0);
        b.put(WGPEER_A_PUBLIC_KEY, p.public_key.as_bytes());
        if n == 0 {
            if flags != 0 {
                b.put_u32(WGPEER_A_FLAGS, flags);
            }
            if let Some(k) = &p.preshared_key {
                b.put(WGPEER_A_PRESHARED_KEY, k.as_bytes());
            }
            if let Some(e) = &p.endpoint {
                b.put(WGPEER_A_ENDPOINT, &sockaddr_bytes(e));
            }
            if let Some(k) = p.persistent_keepalive {
                if !k.is_ordered() {
                    return Err(Error::Invalid(format!("keepalive {k} runs backwards")));
                }
                match flavor {
                    Flavor::Amnezia => b.put_u32(WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, k.to_raw()),
                    Flavor::WireGuard if k.lo() == k.hi() => {
                        b.put_u16(WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, k.lo())
                    }
                    Flavor::WireGuard => {
                        return Err(Error::Invalid(format!("WireGuard's keepalive is one value, not {k}")))
                    }
                };
            }
        }
        if !ips.is_empty() {
            b.nest(WGPEER_A_ALLOWEDIPS);
            for ip in ips {
                let ip = AllowedIp::new(ip.addr, ip.cidr)?;
                b.nest(0);
                match ip.addr {
                    IpAddr::V4(a) => {
                        b.put_u16(WGALLOWEDIP_A_FAMILY, AF_INET).put(WGALLOWEDIP_A_IPADDR, &a.octets())
                    }
                    IpAddr::V6(a) => {
                        b.put_u16(WGALLOWEDIP_A_FAMILY, AF_INET6).put(WGALLOWEDIP_A_IPADDR, &a.octets())
                    }
                };
                b.put_u8(WGALLOWEDIP_A_CIDR_MASK, ip.cidr);
                b.end_nest();
            }
            b.end_nest();
        }
        b.end_nest();
        out.push(b.finish_attrs());
    }
    Ok(())
}

/// The request of a `WG_CMD_GET_DEVICE` dump of one device.
pub fn get_device_message(family: u16, flavor: Flavor, ifname: &str, seq: u32) -> Result<Vec<u8>, Error> {
    check_ifname(ifname)?;
    let mut b = MessageBuilder::new(family, NLM_F_REQUEST | NLM_F_DUMP, seq);
    b.genl_header(WG_CMD_GET_DEVICE, flavor.genl_version());
    b.put_str(WGDEVICE_A_IFNAME, ifname);
    Ok(b.finish())
}

/// A device as a dump reports it.
#[derive(Debug, Clone, Default)]
pub struct Device {
    pub ifindex: u32,
    pub ifname: String,
    pub private_key: Option<Key>,
    pub public_key: Option<Key>,
    pub listen_port: u16,
    pub fwmark: u32,
    /// `None` for a WireGuard device.
    pub obfuscation: Option<Obfuscation>,
    pub header_protection_key: Option<Key>,
    pub peers: Vec<Peer>,
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub public_key: Key,
    pub preshared_key: Option<Key>,
    /// Where the peer was last heard from. With the module's parameter
    /// `bogus_endpoints` set, a made-up address (`main.c`).
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive: U16Range,
    /// Since 1970; `None` before the first handshake.
    pub last_handshake: Option<Duration>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub allowed_ips: Vec<AllowedIp>,
}

/// One device from the payloads (after the generic netlink header) of a
/// dump's messages.
///
/// The device's own attributes come in the first message only. Peers go on
/// across messages, and a peer whose allowed IPs did not fit comes again
/// at the start of the next with its public key and the rest of its
/// allowed IPs; it is joined to the one before.
pub fn parse_device<'a>(payloads: impl IntoIterator<Item = &'a [u8]>) -> Result<Device, Error> {
    let mut d = Device::default();
    for p in payloads {
        for a in Attrs(p) {
            let a = a?;
            match a.ty {
                WGDEVICE_A_IFINDEX => d.ifindex = a.u32()?,
                WGDEVICE_A_IFNAME => d.ifname = a.str()?.to_owned(),
                WGDEVICE_A_PRIVATE_KEY => d.private_key = Some(Key::new(a.key()?)),
                WGDEVICE_A_PUBLIC_KEY => d.public_key = Some(Key::new(a.key()?)),
                WGDEVICE_A_LISTEN_PORT => d.listen_port = a.u16()?,
                WGDEVICE_A_FWMARK => d.fwmark = a.u32()?,
                WGDEVICE_A_HEADER_PROTECTION_KEY => d.header_protection_key = Some(Key::new(a.key()?)),
                WGDEVICE_A_PEERS => {
                    for entry in a.nested() {
                        let peer = parse_peer(&entry?)?;
                        match d.peers.last_mut() {
                            Some(last) if last.public_key == peer.public_key => {
                                last.allowed_ips.extend(peer.allowed_ips)
                            }
                            _ => d.peers.push(peer),
                        }
                    }
                }
                WGDEVICE_A_JC..=WGDEVICE_A_DISABLE_COOKIES => {
                    obfuscation_attr(d.obfuscation.get_or_insert_with(Default::default), &a)?
                }
                _ => {}
            }
        }
    }
    Ok(d)
}

fn obfuscation_attr(o: &mut Obfuscation, a: &Attr<'_>) -> Result<(), Error> {
    match a.ty {
        WGDEVICE_A_JC => o.jc = a.u16()?,
        WGDEVICE_A_JMIN => o.jmin = a.u16()?,
        WGDEVICE_A_JMAX => o.jmax = a.u16()?,
        WGDEVICE_A_S1 => o.s[0] = a.u16()?,
        WGDEVICE_A_S2 => o.s[1] = a.u16()?,
        WGDEVICE_A_S3 => o.s[2] = a.u16()?,
        WGDEVICE_A_S4 => o.s[3] = a.u16()?,
        WGDEVICE_A_H1..=WGDEVICE_A_H4 => o.h[(a.ty - WGDEVICE_A_H1) as usize] = U32Range::from_raw(a.u64()?),
        WGDEVICE_A_I1..=WGDEVICE_A_I5 => o.i[(a.ty - WGDEVICE_A_I1) as usize] = a.str()?.to_owned(),
        WGDEVICE_A_CONTENT_PADDING_ADDITION => o.content_padding_addition = U16Range::from_raw(a.u32()?),
        WGDEVICE_A_REKEY_AFTER_TIME => o.rekey_after_time = U16Range::from_raw(a.u32()?),
        WGDEVICE_A_REKEY_TIMEOUT => o.rekey_timeout = U16Range::from_raw(a.u32()?),
        WGDEVICE_A_REJECT_AFTER_TIME => o.reject_after_time = U16Range::from_raw(a.u32()?),
        WGDEVICE_A_KEEPALIVE_TIMEOUT => o.keepalive_timeout = U16Range::from_raw(a.u32()?),
        WGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS => o.max_handshake_attempts = U16Range::from_raw(a.u32()?),
        WGDEVICE_A_RANDOM_TRAILERS => o.random_trailers = a.u8()? != 0,
        WGDEVICE_A_DISABLE_COOKIES => o.disable_cookies = a.u8()? != 0,
        _ => {} // WGDEVICE_A_PEER: only in WG_CMD_UNKNOWN_PEER
    }
    Ok(())
}

fn parse_peer(entry: &Attr<'_>) -> Result<Peer, Error> {
    let mut key = None;
    let mut p = Peer {
        public_key: Key::ZERO,
        preshared_key: None,
        endpoint: None,
        persistent_keepalive: U16Range::ZERO,
        last_handshake: None,
        rx_bytes: 0,
        tx_bytes: 0,
        allowed_ips: Vec::new(),
    };
    for a in entry.nested() {
        let a = a?;
        match a.ty {
            WGPEER_A_PUBLIC_KEY => key = Some(Key::new(a.key()?)),
            WGPEER_A_PRESHARED_KEY => {
                let k = Key::new(a.key()?);
                p.preshared_key = (!k.is_zero()).then_some(k);
            }
            WGPEER_A_ENDPOINT => p.endpoint = parse_sockaddr(a.payload)?,
            // AmneziaWG: a u16 range in a u32; WireGuard: a u16.
            WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL => {
                p.persistent_keepalive = match a.payload.len() {
                    2 => U16Range::fixed(a.u16()?),
                    _ => U16Range::from_raw(a.u32()?),
                }
            }
            WGPEER_A_LAST_HANDSHAKE_TIME => {
                // struct __kernel_timespec { s64 tv_sec; s64 tv_nsec; }
                if a.payload.len() != 16 {
                    return Err(Error::Malformed("last handshake time"));
                }
                let sec = i64::from_ne_bytes(a.payload[0..8].try_into().unwrap());
                let nsec = i64::from_ne_bytes(a.payload[8..16].try_into().unwrap());
                p.last_handshake = (sec > 0 || nsec > 0)
                    .then(|| Duration::new(sec.max(0) as u64, nsec.clamp(0, 999_999_999) as u32));
            }
            WGPEER_A_RX_BYTES => p.rx_bytes = a.u64()?,
            WGPEER_A_TX_BYTES => p.tx_bytes = a.u64()?,
            WGPEER_A_ALLOWEDIPS => {
                for ip in a.nested() {
                    p.allowed_ips.push(parse_allowed_ip(&ip?)?);
                }
            }
            _ => {} // flags, protocol version, the u64 pad (type 0)
        }
    }
    p.public_key = key.ok_or(Error::Malformed("peer without a public key"))?;
    Ok(p)
}

fn parse_allowed_ip(entry: &Attr<'_>) -> Result<AllowedIp, Error> {
    let (mut family, mut addr, mut cidr) = (None, None, None);
    for a in entry.nested() {
        let a = a?;
        match a.ty {
            WGALLOWEDIP_A_FAMILY => family = Some(a.u16()?),
            WGALLOWEDIP_A_IPADDR => addr = Some(a.payload),
            WGALLOWEDIP_A_CIDR_MASK => cidr = Some(a.u8()?),
            _ => {}
        }
    }
    let ip: IpAddr = match (family, addr) {
        (Some(AF_INET), Some(b)) if b.len() == 4 => <[u8; 4]>::try_from(b).unwrap().into(),
        (Some(AF_INET6), Some(b)) if b.len() == 16 => <[u8; 16]>::try_from(b).unwrap().into(),
        _ => return Err(Error::Malformed("allowed IP")),
    };
    AllowedIp::new(ip, cidr.ok_or(Error::Malformed("allowed IP without a prefix"))?)
}
