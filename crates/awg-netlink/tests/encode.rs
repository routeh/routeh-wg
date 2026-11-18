//! What is sent is checked byte by byte against what the module's policy
//! (`netlink.c`, `device_policy`, `peer_policy`, `allowedip_policy`) takes
//! in strict validation: exact lengths, `NLA_F_NESTED` on nests, no
//! attribute past the family's last.

use std::net::SocketAddr;
use std::time::Duration;

use awg_netlink::attr::{messages, Attr, Attrs, MessageBuilder};
use awg_netlink::device::{get_device_message, parse_device, set_device_messages};
use awg_netlink::uapi::*;
use awg_netlink::*;

const FAMILY: u16 = 0x1d;

fn key(b: u8) -> Key {
    Key::new([b; 32])
}

fn seq() -> impl FnMut() -> u32 {
    let mut n = 0;
    move || {
        n += 1;
        n
    }
}

/// The attributes of a generic netlink message, with their raw type (flags
/// kept) and payload.
fn raw_attrs(payload: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    let mut b = payload;
    while !b.is_empty() {
        let len = u16::from_ne_bytes([b[0], b[1]]) as usize;
        let ty = u16::from_ne_bytes([b[2], b[3]]);
        out.push((ty, b[4..len].to_vec()));
        b = &b[((len + 3) & !3).min(b.len())..];
    }
    out
}

fn genl_payload(msg: &[u8]) -> &[u8] {
    let m = messages(msg).next().unwrap().unwrap();
    &msg[NLMSG_HDRLEN + GENL_HDRLEN..NLMSG_HDRLEN + m.payload.len()]
}

fn full_obfuscation() -> Obfuscation {
    Obfuscation {
        jc: 4,
        jmin: 40,
        jmax: 70,
        s: [15, 18, 20, 23],
        h: [
            U32Range::new(100_000, 200_000).unwrap(),
            U32Range::new(300_000, 400_000).unwrap(),
            U32Range::fixed(500_000),
            U32Range::new(600_000, 700_000).unwrap(),
        ],
        i: [
            "<b 0xc0ff><r 16><c><t>".into(),
            String::new(),
            "<rc 8>".into(),
            String::new(),
            String::new(),
        ],
        content_padding_addition: U16Range::new(0, 32).unwrap(),
        rekey_after_time: U16Range::new(110, 130).unwrap(),
        rekey_timeout: U16Range::ZERO,
        reject_after_time: U16Range::ZERO,
        keepalive_timeout: U16Range::new(8, 12).unwrap(),
        max_handshake_attempts: U16Range::ZERO,
        random_trailers: true,
        disable_cookies: false,
    }
}

fn client_update() -> DeviceUpdate {
    let mut peer = PeerUpdate::new(key(2));
    peer.endpoint = Some("203.0.113.7:51820".parse().unwrap());
    peer.persistent_keepalive = Some(U16Range::new(20, 30).unwrap());
    peer.replace_allowed_ips = true;
    peer.allowed_ips = vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()];
    DeviceUpdate {
        ifname: "tn_vpn".into(),
        private_key: Some(key(1)),
        listen_port: Some(51820),
        fwmark: Some(257),
        replace_peers: true,
        obfuscation: Some(full_obfuscation()),
        header_protection_key: Some(key(9)),
        peers: vec![peer],
    }
}

#[test]
fn set_device_matches_the_module_policy() {
    let msgs = set_device_messages(FAMILY, Flavor::Amnezia, &client_update(), seq()).unwrap();
    assert_eq!(msgs.len(), 1);
    let m = &msgs[0];
    let hdr = messages(m).next().unwrap().unwrap();
    assert_eq!(hdr.ty, FAMILY);
    assert_eq!(hdr.flags, NLM_F_REQUEST | NLM_F_ACK);
    assert_eq!(m[NLMSG_HDRLEN], WG_CMD_SET_DEVICE);

    let attrs = raw_attrs(genl_payload(m));
    let get = |ty: u16| attrs.iter().find(|(t, _)| t & NLA_TYPE_MASK == ty).map(|(t, p)| (*t, p.clone()));

    assert_eq!(get(WGDEVICE_A_IFNAME).unwrap().1, b"tn_vpn\0");
    assert_eq!(get(WGDEVICE_A_FLAGS).unwrap().1, WGDEVICE_F_REPLACE_PEERS.to_ne_bytes());
    assert_eq!(get(WGDEVICE_A_LISTEN_PORT).unwrap().1, 51820u16.to_ne_bytes());
    assert_eq!(get(WGDEVICE_A_FWMARK).unwrap().1, 257u32.to_ne_bytes());
    // NLA_U16, exactly 2 bytes in strict validation
    for ty in [WGDEVICE_A_JC, WGDEVICE_A_JMIN, WGDEVICE_A_JMAX, WGDEVICE_A_S1, WGDEVICE_A_S2, WGDEVICE_A_S3, WGDEVICE_A_S4] {
        assert_eq!(get(ty).unwrap().1.len(), 2, "attr {ty}");
    }
    assert_eq!(get(WGDEVICE_A_S4).unwrap().1, 23u16.to_ne_bytes());
    // NLA_U64: (hi << 32) | lo
    assert_eq!(get(WGDEVICE_A_H1).unwrap().1, ((200_000u64 << 32) | 100_000).to_ne_bytes());
    assert_eq!(get(WGDEVICE_A_H3).unwrap().1, ((500_000u64 << 32) | 500_000).to_ne_bytes());
    // NLA_NUL_STRING; an empty one is a lone NUL and clears the I-packet
    assert_eq!(get(WGDEVICE_A_I1).unwrap().1, b"<b 0xc0ff><r 16><c><t>\0");
    assert_eq!(get(WGDEVICE_A_I2).unwrap().1, b"\0");
    // NLA_U32 holding a u16 range: (hi << 16) | lo
    assert_eq!(get(WGDEVICE_A_CONTENT_PADDING_ADDITION).unwrap().1, (32u32 << 16).to_ne_bytes());
    assert_eq!(get(WGDEVICE_A_REKEY_AFTER_TIME).unwrap().1, ((130u32 << 16) | 110).to_ne_bytes());
    assert_eq!(get(WGDEVICE_A_REKEY_TIMEOUT).unwrap().1, 0u32.to_ne_bytes());
    // NLA_U8
    assert_eq!(get(WGDEVICE_A_RANDOM_TRAILERS).unwrap().1, [1]);
    assert_eq!(get(WGDEVICE_A_DISABLE_COOKIES).unwrap().1, [0]);
    // exact 32
    assert_eq!(get(WGDEVICE_A_HEADER_PROTECTION_KEY).unwrap().1, [9; 32]);
    assert_eq!(get(WGDEVICE_A_PRIVATE_KEY).unwrap().1, [1; 32]);

    // S1–S4 before the header protection key: the module reads S first.
    let pos = |ty: u16| attrs.iter().position(|(t, _)| t & NLA_TYPE_MASK == ty).unwrap();
    assert!(pos(WGDEVICE_A_S4) < pos(WGDEVICE_A_HEADER_PROTECTION_KEY));

    // no attribute beyond the family's last
    assert!(attrs.iter().all(|(t, _)| t & NLA_TYPE_MASK <= WGDEVICE_A_DISABLE_COOKIES));

    // peers: nested, flagged
    let (pt, peers) = get(WGDEVICE_A_PEERS).unwrap();
    assert_eq!(pt, WGDEVICE_A_PEERS | NLA_F_NESTED);
    let entries = raw_attrs(&peers);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, NLA_F_NESTED);
    let p = raw_attrs(&entries[0].1);
    let pget = |ty: u16| p.iter().find(|(t, _)| t & NLA_TYPE_MASK == ty).map(|(t, v)| (*t, v.clone()));
    assert_eq!(pget(WGPEER_A_PUBLIC_KEY).unwrap().1, [2; 32]);
    assert_eq!(pget(WGPEER_A_FLAGS).unwrap().1, WGPEER_F_REPLACE_ALLOWEDIPS.to_ne_bytes());
    // the u32 range, never a bare 20
    assert_eq!(pget(WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL).unwrap().1, ((30u32 << 16) | 20).to_ne_bytes());
    let ep = pget(WGPEER_A_ENDPOINT).unwrap().1;
    assert_eq!(ep.len(), SOCKADDR_IN_LEN);
    assert_eq!(&ep[0..2], &AF_INET.to_ne_bytes());
    assert_eq!(&ep[2..4], &51820u16.to_be_bytes());
    assert_eq!(&ep[4..8], &[203, 0, 113, 7]);
    let (it, ips) = pget(WGPEER_A_ALLOWEDIPS).unwrap();
    assert_eq!(it, WGPEER_A_ALLOWEDIPS | NLA_F_NESTED);
    let ips = raw_attrs(&ips);
    assert_eq!(ips.len(), 2);
    let v6 = raw_attrs(&ips[1].1);
    assert_eq!(v6[0], (WGALLOWEDIP_A_FAMILY, AF_INET6.to_ne_bytes().to_vec()));
    assert_eq!(v6[1], (WGALLOWEDIP_A_IPADDR, vec![0; 16]));
    assert_eq!(v6[2], (WGALLOWEDIP_A_CIDR_MASK, vec![0]));
}

#[test]
fn wireguard_gets_a_u16_keepalive_and_no_obfuscation() {
    let mut u = client_update();
    u.obfuscation = None;
    u.header_protection_key = None;
    u.peers[0].persistent_keepalive = Some(U16Range::fixed(25));
    let msgs = set_device_messages(FAMILY, Flavor::WireGuard, &u, seq()).unwrap();
    let attrs = raw_attrs(genl_payload(&msgs[0]));
    assert!(attrs.iter().all(|(t, _)| t & NLA_TYPE_MASK <= WGDEVICE_A_PEERS));
    let peers = &attrs.iter().find(|(t, _)| t & NLA_TYPE_MASK == WGDEVICE_A_PEERS).unwrap().1;
    let p = raw_attrs(&raw_attrs(peers)[0].1);
    let ka = &p.iter().find(|(t, _)| *t == WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL).unwrap().1;
    assert_eq!(ka, &25u16.to_ne_bytes());

    u.peers[0].persistent_keepalive = Some(U16Range::new(20, 30).unwrap());
    assert!(set_device_messages(FAMILY, Flavor::WireGuard, &u, seq()).is_err());
    assert!(set_device_messages(FAMILY, Flavor::WireGuard, &client_update(), seq()).is_err());
}

#[test]
fn what_the_module_would_misuse_is_refused() {
    let check = |f: &dyn Fn(&mut DeviceUpdate), needle: &str| {
        let mut u = client_update();
        f(&mut u);
        let e = set_device_messages(FAMILY, Flavor::Amnezia, &u, seq()).unwrap_err().to_string();
        assert!(e.contains(needle), "{e:?} lacks {needle:?}");
    };
    check(&|u| u.obfuscation.as_mut().unwrap().jmin = 71, "Jmin (71) is above Jmax (70)");
    check(&|u| u.obfuscation.as_mut().unwrap().h[1] = U32Range::new(150_000, 160_000).unwrap(), "H1 (100000-200000) overlaps H2");
    check(&|u| u.obfuscation.as_mut().unwrap().h[2] = U32Range::from_raw(5), "H3 (5-0) runs backwards");
    check(&|u| u.obfuscation.as_mut().unwrap().s[2] = 11, "S3 (11) must be at least 12");
    check(&|u| u.obfuscation.as_mut().unwrap().i[4] = "<q>".into(), "I5");
    check(&|u| u.ifname = "a/b".into(), "not a device name");
    check(&|u| u.ifname = "sixteen_chars_xx".into(), "not a device name");
    check(&|u| u.obfuscation = None, "header protection key needs the obfuscation");
    // without a key, small S is fine
    let mut u = client_update();
    u.header_protection_key = None;
    u.obfuscation.as_mut().unwrap().s = [0; 4];
    assert!(set_device_messages(FAMILY, Flavor::Amnezia, &u, seq()).is_ok());
}

#[test]
fn many_peers_and_allowed_ips_are_split_and_join_again() {
    let mut u = DeviceUpdate { ifname: "tn_srv".into(), replace_peers: true, ..Default::default() };
    for n in 0..1500u32 {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&n.to_be_bytes());
        let mut p = PeerUpdate::new(Key::new(b));
        p.allowed_ips = vec![format!("10.{}.{}.0/24", n / 256, n % 256).parse().unwrap()];
        u.peers.push(p);
    }
    let mut big = PeerUpdate::new(key(0xee));
    big.allowed_ips = (0..2000u32).map(|n| format!("fd00::{n:x}/128").parse().unwrap()).collect();
    u.peers.push(big);

    let msgs = set_device_messages(FAMILY, Flavor::Amnezia, &u, seq()).unwrap();
    assert!(msgs.len() > 1);
    for (n, m) in msgs.iter().enumerate() {
        let attrs = raw_attrs(genl_payload(m));
        assert_eq!(attrs[0].1, b"tn_srv\0", "every message names the device");
        let has_flags = attrs.iter().any(|(t, _)| *t == WGDEVICE_A_FLAGS);
        assert_eq!(has_flags, n == 0, "REPLACE_PEERS only in the first");
        let peers = attrs.iter().find(|(t, _)| t & NLA_TYPE_MASK == WGDEVICE_A_PEERS).unwrap();
        assert!(peers.1.len() + 4 <= u16::MAX as usize);
    }
    // The set messages have the dump's layout, so the dump's parser reads
    // them back: every peer once, the big one whole.
    let payloads: Vec<&[u8]> = msgs.iter().map(|m| genl_payload(m)).collect();
    let d = parse_device(payloads).unwrap();
    assert_eq!(d.peers.len(), 1501);
    assert_eq!(d.peers[1500].allowed_ips.len(), 2000);
    assert_eq!(d.peers[1499].allowed_ips[0].to_string(), "10.5.219.0/24");
}

/// A dump as `wg_get_device_dump` writes it, in two messages: the device
/// and the first part of a peer, then the rest of its allowed IPs.
#[test]
fn a_dump_in_two_messages_is_one_device() {
    let mut m1 = MessageBuilder::attrs();
    m1.put_u16(WGDEVICE_A_LISTEN_PORT, 51820)
        .put_u32(WGDEVICE_A_FWMARK, 257)
        .put_u32(WGDEVICE_A_IFINDEX, 7)
        .put_str(WGDEVICE_A_IFNAME, "tn_vpn")
        .put_u16(WGDEVICE_A_JC, 4)
        .put_u16(WGDEVICE_A_JMIN, 40)
        .put_u16(WGDEVICE_A_JMAX, 70)
        .put_u16(WGDEVICE_A_S1, 15)
        .put_u16(WGDEVICE_A_S2, 18)
        .put_u16(WGDEVICE_A_S3, 20)
        .put_u16(WGDEVICE_A_S4, 23)
        .put_u64(WGDEVICE_A_H1, (2u64 << 32) | 1)
        .put_u64(WGDEVICE_A_H2, U32Range::fixed(2).to_raw())
        .put_u64(WGDEVICE_A_H3, U32Range::fixed(3).to_raw())
        .put_u64(WGDEVICE_A_H4, U32Range::fixed(4).to_raw())
        .put_u32(WGDEVICE_A_CONTENT_PADDING_ADDITION, 0)
        .put_u32(WGDEVICE_A_REKEY_AFTER_TIME, 0)
        .put_u32(WGDEVICE_A_REKEY_TIMEOUT, 0)
        .put_u32(WGDEVICE_A_REJECT_AFTER_TIME, 0)
        .put_u32(WGDEVICE_A_KEEPALIVE_TIMEOUT, 0)
        .put_u32(WGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS, 0)
        .put_u8(WGDEVICE_A_RANDOM_TRAILERS, 0)
        .put_u8(WGDEVICE_A_DISABLE_COOKIES, 1)
        .put_str(WGDEVICE_A_I1, "<r 4>")
        .put(WGDEVICE_A_PRIVATE_KEY, &[1; 32])
        .put(WGDEVICE_A_PUBLIC_KEY, &[3; 32]);
    m1.nest(WGDEVICE_A_PEERS).nest(0);
    let mut ts = Vec::new();
    ts.extend_from_slice(&1_795_012_345i64.to_ne_bytes());
    ts.extend_from_slice(&500i64.to_ne_bytes());
    let ep: SocketAddr = "[2001:db8::7]:51820".parse().unwrap();
    let mut ep_bytes = Vec::new();
    ep_bytes.extend_from_slice(&AF_INET6.to_ne_bytes());
    ep_bytes.extend_from_slice(&51820u16.to_be_bytes());
    ep_bytes.extend_from_slice(&0u32.to_be_bytes());
    ep_bytes.extend_from_slice(&"2001:db8::7".parse::<std::net::Ipv6Addr>().unwrap().octets());
    ep_bytes.extend_from_slice(&0u32.to_ne_bytes());
    m1.put_u32(WGPEER_A_FLAGS, 8)
        .put(WGPEER_A_PUBLIC_KEY, &[2; 32])
        .put(WGPEER_A_PRESHARED_KEY, &[0; 32])
        .put(WGPEER_A_LAST_HANDSHAKE_TIME, &ts)
        .put_u32(WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, (25 << 16) | 25)
        .put(0, &[]) // nla_put_u64_64bit pad
        .put_u64(WGPEER_A_TX_BYTES, 1000)
        .put_u64(WGPEER_A_RX_BYTES, 2000)
        .put_u32(WGPEER_A_PROTOCOL_VERSION, 1)
        .put(WGPEER_A_ENDPOINT, &ep_bytes);
    m1.nest(WGPEER_A_ALLOWEDIPS)
        .nest(0)
        .put_u8(WGALLOWEDIP_A_CIDR_MASK, 0)
        .put_u16(WGALLOWEDIP_A_FAMILY, AF_INET)
        .put(WGALLOWEDIP_A_IPADDR, &[0, 0, 0, 0])
        .end_nest()
        .end_nest();
    m1.end_nest().end_nest();

    let mut m2 = MessageBuilder::attrs();
    m2.nest(WGDEVICE_A_PEERS)
        .nest(0)
        .put_u32(WGPEER_A_FLAGS, 8)
        .put(WGPEER_A_PUBLIC_KEY, &[2; 32])
        .nest(WGPEER_A_ALLOWEDIPS)
        .nest(0)
        .put_u8(WGALLOWEDIP_A_CIDR_MASK, 0)
        .put_u16(WGALLOWEDIP_A_FAMILY, AF_INET6)
        .put(WGALLOWEDIP_A_IPADDR, &[0; 16])
        .end_nest()
        .end_nest()
        .end_nest()
        .end_nest();

    let (a, b) = (m1.finish_attrs(), m2.finish_attrs());
    let d = parse_device([a.as_slice(), b.as_slice()]).unwrap();
    assert_eq!(d.ifindex, 7);
    assert_eq!(d.ifname, "tn_vpn");
    assert_eq!(d.listen_port, 51820);
    assert_eq!(d.fwmark, 257);
    assert_eq!(d.public_key, Some(key(3)));
    assert!(d.header_protection_key.is_none());
    let o = d.obfuscation.unwrap();
    assert_eq!((o.jc, o.jmin, o.jmax, o.s), (4, 40, 70, [15, 18, 20, 23]));
    assert_eq!(o.h[0], U32Range::new(1, 2).unwrap());
    assert_eq!(o.i[0], "<r 4>");
    assert_eq!(o.i[1], "");
    assert!(o.disable_cookies);
    assert_eq!(d.peers.len(), 1);
    let p = &d.peers[0];
    assert_eq!(p.public_key, key(2));
    assert!(p.preshared_key.is_none(), "an all-zero preshared key is none");
    assert_eq!(p.endpoint, Some(ep));
    assert_eq!(p.persistent_keepalive, U16Range::fixed(25));
    assert_eq!(p.last_handshake, Some(Duration::new(1_795_012_345, 500)));
    assert_eq!((p.tx_bytes, p.rx_bytes), (1000, 2000));
    assert_eq!(p.allowed_ips.iter().map(|i| i.to_string()).collect::<Vec<_>>(), ["0.0.0.0/0", "::/0"]);
}

#[test]
fn a_wireguard_dump_has_no_obfuscation() {
    let mut m = MessageBuilder::attrs();
    m.put_u16(WGDEVICE_A_LISTEN_PORT, 1).put_str(WGDEVICE_A_IFNAME, "wg0");
    m.nest(WGDEVICE_A_PEERS).nest(0);
    m.put(WGPEER_A_PUBLIC_KEY, &[2; 32]).put_u16(WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, 25);
    m.end_nest().end_nest();
    let d = parse_device([m.finish_attrs().as_slice()]).unwrap();
    assert!(d.obfuscation.is_none());
    assert_eq!(d.peers[0].persistent_keepalive, U16Range::fixed(25));
    assert_eq!(d.peers[0].last_handshake, None);
}

#[test]
fn get_device_is_a_dump_by_name() {
    let m = get_device_message(FAMILY, Flavor::Amnezia, "tn_vpn", 5).unwrap();
    let h = messages(&m).next().unwrap().unwrap();
    assert_eq!(h.flags, NLM_F_REQUEST | NLM_F_DUMP);
    assert_eq!(m[NLMSG_HDRLEN], WG_CMD_GET_DEVICE);
    let a: Vec<Attr> = Attrs(genl_payload(&m)).collect::<Result<_, _>>().unwrap();
    // IFINDEX xor IFNAME, else EBADR
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].ty, WGDEVICE_A_IFNAME);
}
