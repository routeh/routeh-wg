//! Numbers from the kernel's headers.
//!
//! The AmneziaWG ones are from `src/uapi/wireguard.h` of
//! amneziawg-linux-kernel-module (3.1.20261113-02); the WireGuard ones are a
//! prefix of the same enums (upstream `include/uapi/linux/wireguard.h`).

// linux/netlink.h
pub const NETLINK_ROUTE: i32 = 0;
pub const NETLINK_GENERIC: i32 = 16;
pub const SOL_NETLINK: i32 = 270;
pub const NETLINK_CAP_ACK: i32 = 10;
pub const NETLINK_EXT_ACK: i32 = 11;

pub const NLMSG_HDRLEN: usize = 16;
pub const NLMSG_NOOP: u16 = 1;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLMSG_OVERRUN: u16 = 4;

pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_DUMP_INTR: u16 = 0x10;
pub const NLM_F_DUMP: u16 = 0x300;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
/// In an `NLMSG_ERROR`: extended-ACK TLVs follow.
pub const NLM_F_ACK_TLVS: u16 = 0x200;
/// In an `NLMSG_ERROR`: the request was not copied back in full.
pub const NLM_F_CAPPED: u16 = 0x100;

pub const NLMSGERR_ATTR_MSG: u16 = 1;

pub const NLA_HDRLEN: usize = 4;
pub const NLA_F_NESTED: u16 = 1 << 15;
pub const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
pub const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

// linux/genetlink.h
pub const GENL_HDRLEN: usize = 4;
pub const GENL_ID_CTRL: u16 = 0x10;
pub const CTRL_CMD_GETFAMILY: u8 = 3;
pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;
pub const CTRL_ATTR_VERSION: u16 = 3;

// linux/rtnetlink.h, linux/if_link.h
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;
pub const IFINFOMSG_LEN: usize = 16;
pub const IFLA_IFNAME: u16 = 3;
pub const IFLA_LINKINFO: u16 = 18;
pub const IFLA_INFO_KIND: u16 = 1;
pub const IFNAMSIZ: usize = 16;

// linux/socket.h (Linux values on every architecture)
pub const AF_UNSPEC: u16 = 0;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
pub const SOCKADDR_IN_LEN: usize = 16;
pub const SOCKADDR_IN6_LEN: usize = 28;

// wireguard.h
pub const WG_KEY_LEN: usize = 32;
pub const WG_CMD_GET_DEVICE: u8 = 0;
pub const WG_CMD_SET_DEVICE: u8 = 1;

pub const WGDEVICE_F_REPLACE_PEERS: u32 = 1 << 0;

pub const WGDEVICE_A_IFINDEX: u16 = 1;
pub const WGDEVICE_A_IFNAME: u16 = 2;
pub const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
pub const WGDEVICE_A_PUBLIC_KEY: u16 = 4;
pub const WGDEVICE_A_FLAGS: u16 = 5;
pub const WGDEVICE_A_LISTEN_PORT: u16 = 6;
pub const WGDEVICE_A_FWMARK: u16 = 7;
pub const WGDEVICE_A_PEERS: u16 = 8;
// AmneziaWG only from here.
pub const WGDEVICE_A_JC: u16 = 9;
pub const WGDEVICE_A_JMIN: u16 = 10;
pub const WGDEVICE_A_JMAX: u16 = 11;
pub const WGDEVICE_A_S1: u16 = 12;
pub const WGDEVICE_A_S2: u16 = 13;
pub const WGDEVICE_A_H1: u16 = 14;
pub const WGDEVICE_A_H2: u16 = 15;
pub const WGDEVICE_A_H3: u16 = 16;
pub const WGDEVICE_A_H4: u16 = 17;
pub const WGDEVICE_A_PEER: u16 = 18;
pub const WGDEVICE_A_S3: u16 = 19;
pub const WGDEVICE_A_S4: u16 = 20;
pub const WGDEVICE_A_I1: u16 = 21;
pub const WGDEVICE_A_I2: u16 = 22;
pub const WGDEVICE_A_I3: u16 = 23;
pub const WGDEVICE_A_I4: u16 = 24;
pub const WGDEVICE_A_I5: u16 = 25;
pub const WGDEVICE_A_HEADER_PROTECTION_KEY: u16 = 26;
pub const WGDEVICE_A_CONTENT_PADDING_ADDITION: u16 = 27;
pub const WGDEVICE_A_REKEY_AFTER_TIME: u16 = 28;
pub const WGDEVICE_A_REKEY_TIMEOUT: u16 = 29;
pub const WGDEVICE_A_REJECT_AFTER_TIME: u16 = 30;
pub const WGDEVICE_A_KEEPALIVE_TIMEOUT: u16 = 31;
pub const WGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS: u16 = 32;
pub const WGDEVICE_A_RANDOM_TRAILERS: u16 = 33;
pub const WGDEVICE_A_DISABLE_COOKIES: u16 = 34;

pub const WGPEER_F_REMOVE_ME: u32 = 1 << 0;
pub const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 1 << 1;
pub const WGPEER_F_UPDATE_ONLY: u32 = 1 << 2;

pub const WGPEER_A_PUBLIC_KEY: u16 = 1;
pub const WGPEER_A_PRESHARED_KEY: u16 = 2;
pub const WGPEER_A_FLAGS: u16 = 3;
pub const WGPEER_A_ENDPOINT: u16 = 4;
pub const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
pub const WGPEER_A_LAST_HANDSHAKE_TIME: u16 = 6;
pub const WGPEER_A_RX_BYTES: u16 = 7;
pub const WGPEER_A_TX_BYTES: u16 = 8;
pub const WGPEER_A_ALLOWEDIPS: u16 = 9;
pub const WGPEER_A_PROTOCOL_VERSION: u16 = 10;

pub const WGALLOWEDIP_A_FAMILY: u16 = 1;
pub const WGALLOWEDIP_A_IPADDR: u16 = 2;
pub const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;

/// `HEADER_PROTECTION_NONCE_SIZE` of `header_protection.h`: every S must be
/// at least this while a header protection key is set.
pub const HEADER_PROTECTION_NONCE_SIZE: u16 = 12;
/// `JP_MAX_PACKET_SIZE` of `junk.c`: the most bytes one I-packet may be.
pub const JP_MAX_PACKET_SIZE: usize = 65535;
