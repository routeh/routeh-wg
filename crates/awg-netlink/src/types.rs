//! Values the module takes and gives: keys, ranges, addresses.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

use crate::uapi::*;
use crate::Error;

/// A Curve25519 key, a preshared key or a header protection key: 32 bytes.
/// Its bytes are wiped when it is dropped and never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct Key([u8; WG_KEY_LEN]);

impl Key {
    pub const ZERO: Key = Key([0; WG_KEY_LEN]);

    pub const fn new(bytes: [u8; WG_KEY_LEN]) -> Self {
        Key(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; WG_KEY_LEN] {
        &self.0
    }
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            // SAFETY: a valid, aligned &mut u8.
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(…)")
    }
}

macro_rules! range {
    ($name:ident, $int:ty, $raw:ty, $bits:expr) => {
        /// A range `lo..=hi` the module picks a random value from each time
        /// it uses it. On the wire it is one integer, `hi` in the upper
        /// half and `lo` in the lower.
        ///
        /// The module never checks `lo <= hi`: it calls
        /// `get_random_u32_inclusive(lo, hi)`, which with `lo > hi` gives a
        /// value outside the range (for junk sizes, past the end of the
        /// buffer it allocated). So a range is made only through `new`,
        /// `fixed` or parsing, which refuse that; one read from the kernel
        /// is checked again before it is sent (`is_ordered`).
        ///
        /// The zero range (`0-0`) means "the module's default" wherever a
        /// default exists (timers, padding, keepalive "off").
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub struct $name {
            lo: $int,
            hi: $int,
        }

        impl $name {
            pub const ZERO: Self = Self { lo: 0, hi: 0 };

            pub const fn new(lo: $int, hi: $int) -> Option<Self> {
                if lo <= hi {
                    Some(Self { lo, hi })
                } else {
                    None
                }
            }
            pub const fn fixed(v: $int) -> Self {
                Self { lo: v, hi: v }
            }
            pub const fn lo(self) -> $int {
                self.lo
            }
            pub const fn hi(self) -> $int {
                self.hi
            }
            pub const fn is_zero(self) -> bool {
                self.lo == 0 && self.hi == 0
            }
            pub const fn is_ordered(self) -> bool {
                self.lo <= self.hi
            }
            pub const fn overlaps(self, other: Self) -> bool {
                self.lo <= other.hi && other.lo <= self.hi
            }
            /// The integer the module stores.
            pub const fn to_raw(self) -> $raw {
                ((self.hi as $raw) << $bits) | self.lo as $raw
            }
            /// As the module reports it, unchecked.
            pub const fn from_raw(raw: $raw) -> Self {
                Self { lo: raw as $int, hi: (raw >> $bits) as $int }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self)
            }
        }

        /// `lo-hi`, as in awg-tools' configuration.
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}-{}", self.lo, self.hi)
            }
        }

        /// `lo-hi`, or one number for `n-n`.
        impl FromStr for $name {
            type Err = Error;
            fn from_str(s: &str) -> Result<Self, Error> {
                let bad = || Error::Invalid(format!("{s:?} is not a range like 100-200"));
                let num = |t: &str| -> Result<$int, Error> {
                    if t.is_empty() || !t.bytes().all(|c| c.is_ascii_digit()) {
                        return Err(bad());
                    }
                    t.parse::<$int>().map_err(|_| bad())
                };
                match s.split_once('-') {
                    None => Ok(Self::fixed(num(s)?)),
                    Some((a, b)) => Self::new(num(a)?, num(b)?).ok_or_else(|| {
                        Error::Invalid(format!("{s:?}: the start is after the end"))
                    }),
                }
            }
        }
    };
}

range!(U16Range, u16, u32, 16);
range!(U32Range, u32, u64, 32);

/// An allowed IP: an address and the length of its prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AllowedIp {
    pub addr: IpAddr,
    pub cidr: u8,
}

impl AllowedIp {
    pub fn new(addr: IpAddr, cidr: u8) -> Result<Self, Error> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if cidr > max {
            return Err(Error::Invalid(format!("{addr}/{cidr}: the prefix is longer than {max}")));
        }
        Ok(Self { addr, cidr })
    }

    /// With the bits past the prefix cleared, as the module keeps it.
    pub fn canonical(self) -> Self {
        match self.addr {
            IpAddr::V4(a) => {
                let m = if self.cidr == 0 { 0 } else { u32::MAX << (32 - self.cidr) };
                Self { addr: Ipv4Addr::from(u32::from(a) & m).into(), cidr: self.cidr }
            }
            IpAddr::V6(a) => {
                let m = if self.cidr == 0 { 0 } else { u128::MAX << (128 - self.cidr) };
                Self { addr: Ipv6Addr::from(u128::from(a) & m).into(), cidr: self.cidr }
            }
        }
    }
}

impl fmt::Display for AllowedIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.cidr)
    }
}

impl FromStr for AllowedIp {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let bad = || Error::Invalid(format!("{s:?} is not an address with a prefix"));
        let (a, c) = s.split_once('/').ok_or_else(bad)?;
        Self::new(a.parse().map_err(|_| bad())?, c.parse().map_err(|_| bad())?)
    }
}

/// `struct sockaddr_in` or `sockaddr_in6`, as `WGPEER_A_ENDPOINT` carries it.
/// The family is in the host's order, the port and flow label in the
/// network's, the scope id in the host's.
pub(crate) fn sockaddr_bytes(sa: &SocketAddr) -> Vec<u8> {
    match sa {
        SocketAddr::V4(a) => {
            let mut b = Vec::with_capacity(SOCKADDR_IN_LEN);
            b.extend_from_slice(&AF_INET.to_ne_bytes());
            b.extend_from_slice(&a.port().to_be_bytes());
            b.extend_from_slice(&a.ip().octets());
            b.resize(SOCKADDR_IN_LEN, 0);
            b
        }
        SocketAddr::V6(a) => {
            let mut b = Vec::with_capacity(SOCKADDR_IN6_LEN);
            b.extend_from_slice(&AF_INET6.to_ne_bytes());
            b.extend_from_slice(&a.port().to_be_bytes());
            b.extend_from_slice(&a.flowinfo().to_be_bytes());
            b.extend_from_slice(&a.ip().octets());
            b.extend_from_slice(&a.scope_id().to_ne_bytes());
            b
        }
    }
}

pub(crate) fn parse_sockaddr(b: &[u8]) -> Result<Option<SocketAddr>, Error> {
    if b.len() < 2 {
        return Err(Error::Malformed("short sockaddr"));
    }
    let family = u16::from_ne_bytes([b[0], b[1]]);
    match (family, b.len()) {
        (AF_INET, SOCKADDR_IN_LEN) => {
            let port = u16::from_be_bytes([b[2], b[3]]);
            let ip = Ipv4Addr::new(b[4], b[5], b[6], b[7]);
            Ok(Some(SocketAddrV4::new(ip, port).into()))
        }
        (AF_INET6, SOCKADDR_IN6_LEN) => {
            let port = u16::from_be_bytes([b[2], b[3]]);
            let flow = u32::from_be_bytes(b[4..8].try_into().unwrap());
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).unwrap());
            let scope = u32::from_ne_bytes(b[24..28].try_into().unwrap());
            Ok(Some(SocketAddrV6::new(ip, port, flow, scope).into()))
        }
        (AF_UNSPEC, _) => Ok(None),
        _ => Err(Error::Malformed("sockaddr of an unknown family or length")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_pack_as_the_module_does() {
        // type.h: u16_range_init: (hi << 16) | lo
        let r = U16Range::new(25, 30).unwrap();
        assert_eq!(r.to_raw(), (30 << 16) | 25);
        assert_eq!(U16Range::from_raw(r.to_raw()), r);
        // A plain keepalive of 25 s is 25-25, not 25.
        assert_eq!(U16Range::fixed(25).to_raw(), (25 << 16) | 25);
        let h = U32Range::new(100_000, 200_000).unwrap();
        assert_eq!(h.to_raw(), (200_000u64 << 32) | 100_000);
        assert_eq!(U32Range::from_raw(h.to_raw()), h);
    }

    #[test]
    fn a_range_never_runs_backwards() {
        assert!(U16Range::new(10, 5).is_none());
        assert!("10-5".parse::<U16Range>().is_err());
        assert!(!U16Range::from_raw(5 << 16 | 10).is_ordered());
    }

    #[test]
    fn ranges_parse_and_print() {
        assert_eq!("7".parse::<U32Range>().unwrap(), U32Range::fixed(7));
        assert_eq!("5-9".parse::<U32Range>().unwrap().to_string(), "5-9");
        for bad in ["", "-", "1-", "-1", "a-b", "1-2-3", "+1", " 1", "4294967296"] {
            assert!(bad.parse::<U32Range>().is_err(), "{bad}");
        }
        assert!("65536".parse::<U16Range>().is_err());
    }

    #[test]
    fn overlap_is_the_module_s() {
        let a = U32Range::new(1, 10).unwrap();
        assert!(a.overlaps(U32Range::new(10, 20).unwrap()));
        assert!(!a.overlaps(U32Range::new(11, 20).unwrap()));
    }

    #[test]
    fn sockaddr_round_trips() {
        for s in ["203.0.113.7:51820", "[2001:db8::1]:443"] {
            let sa: SocketAddr = s.parse().unwrap();
            let b = sockaddr_bytes(&sa);
            assert_eq!(parse_sockaddr(&b).unwrap(), Some(sa));
        }
        let b = sockaddr_bytes(&"192.0.2.4:258".parse().unwrap());
        assert_eq!(b.len(), SOCKADDR_IN_LEN);
        assert_eq!(&b[2..4], &[1, 2], "port in network order");
    }

    #[test]
    fn allowed_ips() {
        let a: AllowedIp = "10.1.2.3/8".parse().unwrap();
        assert_eq!(a.canonical().to_string(), "10.0.0.0/8");
        assert!("10.0.0.0/33".parse::<AllowedIp>().is_err());
        assert_eq!("::/0".parse::<AllowedIp>().unwrap().canonical().to_string(), "::/0");
    }
}
