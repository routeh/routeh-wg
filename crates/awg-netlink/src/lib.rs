//! A netlink binding for the AmneziaWG kernel module
//! (amneziawg-linux-kernel-module, generic netlink family `amneziawg`,
//! version 3) and for the kernel's WireGuard, which shares its base.
//!
//! What is sent and read is built and parsed without a socket (`device`,
//! `link`), so it is tested on any system; the socket and the `Client`
//! over it are Linux only.
//!
//! What the module does that a caller has to know is in `docs/NETLINK.md`.

pub mod attr;
pub mod device;
pub mod link;
pub mod template;
pub mod types;
pub mod uapi;

#[cfg(target_os = "linux")]
mod socket;

pub use device::{Device, DeviceUpdate, Flavor, Obfuscation, Peer, PeerUpdate};
pub use link::Link;
#[cfg(target_os = "linux")]
pub use socket::Client;
pub use types::{AllowedIp, Key, U16Range, U32Range};

use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// The kernel refused a request: its errno and, when it gave one, its
    /// text. The module explains its own refusals only in the kernel log,
    /// with dynamic debug on (`docs/NETLINK.md`).
    Kernel { errno: i32, message: Option<String> },
    /// The generic netlink family does not exist: the module is not loaded.
    NoFamily(&'static str),
    /// A dump the module marked as inconsistent (`NLM_F_DUMP_INTR`), still
    /// so after reading it again.
    Interrupted,
    /// A value that is not to be sent, with why.
    Invalid(String),
    /// An answer this crate cannot read.
    Malformed(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Kernel { errno, message } => {
                let os = std::io::Error::from_raw_os_error(*errno);
                match message {
                    Some(m) => write!(f, "{os}: {m}"),
                    None => write!(f, "{os}"),
                }
            }
            Error::NoFamily(name) => write!(f, "the kernel has no {name} module loaded"),
            Error::Interrupted => f.write_str("the device kept changing while it was read"),
            Error::Invalid(why) => f.write_str(why),
            Error::Malformed(what) => write!(f, "unreadable answer from the kernel: {what}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl Error {
    /// The errno of a refusal of the kernel's.
    pub fn errno(&self) -> Option<i32> {
        match self {
            Error::Kernel { errno, .. } => Some(*errno),
            Error::Io(e) => e.raw_os_error(),
            _ => None,
        }
    }
}
