//! A blocking netlink socket and the client over it. Linux only.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::attr::{messages, parse_error, Message};
use crate::device::{self, Device, DeviceUpdate, Flavor};
use crate::link::{self, Link};
use crate::uapi::*;
use crate::Error;

struct Socket {
    fd: OwnedFd,
    seq: u32,
    buf: Vec<u8>,
}

impl Socket {
    fn open(protocol: i32) -> Result<Self, Error> {
        // SAFETY: plain syscalls; the fd is owned from here on.
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, protocol) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        let r = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // Errors with the kernel's text (extended ACK), the request not
        // copied back. Old kernels lack them; that is not an error.
        for opt in [NETLINK_EXT_ACK, NETLINK_CAP_ACK] {
            let one: i32 = 1;
            unsafe {
                libc::setsockopt(fd.as_raw_fd(), SOL_NETLINK, opt, &one as *const _ as *const libc::c_void, 4);
            }
        }
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(1);
        Ok(Self { fd, seq: seed, buf: vec![0; 64 * 1024] })
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    fn send(&self, msg: &[u8]) -> Result<(), Error> {
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        loop {
            let r = unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    msg.as_ptr() as *const libc::c_void,
                    msg.len(),
                    0,
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_nl>() as u32,
                )
            };
            if r >= 0 {
                return Ok(());
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e.into());
            }
        }
    }

    /// One datagram; the buffer grows to whatever size the kernel has.
    fn recv(&mut self) -> Result<usize, Error> {
        loop {
            let peek = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    self.buf.as_mut_ptr() as *mut libc::c_void,
                    0,
                    libc::MSG_PEEK | libc::MSG_TRUNC,
                )
            };
            if peek < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e.into());
            }
            if peek as usize > self.buf.len() {
                self.buf.resize(peek as usize, 0);
            }
            let n = unsafe {
                libc::recv(self.fd.as_raw_fd(), self.buf.as_mut_ptr() as *mut libc::c_void, self.buf.len(), 0)
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e.into());
            }
            return Ok(n as usize);
        }
    }

    /// Sends a request and reads up to its acknowledgement; `each` sees
    /// every other message of the answer.
    fn request(&mut self, msg: &[u8], seq: u32, mut each: impl FnMut(&Message<'_>) -> Result<(), Error>) -> Result<(), Error> {
        self.send(msg)?;
        loop {
            let n = self.recv()?;
            let buf = std::mem::take(&mut self.buf);
            let r = (|| {
                for m in messages(&buf[..n]) {
                    let m = m?;
                    if m.seq != seq {
                        continue; // a late answer to an earlier request
                    }
                    match m.ty {
                        NLMSG_ERROR => {
                            let (errno, text) = parse_error(&m)?;
                            return if errno == 0 { Ok(true) } else { Err(Error::Kernel { errno, message: text }) };
                        }
                        NLMSG_DONE => return Ok(true),
                        NLMSG_NOOP => {}
                        NLMSG_OVERRUN => return Err(Error::Malformed("netlink overrun")),
                        _ => {
                            if m.flags & NLM_F_DUMP_INTR != 0 {
                                return Err(Error::Interrupted);
                            }
                            // A dump ends with NLMSG_DONE; a request with
                            // NLM_F_ACK with its acknowledgement.
                            each(&m)?;
                        }
                    }
                }
                Ok(false)
            })();
            self.buf = buf;
            if r? {
                return Ok(());
            }
        }
    }
}

/// The module over generic netlink, and its devices over rtnetlink.
pub struct Client {
    flavor: Flavor,
    genl: Socket,
    rtnl: Socket,
    family: u16,
}

impl Client {
    /// Resolves the module's family. Fails with `Error::NoFamily` when the
    /// module is not loaded: the family exists only while it is.
    pub fn new(flavor: Flavor) -> Result<Self, Error> {
        let mut genl = Socket::open(NETLINK_GENERIC)?;
        let rtnl = Socket::open(NETLINK_ROUTE)?;
        let seq = genl.next_seq();
        let msg = link::get_family_message(flavor.family_name(), seq);
        let mut family = None;
        let r = genl.request(&msg, seq, |m| {
            family = Some(link::parse_family(m.payload.get(GENL_HDRLEN..).unwrap_or_default())?.0);
            Ok(())
        });
        match r {
            Err(Error::Kernel { errno, .. }) if errno == libc::ENOENT => {
                return Err(Error::NoFamily(flavor.family_name()))
            }
            r => r?,
        }
        let family = family.ok_or(Error::NoFamily(flavor.family_name()))?;
        Ok(Self { flavor, genl, rtnl, family })
    }

    pub fn flavor(&self) -> Flavor {
        self.flavor
    }

    /// The device by name. A dump that the module reports as interrupted
    /// (the device changed while it was read) is read again, up to three
    /// times.
    pub fn get_device(&mut self, ifname: &str) -> Result<Device, Error> {
        let mut last = Error::Interrupted;
        for _ in 0..3 {
            let seq = self.genl.next_seq();
            let msg = device::get_device_message(self.family, self.flavor, ifname, seq)?;
            let mut payloads: Vec<Vec<u8>> = Vec::new();
            match self.genl.request(&msg, seq, |m| {
                payloads.push(m.payload.get(GENL_HDRLEN..).unwrap_or_default().to_vec());
                Ok(())
            }) {
                Ok(()) => return device::parse_device(payloads.iter().map(Vec::as_slice)),
                Err(Error::Interrupted) => last = Error::Interrupted,
                Err(e) => return Err(e),
            }
        }
        Err(last)
    }

    /// Applies an update. Not atomic: see `device::set_device_messages`.
    pub fn set_device(&mut self, u: &DeviceUpdate) -> Result<(), Error> {
        let genl = &mut self.genl;
        let mut seqs = Vec::new();
        let msgs = device::set_device_messages(self.family, self.flavor, u, || {
            let s = genl.next_seq();
            seqs.push(s);
            s
        })?;
        for (m, s) in msgs.iter().zip(seqs) {
            self.genl.request(m, s, |_| Ok(()))?;
        }
        Ok(())
    }

    /// Makes a device of the module's kind. `EEXIST` when the name is taken.
    pub fn create_link(&mut self, name: &str) -> Result<(), Error> {
        let seq = self.rtnl.next_seq();
        let msg = link::new_link_message(name, self.flavor.link_kind(), seq);
        self.rtnl.request(&msg, seq, |_| Ok(()))
    }

    pub fn delete_link(&mut self, name: &str) -> Result<(), Error> {
        let seq = self.rtnl.next_seq();
        let msg = link::del_link_message(name, seq);
        self.rtnl.request(&msg, seq, |_| Ok(()))
    }

    /// Every device of the module's kind, to take over after a restart.
    pub fn links(&mut self) -> Result<Vec<Link>, Error> {
        let seq = self.rtnl.next_seq();
        let msg = link::get_links_message(seq);
        let kind = self.flavor.link_kind();
        let mut out = Vec::new();
        self.rtnl.request(&msg, seq, |m| {
            if m.ty == RTM_NEWLINK {
                let l = link::parse_link(m.payload)?;
                if l.kind.as_deref() == Some(kind) {
                    out.push(l);
                }
            }
            Ok(())
        })?;
        Ok(out)
    }
}
