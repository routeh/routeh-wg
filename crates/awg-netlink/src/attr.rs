//! Netlink messages and attributes: building and reading, with no socket.
//!
//! Everything is in the host's byte order, as netlink is, except where a
//! field says otherwise (a port in a `sockaddr`).

use crate::uapi::*;
use crate::Error;

const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// A netlink message being built: header, family header, attributes.
pub struct MessageBuilder {
    buf: Vec<u8>,
    nests: Vec<usize>,
}

impl MessageBuilder {
    /// A message of `ty` with `flags`; the caller writes the family header
    /// (`genl_header`, `bytes`) and then attributes.
    pub fn new(ty: u16, flags: u16, seq: u32) -> Self {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&0u32.to_ne_bytes()); // length, set by finish
        buf.extend_from_slice(&ty.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // port id: the kernel's
        Self { buf, nests: Vec::new() }
    }

    /// Attributes alone, to be put into a message later (`bytes`).
    pub fn attrs() -> Self {
        Self { buf: Vec::new(), nests: Vec::new() }
    }

    pub fn finish_attrs(self) -> Vec<u8> {
        assert!(self.nests.is_empty(), "unclosed nested attribute");
        self.buf
    }

    pub fn genl_header(&mut self, cmd: u8, version: u8) -> &mut Self {
        self.buf.extend_from_slice(&[cmd, version, 0, 0]);
        self
    }

    pub fn bytes(&mut self, raw: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(raw);
        self
    }

    pub fn put(&mut self, ty: u16, payload: &[u8]) -> &mut Self {
        let len = NLA_HDRLEN + payload.len();
        assert!(len <= u16::MAX as usize, "attribute too long");
        self.buf.extend_from_slice(&(len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.buf.extend_from_slice(payload);
        self.buf.resize(align4(self.buf.len()), 0);
        self
    }

    pub fn put_u8(&mut self, ty: u16, v: u8) -> &mut Self {
        self.put(ty, &[v])
    }
    pub fn put_u16(&mut self, ty: u16, v: u16) -> &mut Self {
        self.put(ty, &v.to_ne_bytes())
    }
    pub fn put_u32(&mut self, ty: u16, v: u32) -> &mut Self {
        self.put(ty, &v.to_ne_bytes())
    }
    pub fn put_u64(&mut self, ty: u16, v: u64) -> &mut Self {
        self.put(ty, &v.to_ne_bytes())
    }
    /// A NUL-terminated string (`NLA_NUL_STRING`, `NLA_STRING`).
    pub fn put_str(&mut self, ty: u16, s: &str) -> &mut Self {
        let mut v = Vec::with_capacity(s.len() + 1);
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        self.put(ty, &v)
    }

    /// Opens a nested attribute; the kernel's strict validation wants
    /// `NLA_F_NESTED` on it.
    pub fn nest(&mut self, ty: u16) -> &mut Self {
        self.nests.push(self.buf.len());
        self.buf.extend_from_slice(&0u16.to_ne_bytes());
        self.buf.extend_from_slice(&(ty | NLA_F_NESTED).to_ne_bytes());
        self
    }

    pub fn end_nest(&mut self) -> &mut Self {
        let start = self.nests.pop().expect("end_nest without nest");
        let len = self.buf.len() - start;
        assert!(len <= u16::MAX as usize, "nested attribute too long");
        self.buf[start..start + 2].copy_from_slice(&(len as u16).to_ne_bytes());
        self
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn finish(mut self) -> Vec<u8> {
        assert!(self.nests.is_empty(), "unclosed nested attribute");
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

/// One message read from a socket.
#[derive(Debug, Clone, Copy)]
pub struct Message<'a> {
    pub ty: u16,
    pub flags: u16,
    pub seq: u32,
    pub port: u32,
    pub payload: &'a [u8],
}

/// The messages of one datagram.
pub fn messages(mut buf: &[u8]) -> impl Iterator<Item = Result<Message<'_>, Error>> {
    std::iter::from_fn(move || {
        if buf.is_empty() {
            return None;
        }
        if buf.len() < NLMSG_HDRLEN {
            buf = &[];
            return Some(Err(Error::Malformed("short netlink header")));
        }
        let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        if len < NLMSG_HDRLEN || len > buf.len() {
            buf = &[];
            return Some(Err(Error::Malformed("bad netlink message length")));
        }
        let m = Message {
            ty: u16::from_ne_bytes(buf[4..6].try_into().unwrap()),
            flags: u16::from_ne_bytes(buf[6..8].try_into().unwrap()),
            seq: u32::from_ne_bytes(buf[8..12].try_into().unwrap()),
            port: u32::from_ne_bytes(buf[12..16].try_into().unwrap()),
            payload: &buf[NLMSG_HDRLEN..len],
        };
        buf = &buf[align4(len).min(buf.len())..];
        Some(Ok(m))
    })
}

/// One attribute: its type without the flag bits, and its payload.
#[derive(Debug, Clone, Copy)]
pub struct Attr<'a> {
    pub ty: u16,
    pub payload: &'a [u8],
}

impl<'a> Attr<'a> {
    fn fixed<const N: usize>(&self, what: &'static str) -> Result<[u8; N], Error> {
        self.payload
            .get(..N)
            .filter(|_| self.payload.len() == N)
            .map(|b| b.try_into().unwrap())
            .ok_or(Error::Malformed(what))
    }
    pub fn u8(&self) -> Result<u8, Error> {
        Ok(self.fixed::<1>("u8 attribute")?[0])
    }
    pub fn u16(&self) -> Result<u16, Error> {
        Ok(u16::from_ne_bytes(self.fixed("u16 attribute")?))
    }
    pub fn u32(&self) -> Result<u32, Error> {
        Ok(u32::from_ne_bytes(self.fixed("u32 attribute")?))
    }
    pub fn u64(&self) -> Result<u64, Error> {
        Ok(u64::from_ne_bytes(self.fixed("u64 attribute")?))
    }
    pub fn key(&self) -> Result<[u8; WG_KEY_LEN], Error> {
        self.fixed("key attribute")
    }
    /// A string, with or without its trailing NUL.
    pub fn str(&self) -> Result<&'a str, Error> {
        let b = self.payload;
        let b = match b.iter().position(|&c| c == 0) {
            Some(i) => &b[..i],
            None => b,
        };
        std::str::from_utf8(b).map_err(|_| Error::Malformed("string attribute"))
    }
    pub fn nested(&self) -> Attrs<'a> {
        Attrs(self.payload)
    }
}

/// The attributes of a payload.
#[derive(Debug, Clone, Copy)]
pub struct Attrs<'a>(pub &'a [u8]);

impl<'a> Iterator for Attrs<'a> {
    type Item = Result<Attr<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let buf = self.0;
        if buf.is_empty() {
            return None;
        }
        if buf.len() < NLA_HDRLEN {
            self.0 = &[];
            return Some(Err(Error::Malformed("short attribute header")));
        }
        let len = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
        let ty = u16::from_ne_bytes([buf[2], buf[3]]) & NLA_TYPE_MASK;
        if len < NLA_HDRLEN || len > buf.len() {
            self.0 = &[];
            return Some(Err(Error::Malformed("bad attribute length")));
        }
        self.0 = &buf[align4(len).min(buf.len())..];
        Some(Ok(Attr { ty, payload: &buf[NLA_HDRLEN..len] }))
    }
}

/// The error code and the extended-ACK message of an `NLMSG_ERROR`.
/// `errno` 0 is an acknowledgement.
pub fn parse_error(m: &Message<'_>) -> Result<(i32, Option<String>), Error> {
    let p = m.payload;
    if p.len() < 4 {
        return Err(Error::Malformed("short NLMSG_ERROR"));
    }
    let errno = -i32::from_ne_bytes(p[0..4].try_into().unwrap());
    let mut msg = None;
    if m.flags & NLM_F_ACK_TLVS != 0 {
        // The request follows the code: its header only when capped,
        // else the whole of it (its length is in its header).
        let req = &p[4..];
        let skip = if m.flags & NLM_F_CAPPED != 0 || req.len() < 4 {
            NLMSG_HDRLEN
        } else {
            align4(u32::from_ne_bytes(req[0..4].try_into().unwrap()) as usize)
        };
        if let Some(tlvs) = req.get(skip..) {
            for a in Attrs(tlvs).flatten() {
                if a.ty == NLMSGERR_ATTR_MSG {
                    msg = a.str().ok().map(str::to_owned);
                }
            }
        }
    }
    Ok((errno, msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_are_padded_and_nested() {
        let mut b = MessageBuilder::new(0x20, NLM_F_REQUEST, 7);
        b.genl_header(1, 3);
        b.put_u8(1, 0xaa);
        b.nest(8).nest(0).put_u16(3, 0x1234).end_nest().end_nest();
        let m = b.finish();
        // header 16 + genl 4 + u8 attr 8 + nest(4 + nest(4 + u16 attr 8))
        assert_eq!(m.len(), 16 + 4 + 8 + 4 + 4 + 8);
        assert_eq!(u32::from_ne_bytes(m[0..4].try_into().unwrap()) as usize, m.len());
        // u8: len 5, padded to 8.
        assert_eq!(&m[20..24], &[5, 0, 1, 0].map(|x: u8| x)[..] as &[u8]);
        assert_eq!(m[24], 0xaa);
        assert_eq!(&m[25..28], &[0, 0, 0]);
        // outer nest: length 16, type 8 | NESTED
        assert_eq!(u16::from_ne_bytes([m[28], m[29]]), 16);
        assert_eq!(u16::from_ne_bytes([m[30], m[31]]), 8 | NLA_F_NESTED);
        assert_eq!(u16::from_ne_bytes([m[34], m[35]]), NLA_F_NESTED);

        let msg = messages(&m).next().unwrap().unwrap();
        let attrs: Vec<_> = Attrs(&msg.payload[4..]).collect::<Result<_, _>>().unwrap();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].u8().unwrap(), 0xaa);
        assert_eq!(attrs[1].ty, 8);
        let inner: Vec<_> = attrs[1].nested().flatten().collect();
        assert_eq!(inner[0].ty, 0);
        assert_eq!(inner[0].nested().next().unwrap().unwrap().u16().unwrap(), 0x1234);
    }

    #[test]
    fn exact_lengths_are_required() {
        let a = Attr { ty: 1, payload: &[1, 2, 3] };
        assert!(a.u16().is_err());
        assert!(a.u32().is_err());
    }

    #[test]
    fn bad_lengths_end_the_iteration_with_an_error() {
        let buf = [200u8, 0, 1, 0, 0, 0, 0, 0];
        let mut it = Attrs(&buf);
        assert!(it.next().unwrap().is_err());
        assert!(it.next().is_none());
    }

    #[test]
    fn error_message_is_read_from_ack_tlvs() {
        // NLMSG_ERROR, capped, with a message.
        let mut b = MessageBuilder::new(NLMSG_ERROR, NLM_F_CAPPED | NLM_F_ACK_TLVS, 1);
        b.bytes(&(-22i32).to_ne_bytes());
        b.bytes(&[0u8; NLMSG_HDRLEN]);
        b.put_str(NLMSGERR_ATTR_MSG, "Unknown attribute type");
        let m = b.finish();
        let msg = messages(&m).next().unwrap().unwrap();
        let (errno, text) = parse_error(&msg).unwrap();
        assert_eq!(errno, 22);
        assert_eq!(text.as_deref(), Some("Unknown attribute type"));
    }
}
