//! rtnetlink: making, removing and listing the module's devices, and the
//! generic netlink controller that resolves a family's id.
//!
//! A device is made with only its name and kind: the module's `newlink`
//! reads no `IFLA_INFO_DATA`. Its MTU, its addresses and taking it up are
//! not done here (on the router netifd does them).

use crate::attr::{Attrs, MessageBuilder};
use crate::uapi::*;
use crate::Error;

fn ifinfomsg(index: i32) -> [u8; IFINFOMSG_LEN] {
    let mut b = [0u8; IFINFOMSG_LEN];
    // family AF_UNSPEC, pad, type 0
    b[4..8].copy_from_slice(&index.to_ne_bytes());
    b
}

/// `RTM_NEWLINK` with `NLM_F_CREATE | NLM_F_EXCL`: fails with `EEXIST` when
/// a device of that name exists.
pub fn new_link_message(name: &str, kind: &str, seq: u32) -> Vec<u8> {
    let mut b = MessageBuilder::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, seq);
    b.bytes(&ifinfomsg(0));
    b.put_str(IFLA_IFNAME, name);
    b.nest(IFLA_LINKINFO).put_str(IFLA_INFO_KIND, kind).end_nest();
    b.finish()
}

pub fn del_link_message(name: &str, seq: u32) -> Vec<u8> {
    let mut b = MessageBuilder::new(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, seq);
    b.bytes(&ifinfomsg(0));
    b.put_str(IFLA_IFNAME, name);
    b.finish()
}

pub fn get_links_message(seq: u32) -> Vec<u8> {
    let mut b = MessageBuilder::new(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, seq);
    b.bytes(&ifinfomsg(0));
    b.finish()
}

/// A device of a `RTM_GETLINK` dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub index: i32,
    pub name: String,
    /// `IFLA_INFO_KIND`, for a device that has one.
    pub kind: Option<String>,
}

pub fn parse_link(payload: &[u8]) -> Result<Link, Error> {
    if payload.len() < IFINFOMSG_LEN {
        return Err(Error::Malformed("short ifinfomsg"));
    }
    let index = i32::from_ne_bytes(payload[4..8].try_into().unwrap());
    let mut link = Link { index, name: String::new(), kind: None };
    for a in Attrs(&payload[IFINFOMSG_LEN..]) {
        let a = a?;
        match a.ty {
            IFLA_IFNAME => link.name = a.str()?.to_owned(),
            IFLA_LINKINFO => {
                for i in a.nested() {
                    let i = i?;
                    if i.ty == IFLA_INFO_KIND {
                        link.kind = Some(i.str()?.to_owned());
                    }
                }
            }
            _ => {}
        }
    }
    Ok(link)
}

/// `CTRL_CMD_GETFAMILY` of a family by name.
pub fn get_family_message(name: &str, seq: u32) -> Vec<u8> {
    let mut b = MessageBuilder::new(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK, seq);
    b.genl_header(CTRL_CMD_GETFAMILY, 1);
    b.put_str(CTRL_ATTR_FAMILY_NAME, name);
    b.finish()
}

/// The id and version of a family from the controller's answer (payload
/// after the generic netlink header).
pub fn parse_family(attrs: &[u8]) -> Result<(u16, u32), Error> {
    let (mut id, mut version) = (None, 0);
    for a in Attrs(attrs) {
        let a = a?;
        match a.ty {
            CTRL_ATTR_FAMILY_ID => id = Some(a.u16()?),
            CTRL_ATTR_VERSION => version = a.u32()?,
            _ => {}
        }
    }
    Ok((id.ok_or(Error::Malformed("family without an id"))?, version))
}
