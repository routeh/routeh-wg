//! The I1–I5 packet templates (`junk.c`).
//!
//! A template is a row of tags, each one part of the packet the module
//! sends before a handshake:
//!
//! | Tag | Bytes |
//! |---|---|
//! | `<b 0xHEX>` | these bytes (an even number of hex digits, at least two) |
//! | `<c>` | a packet counter, 4 bytes, network order |
//! | `<t>` | the time in seconds, 4 bytes, network order |
//! | `<r N>` | N random bytes |
//! | `<rc N>` | N random letters |
//! | `<rd N>` | N random digits |
//!
//! At most 65535 bytes in all. The empty template sends nothing.
//!
//! This is stricter than the module, never looser: the module ignores text
//! between tags, takes a last tag with no `>`, a sign before a number and a
//! `+` inside hex; all of that is refused here, so what is accepted here is
//! what the module reads the same way.
//!
//! The module frees the old packet before it parses the new one, and keeps
//! the old text when parsing fails: after a refused template, a device
//! sends no I-packet for it while a dump still shows the old text. So a
//! template is checked here before it is sent.

use crate::uapi::JP_MAX_PACKET_SIZE;
use crate::Error;

/// The size of the packet `template` makes, or why the module would refuse it.
pub fn packet_size(template: &str) -> Result<usize, Error> {
    let bad = |why: String| Error::Invalid(format!("template {template:?}: {why}"));
    let mut rest = template;
    let mut size = 0usize;
    loop {
        rest = rest.trim_start_matches([' ', '\t', '\n']);
        if rest.is_empty() {
            break;
        }
        let Some(body) = rest.strip_prefix('<') else {
            return Err(bad(format!("text outside a tag at {rest:?}")));
        };
        let Some(end) = body.find('>') else {
            return Err(bad("a tag without '>'".into()));
        };
        let tag = &body[..end];
        rest = &body[end + 1..];
        if tag.contains('<') {
            return Err(bad(format!("'<' inside the tag <{tag}>")));
        }
        let (key, val) = match tag.split_once(' ') {
            Some((k, v)) => (k, Some(v)),
            None => (tag, None),
        };
        let n = match (key, val) {
            ("b", Some(v)) => {
                let hex = v.strip_prefix("0x").ok_or_else(|| bad(format!("<b {v}>: not 0x…")))?;
                if hex.is_empty() || hex.len() % 2 != 0 || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
                    return Err(bad(format!("<b {v}>: an even number of hex digits is needed")));
                }
                hex.len() / 2
            }
            ("c" | "t", None) => 4,
            ("r" | "rc" | "rd", Some(v)) => {
                if v.is_empty() || !v.bytes().all(|c| c.is_ascii_digit()) {
                    return Err(bad(format!("<{key} {v}>: a number of bytes is needed")));
                }
                // kstrtoint: a number above i32::MAX is refused.
                v.parse::<i32>().map_err(|_| bad(format!("<{key} {v}>: too large")))? as usize
            }
            ("c" | "t", Some(_)) => return Err(bad(format!("<{key}> takes no value"))),
            ("b" | "r" | "rc" | "rd", None) => return Err(bad(format!("<{key}> needs a value"))),
            _ => return Err(bad(format!("unknown tag <{tag}>"))),
        };
        size = size
            .checked_add(n)
            .filter(|&s| s <= JP_MAX_PACKET_SIZE)
            .ok_or_else(|| bad(format!("more than {JP_MAX_PACKET_SIZE} bytes")))?;
    }
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(packet_size("").unwrap(), 0);
        assert_eq!(packet_size("<b 0xc0ff><r 16><c><t>").unwrap(), 2 + 16 + 4 + 4);
        assert_eq!(packet_size("<rc 3> <rd 5>\n<b 0xAbCd>").unwrap(), 3 + 5 + 2);
        assert_eq!(packet_size("<r 0>").unwrap(), 0);
        assert_eq!(packet_size("<r 65535>").unwrap(), 65535);
    }

    #[test]
    fn refused() {
        for t in [
            "x<c>",        // text outside a tag
            "<c",          // no '>'
            "<>",          // empty tag
            "<b>",         // b without value
            "<b 00>",      // no 0x
            "<b 0x>",      // no digits
            "<b 0xabc>",   // odd
            "<b 0x+f>",    // kstrtou8 would take "+f"
            "<c 1>",       // c with value
            "<r>",         // r without value
            "<r -1>",
            "<r +1>",
            "<r 1 2>",
            "<x 1>",
            "<r 65535><c>", // too big
            "<r 99999999999>",
        ] {
            assert!(packet_size(t).is_err(), "{t}");
        }
    }
}
