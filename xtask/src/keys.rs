//! ed25519 keys and signatures in the router's lines, with the same
//! arithmetic (ring 0.17.14):
//!
//! - a secret key: `ed25519-secret <base64 of the 32-byte seed>`;
//! - a public key: `ed25519 <base64 of 32 bytes> [comment]`;
//! - a signature: `ed25519 <base64 of the public key> <base64 of 64 bytes>`.
//!
//! ed25519 is deterministic: the same key and message give the signature
//! the router's own signer gives.

use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64(bytes: &[u8]) -> String {
    let mut s = String::new();
    for c in bytes.chunks(3) {
        let mut w = [0u8; 3];
        w[..c.len()].copy_from_slice(c);
        let n = u32::from(w[0]) << 16 | u32::from(w[1]) << 8 | u32::from(w[2]);
        for i in 0..=c.len() {
            s.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
        for _ in c.len()..3 {
            s.push('=');
        }
    }
    s
}

fn unb64(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes() {
        acc = acc << 6 | ALPHABET.iter().position(|&a| a == c)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

pub struct Secret {
    seed: [u8; 32],
    pair: Ed25519KeyPair,
}

impl Secret {
    fn from_seed(seed: [u8; 32]) -> Self {
        let pair = Ed25519KeyPair::from_seed_unchecked(&seed).expect("any 32 bytes are a seed");
        Self { seed, pair }
    }

    pub fn generate() -> Result<Self, String> {
        use ring::rand::SecureRandom;
        let mut seed = [0u8; 32];
        ring::rand::SystemRandom::new().fill(&mut seed).map_err(|_| "no randomness")?;
        Ok(Self::from_seed(seed))
    }

    /// A secret key file, or its line in an environment variable.
    pub fn read(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        Self::parse(&text).ok_or(format!("{path}: not a line `ed25519-secret <base64 of 32 bytes>`"))
    }

    pub fn parse(line: &str) -> Option<Self> {
        let mut w = line.split_whitespace();
        match (w.next(), w.next(), w.next()) {
            (Some("ed25519-secret"), Some(seed), None) => unb64(seed)?.try_into().ok().map(Self::from_seed),
            _ => None,
        }
    }

    pub fn line(&self) -> String {
        format!("ed25519-secret {}\n", b64(&self.seed))
    }

    pub fn public(&self) -> [u8; 32] {
        self.pair.public_key().as_ref().try_into().expect("32 bytes")
    }

    pub fn public_line(&self, comment: &str) -> String {
        format!("ed25519 {} {comment}\n", b64(&self.public()))
    }

    /// The signature line of `message`.
    pub fn sign(&self, message: &[u8]) -> String {
        format!("ed25519 {} {}\n", b64(&self.public()), b64(self.pair.sign(message).as_ref()))
    }
}

/// The key a signature line names, if the signature of `message` by it holds.
pub fn verify(line: &str, message: &[u8]) -> Result<[u8; 32], String> {
    let mut w = line.split_whitespace();
    let (Some("ed25519"), Some(key), Some(sig), None) = (w.next(), w.next(), w.next(), w.next()) else {
        return Err("not a line `ed25519 <base64 key> <base64 signature>`".into());
    };
    let key: [u8; 32] = unb64(key).and_then(|k| k.try_into().ok()).ok_or("its key is not 32 bytes")?;
    let sig = unb64(sig).filter(|s| s.len() == 64).ok_or("its signature is not 64 bytes")?;
    UnparsedPublicKey::new(&ED25519, key)
        .verify(message, &sig)
        .map_err(|_| "the signature does not hold")?;
    Ok(key)
}

/// The key of a public key file.
pub fn read_public(path: &str) -> Result<[u8; 32], String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let mut w = text.split_whitespace();
    match (w.next(), w.next()) {
        (Some("ed25519"), Some(k)) => unb64(k).and_then(|k| k.try_into().ok()),
        _ => None,
    }
    .ok_or(format!("{path}: not a line `ed25519 <base64 of 32 bytes> [comment]`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let k = Secret::generate().unwrap();
        let again = Secret::parse(&k.line()).unwrap();
        assert_eq!(again.public(), k.public());
        let s = k.sign(b"list");
        assert_eq!(s, again.sign(b"list"), "deterministic");
        assert_eq!(verify(&s, b"list").unwrap(), k.public());
        assert!(verify(&s, b"other").is_err());
        assert_eq!(unb64(&b64(&[1, 2, 3, 4])).unwrap(), vec![1, 2, 3, 4]);
    }
}
