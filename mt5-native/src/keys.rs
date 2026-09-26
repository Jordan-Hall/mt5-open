//! Session-key and trade-key derivations.
//!
//! Both consume the 16-byte credential digest (the password hash). The session
//! key encrypts TLV-7 material under AES-128-CBC with a zero IV and no padding;
//! the trade key is the SHA-256 of the handshake-deciphered TLV-27 material
//! concatenated with the digest.

use crate::cipher::startup_decrypt;
use crate::crypto::password_hash;
use crate::error::{ProtocolError, Result};
use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::NoPadding};
use sha2::{Digest, Sha256};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

/// Derive the AES session key from the credential digest and TLV-7 value.
pub fn derive_session_key_from_digest(digest: &[u8; 16], tag7_value: &[u8]) -> Result<Vec<u8>> {
    if tag7_value.is_empty() {
        return Err(ProtocolError::new("session key TLV 7 is empty"));
    }
    let mut material = tag7_value.to_vec();
    let pad = (16 - material.len() % 16) % 16;
    material.extend(std::iter::repeat_n(0u8, pad));
    let out = Aes128CbcEnc::new(digest.into(), &[0u8; 16].into())
        .encrypt_padded_vec_mut::<NoPadding>(&material);
    Ok(out)
}

/// The zero-padded TLV-7 material, exposed for conformance checks.
pub fn session_key_padded_input(tag7_value: &[u8]) -> Vec<u8> {
    let mut material = tag7_value.to_vec();
    let pad = (16 - material.len() % 16) % 16;
    material.extend(std::iter::repeat_n(0u8, pad));
    material
}

pub fn derive_session_key(login: u64, password: &str, tag7_value: &[u8]) -> Result<Vec<u8>> {
    derive_session_key_from_digest(&password_hash(login, password), tag7_value)
}

/// The handshake-deciphered TLV-27 material, exposed for conformance checks.
pub fn decoded_tag27(digest: &[u8; 16], tag27_value: &[u8]) -> Vec<u8> {
    startup_decrypt(tag27_value, digest).expect("digest key is non-empty")
}

/// Derive the 32-byte trade signing key from the credential digest and TLV-27.
pub fn derive_trade_key_from_digest(digest: &[u8; 16], tag27_value: &[u8]) -> [u8; 32] {
    let transformed = decoded_tag27(digest, tag27_value);
    let mut h = Sha256::new();
    h.update(&transformed);
    h.update(digest);
    h.finalize().into()
}

pub fn derive_trade_key(login: u64, password: &str, tag27_value: &[u8]) -> [u8; 32] {
    derive_trade_key_from_digest(&password_hash(login, password), tag27_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hexutil::{decode, encode};

    fn digest() -> [u8; 16] {
        decode("fb4823de3770686792d6b73aec3396f9")
            .try_into()
            .unwrap()
    }

    #[test]
    fn session_key_fixture() {
        // conformance_vectors key7-01.
        let d = digest();
        let tag7 = decode("00");
        assert_eq!(
            encode(&session_key_padded_input(&tag7)),
            "00000000000000000000000000000000"
        );
        assert_eq!(
            encode(&derive_session_key_from_digest(&d, &tag7).unwrap()),
            "15643cc783ab813e27e8dd486ea7dfc5"
        );
        assert!(derive_session_key_from_digest(&d, &[]).is_err());
    }

    #[test]
    fn trade_key_fixture() {
        // conformance_vectors key27-01.
        let d = digest();
        let tag27 = decode("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        assert_eq!(
            encode(&decoded_tag27(&d, &tag27)),
            "db4966237eb1abaa91d7ca4f3b72ed081a4966235e91abaaf137ca4f1b52ed08"
        );
        assert_eq!(
            encode(&derive_trade_key_from_digest(&d, &tag27)),
            "ee47d3d1b093ebb78e800fd4cf6b817f50d498a2cb874b3d7e74451d18122050"
        );
    }
}
