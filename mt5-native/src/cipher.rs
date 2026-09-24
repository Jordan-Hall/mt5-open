//! The two byte-feedback stream ciphers the protocol uses.
//!
//! They look alike and are not the same. Keep them separate:
//!
//! * [`startup_encrypt`]/[`startup_decrypt`] — the handshake cipher. Feedback is
//!   the CIPHERTEXT byte, and the keystream index restarts at 0 for every call.
//! * [`SessionCipher`] — the post-handshake cipher. Feedback is the PLAINTEXT
//!   byte, and the key position persists across calls for the life of the
//!   connection (state crosses packet boundaries).

use crate::error::{ProtocolError, Result};

/// Fixed key for the handshake cipher.
pub const STARTUP_KEY: [u8; 16] = [
    0x41, 0xb6, 0x7f, 0x58, 0x38, 0x0c, 0xf0, 0x2d, 0x7b, 0x39, 0x08, 0xfe, 0x21, 0xbb, 0x41, 0x58,
];

/// Salt mixed into the one-time-password key derivation.
pub const OTP_SALT: [u8; 16] = [
    0xf0, 0x11, 0xd6, 0x96, 0x50, 0xf6, 0x14, 0x1d, 0xd7, 0xd2, 0x1f, 0x01, 0x5a, 0x1b, 0xad, 0xf9,
];

pub fn startup_encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.is_empty() {
        return Err(ProtocolError::new("empty cipher key"));
    }
    let mut previous = 0u8;
    let mut out = vec![0u8; data.len()];
    for (i, &plain) in data.iter().enumerate() {
        previous = plain ^ previous.wrapping_add(key[i % key.len()]);
        out[i] = previous;
    }
    Ok(out)
}

pub fn startup_decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.is_empty() {
        return Err(ProtocolError::new("empty cipher key"));
    }
    let mut previous = 0u8;
    let mut out = vec![0u8; data.len()];
    for (i, &cipher) in data.iter().enumerate() {
        out[i] = cipher ^ previous.wrapping_add(key[i % key.len()]);
        previous = cipher;
    }
    Ok(out)
}

/// Convenience wrappers that use [`STARTUP_KEY`].
pub fn startup_encrypt_default(data: &[u8]) -> Vec<u8> {
    startup_encrypt(data, &STARTUP_KEY).expect("static key is non-empty")
}
pub fn startup_decrypt_default(data: &[u8]) -> Vec<u8> {
    startup_decrypt(data, &STARTUP_KEY).expect("static key is non-empty")
}

/// The stateful session cipher. Feedback is the plaintext byte; `position`
/// advances through the key (rebasing only on counter overflow), so a message split
/// into chunks yields the same bytes as encrypting it whole.
pub struct SessionCipher {
    key: Vec<u8>,
    pub previous_plain: u8,
    pub position: usize,
}

impl SessionCipher {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.is_empty() {
            return Err(ProtocolError::new("empty session key"));
        }
        Ok(SessionCipher { key: key.to_vec(), previous_plain: 0, position: 0 })
    }

    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; data.len()];
        let mut index = self.position % self.key.len();
        for (i, &plain) in data.iter().enumerate() {
            out[i] = plain ^ self.previous_plain.wrapping_add(self.key[index]);
            self.previous_plain = plain;
            index += 1;
            if index == self.key.len() { index = 0; }
        }
        self.position = self.position.checked_add(data.len()).unwrap_or(index);
        out
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; data.len()];
        let mut index = self.position % self.key.len();
        for (i, &cipher) in data.iter().enumerate() {
            let plain = cipher ^ self.previous_plain.wrapping_add(self.key[index]);
            out[i] = plain;
            self.previous_plain = plain;
            index += 1;
            if index == self.key.len() { index = 0; }
        }
        self.position = self.position.checked_add(data.len()).unwrap_or(index);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hexutil::{decode, encode};

    #[test]
    fn startup_known_vector_and_roundtrip() {
        assert_eq!(encode(&startup_encrypt_default(b"hello")), "29ba55c196");
        assert_eq!(startup_decrypt_default(&decode("29ba55c196")), b"hello");
        for size in [0usize, 1, 15, 16, 17, 32, 34, 255, 1024] {
            let raw: Vec<u8> = (0..size).map(|i| (i * 37 + 5) as u8).collect();
            assert_eq!(startup_decrypt_default(&startup_encrypt_default(&raw)), raw);
        }
    }

    #[test]
    fn session_known_vector_and_state() {
        let mut c = SessionCipher::new(&STARTUP_KEY).unwrap();
        assert_eq!(encode(&c.encrypt(b"hello")), "297b88a8cb");
        assert_eq!(c.position, 5);
        assert_eq!(c.previous_plain, b'o');
    }

    #[test]
    fn session_state_crosses_packet_boundaries() {
        let key: Vec<u8> = (0..29u8).collect();
        let raw: Vec<u8> = (0..256u16).map(|i| i as u8).cycle().take(768).collect();
        let mut c = SessionCipher::new(&key).unwrap();
        let mut encoded = c.encrypt(&raw[..7]);
        encoded.extend(c.encrypt(&raw[7..91]));
        encoded.extend(c.encrypt(&raw[91..]));
        assert_eq!(encoded, SessionCipher::new(&key).unwrap().encrypt(&raw));
        let mut d = SessionCipher::new(&key).unwrap();
        let mut decoded = d.decrypt(&encoded[..33]);
        decoded.extend(d.decrypt(&encoded[33..]));
        assert_eq!(decoded, raw);
    }
    #[test]
    fn counter_overflow_preserves_non_power_of_two_key_phase() {
        let key = [1u8, 2, 3, 4, 5, 6, 7];
        let mut actual = SessionCipher::new(&key).unwrap();
        actual.position = usize::MAX - 3;
        let mut reference = SessionCipher::new(&key).unwrap();
        reference.position = actual.position % key.len();
        let mut rx = SessionCipher::new(&key).unwrap();
        rx.position = actual.position;
        for message in [b"first chunk".as_slice(), b"second chunk"] {
            let encoded = actual.encrypt(message);
            assert_eq!(encoded, reference.encrypt(message));
            assert_eq!(rx.decrypt(&encoded), message);
        }
    }

}
