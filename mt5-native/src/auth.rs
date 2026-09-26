//! Handshake grammars: the hello and authentication request frames, and the
//! plaintext challenge and authentication-result replies.
//!
//! Request payloads are enciphered with the handshake cipher
//! ([`crate::cipher::startup_encrypt_default`]). Reply parsers take already
//! deciphered plaintext.

use crate::cipher::{OTP_SALT, startup_encrypt, startup_encrypt_default};
use crate::crypto::{challenge_response, dotnet_utf16, hardware_id, password_hash};
use crate::error::{ProtocolError, Result};
use crate::frame::{FINAL, Frame};
use crate::md5::md5;
use crate::tlv::{encode_tlvs, parse_tlvs};

/// Build the hello (command 0) request frame. `device_id` defaults to the
/// login hardware id.
pub fn make_hello(
    login: u64,
    sequence: u16,
    build: u16,
    device_id: Option<[u8; 16]>,
    nonce_byte: u8,
    random_word: u32,
) -> Frame {
    let device_id = device_id.unwrap_or_else(|| hardware_id(login));
    let mut payload = Vec::with_capacity(34);
    payload.push(nonce_byte);
    payload.push(0);
    payload.extend_from_slice(&build.to_le_bytes());
    payload.extend_from_slice(&0x514Du16.to_le_bytes());
    payload.extend_from_slice(&login.to_le_bytes());
    payload.extend_from_slice(&device_id);
    payload.extend_from_slice(&random_word.to_le_bytes());
    Frame::new(0, sequence, FINAL, startup_encrypt_default(&payload))
}

/// Build the authentication (command 1) request frame, optionally carrying an
/// OTP as TLV 18.
pub fn make_auth(
    login: u64,
    password: &str,
    challenge: &[u8; 16],
    sequence: u16,
    client_challenge: &[u8; 16],
    nonce_word: u16,
    otp: Option<&str>,
) -> Frame {
    let mut payload = Vec::new();
    payload.extend_from_slice(&nonce_word.to_le_bytes());
    payload.extend_from_slice(&challenge_response(login, password, challenge));
    payload.extend_from_slice(client_challenge);
    if let Some(otp) = otp {
        let mut key_input = Vec::new();
        key_input.extend_from_slice(&password_hash(login, password));
        key_input.extend_from_slice(challenge);
        key_input.extend_from_slice(&OTP_SALT);
        key_input.push(0);
        let otp_key = md5(&key_input);
        let mut otp_plain = dotnet_utf16(otp, None);
        otp_plain.extend_from_slice(&[0, 0]);
        let otp_cipher = startup_encrypt(&otp_plain, &otp_key).expect("otp key non-empty");
        payload.extend_from_slice(&encode_tlvs(&[(18, otp_cipher)]));
    }
    Frame::new(1, sequence, FINAL, startup_encrypt_default(&payload))
}

/// Build the plaintext command-2 certificate continuation. The supplied
/// signature must already be an RSA PKCS#1 v1.5 SHA-1 signature of the server
/// challenge. Only its wire byte reversal is performed here; no key is read.
pub fn certificate_continuation_payload(
    signature: &[u8],
    certificate_der: &[u8],
) -> Result<Vec<u8>> {
    if signature.is_empty() || certificate_der.is_empty() {
        return Err(ProtocolError::new(
            "certificate and signature must be nonempty",
        ));
    }
    let mut body = vec![0; 16];
    body.extend(encode_tlvs(&[
        (4, signature.iter().rev().copied().collect()),
        (3, certificate_der.to_vec()),
    ]));
    Ok(body)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub unknown_i16_0: i16,
    pub status: i32,
    pub unknown_i16_6: i16,
    pub challenge: [u8; 16],
    pub unknown_tail_i16: [i16; 4],
}

/// Parse the 32-byte plaintext challenge reply (`<h i h 16s 4h>`).
pub fn parse_challenge(payload: &[u8]) -> Result<Challenge> {
    if payload.len() != 32 {
        return Err(ProtocolError::new(
            "plaintext challenge reply must be exactly 32 bytes",
        ));
    }
    let unknown_i16_0 = i16::from_le_bytes([payload[0], payload[1]]);
    let status = i32::from_le_bytes([payload[2], payload[3], payload[4], payload[5]]);
    let unknown_i16_6 = i16::from_le_bytes([payload[6], payload[7]]);
    let mut challenge = [0u8; 16];
    challenge.copy_from_slice(&payload[8..24]);
    let mut tail = [0i16; 4];
    for (i, t) in tail.iter_mut().enumerate() {
        *t = i16::from_le_bytes([payload[24 + i * 2], payload[24 + i * 2 + 1]]);
    }
    Ok(Challenge {
        unknown_i16_0,
        status,
        unknown_i16_6,
        challenge,
        unknown_tail_i16: tail,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResult {
    pub unknown_i32_0: i32,
    pub status: i32,
    pub unknown_i32_8: i32,
    pub unknown_i64_12: i64,
    pub unknown_i32_20: i32,
    pub server_build: i16,
    pub secondary_build: i16,
    pub opaque_16_bytes: [u8; 16],
    pub tlvs: Vec<(u8, Vec<u8>)>,
}

/// Safe structural diagnostics: no login, challenge, credential, key, tag
/// values or opaque bytes. Does not establish authentication success/readiness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSummary {
    pub status: i32,
    pub server_build: i16,
    pub record_build: i16,
    pub certificate_required: bool,
    pub tags: Vec<(u8, usize)>,
}

impl AuthResult {
    pub fn summary(&self) -> AuthSummary {
        AuthSummary {
            status: self.status,
            server_build: self.server_build,
            record_build: self.secondary_build,
            certificate_required: self.status == 1003,
            tags: self
                .tlvs
                .iter()
                .map(|(tag, value)| (*tag, value.len()))
                .collect(),
        }
    }
}

/// Parse the plaintext authentication result: a 44-byte fixed head
/// (`<i i i q i h h 16s>`) followed by a TLV list.
pub fn parse_auth_result(payload: &[u8]) -> Result<AuthResult> {
    if payload.len() < 44 {
        return Err(ProtocolError::new(
            "plaintext authentication result is shorter than 44 bytes",
        ));
    }
    let g32 =
        |o: usize| i32::from_le_bytes([payload[o], payload[o + 1], payload[o + 2], payload[o + 3]]);
    let mut q = [0u8; 8];
    q.copy_from_slice(&payload[12..20]);
    let mut opaque = [0u8; 16];
    opaque.copy_from_slice(&payload[28..44]);
    Ok(AuthResult {
        unknown_i32_0: g32(0),
        status: g32(4),
        unknown_i32_8: g32(8),
        unknown_i64_12: i64::from_le_bytes(q),
        unknown_i32_20: g32(20),
        server_build: i16::from_le_bytes([payload[24], payload[25]]),
        secondary_build: i16::from_le_bytes([payload[26], payload[27]]),
        opaque_16_bytes: opaque,
        tlvs: parse_tlvs(&payload[44..])?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::startup_decrypt_default;
    use crate::hexutil::{decode, encode};

    #[test]
    fn summary_preserves_tag_presence_and_lengths_without_values() {
        let mut bytes = vec![0; 44];
        bytes[4..8].copy_from_slice(&1003i32.to_le_bytes());
        bytes[24..26].copy_from_slice(&5500i16.to_le_bytes());
        bytes[26..28].copy_from_slice(&5499i16.to_le_bytes());
        bytes.extend(encode_tlvs(&[
            (7, b"secret-key".to_vec()),
            (28, b"secret-input".to_vec()),
            (28, vec![5]),
            (35, vec![6]),
        ]));
        let summary = parse_auth_result(&bytes).unwrap().summary();
        assert_eq!(summary.status, 1003);
        assert!(summary.certificate_required);
        assert_eq!((summary.server_build, summary.record_build), (5500, 5499));
        assert_eq!(summary.tags, vec![(7, 10), (28, 12), (28, 1), (35, 1)]);
        assert!(!format!("{summary:?}").contains("secret"));
    }

    #[test]
    fn hello_fixture() {
        // conformance_vectors hello-01.
        let hw: [u8; 16] = decode("cf7445431d288e5e9c813a2af6c8ea79")
            .try_into()
            .unwrap();
        let f = make_hello(12345678, 1, 5500, Some(hw), 90, 305419896);
        assert_eq!(f.command, 0);
        assert_eq!(f.flags, FINAL);
        assert_eq!(
            encode(&f.pack()),
            "0022000000010002001bd12c9184c1ff4d74adb5b3d48f1f0301f46eeea8ea46f257ba34faf1d56e90e589"
        );
        assert_eq!(
            encode(&startup_decrypt_default(&f.payload)),
            "5a007c154d514e61bc0000000000cf7445431d288e5e9c813a2af6c8ea7978563412"
        );
    }

    #[test]
    fn hello_default_device_id_is_hardware_id() {
        let f = make_hello(12345678, 1, 5500, None, 90, 305419896);
        let plain = startup_decrypt_default(&f.payload);
        assert_eq!(&plain[14..30], &hardware_id(12345678));
    }

    #[test]
    fn auth_fixture() {
        // conformance_vectors auth-basic.
        let challenge: [u8; 16] = decode("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        let client: [u8; 16] = decode("101112131415161718191a1b1c1d1e1f")
            .try_into()
            .unwrap();
        let f = make_auth(
            12345678,
            "ExamplePassword",
            &challenge,
            2,
            &client,
            4660,
            None,
        );
        assert_eq!(
            encode(&f.pack()),
            "0122000000020002007539d2f4e3124fe83ad20414147b8ede160f9ee70d0aee0e9fcfcfd4efb1ee5b8227"
        );
        assert_eq!(
            encode(&startup_decrypt_default(&f.payload)),
            "34126adecffd4d9459a1de1621b4323809c3101112131415161718191a1b1c1d1e1f"
        );
    }

    #[test]
    fn auth_otp_tlv18() {
        let challenge: [u8; 16] = decode("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        let client: [u8; 16] = decode("101112131415161718191a1b1c1d1e1f")
            .try_into()
            .unwrap();
        let f = make_auth(
            12345678,
            "ExamplePassword",
            &challenge,
            4,
            &client,
            42,
            Some("123456"),
        );
        let plain = startup_decrypt_default(&f.payload);
        let (tag, value) = parse_tlvs(&plain[34..]).unwrap().remove(0);
        assert_eq!(tag, 18);
        let mut ki = Vec::new();
        ki.extend_from_slice(&password_hash(12345678, "ExamplePassword"));
        ki.extend_from_slice(&challenge);
        ki.extend_from_slice(&OTP_SALT);
        ki.push(0);
        let key = md5(&ki);
        assert_eq!(
            crate::cipher::startup_decrypt(&value, &key).unwrap(),
            dotnet_utf16("123456\0", None)
        );
    }

    #[test]
    fn challenge_and_result_roundtrip() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&42i16.to_le_bytes());
        payload.extend_from_slice(&0i32.to_le_bytes());
        payload.extend_from_slice(&5500i16.to_le_bytes());
        payload.extend_from_slice(&(0..16u8).collect::<Vec<_>>());
        for v in [1i16, 2, 3, 4] {
            payload.extend_from_slice(&v.to_le_bytes());
        }
        let c = parse_challenge(&payload).unwrap();
        assert_eq!(c.status, 0);
        assert_eq!(&c.challenge, &(0..16u8).collect::<Vec<_>>()[..]);

        let items = vec![
            (
                0u8,
                "server"
                    .encode_utf16()
                    .flat_map(|u| u.to_le_bytes())
                    .collect::<Vec<u8>>(),
            ),
            (7u8, (0..32u8).collect()),
            (35u8, b"opaque".to_vec()),
        ];
        let mut rp = Vec::new();
        for v in [1i32, 0, 2] {
            rp.extend_from_slice(&v.to_le_bytes());
        }
        rp.extend_from_slice(&3i64.to_le_bytes());
        rp.extend_from_slice(&4i32.to_le_bytes());
        rp.extend_from_slice(&5500i16.to_le_bytes());
        rp.extend_from_slice(&5501i16.to_le_bytes());
        rp.extend_from_slice(&[0u8; 16]);
        rp.extend_from_slice(&encode_tlvs(&items));
        let r = parse_auth_result(&rp).unwrap();
        assert_eq!(r.server_build, 5500);
        assert_eq!(r.secondary_build, 5501);
        assert_eq!(r.tlvs, items);
    }
}
