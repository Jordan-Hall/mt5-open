//! Credential and device-identity derivations.

use crate::md5::{md5, md5_with_state};

/// .NET-style UTF-16LE encoding with optional truncation to `max_code_units`
/// 16-bit units. Truncation that splits a surrogate pair leaves a lone
/// surrogate, which is replaced by U+FFFD (matching a decode-with-replacement
/// followed by re-encoding).
pub fn dotnet_utf16(text: &str, max_code_units: Option<usize>) -> Vec<u8> {
    let mut units: Vec<u16> = text.encode_utf16().collect();
    if let Some(max) = max_code_units {
        units.truncate(max);
    }
    // Sanitize unpaired surrogates.
    let mut i = 0;
    while i < units.len() {
        let u = units[i];
        if (0xD800..=0xDBFF).contains(&u) {
            if i + 1 < units.len() && (0xDC00..=0xDFFF).contains(&units[i + 1]) {
                i += 2; // valid pair
            } else {
                units[i] = 0xFFFD;
                i += 1;
            }
        } else if (0xDC00..=0xDFFF).contains(&u) {
            units[i] = 0xFFFD;
            i += 1;
        } else {
            i += 1;
        }
    }
    let mut out = Vec::with_capacity(units.len() * 2);
    for u in units {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// MD5 over login (u64 LE) + password (UTF-16LE, capped at 16 code units) + the
/// two literal code units 'M','Q'.
pub fn password_hash(login: u64, password: &str) -> [u8; 16] {
    let mut data = Vec::new();
    data.extend_from_slice(&login.to_le_bytes());
    data.extend_from_slice(&dotnet_utf16(password, Some(16)));
    data.extend_from_slice(&[0x4d, 0x00, 0x51, 0x00]);
    md5(&data)
}

/// Challenge response: MD5 of the 16-byte server challenge continued from the
/// password hash as the initial state.
pub fn challenge_response(login: u64, password: &str, challenge: &[u8; 16]) -> [u8; 16] {
    md5_with_state(challenge, &password_hash(login, password))
}

/// Deterministic 16-byte device identifier derived from the login via a
/// Microsoft C `rand`-style LCG feeding an MD5, with byte 0 replaced by the
/// checksum of the remaining fifteen.
pub fn hardware_id(login: u64) -> [u8; 16] {
    let mut state = (login & 0xFFFF_FFFF) as u32;
    let mut material = [0u8; 256];
    for slot in material.iter_mut() {
        state = state.wrapping_mul(214013).wrapping_add(2531011);
        *slot = ((state >> 16) & 0xFF) as u8;
    }
    let mut digest = md5(&material);
    let sum: u32 = digest[1..].iter().map(|&b| b as u32).sum();
    digest[0] = (sum & 0xFF) as u8;
    digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hexutil::{decode, encode};

    #[test]
    fn credential_fixture() {
        // conformance_vectors credential-01.
        let login = 12345678u64;
        let pw = "ExamplePassword";
        let challenge: [u8; 16] = decode("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        assert_eq!(
            encode(&password_hash(login, pw)),
            "fb4823de3770686792d6b73aec3396f9"
        );
        assert_eq!(
            encode(&dotnet_utf16(pw, Some(16))),
            "4500780061006d0070006c006500500061007300730077006f0072006400"
        );
        assert_eq!(
            encode(&challenge_response(login, pw, &challenge)),
            "6adecffd4d9459a1de1621b4323809c3"
        );
    }

    #[test]
    fn hardware_fixture_and_checksum() {
        // conformance_vectors hardware-01.
        assert_eq!(
            encode(&hardware_id(12345678)),
            "cf7445431d288e5e9c813a2af6c8ea79"
        );
        for login in [0u64, 1, 123456789, 0xFFFF_FFFF_FFFF_FFFF] {
            let d = hardware_id(login);
            let sum: u32 = d[1..].iter().map(|&b| b as u32).sum();
            assert_eq!(d[0] as u32, sum & 0xFF);
            assert_eq!(d, hardware_id(login & 0xFFFF_FFFF));
        }
    }

    #[test]
    fn password_truncation() {
        assert_eq!(
            password_hash(12, &"A".repeat(17)),
            password_hash(12, &"A".repeat(16))
        );
        let mut expect = "A".repeat(15);
        expect.push('\u{FFFD}');
        assert_eq!(
            dotnet_utf16(&("A".repeat(15) + "\u{1F600}"), Some(16)),
            dotnet_utf16(&expect, None)
        );
    }
}
