//! Command-12 synchronization login values and request.
//!
//! The additional login values (`login_id`, `extended_login_id` and the two
//! wire tags) are computed from supplied `F28`/`F35` results by the documented
//! wrapper arithmetic. The inner `F28`/`F35` mappings are external and are NOT
//! reproduced here; their results are inputs. All additions wrap mod 2^64.

use crate::md5::md5;
use crate::tlv::encode_tlvs;

/// Wrapper constants from the specification.
const K: u64 = 371664536245528874;
const J: u64 = 1185773498152003;

fn q_of(challenge: &[u8; 16]) -> u64 {
    u64::from_le_bytes(challenge[0..8].try_into().unwrap())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginValues {
    pub login_id: u64,
    pub extended_login_id: u64,
    pub tag88_value: [u8; 8],
    pub tag134_value: [u8; 8],
}

/// Combine supplied `F28`/`F35` results into the login ids and their command-12
/// tag values. `f28_result`/`f35_result` are the external computation outputs.
pub fn login_value_wrapper(
    login: u64,
    client_build: u32,
    server_build: u32,
    challenge: &[u8; 16],
    f28_result: u64,
    f35_result: u64,
) -> LoginValues {
    let l = login;
    let c64 = client_build as u64;
    let q = q_of(challenge);
    let b = server_build;

    // Tag-28 path.
    let mut x = f28_result;
    if b >= 5409 {
        x = x.wrapping_add((b & 7) as u64);
    }
    let login_id = x ^ l ^ c64 ^ q ^ K;

    // Tag-35 path (note the addition sits in a different place).
    let mut y = f35_result;
    y ^= l ^ c64 ^ q;
    if b >= 4852 {
        y ^= J;
        if b >= 5409 {
            y = y.wrapping_add((b & 7) as u64);
        }
    }
    let extended_login_id = y ^ K;

    LoginValues {
        login_id,
        extended_login_id,
        tag88_value: (login_id ^ K).to_le_bytes(),
        tag134_value: (extended_login_id ^ K).to_le_bytes(),
    }
}

/// Build the command-12 initial synchronization request: an ordered TLV list
/// with no leading count. `login_id`/`extended_login_id` come from
/// [`login_value_wrapper`]. `environment_text` supplies tag 127 in the modern
/// profile; its metadata generator (spec §8.2) is out of scope here.
pub fn make_sync_request(
    login: u64,
    client_build: u32,
    server_build: u32,
    unix_seconds: i64,
    login_id: u64,
    extended_login_id: u64,
    environment_text: Option<&str>,
) -> Vec<u8> {
    let e = md5(&[]); // MD5 of empty input.
    let modern = client_build > 4200 && server_build >= 4200;

    let mut items: Vec<(u8, Vec<u8>)> = Vec::new();
    items.push((34, (-1i64).to_le_bytes().to_vec()));
    items.push((39, 0u32.to_le_bytes().to_vec()));
    items.push((108, md5(&login.to_le_bytes())[0..8].to_vec()));
    let mut v139 = login.to_le_bytes().to_vec();
    v139.extend_from_slice(&0u64.to_le_bytes());
    items.push((139, v139));
    let mut v22 = vec![0u8];
    v22.extend_from_slice(&0i64.to_le_bytes());
    items.push((22, v22));
    items.push((24, unix_seconds.to_le_bytes().to_vec()));
    if modern {
        items.push((132, Vec::new()));
        let mut v127: Vec<u8> = environment_text
            .unwrap_or("")
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        v127.extend_from_slice(&[0, 0]);
        items.push((127, v127));
    }
    let mut v7 = 0i64.to_le_bytes().to_vec();
    v7.extend_from_slice(&0u32.to_le_bytes());
    v7.extend_from_slice(&e);
    v7.extend_from_slice(&e);
    items.push((7, v7));
    let mut v40 = 0i64.to_le_bytes().to_vec();
    v40.extend_from_slice(&0u32.to_le_bytes());
    v40.extend_from_slice(&e);
    items.push((40, v40));
    let mut v103 = 0i64.to_le_bytes().to_vec();
    v103.extend_from_slice(&0u32.to_le_bytes());
    items.push((103, v103));
    items.push((17, crate::hexutil::decode("f6eb0645cd1274f152d99793cbd8dad8")));
    items.push((88, (login_id ^ K).to_le_bytes().to_vec()));
    if modern {
        items.push((134, (extended_login_id ^ K).to_le_bytes().to_vec()));
    }

    encode_tlvs(&items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hexutil::{decode, encode};

    #[test]
    fn login_value_wrapper_fixture() {
        // conformance_vectors login-wrap-4199.
        let challenge: [u8; 16] = decode("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let v = login_value_wrapper(12345678, 5500, 4199, &challenge, 18446744073709551614, 81985529216486895);
        assert_eq!(v.login_id, 18289557989361181670);
        assert_eq!(v.extended_login_id, 219878749281440247);
        assert_eq!(encode(&v.tag88_value), "cc8a41fcfbfaf9f8");
        assert_eq!(encode(&v.tag134_value), "ddb8158a63402506");
    }
}
