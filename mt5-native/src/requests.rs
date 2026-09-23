//! Client-originated command requests that carry fixed structures: trade
//! history (command 101), password change (command 107 subtype 12) and tick
//! history (command 105 subtype 14). Each is session-encoded and uncompressed
//! in the covered path; this module builds the plaintext bodies.

use crate::crypto::password_hash;
use crate::error::{ProtocolError, Result};
use crate::subscription::date_token;

/// UTF-16LE, null-padded/truncated to `size` bytes.
fn utf16_field(s: &str, size: usize) -> Vec<u8> {
    let mut v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    v.resize(size, 0);
    v
}

/// Trade-history request (command 101). Subtype 32 requests orders, 33 deals.
/// This builds the no-cache form (21 bytes, cache count zero).
pub fn make_trade_history_request(subtype: u8, from_time: i64, to_time: i64) -> Vec<u8> {
    let mut out = vec![subtype];
    out.extend_from_slice(&from_time.to_le_bytes());
    out.extend_from_slice(&to_time.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // cached window count
    out
}

/// Password-change request (command 107 subtype 12). `is_investor` selects the
/// investor password (flag 1) instead of the main password (flag 0). The digest
/// is the ordinary password hash of the new password.
pub fn make_password_change(login: u64, new_password: &str, is_investor: bool) -> Vec<u8> {
    let mut out = vec![12u8, u8::from(is_investor)];
    out.extend_from_slice(&password_hash(login, new_password));
    out
}

/// The fixed 499-byte request descriptor embedded in a tick-history request.
pub fn request_descriptor_499(symbol: &str, token: u16) -> Vec<u8> {
    let mut d = Vec::with_capacity(499);
    d.extend_from_slice(&499u16.to_le_bytes()); // 0
    d.extend_from_slice(&utf16_field(symbol, 64)); // 2
    d.extend_from_slice(&token.to_le_bytes()); // 66
    d.extend_from_slice(&token.to_le_bytes()); // 68 (repeated)
    d.extend_from_slice(&0i32.to_le_bytes()); // 70
    d.extend_from_slice(&0i32.to_le_bytes()); // 74
    d.extend_from_slice(&0i32.to_le_bytes()); // 78
    d.extend_from_slice(&0i32.to_le_bytes()); // 82
    d.push(2u8); // 86
    d.extend_from_slice(&0i32.to_le_bytes()); // 87
    d.extend_from_slice(&5u16.to_le_bytes()); // 91
    d.extend_from_slice(&6u16.to_le_bytes()); // 93
    d.extend_from_slice(&1u32.to_le_bytes()); // 95
    d.extend(std::iter::repeat_n(0u8, 400)); // 99..499
    d
}

/// Tick-history request (command 105 subtype 14), no-cache form (574 bytes).
pub fn make_tick_history_request(
    symbol: &str,
    year: i32,
    month: i32,
    day: i32,
    request_parameter: u32,
) -> Result<Vec<u8>> {
    let token = date_token(year, month, day)?;
    let mut out = vec![14u8];
    out.extend_from_slice(&utf16_field(symbol, 64));
    out.extend_from_slice(&token.to_le_bytes());
    out.extend_from_slice(&request_parameter.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // cache count
    out.extend_from_slice(&request_descriptor_499(symbol, token));
    if out.len() != 574 {
        return Err(ProtocolError::new("tick-history request must be 574 bytes"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hexutil::encode;

    #[test]
    fn trade_history_fixture() {
        // conformance_vectors command101_request.
        let body = make_trade_history_request(32, 1700000000, 1700086400);
        assert_eq!(encode(&body), "2000f1536500000000804255650000000000000000");
    }

    #[test]
    fn password_change_fixture() {
        // conformance_vectors command107_subtype12.
        let body = make_password_change(12345678, "ExampleNewPass", false);
        assert_eq!(encode(&body), "0c00058201a75078d0ec3bf649cbd29b62c4");
    }

    #[test]
    fn tick_history_request_shape() {
        let body = make_tick_history_request("EURUSD", 2023, 11, 14, 0).unwrap();
        assert_eq!(body.len(), 574);
        assert_eq!(body[0], 14);
        assert_eq!(request_descriptor_499("EURUSD", 27502).len(), 499);
    }
}
