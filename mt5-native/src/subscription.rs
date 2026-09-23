//! Client-originated requests: quote and depth subscriptions, dated bar-history
//! requests, and the external login calculation (F28/F35) HTTP adapter contract.
//!
//! The F28/F35 inner functions live in an external calculation service and are
//! not part of this executable; only the request/response adapter is defined.
//! This module builds the documented POST envelope and returns an explicit
//! marker that the remote result is not synthesized here — never a guessed
//! integer.

use crate::error::{ProtocolError, Result};

/// Quote subscription body: a `0x09` selector, an i32 count, then i32 symbol ids.
pub fn make_subscription_payload(symbol_ids: &[i32]) -> Vec<u8> {
    let mut out = vec![0x09u8];
    out.extend_from_slice(&(symbol_ids.len() as i32).to_le_bytes());
    for id in symbol_ids {
        out.extend_from_slice(&id.to_le_bytes());
    }
    out
}

/// Depth subscription body: a u32 count, then u32 symbol ids.
pub fn make_depth_subscription_payload(symbol_ids: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(symbol_ids.len() as u32).to_le_bytes());
    for id in symbol_ids {
        out.extend_from_slice(&id.to_le_bytes());
    }
    out
}

/// Encode a calendar date into the 16-bit token `((year-1970)<<9)|(month<<5)|day`.
pub fn date_token(year: i32, month: i32, day: i32) -> Result<u16> {
    if !(1970..=2097).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(ProtocolError::new("date outside representable fields"));
    }
    if !is_valid_calendar_date(year, month, day) {
        return Err(ProtocolError::new("invalid calendar date"));
    }
    Ok((((year - 1970) << 9) | (month << 5) | day) as u16)
}

fn is_valid_calendar_date(year: i32, month: i32, day: i32) -> bool {
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let dim = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => return false,
    };
    day >= 1 && day <= dim
}

/// Dated bar-history request (command 102 subtype 9): a `0x09` selector, the
/// symbol as 64 bytes of null-padded UTF-16LE, then `<H H>` of the first
/// parameter (548) and the date token.
pub fn bar_month_request(symbol: &str, year: i32, month: i32, day: i32) -> Result<Vec<u8>> {
    let field: Vec<u8> = symbol.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    if field.len() > 64 {
        return Err(ProtocolError::new("symbol exceeds 64 bytes"));
    }
    let mut out = vec![0x09u8];
    out.extend_from_slice(&field);
    out.extend(std::iter::repeat_n(0u8, 64 - field.len()));
    out.extend_from_slice(&548u16.to_le_bytes());
    out.extend_from_slice(&date_token(year, month, day)?.to_le_bytes());
    Ok(out)
}

/// The documented external login calculation adapter. `tag` is 28 (F28, the
/// `/CheckMT5` guid check) or 35 (F35, the `/DecodeEx` guid decode). The inner
/// remote function is not part of this executable and is not synthesized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpContract {
    pub method: &'static str,
    pub relative_path: &'static str,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub content_length: usize,
    pub result: &'static str,
}

pub fn additional_login_http_contract(tag: u8, value: &[u8], server_build: i32) -> Result<HttpContract> {
    if tag != 28 && tag != 35 {
        return Err(ProtocolError::new("not an additional-login input tag"));
    }
    let mut body = base64_encode(value).into_bytes();
    if tag == 28 && server_build >= 4852 {
        let mut prefixed = b"loginidnew5".to_vec();
        prefixed.extend_from_slice(&body);
        body = prefixed;
    }
    Ok(HttpContract {
        method: "POST",
        relative_path: if tag == 28 { "/CheckMT5?guid=" } else { "/DecodeEx?guid=" },
        content_type: "application/text",
        content_length: body.len(),
        body,
        result: "decimal UInt64 response text; remote function intentionally not synthesized",
    })
}

/// Standard base64 with padding.
pub fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18 & 63) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6 & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hexutil::encode;

    #[test]
    fn subscription_fixtures() {
        assert_eq!(encode(&make_subscription_payload(&[1, 200])), "090200000001000000c8000000");
        assert_eq!(encode(&make_depth_subscription_payload(&[1, 200])), "0200000001000000c8000000");
    }

    #[test]
    fn base64_matches_python() {
        assert_eq!(base64_encode(&[0x00, 0x01, 0x02]), "AAEC");
        assert_eq!(base64_encode(b"any carnal pleasure."), "YW55IGNhcm5hbCBwbGVhc3VyZS4=");
    }

    #[test]
    fn login_contract_fixtures() {
        // request_contract_only_not_inner_function.
        let old = additional_login_http_contract(28, &[0, 1, 2], 4851).unwrap();
        assert_eq!(old.body, b"AAEC");
        assert_eq!(old.relative_path, "/CheckMT5?guid=");
        let new = additional_login_http_contract(28, &[0, 1, 2], 4852).unwrap();
        assert_eq!(new.body, b"loginidnew5AAEC");
        assert_eq!(new.content_length, 15);
        let t35 = additional_login_http_contract(35, &[0, 1, 2], 5500).unwrap();
        assert_eq!(t35.body, b"AAEC");
        assert_eq!(t35.relative_path, "/DecodeEx?guid=");
        assert!(additional_login_http_contract(9, &[], 5500).is_err());
    }

    #[test]
    fn date_and_bar_request() {
        assert_eq!(date_token(2026, 9, 16).unwrap(), 28976);
        assert!(date_token(2100, 1, 1).is_err());
        assert!(date_token(2024, 2, 30).is_err());
        let req = bar_month_request("EURUSD", 2026, 9, 16).unwrap();
        assert_eq!(req.len(), 69);
        assert_eq!(u16::from_le_bytes([req[65], req[66]]), 548);
        assert_eq!(u16::from_le_bytes([req[67], req[68]]), (56 << 9) | (9 << 5) | 16);
    }
}
