//! Quote, depth and dated bar-history requests.

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
    let field: Vec<u8> = symbol
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hexutil::encode;

    #[test]
    fn subscription_fixtures() {
        assert_eq!(
            encode(&make_subscription_payload(&[1, 200])),
            "090200000001000000c8000000"
        );
        assert_eq!(
            encode(&make_depth_subscription_payload(&[1, 200])),
            "0200000001000000c8000000"
        );
    }

    #[test]
    fn date_and_bar_request() {
        assert_eq!(date_token(2026, 9, 16).unwrap(), 28976);
        assert!(date_token(2100, 1, 1).is_err());
        assert!(date_token(2024, 2, 30).is_err());
        let req = bar_month_request("EURUSD", 2026, 9, 16).unwrap();
        assert_eq!(req.len(), 69);
        assert_eq!(u16::from_le_bytes([req[65], req[66]]), 548);
        assert_eq!(
            u16::from_le_bytes([req[67], req[68]]),
            (56 << 9) | (9 << 5) | 16
        );
    }
}
