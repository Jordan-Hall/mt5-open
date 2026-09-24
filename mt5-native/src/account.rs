//! The account record — where the balance is.
//!
//! `AccountRec` is a 2996-byte fixed struct whose layout is validated for
//! contiguity by the conformance suite. The identified numeric fields are read
//! here at their documented offsets; the many opaque spans are left alone.
//!
//! It reaches a client two ways, and both are handled: as tag 37 in the
//! command-12 synchronization response (the record on its own), and as
//! command-55 subtype 19, which is how the balance *updates* after login —
//! `A(bytes[216] || AccountRec[2996])`.
//!
//! This is decode only. Nothing here connects, and reading a balance is a read.

use crate::error::{ProtocolError, Result};

/// The size of one `AccountRec`.
pub const ACCOUNT_REC_SIZE: usize = 2996;

/// The 216-byte prefix that precedes each record inside a subtype-19 update.
const UPDATE_PREFIX: usize = 216;

/// The identified numbers from an account record. Opaque fields are not carried.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AccountState {
    pub login: u64,
    /// Realised money in the account.
    pub balance: f64,
    pub credit: f64,
    /// Margin currently blocked by open positions.
    pub blocked: f64,
    pub leverage: i32,
    pub trade_flags: i32,
}

impl AccountState {
    /// Trade flag bit 8 marks an investor / read-only login (see the trade-key
    /// derivation, which refuses to sign without a real key when this is set).
    pub fn is_read_only(&self) -> bool {
        self.trade_flags & 8 != 0
    }
}

fn f64_at(rec: &[u8], off: usize) -> f64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&rec[off..off + 8]);
    f64::from_le_bytes(b)
}

fn i32_at(rec: &[u8], off: usize) -> i32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&rec[off..off + 4]);
    i32::from_le_bytes(b)
}

fn u64_at(rec: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&rec[off..off + 8]);
    u64::from_le_bytes(b)
}

/// Read one account record. Rejects anything shorter than the fixed size rather
/// than reading a field off the end.
pub fn parse_account_rec(rec: &[u8]) -> Result<AccountState> {
    if rec.len() < ACCOUNT_REC_SIZE {
        return Err(ProtocolError::new(format!(
            "account record is {} bytes, need {ACCOUNT_REC_SIZE}",
            rec.len()
        )));
    }
    Ok(AccountState {
        login: u64_at(rec, 0),
        balance: f64_at(rec, 1836),
        credit: f64_at(rec, 1844),
        blocked: f64_at(rec, 1928),
        leverage: i32_at(rec, 2020),
        trade_flags: i32_at(rec, 456),
    })
}

/// Parse a command-55 subtype-19 body: `u8 subtype(19) || i32 count`, then
/// `count` records of `216 + 2996` bytes, the account record following the
/// prefix. Returns one `AccountState` per record.
pub fn parse_account_update_19(body: &[u8]) -> Result<Vec<AccountState>> {
    if body.len() < 5 {
        return Err(ProtocolError::new("account update too short for subtype + count"));
    }
    if body[0] != 19 {
        return Err(ProtocolError::new("not a subtype-19 account update"));
    }
    let count = i32::from_le_bytes([body[1], body[2], body[3], body[4]]);
    if count < 0 {
        return Err(ProtocolError::new("account update count is negative"));
    }
    let stride = UPDATE_PREFIX + ACCOUNT_REC_SIZE;
    let need = (count as usize).checked_mul(stride).and_then(|n| n.checked_add(5))
        .ok_or_else(|| ProtocolError::new("account update size overflow"))?;
    if body.len() < need {
        return Err(ProtocolError::new(format!(
            "account update is {} bytes, need {need} for {count} records",
            body.len()
        )));
    }
    let mut out = Vec::with_capacity(count as usize);
    let mut off = 5;
    for _ in 0..count {
        let rec = &body[off + UPDATE_PREFIX..off + stride];
        out.push(parse_account_rec(rec)?);
        off += stride;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic record with known numbers at the documented offsets. This
    /// tests the offset arithmetic and the little-endian decode; the offsets
    /// themselves are the ones the conformance layout check holds contiguous.
    fn record_with(login: u64, balance: f64, credit: f64, blocked: f64, leverage: i32, flags: i32) -> Vec<u8> {
        let mut r = vec![0u8; ACCOUNT_REC_SIZE];
        r[0..8].copy_from_slice(&login.to_le_bytes());
        r[456..460].copy_from_slice(&flags.to_le_bytes());
        r[1836..1844].copy_from_slice(&balance.to_le_bytes());
        r[1844..1852].copy_from_slice(&credit.to_le_bytes());
        r[1928..1936].copy_from_slice(&blocked.to_le_bytes());
        r[2020..2024].copy_from_slice(&leverage.to_le_bytes());
        r
    }

    #[test]
    fn reads_the_identified_fields() {
        let rec = record_with(12345678, 136.42, 0.0, 12.5, 500, 0);
        let state = parse_account_rec(&rec).unwrap();
        assert_eq!(state.login, 12345678);
        assert_eq!(state.balance, 136.42);
        assert_eq!(state.blocked, 12.5);
        assert_eq!(state.leverage, 500);
        assert!(!state.is_read_only());
    }

    #[test]
    fn an_investor_login_is_read_only() {
        let rec = record_with(1, 0.0, 0.0, 0.0, 100, 8);
        assert!(parse_account_rec(&rec).unwrap().is_read_only());
    }

    #[test]
    fn a_short_record_is_rejected() {
        assert!(parse_account_rec(&[0u8; 100]).is_err());
    }

    #[test]
    fn subtype_19_yields_one_state_per_record() {
        let mut body = vec![19u8];
        body.extend_from_slice(&2i32.to_le_bytes());
        for (login, bal) in [(10u64, 100.0), (20u64, 250.5)] {
            body.extend_from_slice(&[0u8; UPDATE_PREFIX]);
            body.extend_from_slice(&record_with(login, bal, 0.0, 0.0, 100, 0));
        }
        let states = parse_account_update_19(&body).unwrap();
        assert_eq!(states.len(), 2);
        assert_eq!(states[0].login, 10);
        assert_eq!(states[0].balance, 100.0);
        assert_eq!(states[1].login, 20);
        assert_eq!(states[1].balance, 250.5);
    }

    #[test]
    fn a_truncated_update_is_rejected() {
        let mut body = vec![19u8];
        body.extend_from_slice(&1i32.to_le_bytes());
        body.extend_from_slice(&[0u8; 100]); // nowhere near a full record
        assert!(parse_account_update_19(&body).is_err());
    }
}
