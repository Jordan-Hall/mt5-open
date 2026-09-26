//! Broker-pushed account, order and position changes (command 55).
use crate::{
    account::{AccountState, parse_account_update_19},
    error::{ProtocolError, Result},
    reader::Reader,
    records::{Deal, Order, Record, Symbol},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Add,
    Update,
    Delete,
}

fn transaction(r: &mut Reader) -> Result<Change> {
    let bytes = r.take(152)?;
    match i32::from_le_bytes(bytes[4..8].try_into().unwrap()) {
        0 => Ok(Change::Add),
        1 => Ok(Change::Update),
        2 => Ok(Change::Delete),
        other => Err(ProtocolError::new(format!(
            "unknown transaction action {other}"
        ))),
    }
}

#[derive(Debug, Clone)]
pub enum Update {
    Symbols(Vec<Symbol>),
    Account(Vec<AccountState>),
    Orders(Vec<(Change, Order)>),
    Positions(Vec<PositionChange>),
    Other,
}

#[derive(Debug, Clone)]
pub struct PositionChange {
    pub deal: Deal,
    pub position: Deal,
    pub balance: Option<(f64, f64)>,
    pub related_deals: Vec<Deal>,
    pub related_positions: Vec<Deal>,
}

pub fn decode_update(bytes: &[u8]) -> Result<Update> {
    let mut r = Reader::new(bytes);
    let kind = r.byte()?;
    let result = match kind {
        7 => {
            let mut symbols = Vec::new();
            for _ in 0..r.count(3348)? {
                r.take(32)?;
                let info = r.take(1952)?;
                let group = r.take(1228)?;
                symbols.push(Symbol::parse(info, group)?);
                for _ in 0..14 {
                    let count = r.count(40)?;
                    r.take(count * 40)?;
                }
                r.take(80)?;
            }
            Update::Symbols(symbols)
        }
        19 => return Ok(Update::Account(parse_account_update_19(bytes)?)),
        31 => {
            let mut orders = Vec::new();
            for _ in 0..r.count(788)? {
                let action = transaction(&mut r)?;
                orders.push((action, Order::parse(r.take(636)?)?));
            }
            Update::Orders(orders)
        }
        33 => {
            let mut positions = Vec::new();
            for _ in 0..r.count(1760)? {
                let action = transaction(&mut r)?;
                let deal = Deal::parse(r.take(672)?)?;
                let position = Deal::parse(r.take(672)?)?;
                let account = Record::new(r.take(192)?, 192)?;
                let balance = if action == Change::Add && deal.ticket != 0 {
                    Some((account.f64(8), account.f64(16)))
                } else {
                    None
                };
                r.take(64)?;
                let mut related_deals = Vec::new();
                for _ in 0..r.count(672)? {
                    related_deals.push(Deal::parse(r.take(672)?)?);
                }
                let mut related_positions = Vec::new();
                for _ in 0..r.count(672)? {
                    related_positions.push(Deal::parse(r.take(672)?)?);
                }
                positions.push(PositionChange {
                    deal,
                    position,
                    balance,
                    related_deals,
                    related_positions,
                });
            }
            Update::Positions(positions)
        }
        _ => return Ok(Update::Other),
    };
    if !r.remaining.is_empty() {
        return Err(ProtocolError::new("trailing trade update bytes"));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn position_state_is_the_second_record_and_zero_balance_is_real() {
        let mut bytes = vec![0; 1765];
        bytes[0] = 33;
        bytes[1..5].copy_from_slice(&1i32.to_le_bytes());
        bytes[157..165].copy_from_slice(&100u64.to_le_bytes());
        bytes[829..837].copy_from_slice(&200u64.to_le_bytes());
        bytes[1117..1125].copy_from_slice(&200u64.to_le_bytes());
        bytes[1053..1061].copy_from_slice(&1_000_000u64.to_le_bytes());
        let Update::Positions(changes) = decode_update(&bytes).unwrap() else {
            panic!()
        };
        assert_eq!(changes[0].deal.ticket, 100);
        assert_eq!(changes[0].position.ticket, 200);
        assert_eq!(changes[0].position.volume, 1_000_000);
        assert_eq!(changes[0].balance, Some((0.0, 0.0)));
        bytes[9..13].copy_from_slice(&1i32.to_le_bytes());
        let Update::Positions(changes) = decode_update(&bytes).unwrap() else {
            panic!()
        };
        assert_eq!(changes[0].balance, None);
        bytes.pop();
        assert!(decode_update(&bytes).is_err());
    }
    #[test]
    fn close_by_keeps_execution_and_position_arrays_separate() {
        let mut bytes = vec![0; 1765];
        bytes[0] = 33;
        bytes[1..5].copy_from_slice(&1i32.to_le_bytes());
        bytes.truncate(1757);
        bytes.extend(1i32.to_le_bytes());
        let mut deal = [0; 672];
        deal[..8].copy_from_slice(&101u64.to_le_bytes());
        deal[288..296].copy_from_slice(&202u64.to_le_bytes());
        bytes.extend(deal);
        bytes.extend(1i32.to_le_bytes());
        let mut position = [0; 672];
        position[..8].copy_from_slice(&202u64.to_le_bytes());
        bytes.extend(position);
        let Update::Positions(changes) = decode_update(&bytes).unwrap() else {
            panic!()
        };
        assert_eq!(changes[0].related_deals[0].ticket, 101);
        assert_eq!(changes[0].related_positions[0].ticket, 202);
        assert_eq!(changes[0].related_positions[0].volume, 0);
        bytes.pop();
        assert!(decode_update(&bytes).is_err());
    }
}
