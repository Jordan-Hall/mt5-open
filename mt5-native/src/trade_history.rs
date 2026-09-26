//! Uncached order and deal history, including broker bucket removals.
use crate::{
    error::{ProtocolError, Result},
    reader::Reader,
    records::{Deal, Order},
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum TradeHistory {
    Orders(Vec<Order>),
    Deals(Vec<Deal>),
}

pub fn decode_trade_history(bytes: &[u8]) -> Result<TradeHistory> {
    let mut r = Reader::new(bytes);
    let subtype = r.byte()?;
    if subtype != 32 && subtype != 33 {
        return Err(ProtocolError::new("unknown trade history subtype"));
    }
    let _watermark = r.i32()?;
    let mut orders = BTreeMap::new();
    let mut deals = BTreeMap::new();
    for _ in 0..r.count(12)? {
        r.u64()?;
        let action = r.i32()?;
        if action == 1 || subtype == 32 && action == 4 {
            continue;
        }
        if action == 0 {
            for _ in 0..r.count(8)? {
                let ticket = r.u64()?;
                orders.remove(&ticket);
                deals.remove(&ticket);
            }
        } else {
            r.i32()?;
        }
        for _ in 0..r.count(if subtype == 32 { 636 } else { 672 })? {
            if subtype == 32 {
                let order = Order::parse(r.take(636)?)?;
                orders.insert(order.ticket, order);
            } else {
                let deal = Deal::parse(r.take(672)?)?;
                deals.insert(deal.ticket, deal);
            }
        }
        if action == 0 {
            r.take(16)?;
        }
    }
    if !r.remaining.is_empty() {
        return Err(ProtocolError::new("trailing trade history bytes"));
    }
    Ok(if subtype == 32 {
        TradeHistory::Orders(orders.into_values().collect())
    } else {
        TradeHistory::Deals(deals.into_values().collect())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_history_bucket_removes_replaced_deals() {
        let mut bytes = vec![33];
        bytes.extend(27i32.to_le_bytes());
        bytes.extend(2i32.to_le_bytes());
        bytes.extend(1u64.to_le_bytes());
        bytes.extend(2i32.to_le_bytes());
        bytes.extend(0i32.to_le_bytes());
        bytes.extend(1i32.to_le_bytes());
        let mut deal = [0; 672];
        deal[..8].copy_from_slice(&101u64.to_le_bytes());
        bytes.extend(deal);
        bytes.extend(2u64.to_le_bytes());
        bytes.extend(0i32.to_le_bytes());
        bytes.extend(1i32.to_le_bytes());
        bytes.extend(101u64.to_le_bytes());
        bytes.extend(1i32.to_le_bytes());
        deal[..8].copy_from_slice(&102u64.to_le_bytes());
        deal[192..200].copy_from_slice(&1.25f64.to_le_bytes());
        deal[200..208].copy_from_slice(&9.0f64.to_le_bytes());
        bytes.extend(deal);
        bytes.extend([0; 16]);
        let TradeHistory::Deals(deals) = decode_trade_history(&bytes).unwrap() else {
            panic!()
        };
        assert_eq!(deals.len(), 1);
        assert_eq!(deals[0].ticket, 102);
        assert_eq!(deals[0].price_open, 1.25);
        bytes.push(0);
        assert!(decode_trade_history(&bytes).is_err());
    }
}
