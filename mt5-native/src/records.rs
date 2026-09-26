//! Fixed broker records for modern servers. Offsets are local to each record.

use crate::error::{ProtocolError, Result};

pub(crate) struct Record<'a>(&'a [u8]);

impl<'a> Record<'a> {
    pub(crate) fn new(bytes: &'a [u8], size: usize) -> Result<Self> {
        if bytes.len() != size {
            return Err(ProtocolError::new(format!(
                "record length {}, expected {size}",
                bytes.len()
            )));
        }
        Ok(Self(bytes))
    }
    pub(crate) fn i32(&self, at: usize) -> i32 {
        i32::from_le_bytes(self.0[at..at + 4].try_into().unwrap())
    }
    pub(crate) fn u64(&self, at: usize) -> u64 {
        u64::from_le_bytes(self.0[at..at + 8].try_into().unwrap())
    }
    pub(crate) fn i64(&self, at: usize) -> i64 {
        self.u64(at) as i64
    }
    pub(crate) fn f64(&self, at: usize) -> f64 {
        f64::from_bits(self.u64(at))
    }
    pub(crate) fn text(&self, at: usize, size: usize) -> String {
        let units: Vec<_> = self.0[at..at + size]
            .chunks_exact(2)
            .map(|v| u16::from_le_bytes([v[0], v[1]]))
            .take_while(|v| *v != 0)
            .collect();
        String::from_utf16_lossy(&units)
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct AccountTerms {
    pub currency: String,
    pub currency_digits: i32,
    pub accounting_method: i32,
    pub margin_mode: i32,
}

impl AccountTerms {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let r = Record::new(bytes, 4228)?;
        Ok(Self {
            currency: r.text(3080, 64),
            currency_digits: r.i32(3144),
            accounting_method: r.i32(3552),
            margin_mode: r.i32(3564),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Symbol {
    pub id: i32,
    pub name: String,
    pub digits: i32,
    pub point: f64,
    pub contract_size: f64,
    pub tick_size: f64,
    pub tick_value: f64,
    pub profit_currency: String,
    pub base_currency: String,
    pub margin_currency: String,
    pub calculation_mode: i32,
    pub execution_mode: i32,
    pub trade_mode: i32,
    pub filling_flags: i32,
    pub order_flags: i32,
    pub volume_min: u64,
    pub volume_max: u64,
    pub volume_step: u64,
    pub stops_level: i32,
    pub freeze_level: i32,
    pub initial_margin: f64,
    pub maintenance_margin: f64,
    pub margin_rates: [f64; 8],
    pub maintenance_margin_rates: [f64; 8],
    pub expiration_flags: i32,
    pub margin_flags: u32,
    pub hedged_margin: f64,
}

impl Symbol {
    pub fn parse(info: &[u8], group: &[u8]) -> Result<Self> {
        let r = Record::new(info, 1952)?;
        let g = Record::new(group, 1228)?;
        let digits = r.i32(1424);
        if !(0..=12).contains(&digits) {
            return Err(ProtocolError::new("invalid symbol digits"));
        }
        Ok(Self {
            id: r.i32(1444),
            name: r.text(8, 64),
            digits,
            point: r.f64(1428),
            contract_size: r.f64(1648),
            tick_size: r.f64(1640),
            tick_value: r.f64(1632),
            base_currency: r.text(1288, 32),
            profit_currency: r.text(1320, 32),
            margin_currency: r.text(1352, 32),
            calculation_mode: r.i32(1660),
            execution_mode: g.i32(316),
            trade_mode: g.i32(304),
            filling_flags: g.i32(320),
            order_flags: g.i32(328),
            volume_min: g.u64(744),
            volume_max: g.u64(752),
            volume_step: g.u64(760),
            stops_level: g.i32(308),
            freeze_level: g.i32(312),
            initial_margin: g.f64(836),
            maintenance_margin: g.f64(844),
            margin_rates: std::array::from_fn(|i| g.f64(852 + 8 * i)),
            maintenance_margin_rates: std::array::from_fn(|i| g.f64(916 + 8 * i)),
            expiration_flags: g.i32(324),
            margin_flags: g.i32(832) as u32,
            hedged_margin: g.f64(988),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Order {
    pub ticket: u64,
    pub symbol: String,
    pub kind: i32,
    pub state: i32,
    pub time: i64,
    pub history_stamp: u64,
    pub time_done: i64,
    pub expiration: i64,
    pub price: f64,
    pub stop_limit: f64,
    pub sl: f64,
    pub tp: f64,
    pub volume: u64,
    pub volume_initial: u64,
    pub magic: i64,
    pub comment: String,
}

impl Order {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let r = Record::new(bytes, 636)?;
        Ok(Self {
            ticket: r.u64(0),
            symbol: r.text(88, 64),
            kind: r.i32(184),
            state: r.i32(268),
            time: r.i64(160),
            history_stamp: r.u64(152),
            time_done: r.i64(176),
            expiration: r.i64(168),
            price: r.f64(212),
            stop_limit: r.f64(220),
            sl: r.f64(236),
            tp: r.f64(244),
            volume: r.u64(260),
            volume_initial: r.u64(252),
            magic: r.i64(272),
            comment: r.text(288, 64),
        })
    }
}

/// The same record carries positions in synchronization and executions in history.
/// Its enclosing message determines which meaning applies.
#[derive(Debug, Clone, PartialEq)]
pub struct Deal {
    pub ticket: u64,
    pub order: u64,
    pub position: u64,
    pub symbol: String,
    pub kind: i32,
    pub entry: i32,
    pub time: i64,
    pub time_ms: i64,
    /// Position entry price in current state; execution price in deal history.
    pub price_open: f64,
    pub price: f64,
    pub sl: f64,
    pub tp: f64,
    pub volume: u64,
    pub profit: f64,
    pub commission: f64,
    pub swap: f64,
    pub magic: i64,
    pub comment: String,
    pub profit_rate: f64,
    pub margin_rate: f64,
    pub contract_size: f64,
    pub money_digits: i32,
}

impl Deal {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let r = Record::new(bytes, 672)?;
        Ok(Self {
            ticket: r.u64(0),
            order: r.u64(88),
            position: r.u64(288),
            symbol: r.text(120, 64),
            kind: r.i32(184),
            entry: r.i32(188),
            time: r.i64(104),
            time_ms: r.i64(548),
            price_open: r.f64(192),
            price: r.f64(200),
            sl: r.f64(208),
            tp: r.f64(216),
            volume: r.u64(224),
            profit: r.f64(232),
            commission: r.f64(256),
            swap: r.f64(272),
            magic: r.i64(280),
            comment: r.text(296, 64),
            profit_rate: r.f64(240),
            margin_rate: r.f64(248),
            contract_size: r.f64(360),
            money_digits: r.i32(372),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TradeResult {
    pub request_id: i32,
    pub status: i32,
    pub deal: u64,
    pub ticket: u64,
    pub volume: u64,
    pub price: f64,
    pub comment: String,
}

impl TradeResult {
    pub fn decode_update(bytes: &[u8]) -> Result<Vec<Self>> {
        crate::trade::parse_trade_update_35(bytes)?
            .records
            .into_iter()
            .map(|update| {
                let r = Record::new(&update.result, 260)?;
                Ok(Self {
                    request_id: i32::from_le_bytes(update.request[..4].try_into().unwrap()),
                    status: r.i32(0),
                    deal: r.u64(4),
                    ticket: r.u64(12),
                    volume: r.u64(20),
                    price: r.f64(28),
                    comment: r.text(68, 64),
                })
            })
            .collect()
    }
    pub fn is_final(&self) -> bool {
        self.status >= 10004
    }
    pub fn is_success(&self) -> bool {
        matches!(self.status, 10008..=10010)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn execution_result_keeps_deal_and_order_identifiers_distinct() {
        let mut bytes = vec![0; 1217];
        bytes[0] = 35;
        bytes[1..5].copy_from_slice(&1i32.to_le_bytes());
        bytes[157..161].copy_from_slice(&42i32.to_le_bytes());
        bytes[957..961].copy_from_slice(&10009i32.to_le_bytes());
        bytes[961..969].copy_from_slice(&100u64.to_le_bytes());
        bytes[969..977].copy_from_slice(&200u64.to_le_bytes());
        let r = TradeResult::decode_update(&bytes).unwrap();
        assert_eq!((r[0].request_id, r[0].deal, r[0].ticket), (42, 100, 200));
        assert!(r[0].is_success());
    }
    #[test]
    fn filled_order_keeps_initial_volume_and_zero_remaining() {
        let mut record = [0; 636];
        record[252..260].copy_from_slice(&2_000_000u64.to_le_bytes());
        record[176..184].copy_from_slice(&1234i64.to_le_bytes());
        let order = Order::parse(&record).unwrap();
        assert_eq!(order.volume_initial, 2_000_000);
        assert_eq!(order.volume, 0);
        assert_eq!(order.time_done, 1234);
    }
}
