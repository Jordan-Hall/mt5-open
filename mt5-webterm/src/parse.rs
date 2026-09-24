//! Account, symbol, quote, position, deal and candle decoders.

use crate::protocol::{from_utf16_le, LOT_MULTIPLIER, ORDER_REC_SIZE, QUOTE_SIZE};
use flate2::{Decompress, FlushDecompress, Status};
use std::collections::HashMap;


#[derive(Debug, Clone, Default)]
pub struct Account {
    pub login: u64,
    pub balance: f64,
    pub equity: f64,
    pub margin: f64,
    pub currency: String,
    pub server: String,
    pub leverage: u16,
    pub profit: f64,
}

#[derive(Debug, Clone, Default)]
pub struct Symbol {
    pub name: String,
    pub id: u32,
    pub digits: u32,
    pub point: f64,
    pub tick_size: f64,
    pub tick_value: f64,
    pub contract_size: f64,
    pub min_volume: f64,
    pub volume_step: f64,
    pub max_volume: f64,
}

#[derive(Debug, Clone, Default)]
pub struct Quote {
    pub symbol: String,
    pub symbol_id: u32,
    pub bid: f64,
    pub ask: f64,
    pub time_ms: i64,
}

#[derive(Debug, Clone, Default)]
pub struct Position {
    pub ticket: i64,
    /// MT5's magic number: which engine placed this. Offset 172 in the record,
    /// confirmed against trades of known magic on a live account.
    pub magic: i64,
    pub symbol: String,
    pub side: u32,
    pub volume: f64,
    pub price: f64,
    pub sl: f64,
    pub tp: f64,
    pub profit: f64,
    pub swap: f64,
    pub commission: f64,
    pub time: i64,
    pub comment: String,
}

#[derive(Debug, Clone, Default)]
pub struct Order {
    pub ticket: i64,
    /// MT5's magic number; offset 224 in the order record.
    pub magic: i64,
    pub symbol: String,
    pub kind: u32,
    pub volume: f64,
    pub price: f64,
    pub sl: f64,
    pub tp: f64,
    pub time: i64,
}

#[derive(Debug, Clone, Default)]
pub struct Deal {
    pub ticket: i64,
    pub order: i64,
    pub symbol: String,
    pub side: u32,
    pub volume: f64,
    pub price: f64,
    pub profit: f64,
    pub time: i64,
    pub comment: String,
}

#[derive(Debug, Clone, Default)]
pub struct Candle {
    pub time: i64,
    pub open: f64,
    pub high: f64,
    pub low: f64,
    pub close: f64,
    pub volume: f64,
}

pub fn parse_account(body: &[u8], login: u64, server: &str) -> Account {
    // FL_SCHEMA: u8, i32, i32, f64, f64, w64, u32, u32, w256, u16, w128, ...
    let mut o = 0usize;
    let take = |o: &mut usize, n: usize| -> &[u8] {
        let s = *o;
        *o = (*o + n).min(body.len());
        &body[s..*o]
    };
    let _ = take(&mut o, 1);
    let _ = take(&mut o, 4);
    let _ = take(&mut o, 4);
    let balance = f64_at(take(&mut o, 8));
    let equity = f64_at(take(&mut o, 8));
    let currency = from_utf16_le(take(&mut o, 64));
    let _ = take(&mut o, 4);
    let _ = take(&mut o, 4);
    let _ = take(&mut o, 256);
    let leverage = u16_at(take(&mut o, 2));
    let parsed_server = from_utf16_le(take(&mut o, 128));
    let _ = take(&mut o, 256);
    let _ = take(&mut o, 4);
    let _ = take(&mut o, 1);
    let _ = take(&mut o, 4);
    let _ = take(&mut o, 4);
    let profit = f64_at(take(&mut o, 8));
    let margin = f64_at(take(&mut o, 8));
    Account {
        login,
        balance,
        equity,
        margin,
        currency,
        server: if parsed_server.is_empty() { server.to_string() } else { parsed_server },
        leverage,
        profit,
    }
}

fn f64_at(b: &[u8]) -> f64 {
    if b.len() < 8 {
        return 0.0;
    }
    f64::from_le_bytes(b[..8].try_into().unwrap())
}
fn u16_at(b: &[u8]) -> u16 {
    if b.len() < 2 {
        return 0;
    }
    u16::from_le_bytes(b[..2].try_into().unwrap())
}
fn u32_at(b: &[u8]) -> u32 {
    if b.len() < 4 {
        return 0;
    }
    u32::from_le_bytes(b[..4].try_into().unwrap())
}
fn i64_at(b: &[u8]) -> i64 {
    if b.len() < 8 {
        return 0;
    }
    i64::from_le_bytes(b[..8].try_into().unwrap())
}
fn u64_at(b: &[u8]) -> u64 {
    if b.len() < 8 {
        return 0;
    }
    u64::from_le_bytes(b[..8].try_into().unwrap())
}

pub const SYMBOL_REC_SIZE: usize = 526;
pub const DEAL_REC_SIZE: usize = 356;
pub const ACCOUNT_MIN_SIZE: usize = 768;
pub const MAX_INFLATED_BYTES: usize = 16 * 1024 * 1024;

fn inflate_symbols(data: &[u8], zlib: bool, limit: usize) -> Result<Vec<u8>, String> {
    let mut dec = Decompress::new(zlib);
    let mut output = Vec::new();
    let mut scratch = [0u8; 8192];
    loop {
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let offset = usize::try_from(before_in).map_err(|_| "compressed offset overflow")?;
        let status = dec.decompress(&data[offset..], &mut scratch, FlushDecompress::None)
            .map_err(|_| "invalid compressed symbols")?;
        let written = (dec.total_out() - before_out) as usize;
        if written > limit.saturating_sub(output.len()) {
            return Err("symbol inflation budget exceeded".into());
        }
        output.extend_from_slice(&scratch[..written]);
        if status == Status::StreamEnd {
            if dec.total_in() as usize != data.len() {
                return Err("trailing compressed symbol bytes".into());
            }
            return Ok(output);
        }
        if before_in == dec.total_in() && written == 0 {
            return Err("incomplete compressed symbols".into());
        }
    }
}

/// Strict network-facing decoder. Both decompression and the full record
/// stride are bounded before any fields are read.
pub fn try_parse_symbols(body: &[u8]) -> Result<HashMap<String, Symbol>, String> {
    let compressed = body.get(4..).ok_or("truncated symbol header")?;
    let raw = inflate_symbols(compressed, true, MAX_INFLATED_BYTES)
        .or_else(|_| inflate_symbols(compressed, false, MAX_INFLATED_BYTES))?;
    let records = counted_records(&raw, SYMBOL_REC_SIZE)?;
    let mut map = HashMap::with_capacity(records.len() / SYMBOL_REC_SIZE);
    for record in records.chunks_exact(SYMBOL_REC_SIZE) {
        let name = from_utf16_le(&record[..64]);
        let digits = u32_at(&record[192..]);
        let id = u32_at(&record[196..]);
        if name.is_empty() || digits > 18 {
            return Err("invalid symbol name or digits".into());
        }
        let point = 10f64.powi(-(digits as i32));
        map.insert(name.clone(), Symbol {
            name, id, digits, point, tick_size: point,
            // Volume/contract limits are unknown, not guessed broker settings.
            ..Default::default()
        });
    }
    Ok(map)
}

/// Compatibility decoder. Prefer `try_parse_symbols` when failure must not
/// become an empty symbol set.
pub fn parse_symbols(body: &[u8]) -> HashMap<String, Symbol> {
    try_parse_symbols(body).unwrap_or_default()
}

fn counted_records(body: &[u8], stride: usize) -> Result<&[u8], String> {
    let count = body.get(..4).ok_or("missing record count")?;
    let count = u32_at(count) as usize;
    let bytes = count.checked_mul(stride).ok_or("record count overflow")?;
    let records = body.get(4..).ok_or("missing records")?;
    records.get(..bytes).ok_or_else(|| "truncated record array".into())
}

pub fn try_parse_account(body: &[u8], login: u64, server: &str) -> Result<Account, String> {
    if body.len() < ACCOUNT_MIN_SIZE {
        return Err("truncated account record".into());
    }
    let account = parse_account(body, login, server);
    if [account.balance, account.equity, account.margin, account.profit].iter().any(|v| !v.is_finite()) {
        return Err("non-finite account value".into());
    }
    Ok(account)
}

pub fn try_parse_positions_and_orders(body: &[u8]) -> Result<(Vec<Position>, Vec<Order>), String> {
    let positions = counted_records(body, pos_size())?;
    let order_body = body.get(4 + positions.len()..).ok_or("missing order array")?;
    counted_records(order_body, ORDER_REC_SIZE)?;
    Ok((parse_positions(body), parse_orders(body)))
}

pub fn try_parse_deals(body: &[u8]) -> Result<Vec<Deal>, String> {
    counted_records(body, DEAL_REC_SIZE)?;
    Ok(parse_deals(body))
}

pub fn try_parse_candles(body: &[u8]) -> Result<Vec<Candle>, String> {
    if body.len() % 48 != 0 {
        return Err("truncated candle record".into());
    }
    Ok(parse_candles(body))
}

/// Symbol routing/price scaling is built once, not for every incoming tick.
#[derive(Default)]
pub struct QuoteDecoder {
    by_id: HashMap<u32, (String, f64)>,
}

impl QuoteDecoder {
    pub fn new(symbols: &HashMap<String, Symbol>) -> Self {
        Self { by_id: symbols.values().filter(|s| s.digits <= 18)
            .map(|s| (s.id, (s.name.clone(), 10f64.powi(s.digits as i32)))).collect() }
    }

    pub fn decode(&self, body: &[u8]) -> Result<Vec<Quote>, String> {
        if body.len() % QUOTE_SIZE != 0 {
            return Err("truncated quote record".into());
        }
        let time_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis().min(i64::MAX as u128) as i64).unwrap_or(0);
        let mut output = Vec::with_capacity(body.len() / QUOTE_SIZE);
        for record in body.chunks_exact(QUOTE_SIZE) {
            let id = u32_at(record);
            let Some((name, scale)) = self.by_id.get(&id) else { continue };
            let bid = f64_at(&record[12..]) / scale;
            let ask = f64_at(&record[20..]) / scale;
            if !bid.is_finite() || !ask.is_finite() || bid < 0.0 || ask < 0.0 {
                return Err("invalid quote price".into());
            }
            output.push(Quote { symbol: name.clone(), symbol_id: id, bid, ask, time_ms });
        }
        Ok(output)
    }
}

pub fn parse_quotes(body: &[u8], symbols: &HashMap<String, Symbol>) -> Vec<Quote> {
    QuoteDecoder::new(symbols).decode(body).unwrap_or_default()
}

/// POS_SCHEMA walk matching the Python client.
pub fn pos_size() -> usize {
    8 + 8 + 4 + 4 + 64 + 4 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 64 + 8 + 4 + 4 + 4 + 64 + 4 + 4
}

pub fn parse_positions(body: &[u8]) -> Vec<Position> {
    if body.len() < 4 {
        return vec![];
    }
    let pos_cnt = u32_at(body) as usize;
    let size = pos_size();
    let mut o = 4usize;
    let mut out = Vec::new();
    for _ in 0..pos_cnt {
        if o + size > body.len() {
            break;
        }
        let rec = &body[o..o + size];
        let ticket = i64_at(rec);
        let time = u32_at(&rec[16..]) as i64;
        let symbol = from_utf16_le(&rec[24..88]);
        let side = u32_at(&rec[88..]);
        let price = f64_at(&rec[92..]);
        let sl = f64_at(&rec[108..]);
        let tp = f64_at(&rec[116..]);
        let volume = u64_at(&rec[124..]) as f64 / LOT_MULTIPLIER;
        let profit = f64_at(&rec[132..]);
        let commission = f64_at(&rec[156..]);
        let swap = f64_at(&rec[164..]);
        let comment = from_utf16_le(&rec[188..252]);
        let magic = u64_at(&rec[172..]) as i64;
        out.push(Position { ticket, magic, symbol, side, volume, price, sl, tp, profit, swap, commission, time, comment });
        o += size;
    }
    out
}

pub fn parse_orders(body: &[u8]) -> Vec<Order> {
    if body.len() < 4 {
        return vec![];
    }
    let pos_cnt = u32_at(body) as usize;
    let Some(mut o) = pos_cnt.checked_mul(pos_size()).and_then(|n| n.checked_add(4)) else {
        return vec![];
    };
    if o > body.len().saturating_sub(4) {
        return vec![];
    }
    let order_cnt = u32_at(&body[o..]) as usize;
    o += 4;
    let mut out = Vec::new();
    for _ in 0..order_cnt {
        if o + ORDER_REC_SIZE > body.len() {
            break;
        }
        let rec = &body[o..o + ORDER_REC_SIZE];
        out.push(Order {
            ticket: i64_at(rec),
            magic: u64_at(&rec[224..]) as i64,
            symbol: from_utf16_le(&rec[72..136]),
            kind: u32_at(&rec[148..]),
            volume: u32_at(&rec[204..]) as f64 / LOT_MULTIPLIER,
            price: f64_at(&rec[336..]),
            sl: 0.0,
            tp: 0.0,
            time: 0,
        });
        o += ORDER_REC_SIZE;
    }
    out
}

pub fn parse_deals(body: &[u8]) -> Vec<Deal> {
    let Ok(records) = counted_records(body, DEAL_REC_SIZE) else { return vec![] };
    records.chunks_exact(DEAL_REC_SIZE).map(|record| Deal {
        ticket: i64_at(record),
        order: i64_at(&record[72..]),
        symbol: from_utf16_le(&record[88..152]),
        side: u32_at(&record[156..]),
        price: f64_at(&record[160..]),
        volume: u64_at(&record[192..]) as f64 / LOT_MULTIPLIER,
        profit: f64_at(&record[200..]),
        time: 0,
        comment: from_utf16_le(&record[256..320]),
    }).collect()
}

pub fn parse_candles(body: &[u8]) -> Vec<Candle> {
    let mut out = Vec::new();
    let mut o = 0;
    while o + 48 <= body.len() {
        out.push(Candle {
            time: i32::from_le_bytes(body[o..o + 4].try_into().unwrap()) as i64,
            open: f64_at(&body[o + 4..]),
            high: f64_at(&body[o + 12..]),
            low: f64_at(&body[o + 20..]),
            close: f64_at(&body[o + 28..]),
            volume: i64_at(&body[o + 36..]) as f64,
        });
        o += 48;
    }
    out
}

pub fn parse_trade_event(body: &[u8]) -> Option<(u32, i64, i64, i64, f64, f64)> {
    let ap = 4 + crate::protocol::OP_SIZE;
    if body.len() < ap + 36 {
        return None;
    }
    let retcode = u32_at(&body[ap..]);
    let deal = i64_at(&body[ap + 4..]);
    let order = i64_at(&body[ap + 12..]);
    let volume = i64_at(&body[ap + 20..]);
    let price = f64_at(&body[ap + 28..]);
    Some((retcode, deal, order, volume, price, volume as f64 / LOT_MULTIPLIER))
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    use std::io::Write;
    use flate2::{write::ZlibEncoder, Compression};

    fn compressed(raw: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(raw).unwrap();
        let mut body = vec![0; 4];
        body.extend(encoder.finish().unwrap());
        body
    }

    #[test]
    fn every_truncated_symbol_record_is_rejected_without_panicking() {
        for len in 0..SYMBOL_REC_SIZE {
            let mut raw = 1u32.to_le_bytes().to_vec();
            raw.resize(4 + len, 0);
            assert!(try_parse_symbols(&compressed(&raw)).is_err(), "len {len}");
        }
    }

    #[test]
    fn every_truncated_deal_record_is_rejected_without_panicking() {
        for len in 0..DEAL_REC_SIZE {
            let mut body = 1u32.to_le_bytes().to_vec();
            body.resize(4 + len, 0);
            assert!(try_parse_deals(&body).is_err(), "len {len}");
            assert!(parse_deals(&body).is_empty());
        }
    }

    #[test]
    fn decompression_rejects_incomplete_trailing_and_over_budget_streams() {
        let body = compressed(&[0; 1024]);
        let data = &body[4..];
        assert!(inflate_symbols(data, true, 1023).is_err());
        assert_eq!(inflate_symbols(data, true, 1024).unwrap(), vec![0; 1024]);
        for len in 0..data.len() {
            assert!(inflate_symbols(&data[..len], true, 1024).is_err());
        }
        let mut trailing = data.to_vec(); trailing.push(0);
        assert!(inflate_symbols(&trailing, true, 1024).is_err());
    }

    #[test]
    fn account_and_book_truncation_are_errors_not_empty_successes() {
        for len in 0..ACCOUNT_MIN_SIZE {
            assert!(try_parse_account(&vec![0; len], 1, "demo").is_err());
        }
        assert!(try_parse_positions_and_orders(&[0; 4]).is_err());
        let mut body = u32::MAX.to_le_bytes().to_vec(); body.resize(12, 0);
        assert!(try_parse_positions_and_orders(&body).is_err());
        assert_eq!(try_parse_positions_and_orders(&[0; 8]).unwrap().0.len(), 0);
        assert_eq!(try_parse_account(&vec![0; ACCOUNT_MIN_SIZE], 1, "demo").unwrap().equity, 0.0);
    }

    #[test]
    fn indexed_quotes_match_compatibility_decoder_and_reject_nonfinite_prices() {
        let symbol = Symbol { name: "EURUSD".into(), id: 7, digits: 5, ..Default::default() };
        let symbols = HashMap::from([(symbol.name.clone(), symbol)]);
        let mut body = vec![0; QUOTE_SIZE];
        body[..4].copy_from_slice(&7u32.to_le_bytes());
        body[12..20].copy_from_slice(&123456.0f64.to_le_bytes());
        body[20..28].copy_from_slice(&123457.0f64.to_le_bytes());
        let decoder = QuoteDecoder::new(&symbols);
        let quotes = decoder.decode(&body).unwrap();
        assert_eq!(quotes[0].bid, 1.23456);
        assert_eq!(quotes[0].ask, parse_quotes(&body, &symbols)[0].ask);
        assert!(decoder.decode(&body[..49]).is_err());
        body[12..20].copy_from_slice(&f64::NAN.to_le_bytes());
        assert!(decoder.decode(&body).is_err());
    }
}
