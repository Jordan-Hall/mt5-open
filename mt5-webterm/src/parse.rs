//! Account, symbol, quote, position, deal and candle decoders.

use crate::protocol::{from_utf16_le, LOT_MULTIPLIER, ORDER_REC_SIZE, QUOTE_SIZE};
use flate2::read::ZlibDecoder;
use std::collections::HashMap;
use std::io::Read;

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
    pub commission: f64,
    pub swap: f64,
    /// Seconds, as the server sends them.
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
    let mut equity = f64_at(take(&mut o, 8));
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
    if equity == 0.0 {
        equity = balance;
    }
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

pub fn parse_symbols(body: &[u8]) -> HashMap<String, Symbol> {
    let compressed = if body.len() > 4 { &body[4..] } else { return HashMap::new() };
    let mut raw = Vec::new();
    if ZlibDecoder::new(compressed).read_to_end(&mut raw).is_err() {
        let mut dec = flate2::Decompress::new(false);
        let mut out = vec![0u8; compressed.len().saturating_mul(8).max(64)];
        let _ = dec.decompress(compressed, &mut out, flate2::FlushDecompress::Finish);
        raw = out;
    }
    if raw.len() < 4 {
        return HashMap::new();
    }
    let count = u32::from_le_bytes(raw[0..4].try_into().unwrap()) as usize;
    let mut o = 4usize;
    let mut map = HashMap::new();
    for _ in 0..count {
        if o + 64 + 128 + 4 + 4 > raw.len() {
            break;
        }
        let name = from_utf16_le(&raw[o..o + 64]);
        o += 64;
        o += 128;
        let digits = u32_at(&raw[o..]);
        o += 4;
        let id = u32_at(&raw[o..]);
        o += 4;
        o += 256;
        let _calc = u32_at(&raw[o..]);
        o += 4;
        o += 64;
        o += 2;
        if name.is_empty() {
            continue;
        }
        let point = if digits > 0 { 10f64.powi(-(digits as i32)) } else { 0.01 };
        map.insert(
            name.clone(),
            Symbol {
                name,
                id,
                digits,
                point,
                tick_size: point,
                volume_step: 0.01,
                min_volume: 0.01,
                max_volume: 100.0,
                ..Default::default()
            },
        );
    }
    map
}

pub fn parse_quotes(body: &[u8], symbols: &HashMap<String, Symbol>) -> Vec<Quote> {
    let mut out = Vec::new();
    let mut p = 0;
    let by_id: HashMap<u32, &Symbol> = symbols.values().map(|s| (s.id, s)).collect();
    while p + QUOTE_SIZE <= body.len() {
        let rec = &body[p..p + QUOTE_SIZE];
        let id = u32_at(rec);
        let raw_bid = f64_at(&rec[12..]);
        let raw_ask = f64_at(&rec[20..]);
        p += QUOTE_SIZE;
        let Some(sym) = by_id.get(&id) else { continue };
        let div = 10f64.powi(sym.digits as i32);
        out.push(Quote {
            symbol: sym.name.clone(),
            symbol_id: id,
            bid: raw_bid / div,
            ask: raw_ask / div,
            time_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0),
        });
    }
    out
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
    let mut o = 4 + pos_cnt * pos_size();
    if o + 4 > body.len() {
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

/// Bytes in one web-terminal deal record: i64 ticket, w64 external id, i64
/// order, u32 time, u32, w64 symbol, u32, u32 type, 4 x f64 (price first),
/// u64 volume, 5 x f64 (profit, _, _, commission, swap), 2 x i64, w64 comment,
/// f64, 3 x u32, 2 x i32, f64.
pub const DEAL_REC_SIZE: usize = 356;

pub fn parse_deals(body: &[u8]) -> Vec<Deal> {
    if body.len() < 4 {
        return vec![];
    }
    let count = u32_at(body) as usize;
    // The previous walk stepped 364 bytes per record, so every deal after the
    // first was read from the wrong place. A newer server may append fields;
    // when the body divides evenly into larger records, step by that.
    let records = body.len() - 4;
    let size = match count {
        0 => return vec![],
        n if records % n == 0 && records / n >= DEAL_REC_SIZE => records / n,
        _ => DEAL_REC_SIZE,
    };
    body[4..]
        .chunks_exact(size)
        .take(count)
        .map(|rec| Deal {
            ticket: i64_at(rec),
            order: i64_at(&rec[72..]),
            time: u32_at(&rec[80..]) as i64,
            symbol: from_utf16_le(&rec[88..152]),
            side: u32_at(&rec[156..]),
            price: f64_at(&rec[160..]),
            volume: u64_at(&rec[192..]) as f64 / LOT_MULTIPLIER,
            profit: f64_at(&rec[200..]),
            commission: f64_at(&rec[224..]),
            swap: f64_at(&rec[232..]),
            comment: from_utf16_le(&rec[256..320]),
        })
        .collect()
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
mod tests {
    use super::*;
    use crate::protocol::utf16_le;

    /// One synthetic record laid out field by field from the deal schema, with
    /// a distinct value in every slot so a misread offset shows.
    fn deal_record(ticket: i64, time: u32, symbol: &str, side: u32, comment: &str) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend(ticket.to_le_bytes());
        r.extend(utf16_le("ext", 64));
        r.extend((ticket + 1).to_le_bytes()); // order
        r.extend(time.to_le_bytes());
        r.extend(7u32.to_le_bytes());
        r.extend(utf16_le(symbol, 64));
        r.extend(9u32.to_le_bytes());
        r.extend(side.to_le_bytes());
        for v in [2650.5f64, 2600.0, 2700.0, 11.0] {
            r.extend(v.to_le_bytes());
        }
        r.extend(2_000_000u64.to_le_bytes()); // 0.02 lots
        for v in [12.34f64, 13.0, 14.0, -0.7, -1.25] {
            r.extend(v.to_le_bytes()); // profit, _, _, commission, swap
        }
        r.extend(555i64.to_le_bytes());
        r.extend(666i64.to_le_bytes());
        r.extend(utf16_le(comment, 64));
        r.extend(17.0f64.to_le_bytes());
        for v in [18u32, 19, 20] {
            r.extend(v.to_le_bytes());
        }
        for v in [21i32, 22] {
            r.extend(v.to_le_bytes());
        }
        r.extend(23.0f64.to_le_bytes());
        assert_eq!(r.len(), DEAL_REC_SIZE);
        r
    }

    #[test]
    fn every_deal_in_a_history_reply_is_read_from_its_own_record() {
        let mut body = 2u32.to_le_bytes().to_vec();
        body.extend(deal_record(1001, 1_758_800_000, "XAUUSD", 0, "first"));
        body.extend(deal_record(2002, 1_758_803_600, "BTCUSD", 1, "second"));
        let deals = parse_deals(&body);
        assert_eq!(deals.len(), 2);
        let (a, b) = (&deals[0], &deals[1]);
        assert_eq!((a.ticket, a.order, a.time, a.symbol.as_str(), a.side), (1001, 1002, 1_758_800_000, "XAUUSD", 0));
        assert_eq!((a.price, a.volume, a.profit, a.commission, a.swap), (2650.5, 0.02, 12.34, -0.7, -1.25));
        assert_eq!(a.comment, "first");
        // The second record is where a wrong stride shows.
        assert_eq!((b.ticket, b.order, b.time, b.symbol.as_str(), b.side), (2002, 2003, 1_758_803_600, "BTCUSD", 1));
        assert_eq!(b.comment, "second");
    }

    #[test]
    fn a_short_or_empty_deal_reply_yields_what_is_whole() {
        assert!(parse_deals(&[]).is_empty());
        assert!(parse_deals(&0u32.to_le_bytes()).is_empty());
        let mut body = 2u32.to_le_bytes().to_vec();
        body.extend(deal_record(1, 1, "EURUSD", 0, ""));
        body.extend([0u8; 100]);
        assert_eq!(parse_deals(&body).len(), 1);
    }
}
