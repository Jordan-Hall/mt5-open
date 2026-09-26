//! Account, symbol, quote, position, deal and candle decoders.
//!
//! Times in these records are the server's clock, as sent. The account frame
//! carries the server's offset from UTC (`Account::timezone_shift_seconds`);
//! [`crate::Session`] converts to UTC at its edge.

use crate::protocol::{from_utf16_le, LOT_MULTIPLIER, ORDER_REC_SIZE, QUOTE_SIZE};
use flate2::read::ZlibDecoder;
use std::collections::HashMap;
use std::io::Read;

#[derive(Debug, Clone, Default)]
pub struct Account {
    pub login: u64,
    pub balance: f64,
    pub equity: f64,
    pub currency: String,
    pub server: String,
    pub leverage: u16,
    /// Seconds the server clock runs ahead of UTC. Candles, deals and
    /// positions carry server-clock times.
    pub timezone_shift_seconds: i64,
    /// Nonzero when the server applies a daylight-saving rule on top of the
    /// shift. Not yet observed, so not interpreted.
    pub daylight_mode: u8,
}

#[derive(Debug, Clone, Default)]
pub struct Symbol {
    pub name: String,
    pub id: u32,
    pub digits: u32,
    pub point: f64,
    /// As the server sends it, in the profit currency; zero for most
    /// instruments, whose tick value follows from contract size and tick size.
    pub tick_size: f64,
    pub tick_value: f64,
    pub contract_size: f64,
    pub min_volume: f64,
    pub volume_step: f64,
    pub max_volume: f64,
    /// MT5 calculation mode: 0 forex, 2 CFD, 4 CFD leverage, 5 forex no
    /// leverage, and so on.
    pub calc_mode: u32,
    pub base_currency: String,
    pub profit_currency: String,
    pub margin_currency: String,
    pub trade_mode: u32,
    pub execution_mode: u32,
    pub filling_flags: u32,
    pub stops_level: u32,
    pub freeze_level: u32,
    /// True once the full specification (`CMD_SYMBOL_INFO`) has been read.
    /// The symbol list alone carries only the name, digits, id and
    /// calculation mode; every other trading field is zero until then.
    pub full: bool,
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
    /// Server clock.
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

/// Deal entry: how a deal changed its position.
pub const ENTRY_IN: u32 = 0;
pub const ENTRY_OUT: u32 = 1;
pub const ENTRY_INOUT: u32 = 2;
pub const ENTRY_OUT_BY: u32 = 3;

#[derive(Debug, Clone, Default)]
pub struct Deal {
    pub ticket: i64,
    pub order: i64,
    /// The position this deal opened, changed or closed.
    pub position: i64,
    pub magic: i64,
    pub symbol: String,
    /// MT5 deal type: 0 buy, 1 sell, 2 balance, 3 credit and so on.
    pub kind: u32,
    /// `ENTRY_IN`, `ENTRY_OUT`, `ENTRY_INOUT` or `ENTRY_OUT_BY`.
    pub entry: u32,
    pub volume: f64,
    /// Execution price.
    pub price: f64,
    pub sl: f64,
    pub tp: f64,
    pub profit: f64,
    pub commission: f64,
    pub swap: f64,
    pub contract_size: f64,
    /// Seconds on the server clock.
    pub time: i64,
    /// Milliseconds on the server clock.
    pub time_ms: i64,
    pub comment: String,
}

#[derive(Debug, Clone, Default)]
pub struct Candle {
    /// Server clock.
    pub time: i64,
    pub open: f64,
    pub high: f64,
    pub low: f64,
    pub close: f64,
    pub volume: f64,
}

pub fn parse_account(body: &[u8], login: u64, server: &str) -> Account {
    // u8, i32, i32, f64, f64, w32, u32, u32, w128, u16, w64, w128, i32, u8, ...
    let mut o = 0usize;
    let take = |o: &mut usize, n: usize| -> &[u8] {
        let s = (*o).min(body.len());
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
    // Matched the native session's server time zone (180 minutes) on every
    // account checked. The two doubles further on were once read as profit
    // and margin; they held 50 and 20 on every account whatever was open, so
    // this frame does not carry the account's margin.
    let timezone_shift_seconds = u32_at(take(&mut o, 4)) as i32 as i64;
    let daylight_mode = take(&mut o, 1).first().copied().unwrap_or(0);
    if equity == 0.0 {
        equity = balance;
    }
    Account {
        login,
        balance,
        equity,
        currency,
        server: if parsed_server.is_empty() { server.to_string() } else { parsed_server },
        leverage,
        timezone_shift_seconds,
        daylight_mode,
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

/// Bytes in one symbol-list record: w32 name, w64 description, u32 digits,
/// u32 id, w128 path, u32 calculation mode, 64 bytes, 2 bytes.
pub const SYMBOL_LIST_REC_SIZE: usize = 526;

pub fn parse_symbols(body: &[u8]) -> HashMap<String, Symbol> {
    let compressed = if body.len() > 4 { &body[4..] } else { return HashMap::new() };
    let mut raw = Vec::new();
    if ZlibDecoder::new(compressed).read_to_end(&mut raw).is_err() {
        let mut dec = flate2::Decompress::new(false);
        let mut out = vec![0u8; compressed.len().saturating_mul(8).max(64)];
        let _ = dec.decompress(compressed, &mut out, flate2::FlushDecompress::Finish);
        raw = out;
    }
    parse_symbol_list(&raw)
}

/// The decompressed symbol list: u32 count, then fixed-size records.
pub fn parse_symbol_list(raw: &[u8]) -> HashMap<String, Symbol> {
    if raw.len() < 4 {
        return HashMap::new();
    }
    let count = u32_at(raw) as usize;
    let mut map = HashMap::new();
    for rec in raw[4..].chunks_exact(SYMBOL_LIST_REC_SIZE).take(count) {
        let name = from_utf16_le(&rec[..64]);
        if name.is_empty() {
            continue;
        }
        let digits = u32_at(&rec[192..]);
        let point = if digits > 0 { 10f64.powi(-(digits as i32)) } else { 1.0 };
        map.insert(
            name.clone(),
            Symbol {
                name,
                digits,
                id: u32_at(&rec[196..]),
                point,
                calc_mode: u32_at(&rec[456..]),
                ..Default::default()
            },
        );
    }
    map
}

/// Bytes in one full symbol specification (`CMD_SYMBOL_INFO`).
pub const SYMBOL_INFO_REC_SIZE: usize = 3068;

/// Full specifications: u32 count, then one record per requested symbol id.
/// Offsets were matched against the native session's symbol records for 13
/// instruments with five different contract sizes; the order of neighbouring
/// fields of equal value on that server (tick value before tick size, volume
/// minimum, maximum then step) follows the web terminal's own schema.
pub fn parse_symbol_info(body: &[u8]) -> Vec<Symbol> {
    if body.len() < 4 {
        return vec![];
    }
    let count = u32_at(body) as usize;
    if count == 0 {
        return vec![];
    }
    let records = body.len() - 4;
    // A newer server may append fields: step by the record size the reply
    // declares, never less than the fields read here.
    let size = if records % count == 0 && records / count >= 1896 { records / count } else { SYMBOL_INFO_REC_SIZE };
    body[4..]
        .chunks_exact(size)
        .take(count)
        .filter_map(|r| {
            let name = from_utf16_le(&r[..64]);
            if name.is_empty() {
                return None;
            }
            let lots = |at: usize| u64_at(&r[at..]) as f64 / LOT_MULTIPLIER;
            Some(Symbol {
                name,
                id: u32_at(&r[1412..]),
                digits: u32_at(&r[1392..]),
                point: f64_at(&r[1396..]),
                base_currency: from_utf16_le(&r[1276..1308]),
                profit_currency: from_utf16_le(&r[1308..1340]),
                margin_currency: from_utf16_le(&r[1340..1372]),
                tick_value: f64_at(&r[1440..]),
                tick_size: f64_at(&r[1448..]),
                contract_size: f64_at(&r[1456..]),
                calc_mode: u32_at(&r[1468..]),
                trade_mode: u32_at(&r[1800..]),
                stops_level: u32_at(&r[1804..]),
                freeze_level: u32_at(&r[1808..]),
                execution_mode: u32_at(&r[1812..]),
                filling_flags: u32_at(&r[1816..]),
                min_volume: lots(1872),
                max_volume: lots(1880),
                volume_step: lots(1888),
                full: true,
            })
        })
        .collect()
}

/// Bytes in one tick-statistics record (`CMD_TICK_STATS`), pushed after a
/// subscription: the last bid and ask with their server time, even when the
/// market is closed and no quote will stream.
pub const TICK_STATS_REC_SIZE: usize = 274;

/// Last quotes from a tick-statistics push. `time_ms` is the server clock.
pub fn parse_tick_stats(body: &[u8], symbols: &HashMap<String, Symbol>) -> Vec<Quote> {
    let by_id: HashMap<u32, &Symbol> = symbols.values().map(|s| (s.id, s)).collect();
    body.chunks_exact(TICK_STATS_REC_SIZE)
        .filter_map(|r| {
            let sym = by_id.get(&u32_at(r))?;
            let div = 10f64.powi(sym.digits as i32);
            let (bid, ask) = (f64_at(&r[20..]) / div, f64_at(&r[44..]) / div);
            (bid > 0.0 && ask > 0.0).then(|| Quote {
                symbol: sym.name.clone(),
                symbol_id: sym.id,
                bid,
                ask,
                time_ms: i64_at(&r[208..]),
            })
        })
        .collect()
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

/// Bytes in one web-terminal deal record: i64 ticket, w32 external id, i64
/// order, i64 time, w32 symbol, u32 type, u32 entry, 4 x f64 (price, position
/// price, sl, tp), u64 volume, 5 x f64 (profit, profit rate, margin rate,
/// commission, swap), i64 magic, i64 position, w32 comment, f64 contract
/// size, 5 x u32 (the second is the digits of money, the fourth the
/// milliseconds of the time), f64.
///
/// A history reply is a u32 count and that many deals, then a u32 count and
/// the order history. The body therefore does not divide into deals, and the
/// stride is fixed: an earlier guess from the body length read 940 bytes per
/// deal on an account with order history, and every deal after the first
/// from the wrong place.
///
/// Every field except commission was matched against the native session's
/// deal history for the same accounts: 485 deals with entries in, out and
/// out-by. In/out reversal needs a netting account and was not seen.
/// Commission was zero throughout, so its offset is unconfirmed.
pub const DEAL_REC_SIZE: usize = 356;

pub fn parse_deals(body: &[u8]) -> Vec<Deal> {
    if body.len() < 4 {
        return vec![];
    }
    let count = u32_at(body) as usize;
    body[4..]
        .chunks_exact(DEAL_REC_SIZE)
        .take(count)
        .map(|rec| {
            let time = i64_at(&rec[80..]);
            Deal {
                ticket: i64_at(rec),
                order: i64_at(&rec[72..]),
                time,
                time_ms: time * 1000 + u32_at(&rec[340..]).min(999) as i64,
                symbol: from_utf16_le(&rec[88..152]),
                kind: u32_at(&rec[152..]),
                entry: u32_at(&rec[156..]),
                price: f64_at(&rec[160..]),
                sl: f64_at(&rec[176..]),
                tp: f64_at(&rec[184..]),
                volume: u64_at(&rec[192..]) as f64 / LOT_MULTIPLIER,
                profit: f64_at(&rec[200..]),
                commission: f64_at(&rec[224..]),
                swap: f64_at(&rec[232..]),
                magic: i64_at(&rec[240..]),
                position: i64_at(&rec[248..]),
                comment: from_utf16_le(&rec[256..320]),
                contract_size: f64_at(&rec[320..]),
            }
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

    struct D {
        ticket: i64,
        position: i64,
        time: i64,
        symbol: &'static str,
        kind: u32,
        entry: u32,
        comment: &'static str,
    }

    /// One synthetic record laid out field by field from the deal schema, with
    /// a distinct value in every slot so a misread offset shows.
    fn deal_record(d: &D) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend(d.ticket.to_le_bytes());
        r.extend(utf16_le("ext", 64));
        r.extend((d.ticket + 1).to_le_bytes()); // order
        r.extend(d.time.to_le_bytes());
        r.extend(utf16_le(d.symbol, 64));
        r.extend(d.kind.to_le_bytes());
        r.extend(d.entry.to_le_bytes());
        for v in [2650.5f64, 2649.0, 2600.0, 2700.0] {
            r.extend(v.to_le_bytes()); // price, position price, sl, tp
        }
        r.extend(2_000_000u64.to_le_bytes()); // 0.02 lots
        for v in [12.34f64, 1.25, 0.8, -0.7, -1.25] {
            r.extend(v.to_le_bytes()); // profit, rates, commission, swap
        }
        r.extend(424242i64.to_le_bytes()); // magic
        r.extend(d.position.to_le_bytes());
        r.extend(utf16_le(d.comment, 64));
        r.extend(100.0f64.to_le_bytes()); // contract size
        for v in [5u32, 2, 2, 250, 0] {
            r.extend(v.to_le_bytes()); // .., money digits, milliseconds, ..
        }
        r.extend(0.0f64.to_le_bytes());
        assert_eq!(r.len(), DEAL_REC_SIZE);
        r
    }

    fn reply(deals: &[D], trailing_orders: usize) -> Vec<u8> {
        let mut body = (deals.len() as u32).to_le_bytes().to_vec();
        for d in deals {
            body.extend(deal_record(d));
        }
        // Order history follows the deals in the same reply.
        body.extend((trailing_orders as u32).to_le_bytes());
        body.extend(vec![0x5a; trailing_orders * ORDER_REC_SIZE]);
        body
    }

    fn two() -> [D; 2] {
        [
            D { ticket: 1001, position: 1002, time: 1_758_800_000, symbol: "XAUUSD", kind: 0, entry: ENTRY_IN, comment: "first" },
            D { ticket: 2002, position: 1002, time: 1_758_803_600, symbol: "XAUUSD", kind: 1, entry: ENTRY_OUT_BY, comment: "second" },
        ]
    }

    #[test]
    fn every_deal_is_read_from_its_own_record_with_entry_and_position() {
        let deals = parse_deals(&reply(&two(), 0));
        assert_eq!(deals.len(), 2);
        let (a, b) = (&deals[0], &deals[1]);
        assert_eq!((a.ticket, a.order, a.position, a.time, a.symbol.as_str()), (1001, 1002, 1002, 1_758_800_000, "XAUUSD"));
        assert_eq!((a.kind, a.entry, a.magic, a.time_ms), (0, ENTRY_IN, 424242, 1_758_800_000_250));
        assert_eq!((a.price, a.sl, a.tp, a.volume), (2650.5, 2600.0, 2700.0, 0.02));
        assert_eq!((a.profit, a.commission, a.swap, a.contract_size), (12.34, -0.7, -1.25, 100.0));
        assert_eq!(a.comment, "first");
        // The second record is where a wrong stride shows.
        assert_eq!((b.ticket, b.position, b.time, b.kind, b.entry), (2002, 1002, 1_758_803_600, 1, ENTRY_OUT_BY));
        assert_eq!(b.comment, "second");
    }

    #[test]
    fn order_history_after_the_deals_does_not_change_the_stride() {
        // 2 deals and 3 orders: 4 + 712 + 4 + 1068 bytes divide into two
        // 892-byte "records", the shape that fooled the old walk.
        let deals = parse_deals(&reply(&two(), 3));
        assert_eq!(deals.iter().map(|d| d.ticket).collect::<Vec<_>>(), vec![1001, 2002]);
        assert_eq!(deals[1].entry, ENTRY_OUT_BY);
    }

    #[test]
    fn a_short_or_empty_deal_reply_yields_what_is_whole() {
        assert!(parse_deals(&[]).is_empty());
        assert!(parse_deals(&0u32.to_le_bytes()).is_empty());
        let mut body = 2u32.to_le_bytes().to_vec();
        body.extend(deal_record(&two()[0]));
        body.extend([0u8; 100]);
        assert_eq!(parse_deals(&body).len(), 1);
    }

    fn info_record(name: &str, id: u32, digits: u32, contract: f64, calc: u32, profit_ccy: &str) -> Vec<u8> {
        let mut r = vec![0u8; SYMBOL_INFO_REC_SIZE];
        r[..64].copy_from_slice(&utf16_le(name, 64));
        r[1276..1308].copy_from_slice(&utf16_le("XAU", 32));
        r[1308..1340].copy_from_slice(&utf16_le(profit_ccy, 32));
        r[1340..1372].copy_from_slice(&utf16_le("XAU", 32));
        r[1392..1396].copy_from_slice(&digits.to_le_bytes());
        r[1396..1404].copy_from_slice(&10f64.powi(-(digits as i32)).to_le_bytes());
        r[1412..1416].copy_from_slice(&id.to_le_bytes());
        r[1440..1448].copy_from_slice(&0.5f64.to_le_bytes());
        r[1448..1456].copy_from_slice(&0.25f64.to_le_bytes());
        r[1456..1464].copy_from_slice(&contract.to_le_bytes());
        r[1468..1472].copy_from_slice(&calc.to_le_bytes());
        for (at, v) in [(1800, 4u32), (1804, 20), (1808, 3), (1812, 2), (1816, 2)] {
            r[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
        for (at, lots) in [(1872, 0.01f64), (1880, 100.0), (1888, 0.02)] {
            r[at..at + 8].copy_from_slice(&((lots * LOT_MULTIPLIER) as u64).to_le_bytes());
        }
        r
    }

    #[test]
    fn a_full_specification_carries_sizing_fields() {
        let mut body = 2u32.to_le_bytes().to_vec();
        body.extend(info_record("XAUUSD", 96, 2, 100.0, 4, "USD"));
        body.extend(info_record("EURUSD", 1, 5, 100_000.0, 0, "USD"));
        let v = parse_symbol_info(&body);
        assert_eq!(v.len(), 2);
        let x = &v[0];
        assert!(x.full);
        assert_eq!((x.name.as_str(), x.id, x.digits, x.point), ("XAUUSD", 96, 2, 0.01));
        assert_eq!((x.contract_size, x.tick_value, x.tick_size, x.calc_mode), (100.0, 0.5, 0.25, 4));
        assert_eq!((x.min_volume, x.max_volume, x.volume_step), (0.01, 100.0, 0.02));
        assert_eq!((x.trade_mode, x.stops_level, x.freeze_level, x.execution_mode, x.filling_flags), (4, 20, 3, 2, 2));
        assert_eq!((x.base_currency.as_str(), x.profit_currency.as_str(), x.margin_currency.as_str()), ("XAU", "USD", "XAU"));
        assert_eq!((v[1].name.as_str(), v[1].contract_size, v[1].digits), ("EURUSD", 100_000.0, 5));
    }

    #[test]
    fn the_symbol_list_alone_is_not_a_full_specification() {
        let mut raw = 1u32.to_le_bytes().to_vec();
        let mut rec = vec![0u8; SYMBOL_LIST_REC_SIZE];
        rec[..64].copy_from_slice(&utf16_le("USDX", 64));
        rec[192..196].copy_from_slice(&3u32.to_le_bytes());
        rec[196..200].copy_from_slice(&94u32.to_le_bytes());
        rec[456..460].copy_from_slice(&2u32.to_le_bytes());
        raw.extend(rec);
        let s = &parse_symbol_list(&raw)["USDX"];
        assert_eq!((s.id, s.digits, s.calc_mode, s.point), (94, 3, 2, 0.001));
        assert!(!s.full);
        assert_eq!((s.contract_size, s.min_volume, s.volume_step, s.tick_value), (0.0, 0.0, 0.0, 0.0));
    }

    #[test]
    fn tick_stats_give_the_last_quote_with_its_server_time() {
        let mut symbols = HashMap::new();
        symbols.insert("USDX".to_string(), Symbol { name: "USDX".into(), id: 94, digits: 3, ..Default::default() });
        let mut r = vec![0u8; TICK_STATS_REC_SIZE];
        r[..4].copy_from_slice(&94u32.to_le_bytes());
        r[20..28].copy_from_slice(&101250.0f64.to_le_bytes());
        r[44..52].copy_from_slice(&101285.0f64.to_le_bytes());
        r[208..216].copy_from_slice(&1_700_000_000_123i64.to_le_bytes());
        let mut unknown = r.clone();
        unknown[..4].copy_from_slice(&7u32.to_le_bytes());
        r.extend(unknown);
        let q = parse_tick_stats(&r, &symbols);
        assert_eq!(q.len(), 1);
        assert_eq!((q[0].symbol.as_str(), q[0].bid, q[0].ask, q[0].time_ms), ("USDX", 101.25, 101.285, 1_700_000_000_123));
    }

    #[test]
    fn the_account_frame_gives_the_server_time_zone() {
        let mut body = vec![0u8; 800];
        body[9..17].copy_from_slice(&155.16f64.to_le_bytes());
        body[739..743].copy_from_slice(&10800i32.to_le_bytes());
        body[752..760].copy_from_slice(&50.0f64.to_le_bytes());
        let a = parse_account(&body, 1, "Example-Demo");
        assert_eq!((a.balance, a.equity, a.timezone_shift_seconds, a.daylight_mode), (155.16, 155.16, 10800, 0));
        assert_eq!(a.server, "Example-Demo");
    }
}
