//! The canonical 800-byte trade request record and its signed payload.
//!
//! The record is a fixed, contiguous struct (`TRADE_FIELDS`). A signed trade
//! payload is a `0x00` selector, the 800-byte record, then TLV 85 carrying the
//! HMAC-SHA256 of the record under the 32-byte trade key. Opaque spans are
//! carried verbatim; this is serialization only — nothing is transmitted.

use crate::error::{ProtocolError, Result};
use crate::tlv::encode_tlvs;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    I32,
    I64,
    U64,
    F64,
    Bytes(usize),
}

impl Kind {
    fn size(&self) -> usize {
        match self {
            Kind::I32 => 4,
            Kind::I64 | Kind::U64 | Kind::F64 => 8,
            Kind::Bytes(n) => *n,
        }
    }
}

/// Field order and types of the trade record, contiguous, totalling 800 bytes.
pub const TRADE_FIELDS: [(&str, Kind); 34] = [
    ("request_id", Kind::I32),
    ("opaque_016", Kind::Bytes(64)),
    ("trade_type", Kind::I32),
    ("login", Kind::U64),
    ("opaque_017", Kind::Bytes(72)),
    ("transfer_login", Kind::U64),
    ("text_018", Kind::Bytes(128)),
    ("currency", Kind::Bytes(64)),
    ("volume_units", Kind::U64),
    ("unknown_01a", Kind::I64),
    ("digits", Kind::I32),
    ("unknown_01b", Kind::I64),
    ("opaque_01c", Kind::Bytes(20)),
    ("order_ticket", Kind::I64),
    ("opaque_01d", Kind::Bytes(64)),
    ("unknown_01e", Kind::I64),
    ("expiration_time", Kind::I64),
    ("order_type", Kind::I32),
    ("fill_policy", Kind::I32),
    ("expiration_type", Kind::I32),
    ("flags", Kind::I64),
    ("placed_type", Kind::I32),
    ("opaque_01f", Kind::Bytes(16)),
    ("price", Kind::F64),
    ("order_price", Kind::F64),
    ("stop_loss", Kind::F64),
    ("take_profit", Kind::F64),
    ("deviation", Kind::U64),
    ("opaque_020", Kind::Bytes(32)),
    ("expert_id", Kind::I64),
    ("comment", Kind::Bytes(64)),
    ("deal_ticket", Kind::I64),
    ("by_close_ticket", Kind::I64),
    ("opaque_021", Kind::Bytes(112)),
];

/// Total serialized size of the trade record.
pub fn trade_record_size() -> usize {
    TRADE_FIELDS.iter().map(|(_, k)| k.size()).sum()
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    I32(i32),
    I64(i64),
    U64(u64),
    F64(f64),
    Bytes(Vec<u8>),
}

/// A trade record as ordered, typed fields.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TradeRecord {
    fields: Vec<(&'static str, Value)>,
}

impl TradeRecord {
    /// A zero-initialized record with every field present.
    pub fn zeroed() -> Self {
        let fields = TRADE_FIELDS
            .iter()
            .map(|(name, kind)| {
                let v = match kind {
                    Kind::I32 => Value::I32(0),
                    Kind::I64 => Value::I64(0),
                    Kind::U64 => Value::U64(0),
                    Kind::F64 => Value::F64(0.0),
                    Kind::Bytes(n) => Value::Bytes(vec![0u8; *n]),
                };
                (*name, v)
            })
            .collect();
        TradeRecord { fields }
    }

    pub fn get(&self, name: &str) -> Option<&Value> {
        self.fields.iter().find(|(n, _)| *n == name).map(|(_, v)| v)
    }

    pub fn set(&mut self, name: &'static str, value: Value) -> Result<()> {
        let kind = TRADE_FIELDS
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, k)| *k)
            .ok_or_else(|| ProtocolError::new(format!("unknown trade field {name}")))?;
        let ok = matches!(
            (&value, kind),
            (Value::I32(_), Kind::I32)
                | (Value::I64(_), Kind::I64)
                | (Value::U64(_), Kind::U64)
                | (Value::F64(_), Kind::F64)
        ) || matches!((&value, kind), (Value::Bytes(b), Kind::Bytes(n)) if b.len() == n);
        if !ok {
            return Err(ProtocolError::new(format!("type/size mismatch for field {name}")));
        }
        if let Some(slot) = self.fields.iter_mut().find(|(n, _)| *n == name) {
            slot.1 = value;
        }
        Ok(())
    }
}

/// Serialize a record to its 800 fixed bytes.
pub fn pack_trade_record(record: &TradeRecord) -> Result<Vec<u8>> {
    if record.fields.len() != TRADE_FIELDS.len() {
        return Err(ProtocolError::new("trade record has the wrong field set"));
    }
    let mut out = Vec::with_capacity(trade_record_size());
    for ((name, kind), (fname, value)) in TRADE_FIELDS.iter().zip(record.fields.iter()) {
        if name != fname {
            return Err(ProtocolError::new("trade record field order differs"));
        }
        match (kind, value) {
            (Kind::I32, Value::I32(v)) => out.extend_from_slice(&v.to_le_bytes()),
            (Kind::I64, Value::I64(v)) => out.extend_from_slice(&v.to_le_bytes()),
            (Kind::U64, Value::U64(v)) => out.extend_from_slice(&v.to_le_bytes()),
            (Kind::F64, Value::F64(v)) => out.extend_from_slice(&v.to_le_bytes()),
            (Kind::Bytes(n), Value::Bytes(b)) if b.len() == *n => out.extend_from_slice(b),
            _ => return Err(ProtocolError::new(format!("invalid trade record field: {name}"))),
        }
    }
    Ok(out)
}

/// Parse the 800 fixed bytes into a typed record.
pub fn parse_trade_record(record: &[u8]) -> Result<TradeRecord> {
    if record.len() != trade_record_size() {
        return Err(ProtocolError::new(format!(
            "trade record must contain exactly {} bytes",
            trade_record_size()
        )));
    }
    let mut fields = Vec::with_capacity(TRADE_FIELDS.len());
    let mut off = 0usize;
    for (name, kind) in TRADE_FIELDS.iter() {
        let sz = kind.size();
        let slice = &record[off..off + sz];
        let value = match kind {
            Kind::I32 => Value::I32(i32::from_le_bytes(slice.try_into().unwrap())),
            Kind::I64 => Value::I64(i64::from_le_bytes(slice.try_into().unwrap())),
            Kind::U64 => Value::U64(u64::from_le_bytes(slice.try_into().unwrap())),
            Kind::F64 => Value::F64(f64::from_le_bytes(slice.try_into().unwrap())),
            Kind::Bytes(_) => Value::Bytes(slice.to_vec()),
        };
        fields.push((*name, value));
        off += sz;
    }
    Ok(TradeRecord { fields })
}

/// UTF-16LE, null-padded (or truncated) to `size` bytes.
pub fn utf16_field(s: &str, size: usize) -> Vec<u8> {
    let mut v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    v.resize(size, 0);
    v
}

/// High-level fields for a market/pending trade request. String fields are
/// UTF-16LE; the symbol occupies the `currency` span. Unlisted fields are zero.
#[derive(Debug, Clone, Default)]
pub struct MarketTradeFields {
    pub request_id: i32,
    pub trade_type: i32,
    pub login: u64,
    pub symbol: String,
    pub volume_units: u64,
    pub digits: i32,
    pub order_type: i32,
    pub fill_policy: i32,
    pub expiration_type: i32,
    pub price: f64,
    pub stop_loss: f64,
    pub take_profit: f64,
    pub deviation: u64,
    pub expert_id: i64,
    pub comment: String,
}

/// Build the canonical 800-byte trade record from high-level fields.
pub fn build_trade_record(f: &MarketTradeFields) -> Result<Vec<u8>> {
    let mut r = TradeRecord::zeroed();
    r.set("request_id", Value::I32(f.request_id))?;
    r.set("trade_type", Value::I32(f.trade_type))?;
    r.set("login", Value::U64(f.login))?;
    r.set("currency", Value::Bytes(utf16_field(&f.symbol, 64)))?;
    r.set("volume_units", Value::U64(f.volume_units))?;
    r.set("digits", Value::I32(f.digits))?;
    r.set("order_type", Value::I32(f.order_type))?;
    r.set("fill_policy", Value::I32(f.fill_policy))?;
    r.set("expiration_type", Value::I32(f.expiration_type))?;
    r.set("price", Value::F64(f.price))?;
    r.set("stop_loss", Value::F64(f.stop_loss))?;
    r.set("take_profit", Value::F64(f.take_profit))?;
    r.set("deviation", Value::U64(f.deviation))?;
    r.set("expert_id", Value::I64(f.expert_id))?;
    r.set("comment", Value::Bytes(utf16_field(&f.comment, 64)))?;
    pack_trade_record(&r)
}

/// Build the signed trade payload: `0x00` + record + TLV 85 (HMAC-SHA256).
pub fn make_signed_trade_payload(record: &[u8], signing_key: &[u8; 32]) -> Result<Vec<u8>> {
    if record.len() != trade_record_size() {
        return Err(ProtocolError::new(format!(
            "expected {}-byte record",
            trade_record_size()
        )));
    }
    let mut mac = HmacSha256::new_from_slice(signing_key).expect("hmac key");
    mac.update(record);
    let signature = mac.finalize().into_bytes().to_vec();
    let mut out = Vec::with_capacity(1 + record.len() + 5 + 32);
    out.push(0x00);
    out.extend_from_slice(record);
    out.extend_from_slice(&encode_tlvs(&[(85, signature)]));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::parse_tlvs;

    #[test]
    fn record_size_is_800() {
        assert_eq!(trade_record_size(), 800);
    }

    #[test]
    fn zero_record_round_trips_and_signs() {
        let zero = pack_trade_record(&TradeRecord::zeroed()).unwrap();
        assert_eq!(zero.len(), 800);
        let parsed = parse_trade_record(&zero).unwrap();
        assert_eq!(pack_trade_record(&parsed).unwrap(), zero);
        assert!(matches!(parsed.get("text_018"), Some(Value::Bytes(b)) if b.len() == 128));
        assert!(matches!(parsed.get("comment"), Some(Value::Bytes(b)) if b.len() == 64));
    }

    #[test]
    fn set_fields_and_round_trip() {
        let mut r = TradeRecord::zeroed();
        r.set("request_id", Value::I32(42)).unwrap();
        r.set("login", Value::U64(12345678)).unwrap();
        r.set("price", Value::F64(1.125)).unwrap();
        r.set("volume_units", Value::U64(100000000)).unwrap();
        assert!(r.set("price", Value::I32(1)).is_err()); // wrong type
        assert!(r.set("comment", Value::Bytes(vec![0u8; 10])).is_err()); // wrong size
        let encoded = pack_trade_record(&r).unwrap();
        assert_eq!(parse_trade_record(&encoded).unwrap(), r);
    }

    #[test]
    fn signed_payload_shape() {
        let mut r = TradeRecord::zeroed();
        r.set("request_id", Value::I32(42)).unwrap();
        let encoded = pack_trade_record(&r).unwrap();
        let key: [u8; 32] = (0..32u8).collect::<Vec<_>>().try_into().unwrap();
        let payload = make_signed_trade_payload(&encoded, &key).unwrap();
        assert_eq!(payload[0], 0);
        assert_eq!(&payload[1..801], &encoded[..]);
        assert_eq!(parse_tlvs(&payload[801..]).unwrap()[0].0, 85);
        assert_eq!(payload.len(), 838);
    }
}

/// One record of a command-55 subtype-35 trade update: a 152-byte transaction,
/// the 800-byte echoed request, a 260-byte result, and any per-record extension
/// tail preserved within its stride.
#[derive(Debug, Clone, PartialEq)]
pub struct TradeUpdateRecord {
    pub transaction: Vec<u8>,
    pub request: Vec<u8>,
    pub result: Vec<u8>,
    pub tail: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TradeUpdate35 {
    pub count: i32,
    pub stride: usize,
    pub records: Vec<TradeUpdateRecord>,
}

/// Parse a command-55 subtype-35 body: `u8 subtype(35) || i32 count`, then
/// `count` fixed records of `stride = (remaining / count)` bytes, each split
/// into transaction[152] + request[800] + result[260] + tail. The 1212-byte
/// base excludes the count word.
pub fn parse_trade_update_35(body: &[u8]) -> Result<TradeUpdate35> {
    if body.len() < 5 {
        return Err(ProtocolError::new("trade update too short for subtype + count"));
    }
    if body[0] != 35 {
        return Err(ProtocolError::new("not a subtype-35 trade update"));
    }
    let count = i32::from_le_bytes([body[1], body[2], body[3], body[4]]);
    if count <= 0 {
        return Err(ProtocolError::new("trade update count must be positive"));
    }
    let remaining = body.len() - 5;
    let count_usize = count as usize;
    if !remaining.is_multiple_of(count_usize) {
        return Err(ProtocolError::new("trade update body not divisible by count"));
    }
    let stride = remaining / count_usize;
    if stride < 1212 {
        return Err(ProtocolError::new("trade update stride below the 1212-byte base"));
    }
    let mut records = Vec::with_capacity(count_usize);
    let mut off = 5;
    for _ in 0..count_usize {
        let rec = &body[off..off + stride];
        records.push(TradeUpdateRecord {
            transaction: rec[0..152].to_vec(),
            request: rec[152..952].to_vec(),
            result: rec[952..1212].to_vec(),
            tail: rec[1212..].to_vec(),
        });
        off += stride;
    }
    Ok(TradeUpdate35 { count, stride, records })
}
