//! Live-tick (command 50) and market-watch snapshot (command 51) quote records.
//!
//! Both are sequences of bit-packed records terminated by a strict byte
//! boundary. The layouts differ in field order and interpretation, and several
//! behaviours mirror the observed consumer rather than an idealized grammar:
//!
//! * command 50 orders symbol/seconds/mask; command 51 orders symbol/mask/seconds.
//! * snapshot field 27 is read before field 26 (`SNAPSHOT_ORDER`).
//! * snapshot fields 9..15 and 17 are unsigned; the rest are signed.
//! * `compatibility_time_ms` is projected only when mask bit 26 is set — a
//!   documented consumer defect, preserved here.
//! * command 51 reads mask bits 62 and 63 twice (as an extension, then again as
//!   an additional mask).
//!
//! Encode/decode use deliberately mismatched widths in a few places (symbol id
//! written at 32 and read as signed 32; seconds written at the default 64).
//! These are mirrored, not harmonized.

use std::collections::BTreeMap;

use crate::bitpack::{BitReader, BitWriter};
use crate::error::{ProtocolError, Result};

const U64: u128 = (1u128 << 64) - 1;

/// Live-tick fields: (bit, name, storage width, signed).
pub const LIVE_FIELDS: [(u32, &str, usize, bool); 9] = [
    (0, "bid_integer", 64, true),
    (1, "ask_integer", 64, true),
    (2, "last_integer", 64, true),
    (3, "whole_volume", 64, false),
    (4, "opaque_4", 64, true),
    (5, "opaque_5", 16, true),
    (6, "millisecond_component", 64, true),
    (7, "opaque_7", 64, true),
    (8, "fractional_volume", 64, false),
];

/// Snapshot field read order: 0..=25, then 27, then 26, then 28..=40.
pub fn snapshot_order() -> Vec<u32> {
    let mut v: Vec<u32> = (0..26).collect();
    v.push(27);
    v.push(26);
    v.extend(28..41);
    v
}

fn snapshot_unsigned(bit: u32) -> bool {
    (9..=15).contains(&bit) || bit == 17
}

fn wrap_i64(x: i128) -> i128 {
    ((x + (1i128 << 63)) as u128 & U64) as i128 - (1i128 << 63)
}

/// Input to [`encode_quote`]. `values` is keyed by bit index and covers live
/// fields, snapshot fields and extensions uniformly; `additional_masks` holds
/// the command-51 second reading of bits 62/63.
#[derive(Debug, Clone, Default)]
pub struct QuoteInput {
    pub symbol_id: i128,
    pub seconds: i128,
    pub mask: u64,
    pub values: BTreeMap<u32, i128>,
    pub additional_masks: BTreeMap<u32, i128>,
}

impl QuoteInput {
    fn value(&self, bit: u32) -> Result<i128> {
        self.values
            .get(&bit)
            .copied()
            .ok_or_else(|| ProtocolError::new(format!("missing quote field for bit {bit}")))
    }
}

/// Encode a single quote record (command 50 or 51).
pub fn encode_quote(rec: &QuoteInput, command: u8) -> Result<Vec<u8>> {
    if command != 50 && command != 51 {
        return Err(ProtocolError::new("quote command must be 50 or 51"));
    }
    let mut w = BitWriter::new();
    let mask = rec.mask;
    w.packed(rec.symbol_id, 32)?;

    let first_extension = if command == 50 {
        w.packed(rec.seconds, 64)?;
        w.packed(mask as i128, 64)?;
        for (bit, _, width, _) in LIVE_FIELDS {
            if mask & (1u64 << bit) != 0 {
                w.packed(rec.value(bit)?, width)?;
            }
        }
        9
    } else {
        w.packed(mask as i128, 64)?;
        w.packed(rec.seconds, 64)?;
        for bit in snapshot_order() {
            if mask & (1u64 << bit) != 0 {
                w.packed(rec.value(bit)?, 64)?;
            }
        }
        41
    };
    for bit in first_extension..64 {
        if mask & (1u64 << bit) != 0 {
            w.packed(rec.value(bit)?, 64)?;
        }
    }
    if command == 51 {
        for bit in [62u32, 63] {
            if mask & (1u64 << bit) != 0 {
                let v =
                    rec.additional_masks.get(&bit).copied().ok_or_else(|| {
                        ProtocolError::new(format!("missing additional mask {bit}"))
                    })?;
                w.packed(v, 64)?;
            }
        }
    }
    w.strict_boundary()?;
    Ok(w.data)
}

/// One decoded quote record. Field presence follows the command and mask.
#[derive(Debug, Clone, PartialEq)]
pub struct QuoteRow {
    pub command: u8,
    pub symbol_id: i128,
    pub seconds: i128,
    pub mask: u64,
    /// command 50: present live fields in `LIVE_FIELDS` order.
    pub live: Vec<(&'static str, i128)>,
    pub time_ms: Option<i128>,
    pub volume_units: Option<i128>,
    /// command 51: present snapshot fields in read order.
    pub fields: Vec<(u32, i128)>,
    pub compatibility_time_ms: Option<i128>,
    pub extensions: Vec<(u32, i128)>,
    /// command 51 only.
    pub additional_masks: Option<Vec<(u32, i128)>>,
    pub bits_before_padding: usize,
    pub padding_count: usize,
    pub padding_value: u64,
}

impl QuoteRow {
    pub fn live_get(&self, name: &str) -> Option<i128> {
        self.live.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
    }
    pub fn field_get(&self, bit: u32) -> Option<i128> {
        self.fields.iter().find(|(b, _)| *b == bit).map(|(_, v)| *v)
    }
}

/// Decode a run of quote records for command 50 or 51.
pub fn decode_quotes(data: &[u8], command: u8) -> Result<Vec<QuoteRow>> {
    if command != 50 && command != 51 {
        return Err(ProtocolError::new("quote command must be 50 or 51"));
    }
    let mut r = BitReader::new(data);
    let mut rows = Vec::new();
    while r.position < data.len() * 8 {
        let start = r.position;
        let symbol_id = r.packed(32, true)?;
        let mut live = Vec::new();
        let mut fields = Vec::new();
        let mut time_ms = None;
        let mut volume_units = None;
        let mut compatibility_time_ms = None;
        let seconds;
        let mask;
        let first_extension;

        if command == 50 {
            seconds = r.packed(64, true)?;
            mask = r.packed(64, false)? as u64;
            let mut ms = 0i128;
            let mut whole = 0i128;
            let mut frac = 0i128;
            for (bit, name, width, signed) in LIVE_FIELDS {
                if mask & (1u64 << bit) != 0 {
                    let v = r.packed(width, signed)?;
                    if name == "millisecond_component" {
                        ms = v;
                    } else if name == "whole_volume" {
                        whole = v;
                    } else if name == "fractional_volume" {
                        frac = v;
                    }
                    live.push((name, v));
                }
            }
            time_ms = Some(wrap_i64(seconds * 1000 + ms));
            if mask & ((1u64 << 3) | (1u64 << 8)) != 0 {
                volume_units = Some(((whole * 100_000_000 + frac) as u128 & U64) as i128);
            }
            first_extension = 9;
        } else {
            mask = r.packed(64, false)? as u64;
            seconds = r.packed(64, true)?;
            for bit in snapshot_order() {
                if mask & (1u64 << bit) != 0 {
                    fields.push((bit, r.packed(64, !snapshot_unsigned(bit))?));
                }
            }
            compatibility_time_ms = Some(if mask & (1u64 << 26) != 0 {
                wrap_i64(seconds * 1000)
            } else {
                0
            });
            first_extension = 41;
        }

        let mut extensions = Vec::new();
        for bit in first_extension..64 {
            if mask & (1u64 << bit) != 0 {
                extensions.push((bit, r.packed(64, false)?));
            }
        }
        let additional_masks = if command == 51 {
            let mut am = Vec::new();
            for bit in [62u32, 63] {
                if mask & (1u64 << bit) != 0 {
                    am.push((bit, r.packed(64, false)?));
                }
            }
            Some(am)
        } else {
            None
        };

        let bits_before_padding = r.position - start;
        let (padding_count, padding_value) = r.strict_boundary()?;
        rows.push(QuoteRow {
            command,
            symbol_id,
            seconds,
            mask,
            live,
            time_ms,
            volume_units,
            fields,
            compatibility_time_ms,
            extensions,
            additional_masks,
            bits_before_padding,
            padding_count,
            padding_value,
        });
    }
    Ok(rows)
}

/// The market-watch compatibility projection: overlay a live tick onto a prior
/// quote. Nonzero integer prices replace, scaled by `digits`; zero is retained
/// on the wire but suppressed by this view.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CompatQuote {
    pub bid: Option<f64>,
    pub ask: Option<f64>,
    pub last: Option<f64>,
    pub volume_units: Option<i128>,
    pub time_ms: Option<i128>,
}

pub fn compatibility_quote_update(
    previous: &CompatQuote,
    tick: &QuoteRow,
    digits: i32,
) -> CompatQuote {
    let mut result = previous.clone();
    result.time_ms = tick.time_ms;
    let scale = 10f64.powi(digits);
    let apply = |name: &str, slot: &mut Option<f64>| {
        let value = tick.live_get(name).unwrap_or(0);
        if value != 0 {
            *slot = Some(value as f64 / scale);
        }
    };
    apply("bid_integer", &mut result.bid);
    apply("ask_integer", &mut result.ask);
    apply("last_integer", &mut result.last);
    if let Some(vu) = tick.volume_units
        && vu != 0
    {
        result.volume_units = Some(vu);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hexutil::decode;

    fn input(symbol_id: i128, seconds: i128, mask: u64, pairs: &[(u32, i128)]) -> QuoteInput {
        let mut values = BTreeMap::new();
        for &(b, v) in pairs {
            values.insert(b, v);
        }
        QuoteInput {
            symbol_id,
            seconds,
            mask,
            values,
            additional_masks: BTreeMap::new(),
        }
    }

    #[test]
    fn live_basic_layout() {
        let inp = input(
            1001,
            1700000000,
            7,
            &[(0, 123450), (1, 123460), (2, 123455)],
        );
        let d = &decode_quotes(&encode_quote(&inp, 50).unwrap(), 50).unwrap()[0];
        assert_eq!(d.seconds, 1700000000);
        assert_eq!(d.live_get("ask_integer"), Some(123460));
        assert_eq!(d.time_ms, Some(1700000000000));
    }

    #[test]
    fn live_milliseconds_and_split_volume() {
        let mask = (1u64 << 3) | (1u64 << 6) | (1u64 << 8);
        let inp = input(7, 1700000000, mask, &[(3, 2), (6, 987), (8, 123)]);
        let d = &decode_quotes(&encode_quote(&inp, 50).unwrap(), 50).unwrap()[0];
        assert_eq!(d.time_ms, Some(1700000000987));
        assert_eq!(d.volume_units, Some(200000123));
    }

    #[test]
    fn live_narrow_field_retained() {
        let inp = input(1, 1, 32, &[(5, -2)]);
        let d = &decode_quotes(&encode_quote(&inp, 50).unwrap(), 50).unwrap()[0];
        assert_eq!(d.live_get("opaque_5"), Some(-2));
    }

    #[test]
    fn live_high_extensions_no_additional_masks() {
        let mask = (1u64 << 9) | (1u64 << 63);
        let inp = input(2, 1, mask, &[(9, 71), (63, U64 as i128)]);
        let d = &decode_quotes(&encode_quote(&inp, 50).unwrap(), 50).unwrap()[0];
        assert_eq!(d.extensions, vec![(9, 71), (63, U64 as i128)]);
        assert!(d.additional_masks.is_none());
    }

    #[test]
    fn live_two_records() {
        let a = input(1, 12, 1, &[(0, 123)]);
        let b = input(2, 13, 2, &[(1, 234)]);
        let mut buf = encode_quote(&a, 50).unwrap();
        buf.extend(encode_quote(&b, 50).unwrap());
        let rows = decode_quotes(&buf, 50).unwrap();
        assert_eq!(
            rows.iter().map(|r| r.symbol_id).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(rows[1].live_get("ask_integer"), Some(234));
    }

    #[test]
    fn zero_retained_on_wire_suppressed_by_view() {
        let inp = input(1, 1, 1, &[(0, 0)]);
        let d = &decode_quotes(&encode_quote(&inp, 50).unwrap(), 50).unwrap()[0];
        assert_eq!(d.live_get("bid_integer"), Some(0));
        let prev = CompatQuote {
            bid: Some(1.25),
            ..Default::default()
        };
        assert_eq!(compatibility_quote_update(&prev, d, 5).bid, Some(1.25));
    }

    #[test]
    fn live_truncation_rejected() {
        let inp = input(1, 1700000000, 1, &[(0, 12345)]);
        let packet = encode_quote(&inp, 50).unwrap();
        assert!(decode_quotes(&packet[..packet.len() - 2], 50).is_err());
    }

    #[test]
    fn snapshot_old_fixture_reclassified() {
        // test_revision3::test_snapshot_old_fixture_reclassified.
        let fixture = decode("9bfe25fd1f40fc54d98f8e783f44e2fdfc8807");
        let d = &decode_quotes(&fixture, 51).unwrap()[0];
        assert_eq!(d.mask, 73);
        assert_eq!(d.seconds, 1700000000);
        assert_eq!(d.field_get(0), Some(123450));
        assert_eq!(d.field_get(3), Some(123460));
        assert_eq!(d.field_get(6), Some(123455));
    }

    #[test]
    fn snapshot_field27_before26() {
        let mask = (1u64 << 26) | (1u64 << 27);
        let inp = input(2, 123, mask, &[(27, 101), (26, 987)]);
        let d = &decode_quotes(&encode_quote(&inp, 51).unwrap(), 51).unwrap()[0];
        assert_eq!(
            d.fields.iter().map(|(b, _)| *b).collect::<Vec<_>>(),
            vec![27, 26]
        );
        assert_eq!(d.field_get(26), Some(987));
        assert_eq!(d.compatibility_time_ms, Some(123000));
    }

    #[test]
    fn snapshot_extra_masks_consumed_twice() {
        let mask = (1u64 << 62) | (1u64 << 63);
        let mut inp = input(2, 123, mask, &[(62, 100), (63, 200)]);
        inp.additional_masks.insert(62, 1);
        inp.additional_masks.insert(63, 2);
        let d = &decode_quotes(&encode_quote(&inp, 51).unwrap(), 51).unwrap()[0];
        assert_eq!(d.extensions, vec![(62, 100), (63, 200)]);
        assert_eq!(d.additional_masks, Some(vec![(62, 1), (63, 2)]));
    }

    #[test]
    fn snapshot_all_known_bits() {
        let mask = (1u64 << 41) - 1;
        let pairs: Vec<(u32, i128)> = (0..41).map(|i| (i, (i as i128) * 10 + 1)).collect();
        let inp = input(2, 123, mask, &pairs);
        let d = &decode_quotes(&encode_quote(&inp, 51).unwrap(), 51).unwrap()[0];
        for i in 0..41u32 {
            assert_eq!(d.field_get(i), Some((i as i128) * 10 + 1));
        }
    }
}
