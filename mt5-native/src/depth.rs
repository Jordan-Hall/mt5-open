//! Market-depth records (command 52).
//!
//! A depth record is bit-packed with the same LSB-first `k=2` reader as the
//! quote records: a symbol id, two opaque header values, an entry count, then
//! that many entries. Entry types are 0 reset, 1 sell-book, 2 buy-book, 3
//! sell-market, 4 buy-market. The consumer's outer loop compares a bit cursor
//! against a byte length (a documented defect that can stop after one record);
//! the batch decoder consumes complete records plus at most seven zero bits.
//! Empty broker snapshots are verified; nonempty books need live validation.

use crate::bitpack::{BitReader, BitWriter};
use crate::error::{ProtocolError, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct DepthEntry {
    pub mask: u64,
    pub entry_type: u8,
    pub price_integer: i64,
    pub volume_delta: i64,
    pub auxiliary: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DepthRecord {
    pub symbol_id: i32,
    pub opaque_header_a: i64,
    pub opaque_header_b: u64,
    pub entries: Vec<DepthEntry>,
}

/// Encode one depth record.
pub fn encode_depth_record(rec: &DepthRecord) -> Result<Vec<u8>> {
    let mut w = BitWriter::new();
    w.packed(rec.symbol_id as i128, 32)?;
    w.packed(rec.opaque_header_a as i128, 64)?;
    w.packed(rec.opaque_header_b as i128, 64)?;
    w.packed(rec.entries.len() as i128, 64)?;
    for e in &rec.entries {
        w.packed(e.mask as i128, 64)?;
        w.packed(e.entry_type as i128, 8)?;
        w.packed(e.price_integer as i128, 64)?;
        w.signed_magnitude(e.volume_delta as i128, 64)?;
        w.packed(e.auxiliary as i128, 64)?;
    }
    Ok(w.data)
}

/// Decode one record without assuming byte alignment between records.
pub fn decode_depth_record(data: &[u8]) -> Result<(DepthRecord, usize)> {
    let mut r = BitReader::new(data);
    let record = read_record(&mut r)?;
    Ok((record, r.position))
}

/// Decode all records. Only up to seven zero padding bits may follow the last.
pub fn decode_depth(data: &[u8]) -> Result<Vec<DepthRecord>> {
    let mut r = BitReader::new(data);
    let mut records = Vec::new();
    let mut entries = 0;
    while data.len() * 8 - r.position > 7 {
        let record = read_record(&mut r)?;
        entries += record.entries.len();
        if records.len() >= 1024 || entries > 100_000 {
            return Err(ProtocolError::new("depth batch exceeds limit"));
        }
        records.push(record);
    }
    if r.bits(data.len() * 8 - r.position)? != 0 {
        return Err(ProtocolError::new("nonzero trailing depth bits"));
    }
    Ok(records)
}

fn read_record(r: &mut BitReader) -> Result<DepthRecord> {
    let symbol_id = r.packed(32, true)? as i32;
    let opaque_header_a = r.packed(64, true)? as i64;
    let opaque_header_b = r.packed(64, false)? as u64;
    let count = r.packed(64, false)? as u64;
    if count > 100_000 {
        return Err(ProtocolError::new("implausible depth entry count"));
    }
    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        entries.push(DepthEntry {
            mask: r.packed(64, false)? as u64,
            entry_type: r.packed(8, false)? as u8,
            price_integer: r.packed(64, true)? as i64,
            volume_delta: r
                .signed_magnitude(64)?
                .try_into()
                .map_err(|_| ProtocolError::new("depth volume overflow"))?,
            auxiliary: r.packed(64, true)? as i64,
        });
    }
    Ok(DepthRecord {
        symbol_id,
        opaque_header_a,
        opaque_header_b,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_record() -> DepthRecord {
        DepthRecord {
            symbol_id: 7,
            opaque_header_a: 1700000000,
            opaque_header_b: 0,
            entries: vec![
                DepthEntry {
                    mask: 0,
                    entry_type: 1,
                    price_integer: 123460,
                    volume_delta: 10,
                    auxiliary: 0,
                },
                DepthEntry {
                    mask: 0,
                    entry_type: 2,
                    price_integer: 123450,
                    volume_delta: -3,
                    auxiliary: 0,
                },
            ],
        }
    }

    #[test]
    fn depth_record_round_trips() {
        let rec = fixture_record();
        let body = encode_depth_record(&rec).unwrap();
        let (back, _bits) = decode_depth_record(&body).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn positive_only_depth_matches_reader_widths() {
        // With no negative deltas the encoding is unambiguous; confirm the field
        // order and the projected header/entry values round-trip.
        let rec = DepthRecord {
            symbol_id: 7,
            opaque_header_a: 1700000000,
            opaque_header_b: 0,
            entries: vec![DepthEntry {
                mask: 0,
                entry_type: 1,
                price_integer: 123460,
                volume_delta: 10,
                auxiliary: 0,
            }],
        };
        let body = encode_depth_record(&rec).unwrap();
        assert_eq!(decode_depth_record(&body).unwrap().0, rec);
    }
    #[test]
    fn batch_keeps_unaligned_records_and_rejects_nonzero_padding() {
        let record = fixture_record();
        let encoded = encode_depth_record(&record).unwrap();
        let bits = decode_depth_record(&encoded).unwrap().1;
        let mut w = BitWriter::new();
        for _ in 0..2 {
            let mut r = BitReader::new(&encoded);
            for _ in 0..bits {
                w.bits(r.bits(1).unwrap() as u128, 1).unwrap();
            }
        }
        assert_eq!(decode_depth(&w.data).unwrap(), vec![record.clone(), record]);
        w.bits(1, 1).unwrap();
        assert!(decode_depth(&w.data).is_err());
    }

    #[test]
    fn broker_empty_book_reset_is_retained() {
        let records = decode_depth(&crate::hexutil::decode("f57f0bb9b56a550000")).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].symbol_id, 1);
        assert_eq!(records[0].entries.len(), 1);
        assert_eq!(records[0].entries[0].entry_type, 0);
        assert_eq!(records[0].entries[0].volume_delta, 0);
    }
}
