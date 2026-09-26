//! Quote-history containers: per-column compressed blocks and trailing-hour
//! segments.
//!
//! A column group is a 52-byte container header, then fixed 36-byte column
//! descriptors, then each column's DEFLATE block. Columns are projected onto a
//! row table by column id. Duplicate column IDs keep the first occurrence;
//! unknown column encodings are not assumed to be DEFLATE and are
//! retained as opaque encoded bytes. The declared inflate size is advisory;
//! the tick count in the container header governs how many rows exist.

use std::collections::{BTreeMap, HashSet};

use crate::compression::{deflate, inflate_inner};
use crate::error::{ProtocolError, Result};

const U64: u128 = (1u128 << 64) - 1;
const MAX_TICKS: usize = 1_000_000;
const MAX_BYTES: usize = 16 * 1024 * 1024;

fn wrap_i64(x: i128) -> i128 {
    ((x + (1i128 << 63)) as u128 & U64) as i128 - (1i128 << 63)
}

/// Sequential byte reader with a tracked position.
pub struct ByteReader<'a> {
    data: &'a [u8],
    pub position: usize,
}

impl<'a> ByteReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        ByteReader { data, position: 0 }
    }
    pub fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(size)
            .ok_or_else(|| ProtocolError::new("byte field size overflow"))?;
        let out = self
            .data
            .get(self.position..end)
            .ok_or_else(|| ProtocolError::new("truncated byte field"))?;
        self.position = end;
        Ok(out)
    }
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn i32_at(b: &[u8], o: usize) -> i32 {
    i32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

#[derive(Debug, Clone, PartialEq)]
pub struct Descriptor {
    pub word0: u32,
    pub compressed_size: u32,
    pub inflate_size: u32,
    pub column_id: i32,
    pub descriptor_hex: String,
    pub decoded: Vec<u8>,
    /// Unknown columns retain their original encoding until its grammar is known.
    pub encoded: Vec<u8>,
    pub compression: &'static str,
    /// Whether this column was projected onto the row table. Duplicate and
    /// unknown column ids are decoded but not projected, and — mirroring the
    /// observed consumer — carry no `unused_tail`.
    pub projected: bool,
    pub unused_tail: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Row {
    pub time_ms: Option<i128>,
    pub bid: Option<f64>,
    pub ask: Option<f64>,
    pub last: Option<f64>,
    pub volume: Option<i128>,
    pub auxiliary_64: Option<i128>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ColumnGroup {
    pub tick_count: usize,
    pub rows: Vec<Row>,
    pub descriptors: Vec<Descriptor>,
    pub compressed_bytes: u64,
    pub compressed_limit: u32,
    pub raw_header: Vec<u8>,
}

/// Decode a column group at the reader's current position.
pub fn read_column_group(reader: &mut ByteReader) -> Result<ColumnGroup> {
    read_column_group_limited(reader, MAX_TICKS, MAX_BYTES)
}

pub fn read_column_group_limited(
    reader: &mut ByteReader,
    max_ticks: usize,
    max_bytes: usize,
) -> Result<ColumnGroup> {
    let raw_header = reader.take(52)?.to_vec();
    let compressed_limit = u32_at(&raw_header, 4);
    let tick_count = u32_at(&raw_header, 8) as usize;
    let descriptor_count = i32_at(&raw_header, 48);
    if tick_count > max_ticks || !(0..=4096).contains(&descriptor_count) {
        return Err(ProtocolError::new("group count exceeds configured limit"));
    }

    let mut descriptors = Vec::with_capacity(descriptor_count as usize);
    for _ in 0..descriptor_count {
        let raw = reader.take(36)?;
        descriptors.push(Descriptor {
            word0: u32_at(raw, 0),
            compressed_size: u32_at(raw, 4),
            inflate_size: u32_at(raw, 8),
            column_id: i32_at(raw, 12),
            descriptor_hex: crate::hexutil::encode(raw),
            decoded: Vec::new(),
            encoded: Vec::new(),
            compression: "",
            projected: false,
            unused_tail: Vec::new(),
        });
    }

    let mut compressed_sum: u64 = 0;
    let mut inflated_sum: usize = 0;
    for d in descriptors.iter_mut() {
        compressed_sum += d.compressed_size as u64;
        if compressed_sum > compressed_limit as u64 {
            return Err(ProtocolError::new("compressed byte limit exceeded"));
        }
        let compressed = reader.take(d.compressed_size as usize)?;
        if !matches!(d.column_id, 1 | 2 | 4 | 8 | 16 | 64) {
            d.encoded = compressed.to_vec();
            d.compression = "opaque";
            continue;
        }
        let budget = max_bytes.saturating_sub(inflated_sum);
        let (decoded, fmt) = inflate_inner(compressed, budget)?;
        inflated_sum += decoded.len();
        d.decoded = decoded;
        d.compression = fmt;
    }

    let mut rows = vec![Row::default(); tick_count];
    let mut used: HashSet<i32> = HashSet::new();
    for d in descriptors.iter_mut() {
        let cid = d.column_id;
        if used.contains(&cid) || !matches!(cid, 1 | 2 | 4 | 8 | 16 | 64) {
            continue;
        }
        used.insert(cid);
        d.projected = true;
        let buf = &d.decoded;
        if buf.len() < tick_count * 8 {
            return Err(ProtocolError::new(
                "column shorter than eight bytes per tick",
            ));
        }
        let mut previous = 0i128;
        for i in 0..tick_count {
            let chunk: [u8; 8] = buf[i * 8..i * 8 + 8].try_into().unwrap();
            match cid {
                1 => {
                    let v = i64::from_le_bytes(chunk) as i128;
                    let cumulative = wrap_i64(previous + v);
                    previous = cumulative;
                    rows[i].time_ms = Some(cumulative);
                }
                2 => rows[i].bid = Some(f64::from_le_bytes(chunk)),
                4 => rows[i].ask = Some(f64::from_le_bytes(chunk)),
                8 => rows[i].last = Some(f64::from_le_bytes(chunk)),
                16 => rows[i].volume = Some(u64::from_le_bytes(chunk) as i128),
                64 => rows[i].auxiliary_64 = Some(u64::from_le_bytes(chunk) as i128),
                _ => unreachable!(),
            }
        }
        d.unused_tail = buf[tick_count * 8..].to_vec();
    }

    Ok(ColumnGroup {
        tick_count,
        rows,
        descriptors,
        compressed_bytes: compressed_sum,
        compressed_limit,
        raw_header,
    })
}

/// Column values for [`make_column_group`], typed per the column id.
#[derive(Debug, Clone)]
pub enum ColumnValues {
    F64(Vec<f64>),
    I64(Vec<i64>),
    U64(Vec<u64>),
}

/// Build a column group. Column ids 2/4/8 take doubles, 1 takes i64, others u64.
pub fn make_column_group(
    columns: &[(i32, ColumnValues)],
    count: u32,
    raw: bool,
    word0: u32,
) -> Vec<u8> {
    let mut headers = Vec::new();
    let mut blocks = Vec::new();
    for (cid, values) in columns {
        let decoded: Vec<u8> = match (cid, values) {
            (_, ColumnValues::F64(v)) => v.iter().flat_map(|x| x.to_le_bytes()).collect(),
            (_, ColumnValues::I64(v)) => v.iter().flat_map(|x| x.to_le_bytes()).collect(),
            (_, ColumnValues::U64(v)) => v.iter().flat_map(|x| x.to_le_bytes()).collect(),
        };
        let compressed = deflate(&decoded, raw);
        let mut h = Vec::with_capacity(36);
        h.extend_from_slice(&word0.to_le_bytes());
        h.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        h.extend_from_slice(&(decoded.len() as u32).to_le_bytes());
        h.extend_from_slice(&cid.to_le_bytes());
        h.extend_from_slice(&[0u8; 20]);
        headers.push(h);
        blocks.push(compressed);
    }
    let compressed_sum: usize = blocks.iter().map(|b| b.len()).sum();
    let mut header = vec![0u8; 52];
    header[4..8].copy_from_slice(&(compressed_sum as u32).to_le_bytes());
    header[8..12].copy_from_slice(&count.to_le_bytes());
    header[48..52].copy_from_slice(&(headers.len() as i32).to_le_bytes());
    let mut out = header;
    for h in &headers {
        out.extend_from_slice(h);
    }
    for b in &blocks {
        out.extend_from_slice(b);
    }
    out
}

#[derive(Debug, Clone, PartialEq)]
pub struct TrailingHours {
    pub header: Vec<u8>,
    pub hours: Vec<(usize, ColumnGroup)>,
    pub indices: Vec<Vec<u8>>,
    pub skipped_nonhour_header: bool,
}

/// Decode a trailing-hour segment. When header flag bit 1 is unset, the segment
/// is a non-hour header and no hour groups follow (observed consumer gate).
pub fn read_trailing_hour_segment(reader: &mut ByteReader) -> Result<TrailingHours> {
    let header = reader.take(115)?.to_vec();
    let flags = u16::from_le_bytes([header[93], header[94]]);
    if flags & 2 == 0 {
        return Ok(TrailingHours {
            header,
            hours: Vec::new(),
            indices: Vec::new(),
            skipped_nonhour_header: true,
        });
    }
    let mut indices = Vec::with_capacity(24);
    for _ in 0..24 {
        indices.push(reader.take(16)?.to_vec());
    }
    let mut hours = Vec::new();
    for (index, raw) in indices.iter().enumerate() {
        if u32_at(raw, 4) > 0 {
            let group = read_column_group(reader)?;
            hours.push((index, group));
        }
    }
    Ok(TrailingHours {
        header,
        hours,
        indices,
        skipped_nonhour_header: false,
    })
}

/// Build a trailing-hour segment from per-hour column-group bytes.
pub fn make_trailing_hour_segment(groups: &BTreeMap<u8, Vec<u8>>) -> Result<Vec<u8>> {
    if groups.keys().any(|&h| h >= 24) {
        return Err(ProtocolError::new("hour index outside 0..23"));
    }
    let mut header = vec![0u8; 115];
    header[0..2].copy_from_slice(&115u16.to_le_bytes());
    header[93..95].copy_from_slice(&2u16.to_le_bytes());
    let mut out = header;
    for i in 0..24u8 {
        let present = if groups.contains_key(&i) { 1u32 } else { 0 };
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&present.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
    }
    for body in groups.values() {
        out.extend_from_slice(body);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bid(values: Vec<f64>) -> (i32, ColumnValues) {
        (2, ColumnValues::F64(values))
    }

    #[test]
    fn column_selector_and_bid_projection() {
        let body = make_column_group(&[bid(vec![1.5, 2.5])], 2, false, 1);
        assert_eq!(u32_at(&body, 52), 1); // word0
        assert_eq!(i32_at(&body, 64), 2); // column id
        let g = read_column_group(&mut ByteReader::new(&body)).unwrap();
        assert_eq!(
            g.rows.iter().map(|r| r.bid).collect::<Vec<_>>(),
            vec![Some(1.5), Some(2.5)]
        );
        assert_eq!(
            g.rows.iter().map(|r| r.time_ms).collect::<Vec<_>>(),
            vec![None, None]
        );
    }

    #[test]
    fn time_is_cumulative_i64() {
        let body = make_column_group(
            &[(1, ColumnValues::I64(vec![1700000000000, 123, -23]))],
            3,
            false,
            0,
        );
        let g = read_column_group(&mut ByteReader::new(&body)).unwrap();
        assert_eq!(
            g.rows.iter().map(|r| r.time_ms).collect::<Vec<_>>(),
            vec![
                Some(1700000000000),
                Some(1700000000123),
                Some(1700000000100)
            ]
        );
    }

    #[test]
    fn price_and_volume_and_aux() {
        let body = make_column_group(
            &[
                (2, ColumnValues::F64(vec![1.2345, 1.2346])),
                (4, ColumnValues::F64(vec![1.2347, 1.2348])),
                (8, ColumnValues::F64(vec![1.2346, 1.2347])),
                (16, ColumnValues::U64(vec![42, (1u64 << 63) + 17])),
                (64, ColumnValues::U64(vec![7, 8])),
            ],
            2,
            false,
            0,
        );
        let g = read_column_group(&mut ByteReader::new(&body)).unwrap();
        assert_eq!(g.rows[0].bid, Some(1.2345));
        assert_eq!(g.rows[1].ask, Some(1.2348));
        assert_eq!(g.rows[1].last, Some(1.2347));
        assert_eq!(g.rows[1].volume, Some((1i128 << 63) + 17));
        assert_eq!(g.rows[1].auxiliary_64, Some(8));
    }

    #[test]
    fn raw_deflate_fallback() {
        let body = make_column_group(&[bid(vec![1.5, 2.5])], 2, true, 0);
        let g = read_column_group(&mut ByteReader::new(&body)).unwrap();
        assert_eq!(g.descriptors[0].compression, "raw_deflate");
        assert_eq!(g.rows[1].bid, Some(2.5));
    }

    #[test]
    fn duplicate_column_first_wins_and_unknown_preserved() {
        let dup = make_column_group(
            &[
                (2, ColumnValues::F64(vec![1.5])),
                (2, ColumnValues::F64(vec![9.5])),
            ],
            1,
            false,
            0,
        );
        let g = read_column_group(&mut ByteReader::new(&dup)).unwrap();
        assert_eq!(g.rows[0].bid, Some(1.5));
        assert_eq!(g.descriptors.len(), 2);

        let unknown = make_column_group(&[(99, ColumnValues::U64(vec![17]))], 1, false, 0);
        let g = read_column_group(&mut ByteReader::new(&unknown)).unwrap();
        assert_eq!(g.descriptors[0].compression, "opaque");
        assert_eq!(
            inflate_inner(&g.descriptors[0].encoded, 8).unwrap().0,
            17u64.to_le_bytes()
        );
        let r = &g.rows[0];
        assert!(
            r.time_ms.is_none()
                && r.bid.is_none()
                && r.volume.is_none()
                && r.auxiliary_64.is_none()
        );
    }

    #[test]
    fn tail_preserved_and_short_column_rejected() {
        let body = make_column_group(&[(2, ColumnValues::F64(vec![1.5, 9.5]))], 1, false, 0);
        let g = read_column_group(&mut ByteReader::new(&body)).unwrap();
        assert_eq!(g.descriptors[0].unused_tail, 9.5f64.to_le_bytes());
        // Two ticks declared but one value present -> short column.
        let short = make_column_group(&[(2, ColumnValues::F64(vec![1.5]))], 2, false, 0);
        assert!(read_column_group(&mut ByteReader::new(&short)).is_err());
    }

    #[test]
    fn inflation_budget_enforced() {
        let body = make_column_group(&[(2, ColumnValues::F64(vec![1.5; 1000]))], 1000, false, 0);
        assert!(read_column_group_limited(&mut ByteReader::new(&body), MAX_TICKS, 100).is_err());
    }

    #[test]
    fn trailing_hours_independent_and_empty() {
        let mut groups = BTreeMap::new();
        groups.insert(0u8, make_column_group(&[bid(vec![1.5])], 1, false, 0));
        groups.insert(
            23u8,
            make_column_group(&[bid(vec![9.5, 10.5])], 2, false, 0),
        );
        let packet = make_trailing_hour_segment(&groups).unwrap();
        let mut reader = ByteReader::new(&packet);
        let decoded = read_trailing_hour_segment(&mut reader).unwrap();
        assert_eq!(
            decoded.hours.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            vec![0, 23]
        );
        assert_eq!(decoded.hours[1].1.rows[0].bid, Some(9.5));
        assert_eq!(reader.position, packet.len());

        let empty = make_trailing_hour_segment(&BTreeMap::new()).unwrap();
        let decoded = read_trailing_hour_segment(&mut ByteReader::new(&empty)).unwrap();
        assert!(decoded.hours.is_empty());
        assert_eq!(empty.len(), 115 + 24 * 16);
    }
}
