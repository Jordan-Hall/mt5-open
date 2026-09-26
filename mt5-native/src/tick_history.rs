//! Native tick-history responses, with counted containers and trailing hours.
use crate::{
    bitpack::BitReader,
    error::{ProtocolError, Result},
    history::{ByteReader, Descriptor, Row, read_column_group_limited},
    records::Record,
};

const MAX_TICKS: usize = 1_000_000;
const MAX_EXPANSION: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickCache {
    pub date: u16,
    pub time: i32,
    pub size: i32,
    pub flags: u16,
    pub crc: u32,
}
#[derive(Debug, Clone)]
pub struct TickContainer {
    pub cache: TickCache,
    pub ticks: Vec<Row>,
    pub extensions: Vec<TickExtension>,
}
#[derive(Debug, Clone)]
pub struct TickExtension {
    pub hour: Option<u8>,
    pub column: Descriptor,
}
#[derive(Debug, Clone)]
pub struct TickHistory {
    pub symbol: String,
    pub more: bool,
    pub containers: Vec<TickContainer>,
    pub trailing: Vec<TickContainer>,
}

struct Budget {
    ticks: usize,
    bytes: usize,
}

fn group(
    reader: &mut ByteReader,
    budget: &mut Budget,
    hour: Option<u8>,
    extensions: &mut Vec<TickExtension>,
) -> Result<Vec<Row>> {
    let group = read_column_group_limited(reader, budget.ticks, budget.bytes)?;
    budget.ticks -= group.rows.len();
    budget.bytes -= group
        .descriptors
        .iter()
        .map(|d| d.decoded.len())
        .sum::<usize>();
    extensions.extend(
        group
            .descriptors
            .into_iter()
            .filter(|d| !d.projected || !d.unused_tail.is_empty())
            .map(|column| TickExtension { hour, column }),
    );
    Ok(group.rows)
}

fn container(reader: &mut ByteReader, symbol: &str, budget: &mut Budget) -> Result<TickContainer> {
    let bytes = reader.take(115)?;
    let h = Record::new(bytes, 115)?;
    let header_size = u16::from_le_bytes(bytes[..2].try_into().unwrap());
    let flags = u16::from_le_bytes(bytes[93..95].try_into().unwrap());
    if h.text(2, 64) != symbol || !matches!(header_size, 115 | 499) {
        return Err(ProtocolError::new(
            "tick history container identity/size mismatch",
        ));
    }
    let count = h.i32(82);
    let size = h.i32(70);
    if count < 0 || count as usize > budget.ticks || size < 0 {
        return Err(ProtocolError::new("tick history container bounds exceeded"));
    }
    let cache = TickCache {
        date: u16::from_le_bytes(bytes[66..68].try_into().unwrap()),
        time: h.i32(87),
        size,
        flags,
        crc: h.i32(103) as u32,
    };
    let digits = u16::from_le_bytes(bytes[91..93].try_into().unwrap());
    let body_start = reader.position;
    let mut extensions = Vec::new();
    let ticks = if flags & 2 != 0 {
        let indices = reader.take(24 * 16)?.to_vec();
        let mut ticks = Vec::new();
        for (hour, index) in indices.chunks_exact(16).enumerate() {
            if u32::from_le_bytes(index[4..8].try_into().unwrap()) != 0 {
                ticks.extend(group(reader, budget, Some(hour as u8), &mut extensions)?);
            }
        }
        ticks
    } else if flags & 4 != 0 {
        group(reader, budget, None, &mut extensions)?
    } else {
        if flags & 1 != 0 || digits > 12 {
            return Err(ProtocolError::new(
                "unsupported packed tick compression/precision",
            ));
        }
        let data = reader.take(size as usize)?;
        let mut bits = BitReader::with_limit(
            data,
            h.i32(78)
                .try_into()
                .map_err(|_| ProtocolError::new("negative tick bit count"))?,
            bytes[86] as usize,
        )?;
        let scale = 10f64.powi(digits as i32);
        let mut ticks = Vec::with_capacity(count as usize);
        for _ in 0..count {
            if bits.packed(64, true)? != 5 {
                return Err(ProtocolError::new("unsupported packed tick tag"));
            }
            let time_ms = bits.packed(64, true)?;
            let bid = bits.signed_magnitude(64)? as f64 / scale;
            let ask = bits.signed_magnitude(64)? as f64 / scale;
            let last = bits.signed_magnitude(64)? as f64 / scale;
            let whole = bits.packed(64, false)? as u64;
            let auxiliary_64 = bits.packed(64, false)?;
            bits.packed(32, false)?;
            bits.signed_magnitude(8)?;
            let fraction = bits.packed(64, false)? as u64;
            ticks.push(Row {
                time_ms: Some(time_ms),
                bid: Some(bid),
                ask: Some(ask),
                last: Some(last),
                volume: Some(whole.wrapping_mul(100_000_000).wrapping_add(fraction) as i128),
                auxiliary_64: Some(auxiliary_64),
            });
        }
        budget.ticks -= ticks.len();
        ticks
    };
    let consumed = reader.position - body_start - if flags & 2 != 0 { 384 } else { 0 };
    if consumed != size as usize {
        return Err(ProtocolError::new("tick container data size mismatch"));
    }
    if ticks.len() != count as usize {
        return Err(ProtocolError::new("tick history count mismatch"));
    }
    Ok(TickContainer {
        cache,
        ticks,
        extensions,
    })
}

pub fn decode_tick_history(bytes: &[u8]) -> Result<TickHistory> {
    let mut reader = ByteReader::new(bytes);
    let status = i32::from_le_bytes(reader.take(4)?.try_into().unwrap());
    if !matches!(status, 0 | 14) || reader.take(1)? != [14] {
        return Err(ProtocolError::new(format!(
            "unsupported tick history status {status}"
        )));
    }
    let symbol = Record::new(reader.take(64)?, 64)?.text(0, 64);
    reader.take(16)?;
    let count = i32::from_le_bytes(reader.take(4)?.try_into().unwrap());
    if !(0..=4096).contains(&count) {
        return Err(ProtocolError::new("tick history container count exceeded"));
    }
    let mut budget = Budget {
        ticks: MAX_TICKS,
        bytes: MAX_EXPANSION,
    };
    let mut containers = Vec::new();
    for _ in 0..count {
        containers.push(container(&mut reader, &symbol, &mut budget)?);
    }
    let mut trailing = Vec::new();
    for _ in 0..2 {
        if reader.position < bytes.len() {
            trailing.push(container(&mut reader, &symbol, &mut budget)?);
        }
    }
    if reader.position != bytes.len() {
        return Err(ProtocolError::new("trailing tick history bytes"));
    }
    Ok(TickHistory {
        symbol,
        more: status == 14,
        containers,
        trailing,
    })
}

/// Prices carried forward when a sparse tick omits an unchanged field.
/// Volume stays in the protocol's integer units; no lot conversion is implied.
#[derive(Debug, Clone, PartialEq)]
pub struct HistoricalTick {
    pub time_ms: i64,
    pub bid: f64,
    pub ask: f64,
    pub last: f64,
    pub volume_units: u64,
    pub flags: u64,
}

pub fn materialize_ticks<'a>(
    rows: impl IntoIterator<Item = &'a Row>,
) -> Result<Vec<HistoricalTick>> {
    let mut prices = [0.0; 3];
    let mut volume = 0;
    let mut output = Vec::new();
    for row in rows {
        let flags: u64 = row
            .auxiliary_64
            .ok_or_else(|| ProtocolError::new("tick flags absent"))?
            .try_into()
            .map_err(|_| ProtocolError::new("tick flags overflow"))?;
        for (i, value) in [row.bid, row.ask, row.last].into_iter().enumerate() {
            if let Some(value) = value {
                if !value.is_finite() {
                    return Err(ProtocolError::new("non-finite historical price"));
                }
                if value != 0.0 || flags & (2 << i) != 0 {
                    prices[i] = value;
                }
            }
        }
        if let Some(value) = row.volume {
            if value != 0 || flags & 16 != 0 {
                volume = value
                    .try_into()
                    .map_err(|_| ProtocolError::new("tick volume overflow"))?;
            }
        }
        output.push(HistoricalTick {
            time_ms: row
                .time_ms
                .ok_or_else(|| ProtocolError::new("tick timestamp absent"))?
                .try_into()
                .map_err(|_| ProtocolError::new("tick timestamp overflow"))?,
            bid: prices[0],
            ask: prices[1],
            last: prices[2],
            volume_units: volume,
            flags,
        });
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::{ColumnValues, make_column_group};
    fn packet() -> Vec<u8> {
        let group = make_column_group(
            &[
                (1, ColumnValues::I64(vec![1000, 5])),
                (2, ColumnValues::F64(vec![1.2, 0.0])),
                (4, ColumnValues::F64(vec![1.3, 1.4])),
                (64, ColumnValues::U64(vec![6, 4])),
            ],
            2,
            false,
            0,
        );
        let mut bytes = vec![0; 89];
        bytes[4] = 14;
        bytes[5..7].copy_from_slice(&('X' as u16).to_le_bytes());
        bytes[85..89].copy_from_slice(&1i32.to_le_bytes());
        let mut header = [0; 115];
        header[..2].copy_from_slice(&115u16.to_le_bytes());
        header[2..4].copy_from_slice(&('X' as u16).to_le_bytes());
        header[70..74].copy_from_slice(&(group.len() as i32).to_le_bytes());
        header[82..86].copy_from_slice(&2i32.to_le_bytes());
        header[93] = 4;
        bytes.extend(header);
        bytes.extend(group);
        bytes
    }
    #[test]
    fn sparse_prices_keep_unchanged_values_and_duplicate_timestamps() {
        let mut response = decode_tick_history(&packet()).unwrap();
        response.containers[0].ticks[1].time_ms = Some(1000);
        let rows = materialize_ticks(&response.containers[0].ticks).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].bid, 1.2);
        assert_eq!(rows[1].ask, 1.4);
        assert_eq!(rows[1].time_ms, 1000);
        response.containers[0].ticks[1].auxiliary_64 = Some(6);
        assert_eq!(
            materialize_ticks(&response.containers[0].ticks).unwrap()[1].bid,
            0.0
        );
    }
    #[test]
    fn truncated_and_wrong_identity_containers_fail() {
        let bytes = packet();
        for end in 0..bytes.len() {
            assert!(decode_tick_history(&bytes[..end]).is_err(), "{end}");
        }
        let mut bad = bytes.clone();
        bad[91] = b'Y';
        assert!(decode_tick_history(&bad).is_err());
        let mut bad = bytes;
        bad[171] = 3;
        assert!(decode_tick_history(&bad).is_err());
    }
}
