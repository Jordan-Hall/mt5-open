//! Native M1 history containers. Public timeframes are aggregated by callers.
use crate::{
    bitpack::BitReader,
    error::{ProtocolError, Result},
    reader::Reader,
    records::Record,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub struct Bar {
    pub time: i64,
    pub open: f64,
    pub high: f64,
    pub low: f64,
    pub close: f64,
    pub tick_volume: u64,
    pub real_volume: u64,
    pub spread: i32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BarHistory {
    pub symbol: String,
    pub bars: Vec<Bar>,
}

fn container(r: &mut Reader, symbol: &str) -> Result<Vec<Bar>> {
    let bytes = r.take(129)?;
    let h = Record::new(bytes, 129)?;
    if i16::from_le_bytes(bytes[..2].try_into().unwrap()) != 129 || h.text(2, 64) != symbol {
        return Err(ProtocolError::new(
            "bar header does not match request symbol",
        ));
    }
    let size = h.i32(72);
    let bits = h.i32(80);
    let count = h.i32(84);
    let digits = i16::from_le_bytes(bytes[93..95].try_into().unwrap());
    let flags = u16::from_le_bytes(bytes[95..97].try_into().unwrap());
    if size < 0 || bits < 0 || count < 0 || count > 1_000_000 || !(0..=12).contains(&digits) {
        return Err(ProtocolError::new("invalid bar header bounds"));
    }
    if flags != 0 {
        return Err(ProtocolError::new(format!(
            "unsupported inner bar flags {flags}"
        )));
    }
    let mut b = BitReader::with_limit(r.take(size as usize)?, bits as usize, bytes[88] as usize)?;
    let limit = h.i32(97) as u32 as i128;
    let scale = 10f64.powi(digits as i32);
    let mut bars = Vec::new();
    let (mut time, mut open, mut close) = (0i128, 0i128, 0i128);
    let (mut anchor_flags, mut spread_on, mut real_on) = (0u64, false, false);
    let mut anchored = false;
    while bars.len() < count as usize {
        let tag = b.packed(64, true)?;
        if tag == 2 {
            if !anchored {
                return Err(ProtocolError::new("bar skip before anchor"));
            }
            time += 60 * b.packed(64, true)?;
            continue;
        }
        let run = match tag {
            0 => {
                anchor_flags = b.packed(64, false)? as u64;
                if anchor_flags & 4 != 0 {
                    return Err(ProtocolError::new("unsupported bar anchor flag 4"));
                }
                spread_on |= anchor_flags & 1 != 0;
                real_on |= anchor_flags & 2 != 0;
                time = b.packed(64, true)?;
                open = b.signed_magnitude(64)? as i32 as i128;
                anchored = true;
                1
            }
            1 if anchored => b.packed(64, true)?,
            _ => return Err(ProtocolError::new("invalid bar tag or missing anchor")),
        };
        if run <= 0 || run as usize > count as usize - bars.len() {
            return Err(ProtocolError::new("bar run exceeds declared count"));
        }
        for _ in 0..run {
            if tag == 1 {
                time += 60;
                open += limit * b.signed_magnitude(64)? + close;
            }
            let multiplier = if tag == 0 { 1 } else { limit };
            let high = (multiplier * b.packed(32, true)?) as i32 as i128;
            let low = (multiplier * b.packed(32, true)?) as i32 as i128;
            close =
                (multiplier * b.signed_magnitude(if tag == 0 { 32 } else { 64 })?) as i32 as i128;
            let tick_volume = b.packed(64, false)? as u64;
            let spread = if (tag == 0 && anchor_flags & 1 != 0) || (tag == 1 && spread_on) {
                b.signed_magnitude(32)? as i32
            } else {
                0
            };
            let real_volume = if (tag == 0 && anchor_flags & 2 != 0) || (tag == 1 && real_on) {
                b.packed(64, false)? as u64
            } else {
                0
            };
            for bit in 3..64 {
                if anchor_flags & (1u64 << bit) != 0 {
                    b.packed(64, false)?;
                }
            }
            bars.push(Bar {
                time: time
                    .try_into()
                    .map_err(|_| ProtocolError::new("bar timestamp overflow"))?,
                open: open as f64 / scale,
                high: (open + high) as f64 / scale,
                low: (open - low) as f64 / scale,
                close: (open + close) as f64 / scale,
                tick_volume,
                real_volume,
                spread,
            });
        }
    }
    Ok(bars)
}

pub fn decode_bar_history(bytes: &[u8]) -> Result<Vec<BarHistory>> {
    let mut r = Reader::new(bytes);
    let mut results = Vec::new();
    while !r.remaining.is_empty() {
        let subtype = r.byte()?;
        let symbol = Record::new(r.take(64)?, 64)?.text(0, 64);
        let status = r.i32()?;
        let containers = match (subtype, status) {
            (9, 0) => r.u16()? as usize,
            (14, 1) => 0,
            (14, 0) => {
                r.u16()?;
                if r.u16()? != 0 {
                    return Err(ProtocolError::new("unsupported bar history mode"));
                }
                1
            }
            _ => {
                return Err(ProtocolError::new(format!(
                    "bar history subtype {subtype} status {status}"
                )));
            }
        };
        let mut bars = BTreeMap::new();
        for _ in 0..containers {
            for bar in container(&mut r, &symbol)? {
                bars.insert(bar.time, bar);
            }
        }
        results.push(BarHistory {
            symbol,
            bars: bars.into_values().collect(),
        });
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitpack::BitWriter;

    fn signed(w: &mut BitWriter, value: i128) {
        let magnitude = value.unsigned_abs();
        let length = (128 - magnitude.leading_zeros()).div_ceil(2) as usize * 2;
        let mut units = length / 2;
        while units >= 3 {
            w.bits(3, 2).unwrap();
            units -= 3;
        }
        w.bits(units as u128, 2).unwrap();
        w.bits(u128::from(value < 0), 1).unwrap();
        w.bits(magnitude, length).unwrap();
    }

    fn fixture() -> Vec<u8> {
        let mut w = BitWriter::new();
        for value in [0, 1, 600] {
            w.packed(value, 64).unwrap();
        }
        signed(&mut w, 10000);
        for value in [20, 10] {
            w.packed(value, 32).unwrap();
        }
        signed(&mut w, -3);
        w.packed(9, 64).unwrap();
        signed(&mut w, 2);
        w.packed(1, 64).unwrap();
        w.packed(1, 64).unwrap();
        signed(&mut w, 5);
        for value in [12, 8] {
            w.packed(value, 32).unwrap();
        }
        signed(&mut w, -2);
        w.packed(11, 64).unwrap();
        signed(&mut w, 3);
        let mut name = [0; 64];
        name[..2].copy_from_slice(&('X' as u16).to_le_bytes());
        let mut header = [0; 129];
        header[..2].copy_from_slice(&129i16.to_le_bytes());
        header[2..66].copy_from_slice(&name);
        header[72..76].copy_from_slice(&(w.data.len() as i32).to_le_bytes());
        header[80..84].copy_from_slice(&(w.position as i32).to_le_bytes());
        header[84..88].copy_from_slice(&2i32.to_le_bytes());
        header[88] = 2;
        header[93..95].copy_from_slice(&2i16.to_le_bytes());
        header[97] = 1;
        let mut bytes = vec![9];
        bytes.extend(name);
        bytes.extend(0i32.to_le_bytes());
        bytes.extend(1u16.to_le_bytes());
        bytes.extend(header);
        bytes.extend(w.data);
        bytes
    }

    #[test]
    fn negative_close_deltas_and_sticky_spread_are_preserved() {
        let rows = decode_bar_history(&fixture()).unwrap().remove(0).bars;
        assert_eq!(
            rows[0],
            Bar {
                time: 600,
                open: 100.0,
                high: 100.2,
                low: 99.9,
                close: 99.97,
                tick_volume: 9,
                real_volume: 0,
                spread: 2
            }
        );
        assert_eq!(
            rows[1],
            Bar {
                time: 660,
                open: 100.02,
                high: 100.14,
                low: 99.94,
                close: 100.0,
                tick_volume: 11,
                real_volume: 0,
                spread: 3
            }
        );
    }

    #[test]
    fn truncated_history_and_unknown_inner_compression_are_errors() {
        let bytes = fixture();
        for end in 1..bytes.len() {
            assert!(
                decode_bar_history(&bytes[..end]).is_err(),
                "accepted truncation at {end}"
            );
        }
        let mut bytes = bytes;
        bytes[71 + 95] = 1;
        assert!(
            decode_bar_history(&bytes)
                .unwrap_err()
                .to_string()
                .contains("inner bar flags")
        );
    }
}
