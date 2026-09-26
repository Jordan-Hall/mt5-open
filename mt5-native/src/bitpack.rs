//! Bit-level packed-integer codec used by the live/snapshot quote records.
//!
//! Bits are laid out LSB-first within each byte. A packed integer is a run of
//! `k`-bit unit digits (k=2) that sum to the number of 2-bit groups in the
//! value, terminated by the first non-`sentinel` digit, followed by that many
//! value bits. `strict_boundary` advances to the next byte boundary — and, when
//! already aligned, still consumes a full padding byte. That looks like a defect
//! and is not; it mirrors the observed consumer, so it is preserved exactly.

use crate::error::{ProtocolError, Result};

fn bitlen(v: u128) -> u32 {
    128 - v.leading_zeros()
}

pub struct BitReader<'a> {
    data: &'a [u8],
    limit: usize,
    pub position: usize,
    pub k: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            limit: data.len() * 8,
            position: 0,
            k: 2,
        }
    }
    pub fn with_position(data: &'a [u8], position: usize) -> Self {
        BitReader {
            data,
            limit: data.len() * 8,
            position,
            k: 2,
        }
    }

    pub fn with_limit(data: &'a [u8], limit: usize, k: usize) -> Result<Self> {
        if limit > data.len() * 8 || !(1..=8).contains(&k) {
            return Err(ProtocolError::new("invalid packed stream bounds"));
        }
        Ok(Self {
            data,
            limit,
            position: 0,
            k,
        })
    }

    pub fn bits(&mut self, count: usize) -> Result<u64> {
        if count > 64 || self.position.saturating_add(count) > self.limit {
            return Err(ProtocolError::new("truncated bit field"));
        }
        let mut value = 0u64;
        for i in 0..count {
            let p = self.position + i;
            value |= (((self.data[p / 8] >> (p % 8)) & 1) as u64) << i;
        }
        self.position += count;
        Ok(value)
    }

    /// Read a packed integer of the given storage `width`. When `signed`, the
    /// top storage bit is interpreted as a sign bit.
    fn prefix(&mut self, width: usize) -> Result<usize> {
        if !(1..=8).contains(&self.k) || !matches!(width, 8 | 16 | 32 | 64) {
            return Err(ProtocolError::new("unsupported packed width"));
        }
        let sentinel = (1u64 << self.k) - 1;
        let mut units = 0u64;
        loop {
            let digit = self.bits(self.k)?;
            units += digit;
            if 2 * units as usize > width {
                return Err(ProtocolError::new("packed integer exceeds storage width"));
            }
            if digit != sentinel {
                break;
            }
        }
        Ok(2 * units as usize)
    }

    pub fn signed_magnitude(&mut self, width: usize) -> Result<i128> {
        let length = self.prefix(width)?;
        let negative = self.bits(1)? != 0;
        let value = self.bits(length)? as i128;
        Ok(if negative { -value } else { value })
    }

    pub fn packed(&mut self, width: usize, signed: bool) -> Result<i128> {
        let length = self.prefix(width)?;
        let value = self.bits(length)? as u128;
        if signed && value & (1u128 << (width - 1)) != 0 {
            Ok(value as i128 - (1i128 << width))
        } else {
            Ok(value as i128)
        }
    }

    /// Consume to the next byte boundary (a full byte when already aligned),
    /// returning the number of padding bits and their value.
    pub fn strict_boundary(&mut self) -> Result<(usize, u64)> {
        let end = 8 * (self.position / 8 + 1);
        let count = end - self.position;
        let padding = self.bits(count)?;
        Ok((count, padding))
    }
}

#[derive(Default)]
pub struct BitWriter {
    pub data: Vec<u8>,
    pub position: usize,
    pub k: usize,
}

impl BitWriter {
    pub fn new() -> Self {
        BitWriter {
            data: Vec::new(),
            position: 0,
            k: 2,
        }
    }

    pub fn bits(&mut self, value: u128, count: usize) -> Result<()> {
        if bitlen(value) as usize > count {
            return Err(ProtocolError::new("value does not fit bit field"));
        }
        while self.data.len() * 8 < self.position + count {
            self.data.push(0);
        }
        for i in 0..count {
            let p = self.position + i;
            self.data[p / 8] |= (((value >> i) & 1) as u8) << (p % 8);
        }
        self.position += count;
        Ok(())
    }

    /// Write a packed integer into `width` storage bits.
    pub fn packed(&mut self, value: i128, width: usize) -> Result<()> {
        let lo = -(1i128 << (width - 1));
        let hi = 1i128 << width;
        if !(lo <= value && value < hi) {
            return Err(ProtocolError::new("integer out of range"));
        }
        let masked = (value as u128) & ((1u128 << width) - 1);
        let mut units = bitlen(masked).div_ceil(2) as u64;
        let length = 2 * units as usize;
        let sentinel = (1u64 << self.k) - 1;
        while units >= sentinel {
            self.bits(sentinel as u128, self.k)?;
            units -= sentinel;
        }
        self.bits(units as u128, self.k)?;
        self.bits(masked, length)?;
        Ok(())
    }

    pub fn signed_magnitude(&mut self, value: i128, width: usize) -> Result<()> {
        if !matches!(width, 8 | 16 | 32 | 64)
            || value.unsigned_abs() >= (1u128 << width)
            || !(1..=8).contains(&self.k)
        {
            return Err(ProtocolError::new("signed magnitude outside storage width"));
        }
        let magnitude = value.unsigned_abs();
        let mut units = bitlen(magnitude).div_ceil(2) as u64;
        let length = units as usize * 2;
        let sentinel = (1u64 << self.k) - 1;
        while units >= sentinel {
            self.bits(sentinel as u128, self.k)?;
            units -= sentinel;
        }
        self.bits(units as u128, self.k)?;
        self.bits(u128::from(value < 0), 1)?;
        self.bits(magnitude, length)
    }

    pub fn strict_boundary(&mut self) -> Result<()> {
        let count = 8 * (self.position / 8 + 1) - self.position;
        self.bits(0, count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hexutil::encode;

    #[test]
    fn packed_round_trips_all_widths() {
        for width in [8usize, 16, 32, 64] {
            let cases = [0i128, 1, 3, 4, (1i128 << width) - 1, 1i128 << (width - 1)];
            for value in cases {
                let mut w = BitWriter::new();
                w.packed(value, width).unwrap();
                let got = BitReader::new(&w.data).packed(width, false).unwrap();
                assert_eq!(got, value, "width {width} value {value}");
            }
        }
    }

    #[test]
    fn packed_signed_interpretation() {
        for width in [16usize, 32, 64] {
            let mut w = BitWriter::new();
            w.packed(-2, width).unwrap();
            assert_eq!(BitReader::new(&w.data).packed(width, true).unwrap(), -2);
        }
    }

    #[test]
    fn strict_alignment_inserts_full_byte() {
        let mut w = BitWriter::new();
        w.bits(5, 8).unwrap();
        w.strict_boundary().unwrap();
        assert_eq!(encode(&w.data), "0500");
        let mut r = BitReader::with_position(&w.data, 8);
        assert_eq!(r.strict_boundary().unwrap(), (8, 0));
    }
}
