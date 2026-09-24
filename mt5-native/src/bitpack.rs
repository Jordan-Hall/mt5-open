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
    pub position: usize,
    pub k: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        BitReader { data, position: 0, k: 2 }
    }
    pub fn with_position(data: &'a [u8], position: usize) -> Self {
        BitReader { data, position, k: 2 }
    }

    pub fn bits(&mut self, count: usize) -> Result<u64> {
        if count > 64 {
            return Err(ProtocolError::new("bit field exceeds 64 bits"));
        }
        let end = self.position.checked_add(count)
            .ok_or_else(|| ProtocolError::new("bit position overflow"))?;
        if end.div_ceil(8) > self.data.len() {
            return Err(ProtocolError::new("truncated bit field"));
        }
        let mut value = 0u64;
        let mut written = 0;
        while self.position < end {
            let offset = self.position % 8;
            let count = (end - self.position).min(8 - offset);
            let mask = (1u16 << count) - 1;
            value |= (((self.data[self.position / 8] >> offset) as u16 & mask) as u64) << written;
            self.position += count;
            written += count;
        }
        Ok(value)
    }

    /// Read a packed integer of the given storage `width`. When `signed`, the
    /// top storage bit is interpreted as a sign bit.
    pub fn packed(&mut self, width: usize, signed: bool) -> Result<i128> {
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
        let value = self.bits(2 * units as usize)? as u128;
        if signed && value & (1u128 << (width - 1)) != 0 {
            Ok(value as i128 - (1i128 << width))
        } else {
            Ok(value as i128)
        }
    }

    /// Consume to the next byte boundary (a full byte when already aligned),
    /// returning the number of padding bits and their value.
    pub fn strict_boundary(&mut self) -> Result<(usize, u64)> {
        let count = 8 - self.position % 8;
        let padding = self.bits(count)?;
        Ok((count, padding))
    }
}

pub struct BitWriter {
    pub data: Vec<u8>,
    pub position: usize,
    pub k: usize,
}

impl Default for BitWriter {
    fn default() -> Self { Self::new() }
}

impl BitWriter {
    pub fn new() -> Self {
        BitWriter { data: Vec::new(), position: 0, k: 2 }
    }

    pub fn bits(&mut self, value: u128, count: usize) -> Result<()> {
        if count > 128 || bitlen(value) as usize > count {
            return Err(ProtocolError::new("value does not fit bit field"));
        }
        let end = self.position.checked_add(count)
            .ok_or_else(|| ProtocolError::new("bit position overflow"))?;
        if self.position.div_ceil(8) > self.data.len() {
            return Err(ProtocolError::new("bit position exceeds buffer"));
        }
        self.data.resize(self.data.len().max(end.div_ceil(8)), 0);
        let mut consumed = 0;
        while self.position < end {
            let offset = self.position % 8;
            let count = (end - self.position).min(8 - offset);
            let mask = (((1u16 << count) - 1) << offset) as u8;
            let byte = &mut self.data[self.position / 8];
            *byte = (*byte & !mask) | ((((value >> consumed) as u8) << offset) & mask);
            self.position += count;
            consumed += count;
        }
        Ok(())
    }

    /// Write a packed integer into `width` storage bits.
    pub fn packed(&mut self, value: i128, width: usize) -> Result<()> {
        if !(1..=8).contains(&self.k) || !matches!(width, 8 | 16 | 32 | 64) {
            return Err(ProtocolError::new("unsupported packed width"));
        }
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

    pub fn strict_boundary(&mut self) -> Result<()> {
        let count = 8 - self.position % 8;
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

#[cfg(test)]
mod regression_tests {
    use super::*;

    #[test]
    fn default_writer_has_valid_radix_and_terminates() {
        let mut w = BitWriter::default();
        assert_eq!(w.k, 2);
        w.packed(123, 16).unwrap();
        assert_eq!(BitReader::new(&w.data).packed(16, false).unwrap(), 123);
    }

    #[test]
    fn invalid_bit_counts_positions_and_radices_are_errors() {
        let data = [0; 32];
        assert!(BitReader::new(&data).bits(65).is_err());
        assert!(BitReader::with_position(&data, usize::MAX).bits(1).is_err());
        assert!(BitReader::with_position(&data, usize::MAX).strict_boundary().is_err());
        let mut w = BitWriter::new();
        assert!(w.bits(0, 129).is_err());
        for width in [0, 1, 65, 128, usize::MAX] {
            assert!(w.packed(0, width).is_err());
        }
        for k in [0, 9, usize::MAX] {
            w.k = k;
            assert!(w.packed(0, 64).is_err());
        }
        w.position = usize::MAX;
        assert!(w.bits(0, 1).is_err());
        assert!(w.strict_boundary().is_err());
    }

    #[test]
    fn bytewise_reader_matches_bit_reference_at_every_alignment() {
        let data: Vec<u8> = (0..40).map(|i| (i * 73 + 17) as u8).collect();
        for start in 0..16 {
            for count in 0..=64 {
                let expected = (0..count).fold(0u64, |v, i| {
                    v | (((data[(start + i) / 8] >> ((start + i) % 8)) & 1) as u64) << i
                });
                let mut reader = BitReader::with_position(&data, start);
                assert_eq!(reader.bits(count).unwrap(), expected);
                assert_eq!(reader.position, start + count);
            }
        }
    }

    #[test]
    fn writer_matches_reference_and_clears_overwritten_bits() {
        for start in 0..8 {
            for count in 0..=128 {
                let mask = if count == 128 { u128::MAX } else { (1u128 << count) - 1 };
                let value = 0xa56b_793c_10e2_d48f_b579_c113_935a_dcea_u128 & mask;
                let mut expected = vec![0xff; 18];
                for i in 0..count {
                    let p = start + i;
                    expected[p / 8] = (expected[p / 8] & !(1 << (p % 8)))
                        | (((value >> i) & 1) as u8) << (p % 8);
                }
                let mut w = BitWriter { data: vec![0xff; 18], position: start, k: 2 };
                w.bits(value, count).unwrap();
                assert_eq!(w.data, expected, "start {start}, count {count}");
                assert_eq!(w.position, start + count);
            }
        }
    }
}
