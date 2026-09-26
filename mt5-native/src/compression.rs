//! Payload compression.
//!
//! Two independent schemes appear on the wire:
//!
//! * The outer frame payload can be LZO1X-compressed (flag COMPRESSED), wrapped
//!   in an 8-byte `<i i>` envelope of decompressed and compressed sizes. Only
//!   literal-run encoding is produced here ([`lzo1x_store`]); the full decoder
//!   ([`lzo1x_decompress`]) reads any LZO1X stream ending in the `11 00 00`
//!   marker.
//! * Inner history columns are DEFLATE — zlib-framed, with a raw-DEFLATE
//!   fallback ([`inflate_inner`]).

use crate::error::{ProtocolError, Result};
use flate2::write::{DeflateEncoder, ZlibEncoder};
use flate2::{Compression, Decompress, FlushDecompress, Status};
use std::io::Write;

pub const MAX_MESSAGE: usize = 64 * 1024 * 1024;

/// Decompress an LZO1X stream whose declared output length is `expected_size`.
pub fn lzo1x_decompress(data: &[u8], expected_size: usize, max_output: usize) -> Result<Vec<u8>> {
    if expected_size > max_output {
        return Err(ProtocolError::new("invalid decompressed size"));
    }
    if data.len() < 3 || data[data.len() - 3..] != [0x11, 0x00, 0x00] {
        return Err(ProtocolError::new("missing LZO1X end marker"));
    }
    let mut pos = 0usize;
    let mut out: Vec<u8> = Vec::new();

    macro_rules! read_byte {
        () => {{
            if pos >= data.len() {
                return Err(ProtocolError::new("truncated LZO instruction"));
            }
            let v = data[pos] as usize;
            pos += 1;
            v
        }};
    }
    macro_rules! read_word {
        () => {{
            let lo = read_byte!();
            let hi = read_byte!();
            lo | (hi << 8)
        }};
    }
    // Length extension: a zero seed means "read continuation bytes".
    macro_rules! length_extension {
        ($value:expr, $mask:expr) => {{
            let v: usize = $value;
            if v != 0 {
                v
            } else {
                let mut acc: usize = $mask;
                loop {
                    let extra = read_byte!();
                    if extra != 0 {
                        break acc + extra;
                    }
                    acc += 255;
                    if acc > max_output {
                        return Err(ProtocolError::new("excessive LZO length extension"));
                    }
                }
            }
        }};
    }
    macro_rules! literal {
        ($length:expr) => {{
            let length: usize = $length;
            if length > data.len() - pos || out.len() + length > expected_size {
                return Err(ProtocolError::new(
                    "LZO literal exceeds input or declared output",
                ));
            }
            out.extend_from_slice(&data[pos..pos + length]);
            pos += length;
        }};
    }
    macro_rules! do_match {
        ($distance:expr, $length:expr) => {{
            let distance: usize = $distance;
            let length: usize = $length;
            if distance < 1 || distance > out.len() || out.len() + length > expected_size {
                return Err(ProtocolError::new("invalid LZO match"));
            }
            for _ in 0..length {
                out.push(out[out.len() - distance]);
            }
        }};
    }

    let mut state: usize;
    if data[0] as usize > 17 {
        let count = read_byte!() - 17;
        literal!(count);
        state = count.min(4);
    } else {
        state = 0;
    }

    loop {
        let token = read_byte!();
        let (distance, length, following);
        if token < 16 {
            if state == 0 {
                let n = length_extension!(token, 15) + 3;
                literal!(n);
                state = 4;
                continue;
            }
            let d = (token >> 2) + (read_byte!() << 2) + if state == 4 { 2049 } else { 1 };
            distance = d;
            length = if state == 4 { 3 } else { 2 };
            following = token & 3;
        } else if token < 32 {
            length = length_extension!(token & 7, 7) + 2;
            let operand = read_word!();
            distance = 16384 + ((token & 8) << 11) + (operand >> 2);
            following = operand & 3;
            if distance == 16384 {
                if token != 17 || operand != 0 || pos != data.len() || out.len() != expected_size {
                    return Err(ProtocolError::new(
                        "invalid LZO termination or output length",
                    ));
                }
                return Ok(out);
            }
        } else if token < 64 {
            length = length_extension!(token & 31, 31) + 2;
            let operand = read_word!();
            distance = (operand >> 2) + 1;
            following = operand & 3;
        } else {
            length = (token >> 5) + 1;
            distance = ((token >> 2) & 7) + (read_byte!() << 3) + 1;
            following = token & 3;
        }
        do_match!(distance, length);
        literal!(following);
        state = following;
    }
}

/// LZO1X literal-only encoding (a store, no matches). Always decodes back to
/// `data` via [`lzo1x_decompress`].
pub fn lzo1x_store(data: &[u8]) -> Vec<u8> {
    let size = data.len();
    if size == 0 {
        return vec![0x11, 0x00, 0x00];
    }
    let mut out = Vec::new();
    if size <= 238 {
        out.push((size + 17) as u8);
    } else {
        let remaining = size - 18;
        let zeros = (remaining - 1) / 255;
        let final_byte = (remaining - 1) % 255;
        out.push(0x00);
        out.extend(std::iter::repeat_n(0u8, zeros));
        out.push((final_byte + 1) as u8);
    }
    out.extend_from_slice(data);
    out.extend_from_slice(&[0x11, 0x00, 0x00]);
    out
}

/// Parse the `<i i>` size envelope and LZO1X-decompress the remainder.
pub fn decompress_payload(payload: &[u8], max_output: usize) -> Result<Vec<u8>> {
    if payload.len() < 8 {
        return Err(ProtocolError::new(
            "compressed payload lacks its two size fields",
        ));
    }
    let expected = i32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let compressed = i32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    if compressed < 0 || compressed as usize != payload.len() - 8 {
        return Err(ProtocolError::new(
            "compressed payload length does not match its envelope",
        ));
    }
    if expected < 0 {
        return Err(ProtocolError::new("invalid decompressed size"));
    }
    lzo1x_decompress(&payload[8..], expected as usize, max_output)
}

/// Wrap `plain_payload` in the size envelope with a literal-only LZO1X body.
pub fn make_compressed_payload(plain_payload: &[u8]) -> Result<Vec<u8>> {
    if plain_payload.len() > MAX_MESSAGE {
        return Err(ProtocolError::new(
            "payload exceeds configured output limit",
        ));
    }
    let encoded = lzo1x_store(plain_payload);
    let mut out = Vec::with_capacity(8 + encoded.len());
    out.extend_from_slice(&(plain_payload.len() as i32).to_le_bytes());
    out.extend_from_slice(&(encoded.len() as i32).to_le_bytes());
    out.extend_from_slice(&encoded);
    Ok(out)
}

/// Inflate a DEFLATE stream: zlib-framed first, raw-DEFLATE as a fallback.
/// Returns the bytes and which framing succeeded (`"zlib"` or `"raw_deflate"`).
/// Rejects incomplete streams, trailing bytes, and output beyond `limit`.
pub fn inflate_inner(data: &[u8], limit: usize) -> Result<(Vec<u8>, &'static str)> {
    let mut errors = Vec::new();
    for (header, name) in [(true, "zlib"), (false, "raw_deflate")] {
        match try_inflate(data, limit, header) {
            Ok(v) => return Ok((v, name)),
            Err(e) => errors.push(e.0),
        }
    }
    Err(ProtocolError::new(format!(
        "invalid zlib and raw-DEFLATE stream: {}",
        errors.join("; ")
    )))
}

fn try_inflate(data: &[u8], limit: usize, header: bool) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut decoder = Decompress::new(header);
    loop {
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let mut buffer = [0u8; 8192];
        let capacity = buffer
            .len()
            .min(limit.saturating_sub(out.len()).saturating_add(1));
        let status = decoder
            .decompress(
                &data[before_in as usize..],
                &mut buffer[..capacity],
                FlushDecompress::None,
            )
            .map_err(|e| ProtocolError::new(e.to_string()))?;
        out.extend_from_slice(&buffer[..(decoder.total_out() - before_out) as usize]);
        if out.len() > limit {
            return Err(ProtocolError::new("inflation budget exceeded"));
        }
        if status == Status::StreamEnd {
            break;
        }
        if decoder.total_in() == before_in && decoder.total_out() == before_out {
            return Err(ProtocolError::new("incomplete compressed stream"));
        }
    }
    let offset = decoder.total_in() as usize;
    if offset == data.len() {
        return Ok(out);
    }
    Err(ProtocolError::new("trailing compressed bytes"))
}

/// Compress with zlib (or raw DEFLATE when `raw`). Used to build history
/// fixtures; the exact bytes are not pinned by any vector, only round-trip.
pub fn deflate(data: &[u8], raw: bool) -> Vec<u8> {
    if raw {
        let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).expect("deflate");
        e.finish().expect("deflate finish")
    } else {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).expect("zlib");
        e.finish().expect("zlib finish")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hexutil::decode;

    #[test]
    fn lzo_literals_and_envelope() {
        let data = b"hello";
        let mut encoded = vec![(data.len() + 17) as u8];
        encoded.extend_from_slice(data);
        encoded.extend_from_slice(&[0x11, 0, 0]);
        assert_eq!(
            lzo1x_decompress(&encoded, data.len(), MAX_MESSAGE).unwrap(),
            data
        );
        assert_eq!(
            lzo1x_decompress(&[0x11, 0, 0], 0, MAX_MESSAGE).unwrap(),
            b""
        );
        assert!(lzo1x_decompress(&encoded, 4, MAX_MESSAGE).is_err());
    }

    #[test]
    fn lzo_store_roundtrip_boundaries() {
        for size in [
            0usize, 1, 2, 3, 4, 17, 18, 237, 238, 239, 272, 273, 274, 528, 10000,
        ] {
            let data: Vec<u8> = (0..size).map(|i| (i * 53 + 11) as u8).collect();
            assert_eq!(
                lzo1x_decompress(&lzo1x_store(&data), size, MAX_MESSAGE).unwrap(),
                data
            );
            assert_eq!(
                decompress_payload(&make_compressed_payload(&data).unwrap(), MAX_MESSAGE).unwrap(),
                data
            );
        }
    }

    #[test]
    fn lzo_outer_literal_fixture_shape() {
        // The outer_compression_literal_only vectors are literal stores; confirm
        // our store matches the documented prefix for a short run.
        let data = decode("00010203");
        let encoded = lzo1x_store(&data);
        assert_eq!(encoded[0], (data.len() + 17) as u8);
        assert_eq!(&encoded[encoded.len() - 3..], &[0x11, 0, 0]);
    }

    #[test]
    fn inflate_zlib_and_raw_roundtrip() {
        let data = b"the quick brown fox jumps over the lazy dog".repeat(4);
        for raw in [false, true] {
            let comp = deflate(&data, raw);
            let (back, name) = inflate_inner(&comp, MAX_MESSAGE).unwrap();
            assert_eq!(back, data);
            assert_eq!(name, if raw { "raw_deflate" } else { "zlib" });
        }
        // Budget enforcement.
        let comp = deflate(&data, false);
        assert!(inflate_inner(&comp, 4).is_err());
    }
    #[test]
    fn incomplete_and_concatenated_streams_are_rejected() {
        for raw in [false, true] {
            let stream = deflate(b"complete data", raw);
            assert_eq!(inflate_inner(&stream, 13).unwrap().0, b"complete data");
            for end in 0..stream.len() {
                assert!(inflate_inner(&stream[..end], 13).is_err());
            }
            assert!(inflate_inner(&[stream.as_slice(), stream.as_slice()].concat(), 26).is_err());
        }
    }
}
