//! Tag/length/value lists. Header is `<B i>`: an 8-bit tag and a signed 32-bit
//! length, followed by that many value bytes. Used inside authentication frames
//! and the signed trade payload.

use crate::error::{ProtocolError, Result};

pub fn encode_tlvs(items: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (tag, value) in items {
        out.push(*tag);
        out.extend_from_slice(&(value.len() as i32).to_le_bytes());
        out.extend_from_slice(value);
    }
    out
}

pub fn parse_tlvs(payload: &[u8]) -> Result<Vec<(u8, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < payload.len() {
        if payload.len() - off < 5 {
            return Err(ProtocolError::new("truncated TLV header"));
        }
        let tag = payload[off];
        let size = i32::from_le_bytes([
            payload[off + 1],
            payload[off + 2],
            payload[off + 3],
            payload[off + 4],
        ]);
        off += 5;
        if size < 0 || size as usize > payload.len() - off {
            return Err(ProtocolError::new(format!(
                "invalid size {size} for TLV {tag}"
            )));
        }
        let size = size as usize;
        out.push((tag, payload[off..off + size].to_vec()));
        off += size;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_rejections() {
        let items = vec![(7u8, b"a".to_vec()), (7u8, b"b".to_vec())];
        assert_eq!(parse_tlvs(&encode_tlvs(&items)).unwrap(), items);
        for bad in [
            &b"\x07"[..],
            &b"\x07\xff\xff\xff\xff"[..],
            &b"\x07\x02\x00\x00\x00a"[..],
        ] {
            assert!(parse_tlvs(bad).is_err());
        }
    }
}
