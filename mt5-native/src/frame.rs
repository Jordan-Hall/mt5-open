//! MT5 application framing (revision 3).
//!
//! Header is 9 bytes, little-endian, `<B i H H>`:
//!
//! ```text
//! off0     u8    command    numeric command id (see `command` registry)
//! off1..4  i32   size       payload byte count — SIGNED; negative/oversized are rejected
//! off5..6  u16   sequence   per-message counter (fragments of one message share it)
//! off7..8  u16   flags      bit0 COMPRESSED (0x0001), bit1 FINAL (0x0002)
//! ```
//!
//! The final two header bytes are message flags, not a channel. The payload for
//! control/data commands is enciphered by the session layer; this module handles
//! only the framing, which is cipher-independent.

use crate::error::{ProtocolError, Result};

pub const HEADER_LEN: usize = 9;

/// Payload flags carried in the header's final 16-bit field.
pub const COMPRESSED: u16 = 0x0001;
pub const FINAL: u16 = 0x0002;

/// Maximum single-frame payload the parser will accept (matches the reference).
pub const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// A selection of command ids, named for readability. Unknown ids are preserved
/// verbatim by the parser; this table is documentation, not a gate.
pub mod command {
    pub const HELLO: u8 = 0;
    pub const AUTH: u8 = 1;
    pub const CERT_CONTINUATION: u8 = 2;
    pub const PING: u8 = 10;
    pub const ACCOUNT_STATE: u8 = 12;
    pub const ROUTING_NOTIFICATION: u8 = 32;
    pub const LIVE_TICKS: u8 = 50;
    pub const MARKET_WATCH: u8 = 51;
    pub const MARKET_DEPTH: u8 = 52;
    pub const TRADE_UPDATE: u8 = 55;
    pub const TRADE_HISTORY: u8 = 101;
    pub const QUOTE_HISTORY: u8 = 102;
    pub const SYMBOLS: u8 = 105;
    pub const PASSWORD_CHANGE: u8 = 107;
    pub const TRADE_REQUEST: u8 = 108;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub command: u8,
    pub sequence: u16,
    pub flags: u16,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(command: u8, sequence: u16, flags: u16, payload: Vec<u8>) -> Self {
        Frame { command, sequence, flags, payload }
    }

    pub fn is_final(&self) -> bool {
        self.flags & FINAL != 0
    }

    pub fn is_compressed(&self) -> bool {
        self.flags & COMPRESSED != 0
    }

    /// Serialize header + payload exactly as the terminal transmits it.
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.push(self.command);
        out.extend_from_slice(&(self.payload.len() as i32).to_le_bytes());
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }
}

/// Incremental frame parser. Tolerates header and payload arriving across reads,
/// and rejects a declared length that is negative or exceeds `max_payload`.
pub struct FrameParser {
    max_payload: usize,
    buffer: Vec<u8>,
}

impl Default for FrameParser {
    fn default() -> Self {
        FrameParser::new(MAX_PAYLOAD)
    }
}

impl FrameParser {
    pub fn new(max_payload: usize) -> Self {
        FrameParser { max_payload, buffer: Vec::new() }
    }

    /// Feed received bytes; return every complete frame now available.
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<Frame>> {
        self.buffer.extend_from_slice(data);
        let mut frames = Vec::new();
        let mut consumed = 0usize;
        while self.buffer.len() - consumed >= HEADER_LEN {
            let h = &self.buffer[consumed..consumed + HEADER_LEN];
            let command = h[0];
            let size = i32::from_le_bytes([h[1], h[2], h[3], h[4]]);
            let sequence = u16::from_le_bytes([h[5], h[6]]);
            let flags = u16::from_le_bytes([h[7], h[8]]);
            if size < 0 || size as usize > self.max_payload {
                return Err(ProtocolError::new(format!("invalid payload length {size}")));
            }
            let size = size as usize;
            let end = consumed + HEADER_LEN + size;
            if self.buffer.len() < end {
                break;
            }
            let payload = self.buffer[consumed + HEADER_LEN..end].to_vec();
            frames.push(Frame { command, sequence, flags, payload });
            consumed = end;
        }
        if consumed > 0 {
            self.buffer.drain(..consumed);
        }
        Ok(frames)
    }

    /// Assert the stream ended on a frame boundary (no dangling partial frame).
    pub fn finish(&self) -> Result<()> {
        if !self.buffer.is_empty() {
            return Err(ProtocolError::new(format!(
                "stream ends with {} incomplete frame bytes",
                self.buffer.len()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_layout_known_vector() {
        // Matches tests/core/test_mt5_protocol.py::test_header_layout.
        let f = Frame::new(0x32, 0x1234, 2, b"abc".to_vec());
        assert_eq!(crate::hexutil::encode(&f.pack()), "320300000034120200616263");
        assert_eq!(HEADER_LEN, 9);
    }

    #[test]
    fn incremental_parser_reassembles_across_arbitrary_reads() {
        let frames: Vec<Frame> = (0..100u16)
            .map(|i| Frame::new(i as u8, i.wrapping_mul(7), 2, (0..i as u8).collect()))
            .collect();
        let mut raw = Vec::new();
        for f in &frames {
            raw.extend(f.pack());
        }
        let mut parser = FrameParser::default();
        let mut found = Vec::new();
        let mut off = 0;
        let mut step = 1usize;
        while off < raw.len() {
            let n = ((step * 7 + 3) % 29) + 1;
            step += 1;
            let end = (off + n).min(raw.len());
            found.extend(parser.feed(&raw[off..end]).unwrap());
            off = end;
        }
        parser.finish().unwrap();
        assert_eq!(found, frames);
    }

    #[test]
    fn rejects_invalid_lengths_and_dangling_bytes() {
        for size in [-1i32, (MAX_PAYLOAD as i32).wrapping_add(1)] {
            let mut hdr = vec![1u8];
            hdr.extend_from_slice(&size.to_le_bytes());
            hdr.extend_from_slice(&0u16.to_le_bytes());
            hdr.extend_from_slice(&2u16.to_le_bytes());
            assert!(FrameParser::default().feed(&hdr).is_err());
        }
        let mut parser = FrameParser::default();
        parser.feed(b"\x00\x01").unwrap();
        assert!(parser.finish().is_err());
    }

}
