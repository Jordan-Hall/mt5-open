//! Synchronization-stream reader.
//!
//! The stream is consumed across arbitrary fragment boundaries. A tag of zero
//! triggers a sentinel scan: bytes are skipped until the `0x17` (23) routing
//! sentinel, and the skipped bytes are returned. This is the specifically
//! observed tag-zero scan — not a general resynchronization; an unknown grammar
//! is rejected elsewhere rather than scanned for a plausible tag.

use crate::error::{ProtocolError, Result};

mod account;
pub use account::{AccessPoint, SynchronizedState, parse_sync_account, parse_synchronized_state};

pub struct SegmentedReader {
    chunks: Vec<Vec<u8>>,
    chunk_index: usize,
    offset: usize,
    pub consumed: usize,
}

impl SegmentedReader {
    pub fn new(chunks: impl IntoIterator<Item = Vec<u8>>) -> Self {
        SegmentedReader {
            chunks: chunks.into_iter().collect(),
            chunk_index: 0,
            offset: 0,
            consumed: 0,
        }
    }

    pub fn byte(&mut self) -> Result<u8> {
        while self.chunk_index < self.chunks.len()
            && self.offset == self.chunks[self.chunk_index].len()
        {
            self.chunk_index += 1;
            self.offset = 0;
        }
        if self.chunk_index >= self.chunks.len() {
            return Err(ProtocolError::new("truncated segmented read"));
        }
        let value = self.chunks[self.chunk_index][self.offset];
        self.offset += 1;
        self.consumed += 1;
        Ok(value)
    }

    pub fn take(&mut self, size: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(size);
        for _ in 0..size {
            out.push(self.byte()?);
        }
        Ok(out)
    }

    /// Read the next tag; on a zero tag, skip to the `0x17` sentinel and return
    /// it along with the skipped bytes.
    pub fn sync_tag(&mut self) -> Result<(u8, Vec<u8>)> {
        let mut tag = self.byte()?;
        let mut skipped = Vec::new();
        if tag == 0 {
            loop {
                tag = self.byte()?;
                if tag == 23 {
                    break;
                }
                skipped.push(tag);
            }
        }
        Ok((tag, skipped))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_tag_scan_across_all_fragment_boundaries() {
        let payload = b"\x00\x11\x99\x00\x17routing-body".to_vec();
        for split in 0..=payload.len() {
            let chunks = vec![
                payload[..split].to_vec(),
                Vec::new(),
                payload[split..].to_vec(),
            ];
            let mut r = SegmentedReader::new(chunks);
            let (tag, skipped) = r.sync_tag().unwrap();
            assert_eq!(tag, 23);
            assert_eq!(skipped, vec![0x11, 0x99, 0x00]);
            assert_eq!(r.take(12).unwrap(), b"routing-body");
        }
    }

    #[test]
    fn truncated_zero_tag_rejected() {
        let mut r = SegmentedReader::new(vec![vec![0x00], vec![0x11]]);
        assert!(r.sync_tag().is_err());
    }
}
