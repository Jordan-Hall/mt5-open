//! Synchronization-stream reader.
//!
//! The stream is consumed across arbitrary fragment boundaries. A tag of zero
//! triggers a sentinel scan: bytes are skipped until the `0x17` (23) routing
//! sentinel, and the skipped bytes are returned. This is the specifically
//! observed tag-zero scan, not a general resynchronization; an unknown grammar
//! is rejected elsewhere rather than scanned for a plausible tag.

use crate::error::{ProtocolError, Result};

pub struct SegmentedReader {
    chunks: Vec<Vec<u8>>,
    chunk_index: usize,
    offset: usize,
    pub consumed: usize,
    remaining: usize,
}

impl SegmentedReader {
    pub fn new(chunks: impl IntoIterator<Item = Vec<u8>>) -> Self {
        let chunks: Vec<_> = chunks.into_iter().collect();
        let remaining = chunks.iter().fold(0usize, |total, chunk| total.saturating_add(chunk.len()));
        SegmentedReader { chunks, remaining, chunk_index: 0, offset: 0, consumed: 0 }
    }

    pub fn byte(&mut self) -> Result<u8> {
        while self.chunk_index < self.chunks.len() && self.offset == self.chunks[self.chunk_index].len() {
            self.chunk_index += 1;
            self.offset = 0;
        }
        if self.chunk_index >= self.chunks.len() {
            return Err(ProtocolError::new("truncated segmented read"));
        }
        let value = self.chunks[self.chunk_index][self.offset];
        self.offset += 1;
        self.consumed += 1;
        self.remaining -= 1;
        Ok(value)
    }

    pub fn take(&mut self, size: usize) -> Result<Vec<u8>> {
        if size > self.remaining {
            return Err(ProtocolError::new("truncated segmented read"));
        }
        let mut out = Vec::with_capacity(size);
        while out.len() < size {
            let chunk = &self.chunks[self.chunk_index];
            let take = (size - out.len()).min(chunk.len() - self.offset);
            out.extend_from_slice(&chunk[self.offset..self.offset + take]);
            self.offset += take;
            self.consumed += take;
            self.remaining -= take;
            if self.offset == chunk.len() {
                self.chunk_index += 1;
                self.offset = 0;
            }
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
                if tag == 23 { break; }
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
            let chunks = vec![payload[..split].to_vec(), Vec::new(), payload[split..].to_vec()];
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

    #[test]
    fn oversized_take_is_rejected_without_consuming_or_allocating() {
        let mut r = SegmentedReader::new([vec![], b"ab".to_vec(), vec![], b"cd".to_vec()]);
        assert!(r.take(usize::MAX).is_err());
        assert_eq!(r.consumed, 0);
        assert_eq!(r.take(3).unwrap(), b"abc");
        assert_eq!(r.take(1).unwrap(), b"d");
        assert!(r.take(1).is_err());
        assert!(r.take(0).unwrap().is_empty());
    }
}
