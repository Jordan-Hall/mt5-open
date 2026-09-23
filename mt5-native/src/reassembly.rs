//! Message reassembly across fragmented frames.
//!
//! Fragments of one message share a sequence number; the message is complete on
//! the frame carrying the FINAL flag. The single-buffer assumption (one pending
//! message per sequence, command may not change mid-message) mirrors the
//! observed consumer and is preserved deliberately.

use std::collections::HashMap;

use crate::error::{ProtocolError, Result};
use crate::frame::{Frame, FINAL};

pub const MAX_MESSAGE: usize = 64 * 1024 * 1024;
pub const MAX_PENDING: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub command: u8,
    pub sequence: u16,
    pub payload: Vec<u8>,
    pub fragments: usize,
}

pub struct Reassembler {
    max_message: usize,
    max_pending: usize,
    pending: HashMap<u16, (u8, Vec<u8>, usize)>,
}

impl Default for Reassembler {
    fn default() -> Self {
        Reassembler::new(MAX_MESSAGE, MAX_PENDING)
    }
}

impl Reassembler {
    pub fn new(max_message: usize, max_pending: usize) -> Self {
        Reassembler { max_message, max_pending, pending: HashMap::new() }
    }

    /// Push a frame together with its already-deciphered payload. Returns the
    /// complete message when the FINAL frame arrives.
    pub fn push(&mut self, frame: &Frame, plain_payload: &[u8]) -> Result<Option<Message>> {
        let prior_is_none = !self.pending.contains_key(&frame.sequence);
        if let Some((command, payload, _)) = self.pending.get(&frame.sequence) {
            if *command != frame.command {
                return Err(ProtocolError::new("command changed within a fragmented message"));
            }
            if payload.len() + plain_payload.len() > self.max_message {
                return Err(ProtocolError::new("reassembled message exceeds configured size limit"));
            }
        } else if plain_payload.len() > self.max_message {
            return Err(ProtocolError::new("reassembled message exceeds configured size limit"));
        }
        if prior_is_none && frame.flags & FINAL == 0 && self.pending.len() >= self.max_pending {
            return Err(ProtocolError::new("too many pending fragmented messages"));
        }
        let (command, mut payload, mut count) = self
            .pending
            .remove(&frame.sequence)
            .unwrap_or((frame.command, Vec::new(), 0));
        payload.extend_from_slice(plain_payload);
        count += 1;
        if frame.flags & FINAL != 0 {
            Ok(Some(Message { command, sequence: frame.sequence, payload, fragments: count }))
        } else {
            self.pending.insert(frame.sequence, (command, payload, count));
            Ok(None)
        }
    }

    pub fn finish(&self) -> Result<()> {
        if !self.pending.is_empty() {
            return Err(ProtocolError::new(format!(
                "{} fragmented messages have no final frame",
                self.pending.len()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(command: u8, sequence: u16, flags: u16, payload: &[u8]) -> Frame {
        Frame::new(command, sequence, flags, payload.to_vec())
    }

    #[test]
    fn reassembles_and_interleaves() {
        let mut a = Reassembler::default();
        assert_eq!(a.push(&frame(12, 1, 0, b"a"), b"a").unwrap(), None);
        assert_eq!(
            a.push(&frame(10, 2, FINAL, b""), b"").unwrap(),
            Some(Message { command: 10, sequence: 2, payload: vec![], fragments: 1 })
        );
        assert_eq!(a.push(&frame(12, 1, 0, b"b"), b"b").unwrap(), None);
        assert_eq!(
            a.push(&frame(12, 1, FINAL, b"c"), b"c").unwrap(),
            Some(Message { command: 12, sequence: 1, payload: b"abc".to_vec(), fragments: 3 })
        );
        a.finish().unwrap();
    }

    #[test]
    fn size_limits_enforced() {
        let mut a = Reassembler::new(2, MAX_PENDING);
        a.push(&frame(12, 1, 0, b"a"), b"a").unwrap();
        assert!(a.push(&frame(10, 1, FINAL, b"b"), b"b").is_err()); // command changed
        assert!(a.push(&frame(12, 1, FINAL, b"bc"), b"bc").is_err()); // exceeds max
    }
}
