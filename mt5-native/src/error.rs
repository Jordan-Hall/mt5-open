//! Shared error type for the wire codec.
//!
//! Mirrors the reference model's `ProtocolError`/`InvalidWire` (both subclasses
//! of `ValueError`): a rejected decode is a recoverable error carrying a
//! message, never a panic. Malformed input from the wire must be refused, not
//! guessed at.

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError(pub String);

impl ProtocolError {
    pub fn new(msg: impl Into<String>) -> Self {
        ProtocolError(msg.into())
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProtocolError {}

pub type Result<T> = core::result::Result<T, ProtocolError>;

/// Convenience for building an error from a format string.
#[macro_export]
macro_rules! wire_err {
    ($($arg:tt)*) => { $crate::error::ProtocolError::new(format!($($arg)*)) };
}
