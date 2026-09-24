//! In-process additional-login calculations supplied by the application.
//!
//! The protocol carries opaque inputs in records 28 and 35. Their current
//! computation is not implemented here. No HTTP fallback, service credential,
//! or guessed value is used. Implement this interface only with a verified
//! local calculation for the selected record and broker build.

#![cfg(feature = "live")]

use mt5_native::error::{ProtocolError, Result};

pub trait LoginIdResolver {
    fn resolve_tag(&self, tag: u8, value: &[u8], server_build: i32) -> Result<u64>;
}

impl<F> LoginIdResolver for F
where
    F: Fn(u8, &[u8], i32) -> Result<u64>,
{
    fn resolve_tag(&self, tag: u8, value: &[u8], server_build: i32) -> Result<u64> {
        self(tag, value, server_build)
    }
}

/// Explicitly rejects unresolved additional-login requirements.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedLoginResolver;

impl LoginIdResolver for UnsupportedLoginResolver {
    fn resolve_tag(&self, tag: u8, _value: &[u8], server_build: i32) -> Result<u64> {
        Err(ProtocolError::new(format!(
            "no verified local additional-login resolver for record {tag}, build {server_build}"
        )))
    }
}
