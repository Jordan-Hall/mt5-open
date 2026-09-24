//! In-process extension point for build-specific additional-login calculations.
//!
//! This is not an implementation of the unknown tag-28/tag-35 mappings. The
//! supplied resolver must implement a verified profile; no network fallback,
//! guessed constants, or interpretation of opaque bytes is provided here.

use mt5_native::error::{ProtocolError, Result};
use std::fmt;

pub struct LoginContext<'a> {
    pub login: u64,
    pub client_build: u16,
    pub server_build: u16,
    pub record_build: i16,
    pub server_challenge: &'a [u8; 16],
    pub tags: &'a [(u8, Vec<u8>)],
}

impl LoginContext<'_> {
    /// Fetch an unambiguous input without guessing duplicate-tag precedence.
    pub fn input(&self, tag: u8) -> Result<&[u8]> {
        if tag != 28 && tag != 35 {
            return Err(ProtocolError::new("not an additional-login input tag"));
        }
        let mut values = self.tags.iter().filter(|(key, _)| *key == tag);
        let value = values.next().ok_or_else(|| {
            ProtocolError::new(format!("authentication result missing tag {tag}"))
        })?;
        if values.next().is_some() || value.1.is_empty() {
            return Err(ProtocolError::new(format!(
                "ambiguous or empty login input tag {tag}"
            )));
        }
        Ok(&value.1)
    }
}

impl fmt::Debug for LoginContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginContext")
            .field("client_build", &self.client_build)
            .field("server_build", &self.server_build)
            .field("record_build", &self.record_build)
            .field(
                "tag_lengths",
                &self
                    .tags
                    .iter()
                    .map(|(t, v)| (*t, v.len()))
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

pub struct LoginDerivation {
    pub f28: u64,
    pub f35: u64,
}

/// A caller-owned local calculation, not a hosted-service client. Implementors
/// must validate their supported builds and required inputs before deriving.
pub trait LoginIdResolver {
    fn derive(&self, context: &LoginContext<'_>) -> Result<LoginDerivation>;
}

impl<F> LoginIdResolver for F
where
    F: Fn(&LoginContext<'_>) -> Result<LoginDerivation>,
{
    fn derive(&self, context: &LoginContext<'_>) -> Result<LoginDerivation> {
        self(context)
    }
}

/// Explicit fail-closed default until an independently verified profile exists.
pub struct UnsupportedLoginProfile;

impl LoginIdResolver for UnsupportedLoginProfile {
    fn derive(&self, context: &LoginContext<'_>) -> Result<LoginDerivation> {
        Err(ProtocolError::new(format!(
            "no verified local login derivation for client build {} / server build {}; synchronization was not sent",
            context.client_build, context.server_build
        )))
    }
}
