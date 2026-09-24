//! Offline byte codecs for the reconstructed MT5 application protocol.
//!
//! This crate performs no networking. The sibling `mt5-session` crate provides
//! an explicitly opted-in socket transport. The `live` feature is disabled by
//! default; it is a build gate, not a guarantee of broker compatibility.
//!
//! Framing, crypto, compression, quotes, history, synchronization and trade
//! records have synthetic offline conformance tests. Modern additional-login
//! calculations are not implemented. See `AUTH.md` and `STATUS.md` for the
//! evidence boundary; a passing codec test is not a live trading certification.

pub mod error;
pub mod hexutil;

pub mod frame;
pub mod cipher;
pub mod md5;
pub mod crypto;
pub mod tlv;
pub mod bitpack;
pub mod keys;
pub mod auth;
pub mod compression;
pub mod reassembly;
pub mod subscription;
pub mod requests;
pub mod login;
pub mod metadata;
pub mod handshake;
pub mod quotes;
pub mod depth;
pub mod history;
pub mod sync;
pub mod trade;
pub mod account;

pub mod orders;
pub mod intent;

pub use error::{ProtocolError, Result};
pub use frame::{Frame, FrameParser, COMPRESSED, FINAL};
pub use cipher::{SessionCipher, startup_decrypt_default, startup_encrypt_default};

/// Whether the caller deliberately enabled the optional live feature.
pub const LIVE_ENABLED: bool = cfg!(feature = "live");

/// Tripwire that ANY future live/connect/send path MUST call first. It hard-fails
/// unless the crate was deliberately built with the `live` feature, so this crate
/// cannot be used to trade by accident.
pub fn ensure_live_allowed() {
    // The constant-valued assertion is the point: this is a compile-time policy
    // tripwire, not a runtime check.
    #[allow(clippy::assertions_on_constants)]
    {
        assert!(
            LIVE_ENABLED,
            "mt5-native is DISABLED by policy: live MT5 use is not permitted"
        );
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    // The default build must be inert, and these two say so. They are scoped to
    // the default build because that is the claim: "disabled unless someone
    // deliberately asks" cannot be tested in a build where someone has.
    #[cfg(not(feature = "live"))]
    mod without_live {
        use super::*;

        #[test]
        #[allow(clippy::assertions_on_constants)]
        fn live_is_disabled_by_default() {
            assert!(!LIVE_ENABLED, "mt5-native must ship disabled");
        }

        #[test]
        #[should_panic(expected = "DISABLED by policy")]
        fn guard_refuses_when_disabled() {
            ensure_live_allowed();
        }
    }

    // The mirror image. Opting in has to actually work, or the tripwire is not
    // a gate but a wall, and the only way past a wall is to remove it.
    #[cfg(feature = "live")]
    mod with_live {
        use super::*;

        #[test]
        #[allow(clippy::assertions_on_constants)]
        fn live_is_enabled_only_when_asked_for() {
            assert!(LIVE_ENABLED, "the live feature must set the flag it names");
        }

        #[test]
        fn guard_permits_when_explicitly_enabled() {
            ensure_live_allowed();
        }
    }
}
