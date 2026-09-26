//! Byte codecs for the MT5 application protocol.
//!
//! Authentication, framing, compression, market data, account records and
//! trade encoding are independent of networking. `mt5-session` owns sockets.

pub mod error;
pub mod hexutil;

pub mod account;
pub mod auth;
pub mod bars;
pub mod bitpack;
pub mod challenge;
pub mod cipher;
pub mod compression;
pub mod crypto;
pub mod depth;
pub mod frame;
pub mod handshake;
pub mod history;
pub mod keys;
pub mod login;
pub mod margin;
pub mod md5;
pub mod metadata;
pub mod quotes;
mod reader;
pub mod reassembly;
pub mod records;
pub mod requests;
pub mod subscription;
pub mod sync;
pub mod tick_history;
pub mod tlv;
pub mod trade;
pub mod trade_history;
pub mod updates;

pub use cipher::{SessionCipher, startup_decrypt_default, startup_encrypt_default};
pub use error::{ProtocolError, Result};
pub use frame::{COMPRESSED, FINAL, Frame, FrameParser};

/// Whether the build explicitly enables network use.
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
            "mt5-native networking requires the live feature"
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
        #[should_panic(expected = "requires the live feature")]
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
