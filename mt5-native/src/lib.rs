//! mt5_native — an offline codec for the MT5 application wire protocol
//! (revision 3), built to interoperate with a broker account the operator holds.
//!
//! DISABLED BY POLICY. This crate is a byte-in/byte-out codec only: there is no
//! socket, no connection, and no order-send path anywhere in it, and the host application
//! does not wire it to a broker. The live gate below refuses unless the crate is
//! deliberately built with `--features live`, which this repo does not enable.
//! See DISABLED.md.
//!
//! What is present: revision-3 framing and reassembly, the two byte-feedback
//! stream ciphers, the MD5-based credential/hardware derivations, the hello /
//! authentication / result frame grammars, TLV lists, AES-CBC session-key and
//! trade-key derivations, LZO1X and DEFLATE (de)compression, the bit-packed live
//! and snapshot quote records, market-depth records, the quote-history column
//! groups and trailing-hour segments, the synchronization stream reader and the
//! command-12 synchronization request with its login-value wrapper, quote/depth
//! subscriptions, trade/tick/bar history requests, the password-change request,
//! the F28/F35 external-calculation HTTP contract, the signed 800-byte trade
//! record with its full sign/compress/frame pipeline, and the trade-update
//! parser. Every layer is validated offline against the `mt5_protocol/`
//! conformance vectors.
//!
//! If ever enabled, any execution path must additionally pass the host application's demo
//! reconciliation / idempotency / uncertainty / risk / soak gates before any
//! real use (docs/VANTAGE_TRANSPORT_DECISION.md).

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

/// Whether live use is permitted. False in this repo; only a deliberate
/// `--features live` build could flip it, which policy does not allow.
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
            "mt5-native is DISABLED by policy: live MT5 use is not permitted (see DISABLED.md)"
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
