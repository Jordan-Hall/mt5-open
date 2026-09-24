#![cfg(feature = "live")]

use mt5_session::{LoginIdResolver, UnsupportedLoginResolver};
use mt5_native::error::{ProtocolError, Result};

#[test]
fn unsupported_challenges_never_synthesize_a_value() {
    for build in [0, 4199, 4852, 5409, 5830] {
        for tag in [0, 28, 35, 255] {
            assert!(UnsupportedLoginResolver.resolve_tag(tag, b"sensitive", build).is_err());
        }
    }
    assert!(!UnsupportedLoginResolver.resolve_tag(35, b"sensitive", 5830)
        .unwrap_err().to_string().contains("sensitive"));
}

#[test]
fn callers_can_supply_a_local_resolver_without_a_service_key() {
    let resolver = |tag: u8, bytes: &[u8], build: i32| -> Result<u64> {
        if tag != 28 || build != 4199 || bytes.len() != 8 {
            return Err(ProtocolError::new("unsupported test vector"));
        }
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    };
    assert_eq!(resolver.resolve_tag(28, &42u64.to_le_bytes(), 4199).unwrap(), 42);
    assert!(resolver.resolve_tag(35, &42u64.to_le_bytes(), 5830).is_err());
}
