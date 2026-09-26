//! Connection metadata and the expected account identity.
//! Challenge answers are computed from each authentication response.

use mt5_native::auth::AuthResult;
use mt5_native::challenge::{self, Version};
use mt5_native::error::{ProtocolError, Result};
use serde::Deserialize;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginProfile {
    pub client_build: u16,
    pub server_build: u16,
    environment: String,
    account: ProfileAccount,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileAccount {
    login: u64,
    mode: String,
    server: String,
    #[serde(default)]
    read_only: bool,
}

impl LoginProfile {
    pub fn from_json(input: &str) -> Result<Self> {
        let profile: Self = serde_json::from_str(input)
            .map_err(|_| ProtocolError::new("invalid native login profile JSON"))?;
        if profile.environment.is_empty() || profile.environment.len() > 16 * 1024 {
            return Err(ProtocolError::new(
                "profile requires bounded terminal compatibility metadata",
            ));
        }
        let account = &profile.account;
        if account.login == 0
            || !matches!(account.mode.as_str(), "demo" | "contest" | "real")
            || account.server.is_empty()
            || account.server.encode_utf16().count() > 127
            || account.server.chars().any(char::is_control)
        {
            return Err(ProtocolError::new("invalid expected account identity"));
        }
        Ok(profile)
    }

    /// Validate the configured login before dialing any broker endpoint.
    pub fn account_mode(&self, login: u64) -> Result<&str> {
        if self.account.login != login {
            return Err(ProtocolError::new(
                "native profile belongs to a different account",
            ));
        }
        Ok(&self.account.mode)
    }

    pub fn validate_account(&self, login: u64, server: &str) -> Result<()> {
        self.account_mode(login)?;
        if self.account.server != server {
            return Err(ProtocolError::new(
                "native profile belongs to a different server",
            ));
        }
        Ok(())
    }

    pub(crate) fn environment(&self) -> &str {
        &self.environment
    }

    pub(crate) fn read_only(&self, login: u64) -> Result<bool> {
        self.account_mode(login)?;
        Ok(self.account.read_only)
    }

    pub(crate) fn answers(&self, client_build: u16, result: &AuthResult) -> Result<(u64, u64)> {
        let expected: Vec<u8> = self
            .account
            .server
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut names = result.tlvs.iter().filter(|(tag, _)| *tag == 0);
        if names.next().map(|(_, bytes)| bytes) != Some(&expected) || names.next().is_some() {
            return Err(ProtocolError::new(
                "native login profile does not match the server identity",
            ));
        }
        if client_build != challenge::CLIENT_BUILD
            || self.client_build != client_build
            || result.server_build as i32 != self.server_build as i32
            || result.secondary_build as i32 != self.server_build as i32
        {
            return Err(ProtocolError::new(
                "native login profile does not match the client/server build",
            ));
        }
        let answer = |tag, version| {
            let mut values = result.tlvs.iter().filter(|(t, _)| *t == tag);
            let (_, program) = values
                .next()
                .ok_or_else(|| ProtocolError::new(format!("missing authentication tag {tag}")))?;
            if values.next().is_some() {
                return Err(ProtocolError::new(format!(
                    "duplicate authentication tag {tag}"
                )));
            }
            challenge::solve(version, program, challenge::LOGIN_SEED)
        };
        Ok((answer(28, Version::Tag28)?, answer(35, Version::Tag35)?))
    }
}

impl std::fmt::Debug for LoginProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginProfile")
            .field("client_build", &self.client_build)
            .field("server_build", &self.server_build)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> serde_json::Value {
        serde_json::json!({
            "client_build":6182,"server_build":5830,"environment":"synthetic",
            "account":{"login":12345,"mode":"demo","server":"SyntheticBroker-Demo"}
        })
    }

    fn authentication() -> AuthResult {
        let mut bytes = vec![0; 44];
        bytes[24..26].copy_from_slice(&5830i16.to_le_bytes());
        bytes[26..28].copy_from_slice(&5830i16.to_le_bytes());
        bytes.extend(mt5_native::tlv::encode_tlvs(&[
            (
                0,
                "SyntheticBroker-Demo"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            ),
            (28, vec![0; 24]),
            (35, vec![0; 24]),
        ]));
        mt5_native::auth::parse_auth_result(&bytes).unwrap()
    }

    #[test]
    fn identity_is_required_and_cached_answers_are_not_configuration() {
        let profile = LoginProfile::from_json(&config().to_string()).unwrap();
        assert!(
            profile
                .validate_account(12345, "SyntheticBroker-Demo")
                .is_ok()
        );
        assert!(
            profile
                .validate_account(12346, "SyntheticBroker-Demo")
                .is_err()
        );
        assert!(
            profile
                .validate_account(12345, "SyntheticBroker-Live")
                .is_err()
        );
        let mut value = config();
        value.as_object_mut().unwrap().remove("account");
        assert!(LoginProfile::from_json(&value.to_string()).is_err());
        let mut value = config();
        value["account"].as_object_mut().unwrap().remove("server");
        assert!(LoginProfile::from_json(&value.to_string()).is_err());
        let mut value = config();
        value["f28"] = 123.into();
        assert!(LoginProfile::from_json(&value.to_string()).is_err());
    }

    #[test]
    fn changed_program_is_computed_without_enrollment() {
        let profile = LoginProfile::from_json(&config().to_string()).unwrap();
        let mut auth = authentication();
        let initial = profile.answers(6182, &auth).unwrap();
        let program = &mut auth.tlvs.iter_mut().find(|(tag, _)| *tag == 28).unwrap().1;
        program[..8].copy_from_slice(&(113u64 << 11).to_le_bytes());
        program[8..16].copy_from_slice(&123u64.to_le_bytes());
        program[16..].copy_from_slice(&456u64.to_le_bytes());
        let changed = profile.answers(6182, &auth).unwrap();
        assert_eq!(changed.0, 579);
        assert_ne!(initial.0, changed.0);
        assert_eq!(initial.1, changed.1);
    }

    #[test]
    fn wrong_build_missing_duplicate_or_malformed_fields_are_rejected() {
        let profile = LoginProfile::from_json(&config().to_string()).unwrap();
        assert!(profile.answers(6181, &authentication()).is_err());
        for tag in [0, 28, 35] {
            let mut auth = authentication();
            let field = auth.tlvs.iter().find(|(t, _)| *t == tag).unwrap().clone();
            auth.tlvs.push(field);
            assert!(profile.answers(6182, &auth).is_err());
            auth.tlvs.retain(|(t, _)| *t != tag);
            assert!(profile.answers(6182, &auth).is_err());
            auth.tlvs.push((tag, vec![1]));
            assert!(profile.answers(6182, &auth).is_err());
        }
        let mut auth = authentication();
        auth.secondary_build = 5831;
        assert!(profile.answers(6182, &auth).is_err());
    }
}
