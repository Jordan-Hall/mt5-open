//! An offline driver for authentication and the outgoing sync request.
//!
//! This ties the individual message builders and parsers ([`crate::auth`],
//! [`crate::keys`], [`crate::login`], [`crate::cipher`]) into one ordered state
//! machine: it produces the frames a client would send and consumes the
//! plaintext a server would return, deriving and holding the session and trade
//! keys along the way. It performs no I/O — every method is bytes in / bytes
//! out — and the crate remains DISABLED by policy.
//!
//! ```text
//! Init ──hello()──▶ HelloSent ──on_challenge()──▶ ChallengeReceived
//!      ──auth()──▶ AuthSent ──on_auth_result()──▶ SessionKeysReady
//!                          └─ status 1003 ─▶ CertificateRequired
//!                               └─ certificate_continuation() ─▶ SessionKeysReady
//! SessionKeysReady ──sync()──▶ SyncSent (account synchronization still required)
//! Invalid replies / rejected statuses ─▶ Failed
//! ```

use crate::auth::{AuthResult, certificate_continuation_payload, make_auth, make_hello, parse_auth_result, parse_challenge};
use crate::cipher::SessionCipher;
use crate::crypto::hardware_id;
use crate::error::{ProtocolError, Result};
use crate::frame::{command, Frame, FINAL};
use crate::keys::{derive_session_key, derive_trade_key};
use crate::login::{make_sync_request, LoginValues};
use crate::metadata::environment_metadata;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Init,
    HelloSent,
    ChallengeReceived,
    AuthSent,
    CertificateRequired,
    SessionKeysReady,
    SyncSent,
    Failed,
}

pub struct Handshake {
    login: u64,
    password: String,
    client_build: u16,
    device_id: [u8; 16],
    phase: Phase,
    server_challenge: Option<[u8; 16]>,
    server_build: Option<i16>,
    session_key: Option<Vec<u8>>,
    trade_key: Option<[u8; 32]>,
    session_cipher: Option<SessionCipher>,
    auth_result: Option<AuthResult>,
}

impl Handshake {
    /// Start a handshake; the device id defaults to the login's hardware id.
    pub fn new(login: u64, password: &str, client_build: u16) -> Self {
        Self::with_device_id(login, password, client_build, hardware_id(login))
    }

    pub fn with_device_id(login: u64, password: &str, client_build: u16, device_id: [u8; 16]) -> Self {
        Handshake {
            login,
            password: password.to_string(),
            client_build,
            device_id,
            phase: Phase::Init,
            server_challenge: None,
            server_build: None,
            session_key: None,
            trade_key: None,
            session_cipher: None,
            auth_result: None,
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn session_key(&self) -> Option<&[u8]> {
        self.session_key.as_deref()
    }
    pub fn trade_key(&self) -> Option<&[u8; 32]> {
        self.trade_key.as_ref()
    }
    pub fn server_build(&self) -> Option<i16> {
        self.server_build
    }

    /// Original ordered tags, including additional-login inputs 28/35 and
    /// unknown extensions. Contains sensitive key material; never log it.
    pub fn authentication_result(&self) -> Option<&AuthResult> {
        self.auth_result.as_ref()
    }

    fn fail(&mut self, error: ProtocolError) -> ProtocolError {
        self.phase = Phase::Failed;
        self.server_challenge = None;
        self.server_build = None;
        self.session_key = None;
        self.trade_key = None;
        self.session_cipher = None;
        self.auth_result = None;
        error
    }

    fn expect(&self, want: Phase) -> Result<()> {
        if self.phase != want {
            return Err(ProtocolError::new(format!(
                "handshake step out of order: in {:?}, expected {:?}",
                self.phase, want
            )));
        }
        Ok(())
    }

    /// Step 1 — the hello (command 0) request frame.
    pub fn hello(&mut self, nonce_byte: u8, random_word: u32, sequence: u16) -> Result<Frame> {
        self.expect(Phase::Init)?;
        let f = make_hello(self.login, sequence, self.client_build, Some(self.device_id), nonce_byte, random_word);
        self.phase = Phase::HelloSent;
        Ok(f)
    }

    /// Step 2 — consume the plaintext challenge reply.
    pub fn on_challenge(&mut self, plaintext: &[u8]) -> Result<()> {
        self.expect(Phase::HelloSent)?;
        let reply = parse_challenge(plaintext).map_err(|e| self.fail(e))?;
        if reply.status != 0 {
            return Err(self.fail(ProtocolError::new(format!("challenge rejected with status {}", reply.status))));
        }
        self.server_challenge = Some(reply.challenge);
        self.phase = Phase::ChallengeReceived;
        Ok(())
    }

    /// Step 3 — the authentication (command 1) request frame.
    pub fn auth(&mut self, client_challenge: &[u8; 16], nonce_word: u16, otp: Option<&str>, sequence: u16) -> Result<Frame> {
        self.expect(Phase::ChallengeReceived)?;
        let challenge = self
            .server_challenge
            .ok_or_else(|| ProtocolError::new("no server challenge stored"))?;
        let f = make_auth(self.login, &self.password, &challenge, sequence, client_challenge, nonce_word, otp);
        self.phase = Phase::AuthSent;
        Ok(f)
    }

    /// Step 4 — consume the plaintext authentication result: derive the session
    /// key (TLV 7) and optional trade key (TLV 27). Status 1003 requires a
    /// provisioned certificate before sync; no successful reply implies Ready.
    pub fn on_auth_result(&mut self, plaintext: &[u8]) -> Result<()> {
        self.expect(Phase::AuthSent)?;
        let result = parse_auth_result(plaintext).map_err(|e| self.fail(e))?;
        if result.status != 0 && result.status != 1003 {
            return Err(self.fail(ProtocolError::new(format!("authentication rejected with status {}", result.status))));
        }
        if result.server_build <= 0 {
            return Err(self.fail(ProtocolError::new("unsupported nonpositive server build")));
        }
        let mut session_key = None;
        let mut trade_key = None;
        // Match the observed ordered processing: later recognized tags replace
        // earlier values, but an invalid earlier key cannot be silently ignored.
        for (tag, value) in &result.tlvs {
            match tag {
                7 => session_key = Some(derive_session_key(self.login, &self.password, value).map_err(|e| self.fail(e))?),
                27 => trade_key = Some(derive_trade_key(self.login, &self.password, value)),
                _ => {}
            }
        }
        let session_key = session_key.ok_or_else(|| self.fail(ProtocolError::new("auth result missing session-key TLV 7")))?;
        let cipher = SessionCipher::new(&session_key).map_err(|e| self.fail(e))?;
        self.session_cipher = Some(cipher);
        self.session_key = Some(session_key);
        self.trade_key = trade_key;
        self.server_build = Some(result.server_build);
        self.phase = if result.status == 1003 { Phase::CertificateRequired } else { Phase::SessionKeysReady };
        self.auth_result = Some(result);
        Ok(())
    }

    /// Serialize command 2 using an externally provisioned DER certificate
    /// and RSASSA-PKCS1-v1_5-SHA1 signature over the original server challenge.
    /// The caller handles key access/signing; this codec does not enroll,
    /// parse PFX, or verify ownership of a certificate. No reply wait is
    /// invented: the covered profile sends sync next on the same TX cipher.
    pub fn certificate_continuation(&mut self, signature: &[u8], certificate_der: &[u8], sequence: u16) -> Result<Frame> {
        self.expect(Phase::CertificateRequired)?;
        let body = certificate_continuation_payload(signature, certificate_der)?;
        let cipher = self.session_cipher.as_mut().ok_or_else(|| ProtocolError::new("session cipher not initialized"))?;
        let ciphertext = cipher.encrypt(&body);
        self.phase = Phase::SessionKeysReady;
        Ok(Frame::new(command::CERT_CONTINUATION, sequence, FINAL, ciphertext))
    }

    /// Exact challenge bytes an external certificate signer must sign.
    pub fn certificate_challenge(&self) -> Result<&[u8; 16]> {
        self.expect(Phase::CertificateRequired)?;
        self.server_challenge.as_ref().ok_or_else(|| ProtocolError::new("no server challenge stored"))
    }

    /// The environment metadata this client would present in tag 127.
    pub fn generated_environment(&self) -> String {
        environment_metadata(&self.device_id, self.client_build as u32)
    }

    /// Step 5 — the command-12 synchronization request, session-encoded. Pass
    /// the login values (from the F28/F35 wrapper) and an optional environment
    /// string (the modern profile); `None` generates the documented metadata.
    /// LoginValues are externally resolved inputs, not calculated here. The
    /// caller must resolve any required tag-28/35 values for this connection.
    pub fn sync(
        &mut self,
        unix_seconds: i64,
        login_values: &LoginValues,
        environment_text: Option<&str>,
        sequence: u16,
    ) -> Result<Frame> {
        self.expect(Phase::SessionKeysReady)?;
        let server_build = self.server_build.unwrap_or(0) as u32;
        let generated = self.generated_environment();
        let body = make_sync_request(
            self.login,
            self.client_build as u32,
            server_build,
            unix_seconds,
            login_values.login_id,
            login_values.extended_login_id,
            Some(environment_text.unwrap_or(&generated)),
        );
        let cipher = self
            .session_cipher
            .as_mut()
            .ok_or_else(|| ProtocolError::new("session cipher not initialized"))?;
        let ciphertext = cipher.encrypt(&body);
        self.phase = Phase::SyncSent;
        Ok(Frame::new(command::ACCOUNT_STATE, sequence, FINAL, ciphertext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hexutil::{decode, encode};
    use crate::login::login_value_wrapper;
    use crate::tlv::encode_tlvs;

    fn challenge_reply(challenge: &[u8; 16]) -> Vec<u8> {
        // <h i h 16s 4h>: only the 16-byte challenge at offset 8 matters here.
        let mut v = Vec::new();
        v.extend_from_slice(&42i16.to_le_bytes());
        v.extend_from_slice(&0i32.to_le_bytes());
        v.extend_from_slice(&5500i16.to_le_bytes());
        v.extend_from_slice(challenge);
        for x in [1i16, 2, 3, 4] {
            v.extend_from_slice(&x.to_le_bytes());
        }
        v
    }

    fn auth_result(server_build: i16, tag7: &[u8], tag27: &[u8]) -> Vec<u8> {
        let mut head = vec![0u8; 44];
        head[24..26].copy_from_slice(&server_build.to_le_bytes());
        head.extend_from_slice(&encode_tlvs(&[(7, tag7.to_vec()), (27, tag27.to_vec())]));
        head
    }

    #[test]
    fn full_flow_reproduces_fixtures_and_derives_keys() {
        let mut h = Handshake::new(12345678, "ExamplePassword", 5500);
        assert_eq!(h.phase(), Phase::Init);

        // Hello reproduces conformance hello-01.
        let hello = h.hello(90, 305419896, 1).unwrap();
        assert_eq!(encode(&hello.pack()), "0022000000010002001bd12c9184c1ff4d74adb5b3d48f1f0301f46eeea8ea46f257ba34faf1d56e90e589");
        assert_eq!(h.phase(), Phase::HelloSent);

        // Challenge in, auth out reproduces conformance auth-basic.
        let challenge: [u8; 16] = decode("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        h.on_challenge(&challenge_reply(&challenge)).unwrap();
        let client: [u8; 16] = decode("101112131415161718191a1b1c1d1e1f").try_into().unwrap();
        let auth = h.auth(&client, 4660, None, 2).unwrap();
        assert_eq!(encode(&auth.pack()), "0122000000020002007539d2f4e3124fe83ad20414147b8ede160f9ee70d0aee0e9fcfcfd4efb1ee5b8227");

        // Auth result with TLV 7 / TLV 27 derives the documented keys.
        let tag27 = decode("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        h.on_auth_result(&auth_result(4199, &[0x00], &tag27)).unwrap();
        assert_eq!(h.phase(), Phase::SessionKeysReady);
        assert_eq!(encode(h.session_key().unwrap()), "15643cc783ab813e27e8dd486ea7dfc5");
        assert_eq!(encode(h.trade_key().unwrap()), "ee47d3d1b093ebb78e800fd4cf6b817f50d498a2cb874b3d7e74451d18122050");
        assert_eq!(h.server_build(), Some(4199));

        // Sync frame is command 12 and its body deciphers to the sync request.
        let lv = login_value_wrapper(12345678, 5500, 4199, &challenge, 18446744073709551614, 81985529216486895);
        let frame = h.sync(1700000000, &lv, None, 3).unwrap();
        assert_eq!(h.phase(), Phase::SyncSent);
        assert!(h.sync(1700000000, &lv, None, 4).is_err());
        assert_eq!(frame.command, command::ACCOUNT_STATE);
        assert!(frame.is_final());
        let mut c = SessionCipher::new(h.session_key().unwrap()).unwrap();
        let body = c.decrypt(&frame.payload);
        let expected = make_sync_request(12345678, 5500, 4199, 1700000000, lv.login_id, lv.extended_login_id, None);
        assert_eq!(body, expected);
    }

    #[test]
    fn steps_must_run_in_order() {
        let mut h = Handshake::new(12345678, "ExamplePassword", 5500);
        // Cannot authenticate before a challenge.
        let client = [0u8; 16];
        assert!(h.auth(&client, 0, None, 2).is_err());
        // Cannot sync before the result.
        let lv = LoginValues { login_id: 0, extended_login_id: 0, tag88_value: [0; 8], tag134_value: [0; 8] };
        assert!(h.sync(0, &lv, None, 3).is_err());
    }

    #[test]
    fn modern_environment_is_generated() {
        let h = Handshake::new(12345678, "ExamplePassword", 5500);
        assert!(h.generated_environment().starts_with("file=terminal64.exe\tversion=5500\t"));
    }

    fn auth_sent() -> Handshake {
        let mut h = Handshake::new(12345678, "ExamplePassword", 5500);
        h.hello(1, 2, 1).unwrap();
        h.on_challenge(&challenge_reply(&[3; 16])).unwrap();
        h.auth(&[4; 16], 5, None, 2).unwrap();
        h
    }

    // Synthetic external calculation results for byte/state tests only.
    fn synthetic_login_values() -> LoginValues {
        login_value_wrapper(12345678, 5500, 5500, &[3; 16], 123, 456)
    }

    #[test]
    fn rejected_challenge_is_terminal() {
        let mut h = Handshake::new(12345678, "ExamplePassword", 5500);
        h.hello(1, 2, 1).unwrap();
        let mut reply = challenge_reply(&[3; 16]);
        reply[2..6].copy_from_slice(&1i32.to_le_bytes());
        assert!(h.on_challenge(&reply).is_err());
        assert_eq!(h.phase(), Phase::Failed);
        assert!(h.auth(&[4; 16], 5, None, 2).is_err());
        assert!(h.on_challenge(&challenge_reply(&[3; 16])).is_err());
        assert!(h.session_key().is_none());
    }

    #[test]
    fn rejected_auth_cannot_install_keys_or_sync() {
        for status in [1i32, -1, 1001, 9999] {
            let mut h = auth_sent();
            let mut result = auth_result(5500, &[1], &[2]);
            result[4..8].copy_from_slice(&status.to_le_bytes());
            assert!(h.on_auth_result(&result).is_err());
            assert_eq!(h.phase(), Phase::Failed);
            assert!(h.session_key().is_none());
            assert!(h.trade_key().is_none());
            assert!(h.authentication_result().is_none());
            assert!(h.sync(0, &synthetic_login_values(), None, 3).is_err());
        }
    }

    #[test]
    fn malformed_or_missing_key_results_fail_without_partial_state() {
        let mut missing = vec![0; 44];
        missing[24..26].copy_from_slice(&5500i16.to_le_bytes());
        for result in [vec![0; 43], missing, auth_result(5500, &[], &[1]), auth_result(-1, &[1], &[2])] {
            let mut h = auth_sent();
            assert!(h.on_auth_result(&result).is_err());
            assert_eq!(h.phase(), Phase::Failed);
            assert!(h.session_key().is_none() && h.trade_key().is_none());
        }
    }

    #[test]
    fn certificate_continuation_precedes_sync_and_preserves_cipher_position() {
        let mut h = auth_sent();
        let mut result = auth_result(5500, &[1], &[2]);
        result[4..8].copy_from_slice(&1003i32.to_le_bytes());
        h.on_auth_result(&result).unwrap();
        assert_eq!(h.phase(), Phase::CertificateRequired);
        assert_eq!(h.certificate_challenge().unwrap(), &[3; 16]);
        let lv = synthetic_login_values();
        assert!(h.sync(123, &lv, None, 3).is_err());
        assert!(h.certificate_continuation(&[], &[0x30, 0], 3).is_err());
        assert_eq!(h.phase(), Phase::CertificateRequired);
        let mut rx = SessionCipher::new(h.session_key().unwrap()).unwrap();
        // Synthetic bytes test serialization only, not certificate validity/signing.
        let cert = h.certificate_continuation(&[1, 2, 3], &[0x30, 0], 3).unwrap();
        assert_eq!(cert.command, command::CERT_CONTINUATION);
        assert_eq!(cert.flags, FINAL);
        let plain = rx.decrypt(&cert.payload);
        assert_eq!(&plain[..16], &[0; 16]);
        assert_eq!(crate::tlv::parse_tlvs(&plain[16..]).unwrap(), vec![(4, vec![3, 2, 1]), (3, vec![0x30, 0])]);
        assert_eq!(h.phase(), Phase::SessionKeysReady);
        assert!(h.certificate_continuation(&[1], &[2], 4).is_err());
        let sync = h.sync(123, &lv, None, 4).unwrap();
        let tags = crate::tlv::parse_tlvs(&rx.decrypt(&sync.payload)).unwrap();
        let environment = &tags.iter().find(|(tag, _)| *tag == 127).unwrap().1;
        let mut expected: Vec<u8> = h.generated_environment().encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        expected.extend([0, 0]);
        assert_eq!(*environment, expected);
        assert_eq!(h.phase(), Phase::SyncSent);
    }

    #[test]
    fn extensions_are_retained_and_repeated_keys_use_wire_order() {
        let mut h = auth_sent();
        let mut result = auth_result(5500, &[1], &[2]);
        let extensions = vec![(28, vec![10]), (35, vec![20]), (99, vec![30]), (28, vec![40]), (7, vec![5]), (27, vec![6])];
        result.extend(encode_tlvs(&extensions));
        h.on_auth_result(&result).unwrap();
        assert_eq!(h.session_key().unwrap(), derive_session_key(12345678, "ExamplePassword", &[5]).unwrap());
        assert_eq!(h.trade_key().unwrap(), &derive_trade_key(12345678, "ExamplePassword", &[6]));
        assert_eq!(&h.authentication_result().unwrap().tlvs[2..], &extensions);
        assert!(h.certificate_continuation(&[1], &[2], 3).is_err());
    }

    #[test]
    fn missing_trade_key_does_not_become_a_signing_key() {
        let mut h = auth_sent();
        let mut result = vec![0; 44];
        result[24..26].copy_from_slice(&5500i16.to_le_bytes());
        result.extend(encode_tlvs(&[(7, vec![1])]));
        h.on_auth_result(&result).unwrap();
        assert_eq!(h.phase(), Phase::SessionKeysReady);
        assert!(h.trade_key().is_none());
    }
}
