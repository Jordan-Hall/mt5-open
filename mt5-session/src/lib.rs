//! Direct, blocking TCP transport for the experimental native MT5 codec.
//!
//! No terminal, hosted calculation service, or WebTerminal is used. Completing
//! password authentication is not account readiness. The additional-login
//! mappings remain unverified and must be supplied by an in-process resolver.
//! The raw send/receive methods are low-level escape hatches; they do not apply
//! session encryption and must not be mixed with an active authenticated flow.

#![cfg(feature = "live")]

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mt5_native::account::{AccountState, parse_account_update_19};
use mt5_native::auth::{AuthSummary, parse_auth_result};
use mt5_native::cipher::{SessionCipher, startup_decrypt_default};
use mt5_native::compression::decompress_payload;
use mt5_native::error::{ProtocolError, Result};
use mt5_native::frame::{COMPRESSED, FINAL, Frame, FrameParser, command};
use mt5_native::handshake::{Handshake, Phase};
use mt5_native::login::{LoginValues, login_value_wrapper};
use mt5_native::reassembly::{Message, Reassembler};

pub mod loginid;
pub use loginid::{LoginContext, LoginDerivation, LoginIdResolver, UnsupportedLoginProfile};

const IO_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_PAYLOAD: usize = 4 * 1024 * 1024;
const MAX_MESSAGE: usize = 16 * 1024 * 1024;
const MAX_FRAMES: usize = 1024;
const MAX_DEFERRED: usize = 32;

pub struct Session {
    socket: TcpStream,
    parser: FrameParser,
    pending: VecDeque<Frame>,
    sequence: u16,
    handshake: Option<Handshake>,
    summary: Option<AuthSummary>,
    login: u64,
    client_build: u16,
    rx: Option<SessionCipher>,
    reassembler: Reassembler,
    deferred: VecDeque<Message>,
    deferred_bytes: usize,
    synchronized: bool,
    failed: bool,
}

impl Session {
    /// Uses the exact broker-provided native host and port. DNS resolution is
    /// synchronous; the connect deadline applies after resolution completes.
    pub fn connect(address: impl ToSocketAddrs) -> Result<Self> {
        mt5_native::ensure_live_allowed();
        let targets: Vec<_> = address
            .to_socket_addrs()
            .map_err(|e| ProtocolError::new(format!("address resolution: {e}")))?
            .collect();
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        let mut socket = None;
        for target in targets {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            if let Ok(connected) = TcpStream::connect_timeout(&target, remaining) {
                socket = Some(connected);
                break;
            }
        }
        let socket = socket.ok_or_else(|| {
            ProtocolError::new("no resolved access point connected before the deadline")
        })?;
        socket
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(io_error)?;
        socket
            .set_write_timeout(Some(IO_TIMEOUT))
            .map_err(io_error)?;
        socket.set_nodelay(true).map_err(io_error)?;
        Ok(Self {
            socket,
            parser: FrameParser::new(MAX_PAYLOAD),
            pending: VecDeque::new(),
            sequence: 1,
            handshake: None,
            summary: None,
            login: 0,
            client_build: 0,
            rx: None,
            reassembler: Reassembler::new(MAX_MESSAGE, 8),
            deferred: VecDeque::new(),
            deferred_bytes: 0,
            synchronized: false,
            failed: false,
        })
    }

    fn check_open(&self) -> Result<()> {
        if self.failed {
            Err(ProtocolError::new(
                "session failed; reconnect before retrying",
            ))
        } else {
            Ok(())
        }
    }

    fn fail<T>(&mut self, error: ProtocolError) -> Result<T> {
        self.failed = true;
        self.synchronized = false;
        self.rx = None;
        self.handshake = None;
        self.pending.clear();
        self.deferred.clear();
        self.deferred_bytes = 0;
        self.reassembler = Reassembler::new(MAX_MESSAGE, 8);
        let _ = self.socket.shutdown(Shutdown::Both);
        Err(error)
    }

    fn next_sequence(&mut self) -> u16 {
        let sequence = self.sequence;
        self.sequence = self.sequence.wrapping_add(1).max(1);
        sequence
    }

    /// Raw framing only. Prefer the high-level authentication/sync methods.
    pub fn send(&mut self, frame: &Frame) -> Result<()> {
        self.check_open()?;
        if frame.payload.len() > MAX_PAYLOAD {
            return self.fail(ProtocolError::new("outbound frame exceeds payload limit"));
        }
        if let Err(error) = self.socket.write_all(&frame.pack()) {
            return self.fail(io_error(error));
        }
        Ok(())
    }

    pub fn next_frame(&mut self) -> Result<Frame> {
        self.read_frame(Instant::now() + IO_TIMEOUT)
    }

    fn read_frame(&mut self, deadline: Instant) -> Result<Frame> {
        self.check_open()?;
        let result = (|| {
            let mut buffer = [0u8; 16 * 1024];
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(ProtocolError::new("receive deadline exceeded"));
                }
                if let Some(frame) = self.pending.pop_front() {
                    return Ok(frame);
                }
                self.socket
                    .set_read_timeout(Some(remaining))
                    .map_err(io_error)?;
                let count = match self.socket.read(&mut buffer) {
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    other => other.map_err(io_error)?,
                };
                if count == 0 {
                    self.parser.finish()?;
                    return Err(ProtocolError::new("server closed the connection"));
                }
                self.pending.extend(self.parser.feed(&buffer[..count])?);
            }
        })();
        match result {
            Ok(frame) => Ok(frame),
            Err(error) => self.fail(error),
        }
    }

    fn startup_reply(
        &mut self,
        expected_command: u8,
        sequence: u16,
        deadline: Instant,
    ) -> Result<Vec<u8>> {
        let frame = self.read_frame(deadline)?;
        if frame.command != expected_command || frame.sequence != sequence || frame.flags != FINAL {
            return self.fail(ProtocolError::new(
                "unexpected command, sequence, or unsupported startup fragmentation/compression",
            ));
        }
        Ok(startup_decrypt_default(&frame.payload))
    }

    pub fn authenticate(&mut self, login: u64, password: &str, client_build: u16) -> Result<i16> {
        let summary = self.authenticate_with_otp(login, password, client_build, None)?;
        if summary.certificate_required {
            return Err(ProtocolError::new(
                "certificate required; use certificate_challenge and certificate_continuation",
            ));
        }
        Ok(summary.server_build)
    }

    /// Sends OTP only when provided. Status 1003 is returned as a continuation
    /// requirement, not as readiness. Unknown statuses close the connection.
    pub fn authenticate_with_otp(
        &mut self,
        login: u64,
        password: &str,
        client_build: u16,
        otp: Option<&str>,
    ) -> Result<AuthSummary> {
        self.check_open()?;
        if self.handshake.is_some() {
            return Err(ProtocolError::new(
                "authentication already started; reconnect to authenticate again",
            ));
        }
        if login == 0 || password.is_empty() || client_build == 0 || otp == Some("") {
            return Err(ProtocolError::new(
                "login, password, build, and any supplied OTP must be nonempty",
            ));
        }
        let mut random = [0u8; 23];
        getrandom::getrandom(&mut random)
            .map_err(|_| ProtocolError::new("operating-system entropy unavailable"))?;
        self.login = login;
        self.client_build = client_build;
        let mut hs = Handshake::new(login, password, client_build);
        let deadline = Instant::now() + IO_TIMEOUT;
        let outcome = (|| {
            let sequence = self.next_sequence();
            let hello = hs.hello(
                random[0],
                u32::from_le_bytes(random[1..5].try_into().unwrap()),
                sequence,
            )?;
            self.send(&hello)?;
            hs.on_challenge(&self.startup_reply(command::HELLO, sequence, deadline)?)?;
            let sequence = self.next_sequence();
            let client_challenge: [u8; 16] = random[7..23].try_into().unwrap();
            let auth = hs.auth(
                &client_challenge,
                u16::from_le_bytes([random[5], random[6]]),
                otp,
                sequence,
            )?;
            self.send(&auth)?;
            let plaintext = self.startup_reply(command::AUTH, sequence, deadline)?;
            self.summary = Some(parse_auth_result(&plaintext)?.summary());
            hs.on_auth_result(&plaintext)?;
            Ok(())
        })();
        if let Err(error) = outcome {
            return self.fail(error);
        }
        self.handshake = Some(hs);
        self.summary
            .clone()
            .ok_or_else(|| ProtocolError::new("missing authentication summary"))
    }

    pub fn auth_summary(&self) -> Option<AuthSummary> {
        self.summary.clone()
    }

    pub fn certificate_challenge(&self) -> Result<&[u8; 16]> {
        self.check_open()?;
        self.handshake
            .as_ref()
            .ok_or_else(|| ProtocolError::new("not authenticated"))?
            .certificate_challenge()
    }

    /// The caller supplies a provisioned DER certificate and a PKCS#1 v1.5
    /// SHA-1 signature of certificate_challenge(). This does not enroll keys.
    pub fn certificate_continuation(
        &mut self,
        signature: &[u8],
        certificate_der: &[u8],
    ) -> Result<()> {
        self.check_open()?;
        if signature.is_empty()
            || certificate_der.is_empty()
            || signature.len().saturating_add(certificate_der.len()) > MAX_PAYLOAD - 32
        {
            return Err(ProtocolError::new("invalid certificate continuation size"));
        }
        let sequence = self.next_sequence();
        let hs = self
            .handshake
            .as_mut()
            .ok_or_else(|| ProtocolError::new("not authenticated"))?;
        let frame = hs.certificate_continuation(signature, certificate_der, sequence)?;
        self.send(&frame)
    }

    pub fn login_context(&self) -> Result<LoginContext<'_>> {
        self.check_open()?;
        let hs = self
            .handshake
            .as_ref()
            .ok_or_else(|| ProtocolError::new("not authenticated"))?;
        let result = hs
            .authentication_result()
            .ok_or_else(|| ProtocolError::new("no authentication result"))?;
        Ok(LoginContext {
            login: self.login,
            client_build: self.client_build,
            server_build: result.server_build as u16,
            record_build: result.secondary_build,
            server_challenge: hs.login_challenge()?,
            tags: &result.tlvs,
        })
    }

    pub fn resolve_login_values(
        &self,
        resolver: &(impl LoginIdResolver + ?Sized),
    ) -> Result<LoginValues> {
        let context = self.login_context()?;
        let derived = resolver.derive(&context)?;
        Ok(login_value_wrapper(
            context.login,
            context.client_build as u32,
            context.server_build as u32,
            context.server_challenge,
            derived.f28,
            derived.f35,
        ))
    }

    pub fn synchronize_with(
        &mut self,
        resolver: &(impl LoginIdResolver + ?Sized),
    ) -> Result<(i32, Vec<u8>)> {
        let values = self.resolve_login_values(resolver)?;
        self.synchronize(&values)
    }

    fn read_message(&mut self, deadline: Instant) -> Result<Message> {
        let result = (|| {
            for _ in 0..MAX_FRAMES {
                let frame = self.read_frame(deadline)?;
                if frame.flags & !(FINAL | COMPRESSED) != 0 {
                    return Err(ProtocolError::new("unsupported session frame flags"));
                }
                let rx = self
                    .rx
                    .as_mut()
                    .ok_or_else(|| ProtocolError::new("no receive cipher"))?;
                let plain = rx.decrypt(&frame.payload);
                let plain = if frame.is_compressed() {
                    decompress_payload(&plain, MAX_MESSAGE)?
                } else {
                    plain
                };
                if let Some(message) = self.reassembler.push(&frame, &plain)? {
                    return Ok(message);
                }
            }
            Err(ProtocolError::new(
                "session message exceeded fragment budget",
            ))
        })();
        match result {
            Ok(message) => Ok(message),
            Err(error) => self.fail(error),
        }
    }

    /// Explicit low-level input API; supplied values must belong to this exact
    /// connection. Prefer synchronize_with to avoid cross-session value reuse.
    /// Status zero means sync was accepted, NOT complete account readiness.
    pub fn synchronize(&mut self, login_values: &LoginValues) -> Result<(i32, Vec<u8>)> {
        self.check_open()?;
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProtocolError::new("system clock precedes Unix epoch"))?
            .as_secs();
        let seconds =
            i64::try_from(seconds).map_err(|_| ProtocolError::new("system clock out of range"))?;
        let sequence = self.next_sequence();
        let hs = self
            .handshake
            .as_mut()
            .ok_or_else(|| ProtocolError::new("not authenticated"))?;
        if hs.phase() != Phase::SessionKeysReady {
            return Err(ProtocolError::new(
                "session keys not ready for synchronization",
            ));
        }
        let key = hs
            .session_key()
            .ok_or_else(|| ProtocolError::new("no session key"))?
            .to_vec();
        let frame = hs.sync(seconds, login_values, None, sequence)?;
        self.rx = Some(SessionCipher::new(&key)?);
        self.send(&frame)?;
        let deadline = Instant::now() + IO_TIMEOUT;
        for _ in 0..MAX_FRAMES {
            let message = self.read_message(deadline)?;
            if message.command == command::ACCOUNT_STATE && message.sequence == sequence {
                if message.payload.len() < 4 {
                    return self.fail(ProtocolError::new("sync reply too short for status"));
                }
                let status = i32::from_le_bytes(message.payload[..4].try_into().unwrap());
                if status != 0 {
                    return self.fail(ProtocolError::new(format!(
                        "synchronization rejected with status {status}"
                    )));
                }
                self.synchronized = true;
                return Ok((status, message.payload));
            }
            if self.deferred.len() >= MAX_DEFERRED
                || self.deferred_bytes.saturating_add(message.payload.len()) > MAX_MESSAGE
            {
                return self.fail(ProtocolError::new(
                    "too many unrelated messages before sync response",
                ));
            }
            self.deferred_bytes += message.payload.len();
            self.deferred.push_back(message);
        }
        self.fail(ProtocolError::new(
            "synchronization response budget exceeded",
        ))
    }

    /// Reads the command-55 account update profile, checks account identity,
    /// and keeps the receive cipher aligned through compressed/interleaved data.
    /// Parsing every command-12 account/symbol record is still out of scope.
    pub fn read_account_state(&mut self) -> Result<AccountState> {
        self.check_open()?;
        if !self.synchronized {
            return Err(ProtocolError::new(
                "synchronize before reading account state",
            ));
        }
        let deadline = Instant::now() + IO_TIMEOUT;
        for _ in 0..256 {
            let message = if let Some(message) = self.deferred.pop_front() {
                self.deferred_bytes -= message.payload.len();
                message
            } else {
                self.read_message(deadline)?
            };
            if message.command == command::TRADE_UPDATE && message.payload.first() == Some(&19) {
                let states = match parse_account_update_19(&message.payload) {
                    Ok(states) => states,
                    Err(error) => return self.fail(error),
                };
                if let Some(account) = states.into_iter().find(|state| state.login == self.login) {
                    return Ok(account);
                }
                return self.fail(ProtocolError::new(
                    "account update did not contain the authenticated account",
                ));
            }
        }
        self.fail(ProtocolError::new(
            "no account update within message budget",
        ))
    }
}

fn io_error(error: std::io::Error) -> ProtocolError {
    ProtocolError::new(format!("socket I/O: {error}"))
}
