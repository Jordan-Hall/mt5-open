//! Native MT5 authentication, market data and trading over blocking TCP.
//! Network access requires `live`. `Session` owns the wire state; `client::Client`
//! applies account updates and correlates history and trade results.

#![cfg(feature = "live")]

use mt5_native::account::AccountState;
use mt5_native::auth::AuthSummary;
use mt5_native::cipher::SessionCipher;
use mt5_native::compression::{MAX_MESSAGE, decompress_payload};
use mt5_native::error::{ProtocolError, Result};
use mt5_native::frame::{FINAL, Frame, command};
use mt5_native::handshake::{Handshake, Phase};
use mt5_native::reassembly::{Message, Reassembler};
use mt5_native::sync::{SynchronizedState, parse_synchronized_state};
use std::net::ToSocketAddrs;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub mod client;
pub mod connection;
pub mod endpoints;
pub use mt5_native as protocol;
mod profile;
use connection::{Connection, IO_TIMEOUT};
pub use profile::LoginProfile;

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| ProtocolError::new("operating-system entropy unavailable"))?;
    Ok(bytes)
}

enum State {
    Connected,
    Authenticated {
        handshake: Box<Handshake>,
        login: u64,
        client_build: u16,
    },
    Ready {
        rx: SessionCipher,
        tx: SessionCipher,
        trade_key: Option<[u8; 32]>,
        account: AccountState,
        read_only: bool,
        messages: Reassembler,
    },
    Failed,
}

/// A verified account and the complete synchronization payload.
/// Retain the payload when other account, symbol or broker records are needed.
pub struct Synchronization {
    pub account: AccountState,
    pub state: SynchronizedState,
    pub payload: Vec<u8>,
}

pub struct Session {
    connection: Connection,
    state: State,
    summary: Option<AuthSummary>,
}

impl Session {
    pub fn peer_addr(&self) -> Result<std::net::SocketAddr> {
        self.connection.peer_addr()
    }
    pub fn connect(address: impl ToSocketAddrs) -> Result<Self> {
        Ok(Self {
            connection: Connection::connect(address)?,
            state: State::Connected,
            summary: None,
        })
    }

    /// Accept the password challenge. Account synchronization is a separate step.
    /// A failed attempt consumes the connection; reconnect before trying again.
    pub fn authenticate(&mut self, login: u64, password: &str, client_build: u16) -> Result<i16> {
        if !matches!(self.state, State::Connected) {
            return Err(ProtocolError::new(
                "authentication requires a new connection",
            ));
        }
        self.state = State::Failed;
        let mut handshake = Handshake::new(login, password, client_build);
        let sequence = self.connection.next_sequence();
        let hello = handshake.hello(
            random_bytes::<1>()?[0],
            u32::from_le_bytes(random_bytes()?),
            sequence,
        )?;
        self.connection.send(&hello)?;
        handshake.on_challenge(&self.connection.startup_reply(command::HELLO, sequence)?)?;
        let sequence = self.connection.next_sequence();
        let auth = handshake.auth(
            &random_bytes()?,
            u16::from_le_bytes(random_bytes()?),
            None,
            sequence,
        )?;
        self.connection.send(&auth)?;
        handshake.on_auth_result(&self.connection.startup_reply(command::AUTH, sequence)?)?;
        self.summary = handshake
            .authentication_result()
            .map(|result| result.summary());
        if handshake.phase() != Phase::SessionKeysReady {
            return Err(ProtocolError::new(
                "account requires certificate authentication; socket enrollment is not implemented",
            ));
        }
        let build = handshake
            .server_build()
            .ok_or_else(|| ProtocolError::new("missing server build"))?;
        self.state = State::Authenticated {
            handshake: Box::new(handshake),
            login,
            client_build,
        };
        Ok(build)
    }

    pub fn auth_summary(&self) -> Option<AuthSummary> {
        self.summary.clone()
    }

    /// Compute both challenge answers and validate synchronization and account identity.
    pub fn synchronize(&mut self, profile: &LoginProfile) -> Result<Synchronization> {
        let State::Authenticated {
            handshake,
            client_build,
            login,
        } = &self.state
        else {
            return Err(ProtocolError::new(
                "synchronization requires password authentication",
            ));
        };
        profile.account_mode(*login)?;
        let result = handshake
            .authentication_result()
            .ok_or_else(|| ProtocolError::new("missing authentication result"))?;
        let (answer28, answer35) = profile.answers(*client_build, result)?;
        let values = handshake.login_values(answer28, answer35)?;
        let record_build = result.secondary_build;
        let State::Authenticated {
            mut handshake,
            login,
            ..
        } = std::mem::replace(&mut self.state, State::Failed)
        else {
            unreachable!()
        };
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProtocolError::new("system clock is before the Unix epoch"))?
            .as_secs() as i64;
        let sequence = self.connection.next_sequence();
        self.connection.send(&handshake.sync(
            seconds,
            &values,
            Some(profile.environment()),
            sequence,
        )?)?;
        let mut rx = SessionCipher::new(
            handshake
                .session_key()
                .ok_or_else(|| ProtocolError::new("missing session key"))?,
        )?;
        let deadline = Instant::now() + IO_TIMEOUT;
        let mut payload = Vec::new();
        loop {
            let frame = self.connection.frame_before(deadline)?;
            if frame.command == command::PING && frame.payload.is_empty() {
                continue;
            }
            if frame.command != command::ACCOUNT_STATE || frame.sequence != sequence {
                return Err(ProtocolError::new(
                    "unexpected frame during account synchronization",
                ));
            }
            let bytes = rx.decrypt(&frame.payload);
            let bytes = if frame.is_compressed() {
                decompress_payload(&bytes, MAX_MESSAGE - payload.len())?
            } else {
                bytes
            };
            if bytes.len() > MAX_MESSAGE - payload.len() {
                return Err(ProtocolError::new("synchronization exceeds message limit"));
            }
            payload.extend_from_slice(&bytes);
            if frame.is_final() {
                break;
            }
        }
        let state = parse_synchronized_state(&payload, record_build)?;
        let account = state.account;
        if account.login != login {
            return Err(ProtocolError::new(
                "synchronized account does not match requested login",
            ));
        }
        self.state = State::Ready {
            rx,
            tx: handshake.take_send_cipher()?,
            trade_key: handshake.trade_key().copied(),
            account,
            read_only: account.is_read_only() || profile.read_only(login)?,
            messages: Reassembler::default(),
        };
        Ok(Synchronization {
            account,
            state,
            payload,
        })
    }

    /// The latest verified account record received by this session.
    pub fn account(&self) -> Result<AccountState> {
        match self.state {
            State::Ready { account, .. } => Ok(account),
            _ => Err(ProtocolError::new(
                "account is unavailable before successful synchronization",
            )),
        }
    }

    /// Whether broker permissions or the enrolled profile prohibit mutations.
    pub fn is_read_only(&self) -> Result<bool> {
        match self.state {
            State::Ready { read_only, .. } => Ok(read_only),
            _ => Err(ProtocolError::new(
                "synchronize before reading session permissions",
            )),
        }
    }

    /// Send a session request. A write failure consumes the connection because
    /// a partial write leaves both cipher position and broker effects uncertain.
    pub fn send_request(&mut self, command: u8, payload: &[u8]) -> Result<u16> {
        self.send_encoded(command, payload, FINAL)
    }

    fn send_encoded(&mut self, command: u8, payload: &[u8], flags: u16) -> Result<u16> {
        if payload.len() > mt5_native::frame::MAX_PAYLOAD {
            return Err(ProtocolError::new("request exceeds frame limit"));
        }
        let State::Ready { tx, read_only, .. } = &mut self.state else {
            return Err(ProtocolError::new(
                "synchronize before sending session requests",
            ));
        };
        if *read_only
            && !matches!(
                command,
                command::PING
                    | command::TRADE_HISTORY
                    | command::QUOTE_HISTORY
                    | command::SYMBOLS
                    | 106
            )
        {
            return Err(ProtocolError::new(
                "command is not allowed in a read-only session",
            ));
        }
        let sequence = self.connection.next_sequence();
        let frame = Frame::new(command, sequence, flags, tx.encrypt(payload));
        if let Err(error) = self.connection.send(&frame) {
            self.state = State::Failed;
            return Err(error);
        }
        Ok(sequence)
    }

    /// The returned sequence acknowledges transmission only. Detailed results
    /// must be correlated through the echoed request ID in command 55/35.
    pub fn send_trade(&mut self, record: &[u8]) -> Result<u16> {
        let State::Ready {
            trade_key,
            read_only,
            ..
        } = &self.state
        else {
            return Err(ProtocolError::new("synchronize before trading"));
        };
        if *read_only {
            return Err(ProtocolError::new("account is read-only"));
        }
        let key = trade_key
            .as_ref()
            .ok_or_else(|| ProtocolError::new("no trade signing key"))?;
        let body = mt5_native::trade::make_signed_trade_payload(record, key)?;
        let payload = mt5_native::compression::make_compressed_payload(&body)?;
        self.send_encoded(
            command::TRADE_REQUEST,
            &payload,
            FINAL | mt5_native::frame::COMPRESSED,
        )
    }

    pub fn subscribe(&mut self, symbol_ids: &[i32]) -> Result<u16> {
        self.send_request(
            command::SYMBOLS,
            &mt5_native::subscription::make_subscription_payload(symbol_ids),
        )
    }

    /// Receive complete messages while preserving the cipher position between calls.
    pub fn next_message(&mut self) -> Result<Message> {
        self.poll_message(IO_TIMEOUT)?
            .ok_or_else(|| ProtocolError::new("receive deadline exceeded"))
    }

    /// Idle timeouts preserve ciphers and partial frames; malformed data or a
    /// disconnected socket consumes the session.
    pub fn poll_message(&mut self, timeout: Duration) -> Result<Option<Message>> {
        if !matches!(self.state, State::Ready { .. }) {
            return Err(ProtocolError::new(
                "synchronize before receiving session messages",
            ));
        }
        let State::Ready {
            mut rx,
            tx,
            trade_key,
            mut account,
            mut read_only,
            mut messages,
        } = std::mem::replace(&mut self.state, State::Failed)
        else {
            unreachable!()
        };
        let deadline = Instant::now() + timeout;
        loop {
            let Some(frame) = self.connection.poll_frame(deadline)? else {
                self.state = State::Ready {
                    rx,
                    tx,
                    trade_key,
                    account,
                    read_only,
                    messages,
                };
                return Ok(None);
            };
            let bytes = rx.decrypt(&frame.payload);
            let bytes = if frame.is_compressed() {
                decompress_payload(&bytes, MAX_MESSAGE)?
            } else {
                bytes
            };
            if let Some(message) = messages.push(&frame, &bytes)? {
                if message.command == 55 && message.payload.first() == Some(&19) {
                    let updates = mt5_native::account::parse_account_update_19(&message.payload)?;
                    if updates.iter().any(|update| update.login != account.login) {
                        return Err(ProtocolError::new(
                            "account update does not match authenticated login",
                        ));
                    }
                    for update in updates {
                        read_only |= update.is_read_only();
                        account = update;
                    }
                }
                self.state = State::Ready {
                    rx,
                    tx,
                    trade_key,
                    account,
                    read_only,
                    messages,
                };
                return Ok(Some(message));
            }
        }
    }
}
