//! A socket for the `mt5_native` codec.
//!
//! Everything in the codec is bytes in and bytes out, deliberately, and this
//! crate is the one place that talks to a network. It exists so the offline
//! work can finally be told whether it is right: the conformance vectors prove
//! the encoder agrees with a recording, not that a server accepts what it
//! builds. Those are different claims and only one of them has been tested.
//!
//! **Connect and authenticate only.** There is no order path here and no way
//! to reach one from here: nothing in this crate builds, signs or sends a
//! trade, and the codec's execution modules are not used. Placing an order
//! over this socket is a later stage with its own gate.
//!
//! The socket is blocking on purpose. An engine wants this on a thread of its
//! own anyway, and a blocking read with a timeout is easier to be sure about
//! than a future that may or may not still be polled.

#![cfg(feature = "live")]

use std::collections::VecDeque;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use mt5_native::account::{AccountState, parse_account_update_19};
use mt5_native::auth::AuthSummary;
use mt5_native::cipher::{SessionCipher, startup_decrypt_default};
use mt5_native::error::{ProtocolError, Result};
use mt5_native::frame::{Frame, FrameParser};
use mt5_native::handshake::{Handshake, Phase};
use mt5_native::login::{LoginValues, login_value_wrapper};

pub mod loginid;
pub use loginid::LoginIdService;

/// How long one read waits before giving up on a quiet server.
const READ_TIMEOUT: Duration = Duration::from_secs(20);

/// How long the connect itself is given.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// The largest payload a frame may claim. A corrupt or hostile length field is
/// a bad allocation waiting to happen, so it is bounded here rather than
/// trusted.
const MAX_PAYLOAD: usize = 4 * 1024 * 1024;

/// Operating-system entropy, without taking a dependency for it.
///
/// `RandomState` is seeded per process from the OS and is what the standard
/// library trusts to keep hash maps from being collided on purpose. The
/// handshake needs a client challenge and two nonces; this is enough for that
/// and is not offered for anything else.
fn entropy() -> u64 {
    let mut h = RandomState::new().build_hasher();
    h.write_u64(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0));
    h.finish()
}

fn entropy_16() -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&entropy().to_le_bytes());
    out[8..].copy_from_slice(&entropy().to_le_bytes());
    out
}

/// A connected, framed link to an access server.
pub struct Session {
    socket: TcpStream,
    parser: FrameParser,
    pending: VecDeque<Frame>,
    buffer: Vec<u8>,
    sequence: u16,
    /// Retained after a handshake so the caller can ask what the server
    /// required. Carries no credentials out of it: only `AuthSummary` is
    /// exposed, and that holds tag numbers and lengths, never values.
    handshake: Option<Handshake>,
    /// Kept from `authenticate` because the loginid wrapper needs them and they
    /// are not otherwise recoverable from the handshake.
    login: u64,
    client_build: u16,
    /// The receive keystream, live once synchronization has run. Its position
    /// persists across every inbound session-encrypted frame, so it is held
    /// here rather than rebuilt per call.
    rx: Option<SessionCipher>,
}

impl Session {
    /// Open a socket. Nothing is sent: a connection is not a login.
    pub fn connect(address: impl ToSocketAddrs) -> Result<Session> {
        mt5_native::ensure_live_allowed();
        let target = address
            .to_socket_addrs()
            .map_err(|e| ProtocolError::new(format!("address: {e}")))?
            .next()
            .ok_or_else(|| ProtocolError::new("address resolved to nothing"))?;
        let socket = TcpStream::connect_timeout(&target, CONNECT_TIMEOUT)
            .map_err(|e| ProtocolError::new(format!("connect: {e}")))?;
        socket
            .set_read_timeout(Some(READ_TIMEOUT))
            .map_err(|e| ProtocolError::new(format!("read timeout: {e}")))?;
        // Handshake frames are small; latency matters more than packing them.
        let _ = socket.set_nodelay(true);
        Ok(Session {
            socket,
            parser: FrameParser::new(MAX_PAYLOAD),
            pending: VecDeque::new(),
            buffer: vec![0u8; 16 * 1024],
            sequence: 1,
            handshake: None,
            login: 0,
            client_build: 0,
            rx: None,
        })
    }

    /// Read the next inbound session frame after READY, decrypting it on the
    /// persistent receive keystream. Every inbound frame must pass through here
    /// exactly once, in order, or the keystream desyncs -- so a caller waiting
    /// for one message still decrypts the ones before it.
    ///
    /// Returns `(command, decoded_payload)`.
    fn next_session_frame(&mut self) -> Result<(u8, Vec<u8>)> {
        let frame = self.next_frame()?;
        let rx = self
            .rx
            .as_mut()
            .ok_or_else(|| ProtocolError::new("no receive keystream; synchronize first"))?;
        Ok((frame.command, rx.decrypt(&frame.payload)))
    }

    /// Wait for the account state and read the balance from it.
    ///
    /// After READY the server sends the account record as command-55 subtype 19
    /// (`A(bytes[216] || AccountRec[2996])`). This decrypts inbound frames in
    /// order until that one arrives and returns the first account record in it.
    /// Frames before it (quotes, other updates) are decrypted and skipped so the
    /// keystream stays aligned. Still a read -- no order is sent.
    pub fn read_account_state(&mut self) -> Result<AccountState> {
        for _ in 0..256 {
            let (command, payload) = self.next_session_frame()?;
            if command == mt5_native::frame::command::TRADE_UPDATE
                && payload.first() == Some(&19)
            {
                let states = parse_account_update_19(&payload)?;
                return states
                    .into_iter()
                    .next()
                    .ok_or_else(|| ProtocolError::new("account update carried no records"));
            }
        }
        Err(ProtocolError::new("no account update arrived within 256 frames"))
    }

    fn next_sequence(&mut self) -> u16 {
        let n = self.sequence;
        self.sequence = self.sequence.wrapping_add(1).max(1);
        n
    }

    /// Put one frame on the wire.
    pub fn send(&mut self, frame: &Frame) -> Result<()> {
        self.socket
            .write_all(&frame.pack())
            .map_err(|e| ProtocolError::new(format!("write: {e}")))?;
        self.socket
            .flush()
            .map_err(|e| ProtocolError::new(format!("flush: {e}")))
    }

    /// Take the next frame, reading until one completes.
    ///
    /// A server that closes mid-frame is an error, not an end: half a frame is
    /// not a message, and treating it as one is how a parser starts inventing
    /// fields it never received.
    pub fn next_frame(&mut self) -> Result<Frame> {
        loop {
            if let Some(frame) = self.pending.pop_front() {
                return Ok(frame);
            }
            let read = self
                .socket
                .read(&mut self.buffer)
                .map_err(|e| ProtocolError::new(format!("read: {e}")))?;
            if read == 0 {
                return Err(ProtocolError::new("the server closed the connection"));
            }
            for frame in self.parser.feed(&self.buffer[..read])? {
                self.pending.push_back(frame);
            }
        }
    }

    /// Hello, challenge, auth — up to the point where session keys exist.
    ///
    /// Returns the server build, which decides what the rest of the protocol
    /// may do: the trade profile refuses outright below a certain build, and
    /// knowing that early is the difference between a clear refusal and a
    /// malformed order.
    pub fn authenticate(&mut self, login: u64, password: &str, client_build: u16) -> Result<i16> {
        self.login = login;
        self.client_build = client_build;
        let mut hs = Handshake::new(login, password, client_build);

        let seq = self.next_sequence();
        let hello = hs.hello((entropy() & 0xff) as u8, entropy() as u32, seq)?;
        self.send(&hello)?;

        // Before any session key exists, both directions use the startup
        // transform under a fixed key. The codec encrypts what it builds, so
        // inbound payloads have to be decrypted here -- `on_challenge` and
        // `on_auth_result` both take plaintext. The transform resets its
        // feedback per message, so each payload decodes independently.
        let challenge = self.next_frame()?;
        hs.on_challenge(&startup_decrypt_default(&challenge.payload))?;

        let seq = self.next_sequence();
        let auth = hs.auth(&entropy_16(), entropy() as u16, None, seq)?;
        self.send(&auth)?;

        let result = self.next_frame()?;
        hs.on_auth_result(&startup_decrypt_default(&result.payload))?;

        // Kept whatever the outcome: a rejection is worth inspecting too.
        let phase = hs.phase();
        let build = hs.server_build();
        self.handshake = Some(hs);

        match phase {
            Phase::SessionKeysReady => {
                build.ok_or_else(|| ProtocolError::new("authenticated without a server build"))
            }
            Phase::CertificateRequired => Err(ProtocolError::new(
                "this account asks for a certificate, which is issued outside this client",
            )),
            other => Err(ProtocolError::new(format!("authentication ended in {other:?}"))),
        }
    }
    /// Resolve the command-12 login values via the loginid service.
    ///
    /// This is the step the terminal itself cannot do without a service: the
    /// tag-28 and tag-35 blobs the server returned in the auth result are POSTed
    /// to the configured service, which returns the two integers, and the
    /// documented wrapper folds them (with the server challenge and builds) into
    /// the login ids. Nothing here computes what the service computes.
    ///
    /// Errors if the server did not send both input tags -- in which case the
    /// service is not the missing piece and something earlier is wrong.
    pub fn resolve_login_values(&self, service: &LoginIdService) -> Result<LoginValues> {
        let hs = self.handshake.as_ref().ok_or_else(|| ProtocolError::new("not authenticated"))?;
        let result = hs
            .authentication_result()
            .ok_or_else(|| ProtocolError::new("no authentication result to read tags from"))?;
        let tag = |t: u8| {
            result
                .tlvs
                .iter()
                .find(|(k, _)| *k == t)
                .map(|(_, v)| v.as_slice())
                .ok_or_else(|| ProtocolError::new(format!("auth result carried no tag {t}")))
        };
        let tag28 = tag(28)?;
        let tag35 = tag(35)?;
        let server_build = hs.server_build().ok_or_else(|| ProtocolError::new("no server build"))? as i32;
        let challenge = *hs.certificate_challenge()?;

        let f28 = service.resolve_tag(28, tag28, server_build)?;
        let f35 = service.resolve_tag(35, tag35, server_build)?;

        Ok(login_value_wrapper(
            self.login,
            self.client_build as u32,
            server_build as u32,
            &challenge,
            f28,
            f35,
        ))
    }

    /// Authenticate through to READY: resolve the login values, then synchronize.
    ///
    /// Returns the command-12 status and the decoded account-state stream. Still
    /// no order path -- the reply is account state, which is a read.
    pub fn synchronize_via_service(&mut self, service: &LoginIdService) -> Result<(i32, Vec<u8>)> {
        let values = self.resolve_login_values(service)?;
        self.synchronize(&values)
    }

    /// What the server asked for during the handshake.
    ///
    /// Structural only -- tag numbers and their lengths, the status and the
    /// builds. No login, challenge, credential, key or tag value leaves here.
    /// It answers the one question the specification says must be evaluated
    /// per connection: whether this server sends the tag-28/tag-35 TLVs whose
    /// derived values synchronization would need.
    pub fn auth_summary(&self) -> Option<AuthSummary> {
        self.handshake.as_ref()?.authentication_result().map(|r| r.summary())
    }

    /// Send command-12 synchronization and read the reply.
    ///
    /// This is the gate to `READY`, and everything worth having -- balance,
    /// symbols, quotes, orders -- lives past it. The request carries login
    /// values derived from the tag-28/tag-35 material; the specification
    /// declines to say whether a server accepts zeros there, so the only way
    /// to find out is to ask one.
    ///
    /// Returns the response status and the decoded stream. Still no order: the
    /// reply is account state, which is read.
    pub fn synchronize(&mut self, login_values: &LoginValues) -> Result<(i32, Vec<u8>)> {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let sequence = self.next_sequence();

        // Build the frame and take the key before sending, so the mutable
        // borrow of the handshake ends first.
        let (frame, key) = {
            let hs = self
                .handshake
                .as_mut()
                .ok_or_else(|| ProtocolError::new("not authenticated"))?;
            let frame = hs.sync(seconds, login_values, None, sequence)?;
            let key = hs
                .session_key()
                .ok_or_else(|| ProtocolError::new("no session key"))?
                .to_vec();
            (frame, key)
        };
        self.send(&frame)?;

        // The reply is one continuous stream once each frame is deciphered --
        // its status, tags and records can all straddle frame boundaries, so
        // the pieces are concatenated before anything is read out of them.
        // Receive runs its own keystream, separate from the one that just
        // encrypted the request, and its position persists for the life of the
        // connection: it is stored on the session so later inbound frames
        // (account updates, quotes) stay aligned rather than desyncing.
        let mut rx = SessionCipher::new(&key)?;
        let mut stream = Vec::new();
        loop {
            let reply = self.next_frame()?;
            stream.extend_from_slice(&rx.decrypt(&reply.payload));
            if reply.is_final() {
                break;
            }
        }
        self.rx = Some(rx);
        if stream.len() < 4 {
            return Err(ProtocolError::new(format!(
                "synchronization reply was {} bytes, too short for a status",
                stream.len()
            )));
        }
        let status = i32::from_le_bytes([stream[0], stream[1], stream[2], stream[3]]);
        Ok((status, stream))
    }

}
