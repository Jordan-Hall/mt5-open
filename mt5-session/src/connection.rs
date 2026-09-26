//! Bounded TCP framing. Authentication and session state live in `Session`.

use mt5_native::error::{ProtocolError, Result};
use mt5_native::frame::{Frame, FrameParser};
use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

pub const IO_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_PAYLOAD: usize = 4 * 1024 * 1024;

pub struct Connection {
    socket: TcpStream,
    parser: FrameParser,
    pending: VecDeque<Frame>,
    buffer: Vec<u8>,
    sequence: u16,
}

impl Connection {
    pub fn connect(address: impl ToSocketAddrs) -> Result<Self> {
        mt5_native::ensure_live_allowed();
        let targets = address
            .to_socket_addrs()
            .map_err(|e| ProtocolError::new(format!("address: {e}")))?
            .collect::<Vec<_>>();
        let attempt_timeout = if targets.len() > 1 {
            Duration::from_secs(3)
        } else {
            CONNECT_TIMEOUT
        };
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        let mut last_error = ProtocolError::new("address resolved to nothing");
        for target in targets {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            match TcpStream::connect_timeout(&target, remaining.min(attempt_timeout)) {
                Ok(socket) => {
                    socket
                        .set_read_timeout(Some(IO_TIMEOUT))
                        .map_err(|e| ProtocolError::new(e.to_string()))?;
                    socket
                        .set_write_timeout(Some(IO_TIMEOUT))
                        .map_err(|e| ProtocolError::new(e.to_string()))?;
                    socket
                        .set_nodelay(true)
                        .map_err(|e| ProtocolError::new(e.to_string()))?;
                    return Ok(Self {
                        socket,
                        parser: FrameParser::new(MAX_PAYLOAD),
                        pending: VecDeque::new(),
                        buffer: vec![0; 16 * 1024],
                        sequence: 1,
                    });
                }
                Err(error) => last_error = ProtocolError::new(format!("connect: {error}")),
            }
        }
        Err(last_error)
    }

    pub fn peer_addr(&self) -> Result<SocketAddr> {
        self.socket
            .peer_addr()
            .map_err(|e| ProtocolError::new(format!("peer address: {e}")))
    }

    pub(crate) fn next_sequence(&mut self) -> u16 {
        let current = self.sequence;
        self.sequence = current.wrapping_add(1).max(1);
        current
    }

    pub fn send(&mut self, frame: &Frame) -> Result<()> {
        self.socket
            .write_all(&frame.pack())
            .map_err(|e| ProtocolError::new(format!("write: {e}")))
    }

    pub fn next_frame(&mut self) -> Result<Frame> {
        self.frame_before(Instant::now() + IO_TIMEOUT)
    }

    pub(crate) fn frame_before(&mut self, deadline: Instant) -> Result<Frame> {
        self.poll_frame(deadline)?
            .ok_or_else(|| ProtocolError::new("receive deadline exceeded"))
    }

    pub(crate) fn poll_frame(&mut self, deadline: Instant) -> Result<Option<Frame>> {
        loop {
            if let Some(frame) = self.pending.pop_front() {
                return Ok(Some(frame));
            }
            let Some(remaining) = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
            else {
                return Ok(None);
            };
            self.socket
                .set_read_timeout(Some(remaining))
                .map_err(|e| ProtocolError::new(e.to_string()))?;
            let read = match self.socket.read(&mut self.buffer) {
                Ok(read) => read,
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    return Ok(None);
                }
                Err(error) => return Err(ProtocolError::new(format!("read: {error}"))),
            };
            if read == 0 {
                return Err(ProtocolError::new("server closed the connection"));
            }
            self.pending.extend(self.parser.feed(&self.buffer[..read])?);
        }
    }

    pub(crate) fn startup_reply(&mut self, command: u8, sequence: u16) -> Result<Vec<u8>> {
        let frame = self.next_frame()?;
        if frame.command != command
            || frame.sequence != sequence
            || !frame.is_final()
            || frame.is_compressed()
        {
            return Err(ProtocolError::new("unexpected authentication reply frame"));
        }
        Ok(mt5_native::cipher::startup_decrypt_default(&frame.payload))
    }
}
