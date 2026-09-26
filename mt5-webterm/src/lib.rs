//! Native MetaQuotes web-terminal client: WebSocket to `wss://host:443/terminal`.
//! Connects directly to the broker web terminal.

pub mod client;
pub mod crypto;
pub mod parse;
pub mod protocol;
pub mod search;
pub mod session;
mod tls;

pub use client::{Client, Error};
pub use parse::{Account, Candle, Deal, Order, Position, Quote, Symbol};
pub use search::{find_web_terminal, pick_web_terminal};
pub use session::{Command, OrderKind, Receipt, Session, SessionError, Side, Snapshot};
