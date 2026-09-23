//! A long-running account session on top of [`Client`]: the part every host
//! application needs and should not have to learn the hard way.
//!
//! * The session is redialled every ten minutes. A web-terminal session goes
//!   stale long before the socket admits it: it has been seen reporting an
//!   empty position list with a frozen account frame while still healthy,
//!   which a host reads as "every trade closed".
//! * A refused login backs off (5 s up to 5 min) instead of retrying every few
//!   seconds, which a broker sees as abuse.
//! * A quote that has not filled yet is never reported as zero.
//! * Equity is balance plus floating profit: the account frame reports equity
//!   as the balance.
//! * A new order or position is identified by difference when the trade answer
//!   carries ticket 0, which it does for some commands.
//!
//! Everything here uses this crate's own types, so a host maps them into its
//! own model at its edge.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use futures_util::stream::{self, Stream};
use tokio::sync::Mutex;

use crate::protocol::{
    pack_op, FILL_FOK, FILL_RETURN, TRADE_CANCEL, TRADE_MARKET, TRADE_MODIFY, TRADE_MODIFY_ORDER, TRADE_PENDING, TYPE_BUY,
    TYPE_SELL,
};
use crate::{Account, Candle, Client, Deal, Order, Position, Quote, Symbol};

/// Seconds to wait after the nth consecutive failed dial.
const RECONNECT_BACKOFF: &[u64] = &[5, 15, 30, 60, 120, 300];
/// How long a session is trusted before it is dialled again.
const SESSION_MAX_AGE: Duration = Duration::from_secs(10 * 60);
/// Longest comment the web terminal accepts on an order.
const MAX_COMMENT_CHARS: usize = 26;

#[derive(Debug, Clone, PartialEq)]
pub enum SessionError {
    /// Cannot reach or log in to the server right now; try again later.
    Unavailable(String),
    /// The server refused the trade request.
    Rejected { retcode: u32, message: String },
    Other(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Unavailable(m) | SessionError::Other(m) => f.write_str(m),
            SessionError::Rejected { retcode, message } => write!(f, "rejected ({retcode}): {message}"),
        }
    }
}

impl std::error::Error for SessionError {}

fn other(e: impl std::fmt::Display) -> SessionError {
    SessionError::Other(e.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Buy,
    Sell,
}

impl Side {
    /// From the protocol's position/deal side code (0 buy, 1 sell).
    pub fn from_code(code: u32) -> Self {
        if code == 1 { Side::Sell } else { Side::Buy }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderKind {
    BuyLimit,
    SellLimit,
    BuyStop,
    SellStop,
    BuyStopLimit,
    SellStopLimit,
}

impl OrderKind {
    /// From the protocol's order type code.
    pub fn from_code(code: u32) -> Self {
        match code {
            3 => OrderKind::SellLimit,
            4 => OrderKind::BuyStop,
            5 => OrderKind::SellStop,
            6 => OrderKind::BuyStopLimit,
            7 => OrderKind::SellStopLimit,
            _ => OrderKind::BuyLimit,
        }
    }

    fn code(self) -> u32 {
        match self {
            OrderKind::BuyLimit => 2,
            OrderKind::SellLimit => 3,
            OrderKind::BuyStop => 4,
            OrderKind::SellStop => 5,
            OrderKind::BuyStopLimit => 6,
            OrderKind::SellStopLimit => 7,
        }
    }
}

/// What the account holds right now.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// Balance from the server; `equity` is recomputed as balance + floating.
    pub account: Account,
    pub positions: Vec<Position>,
    pub orders: Vec<Order>,
    /// Live quotes for every symbol with an open position or order. A symbol
    /// whose book has not filled yet is absent, never zero.
    pub quotes: HashMap<String, Quote>,
    pub symbols: HashMap<String, Symbol>,
    pub timestamp_ms: i64,
    /// True when this call redialled the session first.
    pub refreshed: bool,
}

/// A trade request.
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    Market { symbol: String, side: Side, volume: f64, sl: f64, tp: f64, comment: String },
    Pending { symbol: String, kind: OrderKind, volume: f64, price: f64, sl: f64, tp: f64, stop_limit: f64, comment: String },
    /// Close all of a position, or `volume` of it.
    ClosePosition { ticket: i64, volume: Option<f64> },
    CancelOrder { ticket: i64 },
    ModifyPosition { ticket: i64, sl: f64, tp: f64 },
    ModifyOrder { ticket: i64, price: f64, sl: f64, tp: f64 },
}

/// The server's answer to an accepted trade request.
#[derive(Debug, Clone, PartialEq)]
pub struct Receipt {
    pub retcode: u32,
    /// The order or position created or acted on. None when an entry was
    /// accepted but no new ticket could be found, which a host should treat
    /// as uncertain.
    pub ticket: Option<i64>,
    pub deal: Option<i64>,
    pub price: Option<f64>,
}

pub struct Session {
    login: u64,
    password: String,
    server: String,
    inner: Mutex<Option<Client>>,
    subscribed: Mutex<HashSet<String>>,
    opened_at: Mutex<Option<Instant>>,
    backoff: Mutex<(u32, Option<Instant>)>,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

impl Session {
    pub fn new(login: u64, password: String, server: String) -> Self {
        Self {
            login,
            password,
            server,
            inner: Mutex::new(None),
            subscribed: Mutex::new(HashSet::new()),
            opened_at: Mutex::new(None),
            backoff: Mutex::new((0, None)),
        }
    }

    /// Drop the cached connection so the next call dials a fresh one.
    async fn reconnect(&self) -> Result<Client, SessionError> {
        *self.inner.lock().await = None;
        self.subscribed.lock().await.clear();
        self.client().await
    }

    async fn client(&self) -> Result<Client, SessionError> {
        let mut g = self.inner.lock().await;
        if g.is_none() {
            {
                let b = self.backoff.lock().await;
                if let Some(until) = b.1 {
                    if Instant::now() < until {
                        let left = (until - Instant::now()).as_secs();
                        return Err(SessionError::Unavailable(format!(
                            "waiting {left}s before dialling again after {} failed logins",
                            b.0
                        )));
                    }
                }
            }
            match Client::connect(self.login, &self.password, &self.server).await {
                Ok(c) => {
                    *g = Some(c);
                    *self.opened_at.lock().await = Some(Instant::now());
                    *self.backoff.lock().await = (0, None);
                }
                Err(e) => {
                    let mut b = self.backoff.lock().await;
                    b.0 = b.0.saturating_add(1);
                    let wait = RECONNECT_BACKOFF
                        .get((b.0 as usize).saturating_sub(1))
                        .copied()
                        .unwrap_or(*RECONNECT_BACKOFF.last().unwrap());
                    b.1 = Some(Instant::now() + Duration::from_secs(wait));
                    return Err(SessionError::Unavailable(format!("{e}; next attempt in {wait}s")));
                }
            }
        }
        Ok(g.as_ref().unwrap().clone())
    }

    pub async fn snapshot(&self) -> Result<Snapshot, SessionError> {
        let mut c = self.client().await?;
        let stale = self.opened_at.lock().await.map(|t| t.elapsed() >= SESSION_MAX_AGE).unwrap_or(true);
        if stale {
            c = self.reconnect().await?;
        }
        let mut account = c.account().await.map_err(|e| SessionError::Unavailable(e.to_string()))?;
        let positions = c.positions().await.map_err(other)?;
        let orders = c.orders().await.map_err(other)?;

        let mut wanted: Vec<String> =
            positions.iter().map(|p| p.symbol.clone()).chain(orders.iter().map(|o| o.symbol.clone())).collect();
        wanted.sort();
        wanted.dedup();
        if !wanted.is_empty() {
            let mut sub = self.subscribed.lock().await;
            let fresh: Vec<String> = wanted.iter().filter(|s| !sub.contains(*s)).cloned().collect();
            if !fresh.is_empty() {
                let _ = c.subscribe(&fresh).await;
                sub.extend(fresh);
            }
        }
        let mut quotes = HashMap::new();
        for sym in &wanted {
            let mut q = c.quote(sym).await;
            if q.as_ref().map_or(true, |x| x.bid <= 0.0 || x.ask <= 0.0) {
                q = tokio::time::timeout(Duration::from_millis(1500), c.wait_quote(sym)).await.ok().and_then(|r| r.ok());
            }
            if let Some(x) = q.filter(|x| x.bid > 0.0 && x.ask > 0.0) {
                quotes.insert(sym.clone(), x);
            }
        }
        let floating: f64 = positions.iter().map(|p| p.profit + p.swap + p.commission).sum();
        account.equity = account.balance + floating;
        Ok(Snapshot {
            account,
            positions,
            orders,
            quotes,
            symbols: c.symbols().await,
            timestamp_ms: now_ms(),
            refreshed: stale,
        })
    }

    /// Candles of `tf` ("M1", "M5", "M15", "M30", "H1", "H4", "D1") with
    /// `from <= time < to`.
    pub async fn history(&self, symbol: &str, tf: &str, tf_seconds: i64, from: i64, to: i64) -> Result<Vec<Candle>, SessionError> {
        let c = self.client().await?;
        let count = ((to - from).abs() / tf_seconds.max(1)).clamp(1, 5000) as usize;
        let rows = c.candles(symbol, tf, count).await.map_err(other)?;
        Ok(rows.into_iter().filter(|r| r.time >= from && r.time < to).collect())
    }

    /// The last `count` candles, optionally all before `before`.
    pub async fn history_latest(&self, symbol: &str, tf: &str, count: usize, before: Option<i64>) -> Result<Vec<Candle>, SessionError> {
        let c = self.client().await?;
        let mut rows = c.candles(symbol, tf, count + 10).await.map_err(other)?;
        if let Some(b) = before {
            rows.retain(|r| r.time < b);
        }
        if rows.len() > count {
            rows = rows[rows.len() - count..].to_vec();
        }
        Ok(rows)
    }

    pub async fn deals(&self, from: i64, to: i64) -> Result<Vec<Deal>, SessionError> {
        let c = self.client().await?;
        c.deals(from.max(0) as u32, to.max(0) as u32).await.map_err(other)
    }

    /// A live stream of quotes: each symbol is emitted when its quote moves.
    /// It stays open; it does not end after the current quotes.
    pub async fn ticks(&self, symbols: &[String]) -> Result<impl Stream<Item = Quote> + Send + 'static, SessionError> {
        let c = self.client().await?;
        let _ = c.subscribe(symbols).await;
        let wanted: Vec<String> = symbols.to_vec();
        let seen: HashMap<String, i64> = HashMap::new();
        Ok(stream::unfold((c, wanted, seen, Vec::<Quote>::new()), |(c, wanted, mut seen, mut queue)| async move {
            loop {
                if let Some(q) = queue.pop() {
                    return Some((q, (c, wanted, seen, queue)));
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
                for s in &wanted {
                    let Some(q) = c.quote(s).await else { continue };
                    if q.bid <= 0.0 || q.ask <= 0.0 {
                        continue;
                    }
                    if q.time_ms > seen.get(s).copied().unwrap_or(0) {
                        seen.insert(s.clone(), q.time_ms);
                        queue.push(q);
                    }
                }
            }
        }))
    }

    pub async fn resubscribe(&self, symbols: &[String]) -> Result<(), SessionError> {
        let c = self.client().await?;
        c.subscribe(symbols).await.map_err(other)
    }

    pub async fn send(&self, cmd: &Command) -> Result<Receipt, SessionError> {
        let c = self.client().await?;
        let op = match cmd {
            Command::Market { symbol, side, volume, sl, tp, comment } => {
                let _ = c.subscribe(std::slice::from_ref(symbol)).await;
                let q = c.wait_quote(symbol).await.ok();
                let digits = c.symbol(symbol).await.map(|x| x.digits).unwrap_or(2);
                let price = q.as_ref().map(|q| if *side == Side::Buy { q.ask } else { q.bid }).unwrap_or(0.0);
                let code = if *side == Side::Buy { TYPE_BUY } else { TYPE_SELL };
                pack_op(symbol, rand::random(), TRADE_MARKET, *volume, digits, code, price, *sl, *tp, 0, FILL_FOK,
                    &short_comment(comment), 0, 0.0, 30)
            }
            Command::Pending { symbol, kind, volume, price, sl, tp, stop_limit, comment } => {
                let _ = c.subscribe(std::slice::from_ref(symbol)).await;
                let digits = c.symbol(symbol).await.map(|x| x.digits).unwrap_or(2);
                pack_op(symbol, rand::random(), TRADE_PENDING, *volume, digits, kind.code(), *price, *sl, *tp, 0, FILL_RETURN,
                    &short_comment(comment), 0, *stop_limit, 30)
            }
            Command::ClosePosition { ticket, volume } => {
                let positions = c.positions().await.map_err(other)?;
                let p = positions.iter().find(|p| p.ticket == *ticket).ok_or_else(|| other("position not found"))?;
                let q = c.wait_quote(&p.symbol).await.ok();
                let price = q.as_ref().map(|q| if p.side == 0 { q.bid } else { q.ask }).unwrap_or(p.price);
                let digits = c.symbol(&p.symbol).await.map(|x| x.digits).unwrap_or(2);
                let code = if p.side == 0 { TYPE_SELL } else { TYPE_BUY };
                pack_op(&p.symbol, rand::random(), TRADE_MARKET, volume.unwrap_or(p.volume), digits, code, price, 0.0, 0.0, 0,
                    FILL_FOK, "", *ticket as u64, 0.0, 30)
            }
            Command::CancelOrder { ticket } => {
                let orders = c.orders().await.map_err(other)?;
                let o = orders.iter().find(|o| o.ticket == *ticket).ok_or_else(|| other("order not found"))?;
                let digits = c.symbol(&o.symbol).await.map(|x| x.digits).unwrap_or(2);
                pack_op(&o.symbol, rand::random(), TRADE_CANCEL, o.volume, digits, o.kind, o.price, 0.0, 0.0, *ticket as u64,
                    FILL_FOK, "", 0, 0.0, 30)
            }
            Command::ModifyPosition { ticket, sl, tp } => {
                let positions = c.positions().await.map_err(other)?;
                let p = positions.iter().find(|p| p.ticket == *ticket).ok_or_else(|| other("position not found"))?;
                let digits = c.symbol(&p.symbol).await.map(|x| x.digits).unwrap_or(2);
                pack_op(&p.symbol, rand::random(), TRADE_MODIFY, p.volume, digits, p.side, 0.0, *sl, *tp, *ticket as u64,
                    FILL_RETURN, "", *ticket as u64, 0.0, 30)
            }
            Command::ModifyOrder { ticket, price, sl, tp } => {
                let orders = c.orders().await.map_err(other)?;
                let o = orders.iter().find(|o| o.ticket == *ticket).ok_or_else(|| other("order not found"))?;
                let digits = c.symbol(&o.symbol).await.map(|x| x.digits).unwrap_or(2);
                pack_op(&o.symbol, rand::random(), TRADE_MODIFY_ORDER, o.volume, digits, o.kind, *price, *sl, *tp,
                    *ticket as u64, FILL_RETURN, "", 0, 0.0, 30)
            }
        };
        let entry = matches!(cmd, Command::Market { .. } | Command::Pending { .. });
        let before = if entry { live_tickets(&c).await } else { HashSet::new() };
        let (ret, deal, mut ticket, price) = c.send_op(&op).await.map_err(other)?;
        if !(ret == 0 || ret == 10009) {
            return Err(SessionError::Rejected { retcode: ret, message: format!("retcode {ret}") });
        }
        // The book can lag a moment behind the fill, so look again rather
        // than give up on the first empty answer.
        if entry && ticket == 0 {
            for attempt in 0..3 {
                if attempt > 0 {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
                if let Some(t) = live_tickets(&c).await.difference(&before).copied().max() {
                    ticket = t;
                    break;
                }
            }
        }
        Ok(Receipt {
            retcode: ret,
            ticket: Some(ticket).filter(|t| *t != 0),
            deal: Some(deal).filter(|d| *d != 0),
            price: Some(price).filter(|p| *p != 0.0),
        })
    }
}

fn short_comment(comment: &str) -> String {
    comment.chars().take(MAX_COMMENT_CHARS).collect()
}

/// Every ticket the account holds, orders and positions together.
async fn live_tickets(c: &Client) -> HashSet<i64> {
    let mut s = HashSet::new();
    if let Ok(v) = c.orders().await {
        s.extend(v.iter().map(|o| o.ticket));
    }
    if let Ok(v) = c.positions().await {
        s.extend(v.iter().map(|p| p.ticket));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_codes_round_trip_through_the_kinds() {
        for code in 2..=7 {
            assert_eq!(OrderKind::from_code(code).code(), code);
        }
        assert_eq!(Side::from_code(0), Side::Buy);
        assert_eq!(Side::from_code(1), Side::Sell);
    }

    #[test]
    fn comments_are_cut_to_what_the_server_accepts() {
        assert_eq!(short_comment("abcdefghijklmnopqrstuvwxyz0123").chars().count(), MAX_COMMENT_CHARS);
    }
}
