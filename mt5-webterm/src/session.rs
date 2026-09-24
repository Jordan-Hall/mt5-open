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
//! * Account values remain as reported; missing trade tickets remain unknown.
//! * Trade transport failures are uncertain outcomes, never automatic retries.
//!
//! Everything here uses this crate's own types, so a host maps them into its
//! own model at its edge.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use futures_util::stream::{self, Stream};
use tokio::sync::Mutex;

use crate::protocol::{
    pack_op, history_window, timeframe_seconds, validate_fixed_string, FILL_FOK, FILL_RETURN, TRADE_CANCEL, TRADE_MARKET, TRADE_MODIFY, TRADE_MODIFY_ORDER, TRADE_PENDING, TYPE_BUY,
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
    /// The request may have taken effect; reconcile before another transmission.
    Uncertain(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Unavailable(m) | SessionError::Other(m) | SessionError::Uncertain(m) => f.write_str(m),
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
    /// Values reported by the server; zero equity is not replaced by balance.
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
    trading: Mutex<()>,
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
            trading: Mutex::new(()),
            subscribed: Mutex::new(HashSet::new()),
            opened_at: Mutex::new(None),
            backoff: Mutex::new((0, None)),
        }
    }

    async fn client(&self) -> Result<Client, SessionError> {
        let mut g = self.inner.lock().await;
        let expired = self.opened_at.lock().await.is_some_and(|t| t.elapsed() >= SESSION_MAX_AGE);
        if expired || g.as_ref().is_some_and(|client| !client.is_connected()) {
            *g = None;
            self.subscribed.lock().await.clear();
        }
        if g.is_none() {
            {
                let b = self.backoff.lock().await;
                if let Some(until) = b.1 {
                    if Instant::now() < until {
                        let left = until.saturating_duration_since(Instant::now()).as_secs();
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
        let stale = self.opened_at.lock().await.map(|t| t.elapsed() >= SESSION_MAX_AGE).unwrap_or(true);
        let c = self.client().await?;
        let account = c.account().await.map_err(|e| SessionError::Unavailable(e.to_string()))?;
        let (positions, orders) = c.positions_and_orders().await.map_err(other)?;

        let mut wanted: Vec<String> =
            positions.iter().map(|p| p.symbol.clone()).chain(orders.iter().map(|o| o.symbol.clone())).collect();
        wanted.sort();
        wanted.dedup();
        if !wanted.is_empty() {
            let mut sub = self.subscribed.lock().await;
            let fresh: Vec<String> = wanted.iter().filter(|s| !sub.contains(*s)).cloned().collect();
            if !fresh.is_empty() {
                c.subscribe(&fresh).await.map_err(other)?;
                sub.extend(fresh);
            }
        }
        // A single total warm-up budget, rather than 1.5 seconds per symbol.
        let notifier = c.quote_notifier();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
        let mut quotes = HashMap::new();
        loop {
            let changed = notifier.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            for symbol in &wanted {
                if let Some(quote) = c.quote(symbol).await { quotes.insert(symbol.clone(), quote); }
            }
            if quotes.len() == wanted.len() || !c.is_connected() { break; }
            if tokio::time::timeout_at(deadline, changed).await.is_err() { break; }
        }
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
        if from < 0 || from > to || tf_seconds != timeframe_seconds(tf).map_err(other)? {
            return Err(other("invalid history range or timeframe duration"));
        }
        let c = self.client().await?;
        let mut rows = c.candles_range(symbol, tf, from, to).await.map_err(other)?;
        rows.retain(|r| r.time >= from && r.time < to);
        rows.sort_by_key(|r| r.time);
        Ok(rows)
    }

    /// The last `count` candles, optionally all before `before`. The wire
    /// request itself targets the requested historical window.
    pub async fn history_latest(&self, symbol: &str, tf: &str, count: usize, before: Option<i64>) -> Result<Vec<Candle>, SessionError> {
        if count == 0 { return Ok(Vec::new()); }
        let end = before.unwrap_or_else(|| now_ms() / 1000);
        let (from, to) = history_window(tf, count, end).map_err(other)?;
        let c = self.client().await?;
        let mut rows = c.candles_range(symbol, tf, from, to).await.map_err(other)?;
        rows.retain(|r| r.time >= from && r.time < to);
        rows.sort_by_key(|r| r.time);
        if rows.len() > count { rows.drain(..rows.len() - count); }
        Ok(rows)
    }

    pub async fn deals(&self, from: i64, to: i64) -> Result<Vec<Deal>, SessionError> {
        let c = self.client().await?;
        let from = u32::try_from(from).map_err(|_| other("deal start exceeds wire timestamp range"))?;
        let to = u32::try_from(to).map_err(|_| other("deal end exceeds wire timestamp range"))?;
        c.deals(from, to).await.map_err(other)
    }

    /// A live stream of quotes: each symbol is emitted when its quote moves.
    /// Emits latest cached changes, not a lossless tick archive. Ends on
    /// disconnection so the host can obtain a fresh session/subscription.
    pub async fn ticks(&self, symbols: &[String]) -> Result<impl Stream<Item = Quote> + Send + 'static, SessionError> {
        let c = self.client().await?;
        c.subscribe(symbols).await.map_err(other)?;
        let wanted: Vec<String> = symbols.to_vec();
        let seen: HashMap<String, (i64, u64, u64)> = HashMap::new();
        Ok(stream::unfold((c, wanted, seen, VecDeque::<Quote>::new()), |(c, wanted, mut seen, mut queue)| async move {
            let notifier = c.quote_notifier();
            loop {
                if let Some(q) = queue.pop_front() {
                    return Some((q, (c, wanted, seen, queue)));
                }
                let changed = notifier.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if !c.is_connected() || wanted.is_empty() { return None; }
                for symbol in &wanted {
                    let Some(q) = c.quote(symbol).await else { continue };
                    let revision = (q.time_ms, q.bid.to_bits(), q.ask.to_bits());
                    if seen.get(symbol) != Some(&revision) {
                        seen.insert(symbol.clone(), revision);
                        queue.push_back(q);
                    }
                }
                if queue.is_empty() { changed.await; }
            }
        }))
    }

    pub async fn resubscribe(&self, symbols: &[String]) -> Result<(), SessionError> {
        let c = self.client().await?;
        c.subscribe(symbols).await.map_err(other)
    }

    pub async fn send(&self, cmd: &Command) -> Result<Receipt, SessionError> {
        validate_command(cmd)?;
        let _trade = self.trading.lock().await;
        let c = self.client().await?;
        let op = match cmd {
            Command::Market { symbol, side, volume, sl, tp, comment } => {
                let q = c.wait_quote(symbol).await.map_err(other)?;
                let digits = c.symbol(symbol).await.ok_or_else(|| other("unknown symbol"))?.digits;
                let price = if *side == Side::Buy { q.ask } else { q.bid };
                let code = if *side == Side::Buy { TYPE_BUY } else { TYPE_SELL };
                pack_op(symbol, rand::random(), TRADE_MARKET, *volume, digits, code, price, *sl, *tp, 0, FILL_FOK,
                    &short_comment(comment), 0, 0.0, 30)
            }
            Command::Pending { symbol, kind, volume, price, sl, tp, stop_limit, comment } => {
                let digits = c.symbol(symbol).await.ok_or_else(|| other("unknown symbol"))?.digits;
                pack_op(symbol, rand::random(), TRADE_PENDING, *volume, digits, kind.code(), *price, *sl, *tp, 0, FILL_RETURN,
                    &short_comment(comment), 0, *stop_limit, 30)
            }
            Command::ClosePosition { ticket, volume } => {
                let positions = c.positions().await.map_err(other)?;
                let p = positions.iter().find(|p| p.ticket == *ticket).ok_or_else(|| other("position not found"))?;
                if p.side > 1 || !p.volume.is_finite() || p.volume <= 0.0 || volume.is_some_and(|v| v > p.volume) {
                    return Err(other("invalid close side or volume"));
                }
                let q = c.wait_quote(&p.symbol).await.map_err(other)?;
                let price = if p.side == 0 { q.bid } else { q.ask };
                let digits = c.symbol(&p.symbol).await.ok_or_else(|| other("unknown position symbol"))?.digits;
                let code = if p.side == 0 { TYPE_SELL } else { TYPE_BUY };
                pack_op(&p.symbol, rand::random(), TRADE_MARKET, volume.unwrap_or(p.volume), digits, code, price, 0.0, 0.0, 0,
                    FILL_FOK, "", *ticket as u64, 0.0, 30)
            }
            Command::CancelOrder { ticket } => {
                let orders = c.orders().await.map_err(other)?;
                let o = orders.iter().find(|o| o.ticket == *ticket).ok_or_else(|| other("order not found"))?;
                let digits = c.symbol(&o.symbol).await.ok_or_else(|| other("unknown order symbol"))?.digits;
                pack_op(&o.symbol, rand::random(), TRADE_CANCEL, o.volume, digits, o.kind, o.price, 0.0, 0.0, *ticket as u64,
                    FILL_FOK, "", 0, 0.0, 30)
            }
            Command::ModifyPosition { ticket, sl, tp } => {
                let positions = c.positions().await.map_err(other)?;
                let p = positions.iter().find(|p| p.ticket == *ticket).ok_or_else(|| other("position not found"))?;
                let digits = c.symbol(&p.symbol).await.ok_or_else(|| other("unknown position symbol"))?.digits;
                pack_op(&p.symbol, rand::random(), TRADE_MODIFY, p.volume, digits, p.side, 0.0, *sl, *tp, *ticket as u64,
                    FILL_RETURN, "", *ticket as u64, 0.0, 30)
            }
            Command::ModifyOrder { ticket, price, sl, tp } => {
                let orders = c.orders().await.map_err(other)?;
                let o = orders.iter().find(|o| o.ticket == *ticket).ok_or_else(|| other("order not found"))?;
                let digits = c.symbol(&o.symbol).await.ok_or_else(|| other("unknown order symbol"))?.digits;
                pack_op(&o.symbol, rand::random(), TRADE_MODIFY_ORDER, o.volume, digits, o.kind, *price, *sl, *tp,
                    *ticket as u64, FILL_RETURN, "", 0, 0.0, 30)
            }
        };
        let (ret, deal, ticket, price) = c.send_op(&op).await
            .map_err(|e| SessionError::Uncertain(e.to_string()))?;
        if ret == 0 {
            return Err(SessionError::Uncertain("trade response did not contain a broker execution result".into()));
        }
        if !matches!(ret, 10008 | 10009 | 10010) {
            return Err(SessionError::Rejected { retcode: ret, message: format!("retcode {ret}") });
        }
        // A ticket is returned only when the broker supplied it. An unrelated
        // account delta is not evidence that this request created that ticket.
        Ok(Receipt {
            retcode: ret,
            ticket: Some(ticket).filter(|t| *t != 0),
            deal: Some(deal).filter(|d| *d != 0),
            price: Some(price).filter(|p| p.is_finite() && *p > 0.0),
        })
    }
}

fn short_comment(comment: &str) -> String {
    let mut units = 0;
    comment.chars().take_while(|ch| {
        units += ch.len_utf16();
        units <= MAX_COMMENT_CHARS
    }).collect()
}

fn validate_command(command: &Command) -> Result<(), SessionError> {
    let positive = |volume: f64| {
        if !volume.is_finite() || volume <= 0.0 || volume * crate::protocol::LOT_MULTIPLIER >= u64::MAX as f64 {
            Err(other("invalid trade volume"))
        } else { Ok(()) }
    };
    let prices = |values: &[f64]| {
        if values.iter().any(|p| !p.is_finite() || *p < 0.0) {
            Err(other("invalid trade price"))
        } else { Ok(()) }
    };
    let ticket = |ticket: i64| if ticket > 0 { Ok(()) } else { Err(other("invalid ticket")) };
    match command {
        Command::Market { symbol, volume, sl, tp, comment, .. } => {
            validate_fixed_string(symbol, 32, "symbol").map_err(other)?;
            positive(*volume)?; prices(&[*sl, *tp])?;
            if comment.contains('\0') { return Err(other("comment contains NUL")); }
        }
        Command::Pending { symbol, volume, price, sl, tp, stop_limit, comment, .. } => {
            validate_fixed_string(symbol, 32, "symbol").map_err(other)?;
            positive(*volume)?; prices(&[*price, *sl, *tp, *stop_limit])?;
            if *price == 0.0 || comment.contains('\0') { return Err(other("invalid pending price or comment")); }
        }
        Command::ClosePosition { ticket: id, volume } => { ticket(*id)?; if let Some(v) = volume { positive(*v)?; } }
        Command::CancelOrder { ticket: id } => ticket(*id)?,
        Command::ModifyPosition { ticket: id, sl, tp } => { ticket(*id)?; prices(&[*sl, *tp])?; }
        Command::ModifyOrder { ticket: id, price, sl, tp } => { ticket(*id)?; prices(&[*price, *sl, *tp])?; if *price == 0.0 { return Err(other("zero order price")); } }
    }
    Ok(())
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

#[cfg(test)]
mod input_regressions {
    use super::*;
    #[test]
    fn supplementary_comments_fit_utf16_wire_budget() {
        assert_eq!(short_comment(&"😀".repeat(40)).encode_utf16().count(), 26);
    }
    #[test]
    fn invalid_commands_fail_before_connecting() {
        for volume in [f64::NAN, f64::INFINITY, -1.0, 0.0, f64::MAX] {
            assert!(validate_command(&Command::Market { symbol: "TEST".into(), side: Side::Buy,
                volume, sl: 0.0, tp: 0.0, comment: String::new() }).is_err());
        }
        assert!(validate_command(&Command::ModifyPosition { ticket: 1, sl: f64::NAN, tp: 0.0 }).is_err());
        assert!(validate_command(&Command::ClosePosition { ticket: -1, volume: None }).is_err());
    }
}
