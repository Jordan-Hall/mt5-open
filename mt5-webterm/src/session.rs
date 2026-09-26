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
//! * A connection whose socket has closed is dialled again on the next call,
//!   and tick streams follow the new connection.
//! * Times are UTC. The server sends candles, deals and positions on its own
//!   clock; the account frame says how far that runs ahead of UTC.
//! * Symbols in use carry their full specification, and their tick value in
//!   the account currency is derived from contract size, tick size and the
//!   quote of a converting currency pair.
//!
//! Everything here uses this crate's own types, so a host maps them into its
//! own model at its edge.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
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
    /// Opening times are UTC.
    pub positions: Vec<Position>,
    pub orders: Vec<Order>,
    /// Quotes for every symbol with an open position or order and every
    /// symbol a host has asked for. A symbol whose book has not filled yet is
    /// absent, never zero. Times are UTC.
    pub quotes: HashMap<String, Quote>,
    /// The symbol list. Symbols a host trades or has asked for carry their
    /// full specification (`Symbol::full`).
    pub symbols: HashMap<String, Symbol>,
    /// Money per tick per lot in the account currency, for fully specified
    /// symbols whose profit currency converts to it. A symbol whose rate is
    /// unknown is absent rather than guessed.
    pub tick_values: HashMap<String, f64>,
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

/// The live connection and what was asked of it, shared with tick streams so
/// a stream follows the session across redials instead of holding on to the
/// socket it started with.
struct Live {
    client: Option<Client>,
    /// Incremented on every dial, so a stream can tell it must subscribe again.
    generation: u64,
    /// Symbols subscribed on the current client.
    subscribed: HashSet<String>,
}

pub struct Session {
    login: u64,
    password: String,
    server: String,
    live: Arc<Mutex<Live>>,
    /// Symbols a host has streamed or re-asked for; kept across redials.
    interest: Arc<Mutex<HashSet<String>>>,
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
            live: Arc::new(Mutex::new(Live { client: None, generation: 0, subscribed: HashSet::new() })),
            interest: Arc::new(Mutex::new(HashSet::new())),
            opened_at: Mutex::new(None),
            backoff: Mutex::new((0, None)),
        }
    }

    /// Drop the cached connection so the next call dials a fresh one.
    async fn reconnect(&self) -> Result<Client, SessionError> {
        {
            let mut live = self.live.lock().await;
            live.client = None;
            live.subscribed.clear();
        }
        self.client().await
    }

    async fn client(&self) -> Result<Client, SessionError> {
        let mut live = self.live.lock().await;
        if live.client.as_ref().is_some_and(|c| c.is_closed()) {
            // The socket died under us. Dial again rather than answer every
            // request with a timeout until the scheduled refresh.
            live.client = None;
            live.subscribed.clear();
        }
        if live.client.is_none() {
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
                    live.client = Some(c);
                    live.generation += 1;
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
        Ok(live.client.as_ref().unwrap().clone())
    }

    /// Subscribe `names` on `c` unless already subscribed on it.
    async fn ensure_subscribed(&self, c: &Client, names: &[String]) {
        let fresh: Vec<String> = {
            let live = self.live.lock().await;
            names.iter().filter(|s| !live.subscribed.contains(*s)).cloned().collect()
        };
        if !fresh.is_empty() && c.subscribe(&fresh).await.is_ok() {
            self.live.lock().await.subscribed.extend(fresh);
        }
    }

    /// Seconds the server clock runs ahead of UTC, once a session has dialled.
    pub async fn timezone_shift_seconds(&self) -> Result<i64, SessionError> {
        Ok(self.client().await?.timezone_shift_seconds())
    }

    pub async fn snapshot(&self) -> Result<Snapshot, SessionError> {
        let mut c = self.client().await?;
        let stale = self.opened_at.lock().await.map(|t| t.elapsed() >= SESSION_MAX_AGE).unwrap_or(true);
        if stale {
            c = self.reconnect().await?;
        }
        let mut account = c.account().await.map_err(|e| SessionError::Unavailable(e.to_string()))?;
        let shift = account.timezone_shift_seconds;
        let mut positions = c.positions().await.map_err(other)?;
        for p in &mut positions {
            p.time -= shift;
        }
        let orders = c.orders().await.map_err(other)?;

        let mut wanted: Vec<String> = positions
            .iter()
            .map(|p| p.symbol.clone())
            .chain(orders.iter().map(|o| o.symbol.clone()))
            .chain(self.interest.lock().await.iter().cloned())
            .collect();
        wanted.sort();
        wanted.dedup();
        let pairs = self.load_specs(&c, &wanted, &account.currency).await;
        let mut streamed: Vec<String> = wanted.iter().cloned().chain(pairs.values().map(|p| p.name.clone())).collect();
        streamed.sort();
        streamed.dedup();
        self.ensure_subscribed(&c, &streamed).await;
        let mut quotes = HashMap::new();
        for sym in &streamed {
            let mut q = c.quote(sym).await;
            if q.as_ref().map_or(true, |x| x.bid <= 0.0 || x.ask <= 0.0) {
                q = tokio::time::timeout(Duration::from_millis(1500), c.wait_quote(sym)).await.ok().and_then(|r| r.ok());
            }
            if let Some(x) = q.filter(|x| x.bid > 0.0 && x.ask > 0.0) {
                quotes.insert(sym.clone(), x);
            }
        }
        let symbols = c.symbols().await;
        let tick_values = wanted
            .iter()
            .filter_map(|name| {
                let s = symbols.get(name).filter(|s| s.full)?;
                let rate = conversion_rate(&s.profit_currency, &account.currency, &pairs, &quotes)?;
                let v = tick_value(s, rate);
                (v > 0.0).then(|| (name.clone(), v))
            })
            .collect();
        let floating: f64 = positions.iter().map(|p| p.profit + p.swap + p.commission).sum();
        account.equity = account.balance + floating;
        Ok(Snapshot {
            account,
            positions,
            orders,
            quotes,
            symbols,
            tick_values,
            timestamp_ms: now_ms(),
            refreshed: stale,
        })
    }

    /// Read full specifications for `wanted` that lack one, and for the
    /// currency pairs that convert their profit currency to `deposit`.
    /// Returns the conversion pair chosen for each profit currency.
    async fn load_specs(&self, c: &Client, wanted: &[String], deposit: &str) -> HashMap<String, Symbol> {
        let listed = c.symbols().await;
        let missing: Vec<String> = wanted.iter().filter(|n| listed.get(*n).is_some_and(|s| !s.full)).cloned().collect();
        if !missing.is_empty() {
            let _ = c.symbol_info(&missing).await;
        }
        let listed = c.symbols().await;
        let currencies: HashSet<String> = wanted
            .iter()
            .filter_map(|n| listed.get(n).filter(|s| s.full).map(|s| s.profit_currency.clone()))
            .filter(|p| !p.is_empty() && p != deposit)
            .collect();
        let mut candidates: Vec<String> = Vec::new();
        for p in &currencies {
            candidates.extend(pair_candidates(&listed, p, deposit).into_iter().filter(|n| !listed[n].full));
        }
        if !candidates.is_empty() {
            let _ = c.symbol_info(&candidates).await;
        }
        let listed = c.symbols().await;
        currencies
            .into_iter()
            .filter_map(|p| {
                let pair = pair_candidates(&listed, &p, deposit)
                    .into_iter()
                    .map(|n| &listed[&n])
                    .find(|s| s.full && pair_direction(s, &p, deposit).is_some())?;
                Some((p, pair.clone()))
            })
            .collect()
    }

    /// Candles of `tf` ("M1", "M5", "M15", "M30", "H1", "H4", "D1") with
    /// `from <= time < to`. Times in and out are UTC.
    pub async fn history(&self, symbol: &str, tf: &str, tf_seconds: i64, from: i64, to: i64) -> Result<Vec<Candle>, SessionError> {
        let c = self.client().await?;
        let shift = c.timezone_shift_seconds();
        // Asked for the window itself: this used to count back from now, so
        // any range older than the latest candles came back empty.
        let from = from.max(to - tf_seconds.max(1) * 5000);
        let rows = c.candles_between(symbol, tf, from + shift, to + shift).await.map_err(other)?;
        Ok(rows
            .into_iter()
            .map(|mut r| {
                r.time -= shift;
                r
            })
            .filter(|r| r.time >= from && r.time < to)
            .collect())
    }

    /// The last `count` candles, optionally all before `before`. Times in
    /// and out are UTC.
    pub async fn history_latest(&self, symbol: &str, tf: &str, count: usize, before: Option<i64>) -> Result<Vec<Candle>, SessionError> {
        let c = self.client().await?;
        let shift = c.timezone_shift_seconds();
        // The server's candles are on its own clock: "now" there is ahead of
        // UTC by the shift, and a window ending at UTC now left out the most
        // recent hours.
        let (from, to) = rates_window(tf, count, before.map(|b| b + shift), now_ms() / 1000 + shift);
        let mut rows = c.candles_between(symbol, tf, from, to).await.map_err(other)?;
        for r in &mut rows {
            r.time -= shift;
        }
        if let Some(b) = before {
            rows.retain(|r| r.time < b);
        }
        if rows.len() > count {
            rows = rows[rows.len() - count..].to_vec();
        }
        Ok(rows)
    }

    /// Deals executed with `from <= time < to`. Times in and out are UTC;
    /// `Deal::time` and `Deal::time_ms` are converted.
    pub async fn deals(&self, from: i64, to: i64) -> Result<Vec<Deal>, SessionError> {
        let c = self.client().await?;
        let shift = c.timezone_shift_seconds();
        let window = |t: i64| (t + shift).clamp(0, u32::MAX as i64) as u32;
        let rows = c.deals(window(from), window(to)).await.map_err(other)?;
        Ok(rows
            .into_iter()
            .map(|mut d| {
                d.time -= shift;
                d.time_ms -= shift * 1000;
                d
            })
            .filter(|d| d.time >= from && d.time < to)
            .collect())
    }

    /// A live stream of quotes: each symbol is emitted when its quote moves.
    /// It stays open and follows the session across redials, subscribing
    /// again on each new connection. It never dials by itself.
    pub async fn ticks(&self, symbols: &[String]) -> Result<impl Stream<Item = Quote> + Send + 'static, SessionError> {
        let c = self.client().await?;
        self.interest.lock().await.extend(symbols.iter().cloned());
        self.ensure_subscribed(&c, symbols).await;
        let wanted: Vec<String> = symbols.to_vec();
        let live = self.live.clone();
        let generation = live.lock().await.generation;
        let seen: HashMap<String, i64> = HashMap::new();
        Ok(stream::unfold(
            (live, generation, wanted, seen, Vec::<Quote>::new()),
            |(live, mut generation, wanted, mut seen, mut queue)| async move {
                loop {
                    if let Some(q) = queue.pop() {
                        return Some((q, (live, generation, wanted, seen, queue)));
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    let (c, current) = {
                        let g = live.lock().await;
                        (g.client.clone(), g.generation)
                    };
                    let Some(c) = c.filter(|c| !c.is_closed()) else { continue };
                    if current != generation {
                        let fresh: Vec<String> = {
                            let g = live.lock().await;
                            wanted.iter().filter(|s| !g.subscribed.contains(*s)).cloned().collect()
                        };
                        if fresh.is_empty() || c.subscribe(&fresh).await.is_ok() {
                            live.lock().await.subscribed.extend(fresh);
                            generation = current;
                        }
                    }
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
            },
        ))
    }

    /// Ask again for symbols whose prices have gone quiet. Symbols already
    /// subscribed on the live connection are not asked for again.
    pub async fn resubscribe(&self, symbols: &[String]) -> Result<(), SessionError> {
        let c = self.client().await?;
        self.interest.lock().await.extend(symbols.iter().cloned());
        self.ensure_subscribed(&c, symbols).await;
        Ok(())
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

/// The seconds window that holds the last `count` candles of `tf` ending at
/// `before` (or now). Scrolling back asks for twice the span plus a weekend,
/// so a closed market does not leave the chart short; callers keep only the
/// last `count`.
fn rates_window(tf: &str, count: usize, before: Option<i64>, now: i64) -> (i64, i64) {
    let sec: i64 = match tf {
        "M1" => 60,
        "M5" => 300,
        "M15" => 900,
        "M30" => 1800,
        "H1" => 3600,
        "H4" => 14400,
        "D1" => 86400,
        _ => 300,
    };
    match before {
        // The latest candles: the window charts have always loaded with.
        None => (now - (count as i64 + 10) * sec, now),
        Some(to) => (to - (count as i64 + 10) * sec * 2 - 3 * 86400, to),
    }
}

/// Currency pairs, by name, that could convert between `a` and `b`: shortest
/// name first, so a plain "GBPUSD" wins over a suffixed variant.
fn pair_candidates(listed: &HashMap<String, Symbol>, a: &str, b: &str) -> Vec<String> {
    let (ab, ba) = (format!("{a}{b}"), format!("{b}{a}"));
    let mut v: Vec<String> = listed
        .values()
        .filter(|s| matches!(s.calc_mode, 0 | 5) && (s.name.starts_with(&ab) || s.name.starts_with(&ba)))
        .map(|s| s.name.clone())
        .collect();
    v.sort_by(|x, y| x.len().cmp(&y.len()).then_with(|| x.cmp(y)));
    v
}

/// Some(true) when `pair` quotes `from` in `to`, Some(false) when it quotes
/// `to` in `from`.
fn pair_direction(pair: &Symbol, from: &str, to: &str) -> Option<bool> {
    if pair.base_currency == from && pair.profit_currency == to {
        Some(true)
    } else if pair.base_currency == to && pair.profit_currency == from {
        Some(false)
    } else {
        None
    }
}

/// Units of `to` per unit of `from`, priced on the side that makes a loss
/// larger, as the terminal prices risk.
fn conversion_rate(from: &str, to: &str, pairs: &HashMap<String, Symbol>, quotes: &HashMap<String, Quote>) -> Option<f64> {
    if from == to {
        return Some(1.0);
    }
    let pair = pairs.get(from)?;
    let q = quotes.get(&pair.name).filter(|q| q.bid > 0.0 && q.ask > 0.0)?;
    Some(if pair_direction(pair, from, to)? { q.ask } else { 1.0 / q.bid })
}

/// Money per tick per lot in the account currency, given the rate from the
/// symbol's profit currency. Forex and CFD modes derive it from contract size
/// and tick size; other modes carry it in the specification.
fn tick_value(s: &Symbol, rate: f64) -> f64 {
    let tick = if s.tick_size > 0.0 { s.tick_size } else { s.point };
    let v = match s.calc_mode {
        0 | 2 | 3 | 4 | 5 | 32 => tick * s.contract_size * rate,
        _ => s.tick_value * rate,
    };
    if v.is_finite() && v > 0.0 { v } else { 0.0 }
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
    fn scrolling_back_asks_for_candles_before_the_oldest_one_shown() {
        let now = 1_790_000_000;
        let before = now - 30 * 86400;
        let (from, to) = rates_window("H1", 100, Some(before), now);
        assert_eq!(to, before, "the window ends where the chart's oldest candle is, not now");
        assert!(to - from >= 100 * 3600, "the window holds the candles asked for");
        assert_eq!(rates_window("M5", 10, None, now), (now - 20 * 300, now), "the latest candles use the usual window");
    }

    fn fx(name: &str, base: &str, profit: &str, contract: f64, digits: u32) -> Symbol {
        Symbol {
            name: name.into(),
            base_currency: base.into(),
            profit_currency: profit.into(),
            contract_size: contract,
            digits,
            point: 10f64.powi(-(digits as i32)),
            full: true,
            ..Default::default()
        }
    }

    fn quote(name: &str, bid: f64, ask: f64) -> (String, Quote) {
        (name.to_string(), Quote { symbol: name.into(), bid, ask, ..Default::default() })
    }

    #[test]
    fn tick_value_converts_the_profit_currency_to_the_account_currency() {
        let gold = Symbol { calc_mode: 4, ..fx("XAUUSD", "XAU", "USD", 100.0, 2) };
        let pairs: HashMap<String, Symbol> = [("USD".to_string(), fx("GBPUSD", "GBP", "USD", 100_000.0, 5))].into();
        let quotes: HashMap<String, Quote> = [quote("GBPUSD", 1.25, 1.2502)].into();
        // A GBP account: one gold tick (0.01 x 100 oz = 1 USD) is 1/1.25 GBP.
        let rate = conversion_rate("USD", "GBP", &pairs, &quotes).unwrap();
        assert!((tick_value(&gold, rate) - 0.8).abs() < 1e-12);
        // A USD account needs no pair.
        assert_eq!(tick_value(&gold, conversion_rate("USD", "USD", &pairs, &quotes).unwrap()), 1.0);
        // The forward direction prices on the ask.
        let pairs: HashMap<String, Symbol> = [("GBP".to_string(), fx("GBPUSD", "GBP", "USD", 100_000.0, 5))].into();
        assert_eq!(conversion_rate("GBP", "USD", &pairs, &quotes), Some(1.2502));
    }

    #[test]
    fn an_unconvertible_or_unquoted_symbol_has_no_tick_value() {
        let pairs: HashMap<String, Symbol> = [("JPY".to_string(), fx("GBPJPY", "GBP", "JPY", 100_000.0, 3))].into();
        assert_eq!(conversion_rate("JPY", "GBP", &pairs, &HashMap::new()), None, "no quote, no rate");
        assert_eq!(conversion_rate("CHF", "GBP", &pairs, &HashMap::new()), None, "no pair, no rate");
        let unknown = Symbol { calc_mode: 1, tick_value: 0.0, ..fx("FUT", "USD", "USD", 1.0, 2) };
        assert_eq!(tick_value(&unknown, 1.0), 0.0);
    }

    #[test]
    fn the_plain_pair_is_chosen_over_suffixed_ones_and_non_forex_is_ignored() {
        let mut listed = HashMap::new();
        for (name, calc) in [("GBPUSD.x", 0), ("GBPUSD", 0), ("USDGBPIDX", 2), ("EURUSD", 0)] {
            listed.insert(name.to_string(), Symbol { name: name.into(), calc_mode: calc, ..Default::default() });
        }
        assert_eq!(pair_candidates(&listed, "USD", "GBP"), vec!["GBPUSD".to_string(), "GBPUSD.x".to_string()]);
    }

    #[test]
    fn comments_are_cut_to_what_the_server_accepts() {
        assert_eq!(short_comment("abcdefghijklmnopqrstuvwxyz0123").chars().count(), MAX_COMMENT_CHARS);
    }
}
