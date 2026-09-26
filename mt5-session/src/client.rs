//! Persistent broker session with request correlation and authoritative updates.
use crate::{LoginProfile, Session, endpoints::EndpointPool};
use mt5_native::{
    depth::{DepthRecord, decode_depth},
    error::{ProtocolError, Result},
    quotes::decode_quotes,
    reassembly::Message,
    records::{Symbol, TradeResult},
    subscription::make_depth_subscription_payload,
    sync::SynchronizedState,
    updates::{Change, Update, decode_update},
};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

mod history;
mod margin;

/// A request goes out after this long without sending anything, and the
/// broker answers it.
const KEEPALIVE: Duration = Duration::from_secs(10);
/// With keepalives answered, a live connection is never silent this long: on
/// a closed market the answers were at most 20 s apart. A connection whose
/// peer vanished without closing it (no FIN, no RST) would otherwise poll
/// empty forever while quotes silently stop.
pub const RECEIVE_DEADLINE: Duration = Duration::from_secs(45);

#[derive(Clone)]
pub struct Config {
    pub address: String,
    pub login: u64,
    pub password: String,
    pub client_build: u16,
    pub profile: LoginProfile,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Quote {
    pub symbol: String,
    pub time_ms: i64,
    pub bid: f64,
    pub ask: f64,
}

pub enum TradeOutcome {
    Confirmed(TradeResult),
    Uncertain(String),
}

pub struct Client {
    session: Session,
    pub state: SynchronizedState,
    pub quotes: BTreeMap<String, Quote>,
    pub account_mode: Option<String>,
    subscriptions: BTreeSet<i32>,
    symbol_ids: BTreeMap<i32, usize>,
    changed_quotes: Vec<Quote>,
    depth_subscriptions: BTreeSet<u32>,
    changed_depth: Vec<DepthRecord>,
    last_send: Instant,
    last_receive: Instant,
    receive_deadline: Duration,
    healthy: bool,
}

impl Client {
    pub fn connect(config: &Config) -> Result<Self> {
        // Check enrollment before parsing/dialing another account's addresses.
        config.profile.account_mode(config.login)?;
        Self::connect_with_endpoints(config, &mut EndpointPool::new(&config.address)?)
    }

    pub fn connect_with_endpoints(config: &Config, endpoints: &mut EndpointPool) -> Result<Self> {
        let account_mode = Some(config.profile.account_mode(config.login)?.to_string());
        let mut session = endpoints.connect()?;
        session.authenticate(config.login, &config.password, config.client_build)?;
        let state = session.synchronize(&config.profile)?.state;
        endpoints.learn(&state.access_points);
        endpoints.authenticated(session.peer_addr()?);
        let symbol_ids = state
            .symbols
            .iter()
            .enumerate()
            .map(|(index, s)| (s.id, index))
            .collect();
        Ok(Self {
            session,
            state,
            quotes: BTreeMap::new(),
            account_mode,
            subscriptions: BTreeSet::new(),
            symbol_ids,
            changed_quotes: Vec::new(),
            depth_subscriptions: BTreeSet::new(),
            changed_depth: Vec::new(),
            last_send: Instant::now(),
            last_receive: Instant::now(),
            receive_deadline: RECEIVE_DEADLINE,
            healthy: true,
        })
    }

    pub fn symbol(&self, name: &str) -> Result<&Symbol> {
        self.state
            .symbols
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| ProtocolError::new(format!("unknown symbol {name}")))
    }

    pub fn peer_addr(&self) -> Result<std::net::SocketAddr> {
        self.session.peer_addr()
    }

    pub fn subscribe(&mut self, names: &[String]) -> Result<()> {
        let mut ids: Vec<_> = names
            .iter()
            .map(|name| self.symbol(name).map(|s| s.id))
            .collect::<Result<_>>()?;
        if let Some(terms) = &self.state.terms {
            for name in names {
                let symbol = self.symbol(name)?;
                for currency in [&symbol.profit_currency, &symbol.margin_currency] {
                    if let Some(path) = self.conversion_path(currency, &terms.currency, false) {
                        ids.extend(path.into_iter().map(|(s, _)| s.id));
                    }
                }
            }
        }
        self.subscriptions.extend(ids);
        self.session
            .subscribe(&self.subscriptions.iter().copied().collect::<Vec<_>>())?;
        self.last_send = Instant::now();
        Ok(())
    }

    /// Subscribe to broker depth deltas. An empty response is not fabricated liquidity.
    pub fn subscribe_depth(&mut self, names: &[String]) -> Result<()> {
        let ids: Vec<u32> = names
            .iter()
            .map(|n| {
                self.symbol(n).and_then(|s| {
                    s.id.try_into()
                        .map_err(|_| ProtocolError::new("negative depth symbol ID"))
                })
            })
            .collect::<Result<_>>()?;
        self.depth_subscriptions.extend(ids);
        self.session.send_request(
            106,
            &make_depth_subscription_payload(
                &self.depth_subscriptions.iter().copied().collect::<Vec<_>>(),
            ),
        )?;
        self.last_send = Instant::now();
        Ok(())
    }

    /// Preserve ordered wire deltas until their broker-specific book rules are verified.
    pub fn take_depth_updates(&mut self) -> Vec<DepthRecord> {
        std::mem::take(&mut self.changed_depth)
    }

    pub fn take_quotes(&mut self) -> Vec<Quote> {
        std::mem::take(&mut self.changed_quotes)
    }

    fn conversion_path(&self, from: &str, to: &str, quoted: bool) -> Option<Vec<(&Symbol, bool)>> {
        let mut queue = std::collections::VecDeque::from([(from.to_string(), Vec::new())]);
        let mut visited = BTreeSet::from([from.to_string()]);
        while let Some((currency, path)) = queue.pop_front() {
            if currency == to {
                return Some(path);
            }
            if path.len() >= 3 {
                continue;
            }
            for s in &self.state.symbols {
                if quoted
                    && !self
                        .quotes
                        .get(&s.name)
                        .is_some_and(|q| q.bid > 0.0 && q.ask > 0.0)
                {
                    continue;
                }
                let (next, forward) = if s.base_currency == currency {
                    (&s.profit_currency, true)
                } else if s.profit_currency == currency {
                    (&s.base_currency, false)
                } else {
                    continue;
                };
                if next.is_empty() || !visited.insert(next.clone()) {
                    continue;
                }
                let mut next_path = path.clone();
                next_path.push((s, forward));
                queue.push_back((next.clone(), next_path));
            }
        }
        None
    }

    pub fn conversion_rate(&self, from: &str, to: &str, loss: bool) -> Option<f64> {
        let mut rate = 1.0;
        for (s, forward) in self.conversion_path(from, to, true)? {
            let q = self.quotes.get(&s.name)?;
            rate *= if forward {
                if loss { q.ask } else { q.bid }
            } else {
                1.0 / if loss { q.bid } else { q.ask }
            };
        }
        Some(rate)
    }

    pub fn poll(&mut self, timeout: Duration) -> Result<Option<Message>> {
        if !self.healthy {
            return Err(ProtocolError::new(
                "native state requires a fresh synchronization",
            ));
        }
        let result = self.poll_inner(timeout);
        if result.is_err() {
            self.healthy = false;
        }
        result
    }

    fn poll_inner(&mut self, timeout: Duration) -> Result<Option<Message>> {
        if self.last_send.elapsed() >= KEEPALIVE {
            self.session.send_request(10, &[])?;
            self.last_send = Instant::now();
        }
        let message = self.session.poll_message(timeout)?;
        match &message {
            Some(m) => {
                self.last_receive = Instant::now();
                self.apply(m)?;
            }
            None if self.last_receive.elapsed() >= self.receive_deadline => {
                return Err(ProtocolError::new(format!(
                    "broker sent nothing for {} s",
                    self.receive_deadline.as_secs()
                )));
            }
            None => (),
        }
        Ok(message)
    }

    /// How long the connection may stay silent before it is presumed dead.
    /// Defaults to [`RECEIVE_DEADLINE`]; shorter only makes sense in tests.
    pub fn set_receive_deadline(&mut self, deadline: Duration) {
        self.receive_deadline = deadline;
    }

    fn apply(&mut self, m: &Message) -> Result<()> {
        match m.command {
            50 | 51 => {
                for row in decode_quotes(&m.payload, m.command)? {
                    let id: i32 = row
                        .symbol_id
                        .try_into()
                        .map_err(|_| ProtocolError::new("quote symbol ID overflow"))?;
                    let index = *self
                        .symbol_ids
                        .get(&id)
                        .ok_or_else(|| ProtocolError::new("quote for unknown symbol ID"))?;
                    let s = &self.state.symbols[index];
                    let scale = 10f64.powi(s.digits);
                    let (bid, ask, component) = if m.command == 50 {
                        (
                            row.live_get("bid_integer"),
                            row.live_get("ask_integer"),
                            row.live_get("millisecond_component"),
                        )
                    } else {
                        (row.field_get(0), row.field_get(3), row.field_get(26))
                    };
                    let time_ms = (row.seconds * 1000 + component.unwrap_or(0))
                        .try_into()
                        .map_err(|_| ProtocolError::new("quote timestamp overflow"))?;
                    let quote = self.quotes.entry(s.name.clone()).or_insert_with(|| Quote {
                        symbol: s.name.clone(),
                        time_ms,
                        bid: 0.0,
                        ask: 0.0,
                    });
                    if let Some(v) = bid {
                        if v > 0 {
                            quote.bid = v as f64 / scale;
                        }
                    }
                    if let Some(v) = ask {
                        if v > 0 {
                            quote.ask = v as f64 / scale;
                        }
                    }
                    quote.time_ms = time_ms;
                    if quote.bid > 0.0 && quote.ask > 0.0 {
                        if self.changed_quotes.len() >= 100_000 {
                            return Err(ProtocolError::new("quote consumer fell behind"));
                        }
                        self.changed_quotes.push(quote.clone());
                    }
                }
            }
            52 => {
                let records = decode_depth(&m.payload)?;
                if self.changed_depth.len() + records.len() > 10_000 {
                    return Err(ProtocolError::new("depth consumer fell behind"));
                }
                for record in records {
                    if !self.symbol_ids.contains_key(&record.symbol_id) {
                        return Err(ProtocolError::new("unknown depth symbol ID"));
                    }
                    self.changed_depth.push(record);
                }
            }
            55 => match decode_update(&m.payload)? {
                Update::Symbols(symbols) => {
                    for symbol in symbols {
                        if let Some(index) = self.symbol_ids.get(&symbol.id) {
                            self.state.symbols[*index] = symbol;
                        } else {
                            self.symbol_ids.insert(symbol.id, self.state.symbols.len());
                            self.state.symbols.push(symbol);
                        }
                    }
                }
                Update::Account(accounts) => {
                    for account in accounts {
                        if account.login == self.state.account.login {
                            self.state.account = account;
                        }
                    }
                }
                Update::Orders(orders) => {
                    for (change, order) in orders {
                        self.state.orders.retain(|o| o.ticket != order.ticket);
                        if change != Change::Delete {
                            self.state.orders.push(order);
                        }
                    }
                }
                Update::Positions(changes) => {
                    for change in changes {
                        for position in
                            std::iter::once(change.position).chain(change.related_positions)
                        {
                            self.state.positions.retain(|p| p.ticket != position.ticket);
                            if position.volume > 0 && position.position != 0 {
                                self.state.positions.push(position);
                            }
                        }
                        if let Some((balance, credit)) = change.balance {
                            self.state.account.balance = balance;
                            self.state.account.credit = credit;
                        }
                    }
                    let names: Vec<_> = self
                        .state
                        .positions
                        .iter()
                        .filter_map(|p| {
                            self.symbol(&p.symbol)
                                .ok()
                                .filter(|s| !self.subscriptions.contains(&s.id))
                                .map(|s| s.name.clone())
                        })
                        .collect();
                    if !names.is_empty() {
                        self.subscribe(&names)?;
                    }
                }
                Update::Other => (),
            },
            _ => (),
        }
        Ok(())
    }

    fn request(&mut self, command: u8, payload: &[u8]) -> Result<Message> {
        let sequence = self.session.send_request(command, payload)?;
        self.last_send = Instant::now();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| ProtocolError::new("request deadline exceeded"))?;
            if let Some(m) = self.poll(remaining.min(Duration::from_secs(1)))? {
                if m.command == command && m.sequence == sequence {
                    return Ok(m);
                }
            }
        }
    }

    /// Once transmission starts, any failure is uncertain. The client never
    /// retries a trade. Request IDs correlate results; they do not deduplicate.
    pub fn trade(&mut self, record: &[u8]) -> Result<TradeOutcome> {
        if !self.healthy {
            return Err(ProtocolError::new(
                "native state requires a fresh synchronization",
            ));
        }
        mt5_native::trade::parse_trade_record(record)?;
        if self.session.is_read_only()? {
            return Err(ProtocolError::new("account is read-only"));
        }
        let request = i32::from_le_bytes(record[..4].try_into().unwrap());
        if request <= 0 {
            return Err(ProtocolError::new("trade request ID must be positive"));
        }
        if let Err(error) = self.session.send_trade(record) {
            return Ok(TradeOutcome::Uncertain(error.to_string()));
        }
        self.last_send = Instant::now();
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut ticket = 0;
        loop {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Ok(TradeOutcome::Uncertain(
                    "trade result deadline exceeded".into(),
                ));
            };
            let received = self.poll(remaining.min(Duration::from_secs(1)));
            let m = match received {
                Ok(Some(m)) => m,
                Ok(None) => continue,
                Err(e) => return Ok(TradeOutcome::Uncertain(e.to_string())),
            };
            if m.command == 55 && m.payload.first() == Some(&35) {
                let results = match TradeResult::decode_update(&m.payload) {
                    Ok(v) => v,
                    Err(e) => return Ok(TradeOutcome::Uncertain(e.to_string())),
                };
                for r in results {
                    if r.request_id == request
                        || r.request_id == 0 && ticket != 0 && ticket == r.ticket
                    {
                        if r.ticket != 0 {
                            ticket = r.ticket;
                        }
                        if r.status == 10012 {
                            return Ok(TradeOutcome::Uncertain(
                                "broker reported a trade timeout".into(),
                            ));
                        }
                        if r.is_final() {
                            return Ok(TradeOutcome::Confirmed(r));
                        }
                    }
                }
            }
        }
    }
}
