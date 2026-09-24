//! Bounded, single-owner WebTerminal transport with serialized RPCs.

use crate::crypto::{aes_decrypt, aes_encrypt, STATIC_KEY};
use crate::parse::{
    try_parse_account, try_parse_candles, try_parse_deals, try_parse_positions_and_orders,
    try_parse_symbols, parse_trade_event, Account, Candle, Deal, Order, Position, Quote,
    QuoteDecoder, Symbol,
};
use crate::protocol::*;
use crate::search::{find_web_terminal, parse_endpoint};
use futures_util::{SinkExt, StreamExt};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, Notify, RwLock};
use tokio::time::{Instant, MissedTickBehavior, timeout, timeout_at};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, protocol::WebSocketConfig, Message};
use tokio_tungstenite::{connect_async_tls_with_config, Connector, WebSocketStream};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const QUOTE_MAX_AGE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Msg(String),
    #[error("connection closed")]
    Closed,
    #[error("request timed out; reconnect before retrying a read; reconcile a trade before retrying")]
    Timeout,
}

impl From<String> for Error {
    fn from(s: String) -> Self { Self::Msg(s) }
}

struct Outbound {
    cmd: u16,
    payload: Vec<u8>,
    expect_reply: bool,
    deadline: Instant,
    reply: oneshot::Sender<Result<Option<Frame>, Error>>,
}

#[derive(Default)]
struct Cache {
    quotes: HashMap<String, (Quote, Instant)>,
    symbols: HashMap<String, Symbol>,
    decoder: QuoteDecoder,
    account: Option<Account>,
}

struct Inner {
    tx: mpsc::Sender<Outbound>,
    cache: Arc<RwLock<Cache>>,
    changed: Arc<Notify>,
    closed: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
    login: u64,
    server: String,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.changed.notify_waiters();
        self.task.abort();
    }
}

#[derive(Clone)]
pub struct Client { inner: Arc<Inner> }

impl Client {
    pub async fn connect(login: u64, password: &str, server: &str) -> Result<Self, Error> {
        validate_login(password, server)?;
        let (host, port) = find_web_terminal(server).await?;
        Self::dial(&host, port, login, password, server, crate::tls::client_config()?).await
    }

    /// Bypass directory discovery with a broker-provided certificate hostname.
    pub async fn connect_via(endpoint: &str, login: u64, password: &str, server: &str) -> Result<Self, Error> {
        Self::connect_via_with_tls(endpoint, login, password, server, crate::tls::client_config()?).await
    }

    /// Supply an explicitly configured trust store, for example a broker's
    /// private CA. The default entry points always verify public PKI and DNS.
    pub async fn connect_via_with_tls(
        endpoint: &str, login: u64, password: &str, server: &str,
        tls: Arc<rustls::ClientConfig>,
    ) -> Result<Self, Error> {
        validate_login(password, server)?;
        let (host, port) = parse_endpoint(endpoint)?;
        Self::dial(&host, port, login, password, server, tls).await
    }

    async fn dial(
        host: &str, port: u16, login: u64, password: &str, server: &str,
        tls: Arc<rustls::ClientConfig>,
    ) -> Result<Self, Error> {
        let mut req = format!("wss://{host}:{port}/terminal").into_client_request().map_err(|e| e.to_string())?;
        req.headers_mut().insert("Origin", format!("https://{host}:{port}").parse().map_err(|e| format!("{e}"))?);
        let config = WebSocketConfig {
            max_message_size: Some(MAX_WIRE_BYTES),
            max_frame_size: Some(MAX_WIRE_BYTES),
            ..Default::default()
        };
        let (mut ws, _) = timeout(REQUEST_TIMEOUT,
            connect_async_tls_with_config(req, Some(config), true, Some(Connector::Rustls(tls))))
            .await.map_err(|_| Error::Timeout)?.map_err(|e| e.to_string())?;
        let key = timeout(REQUEST_TIMEOUT, async {
            send_frame(&mut ws, &STATIC_KEY, CMD_AUTH, &[0; 64]).await?;
            let auth = receive_frame(&mut ws, &STATIC_KEY).await?;
            if auth.cmd_id != CMD_AUTH || auth.res_code != 0 || auth.body.len() < 98 {
                return Err(Error::Msg(format!("invalid authentication response: command {}, status {}", auth.cmd_id, auth.res_code)));
            }
            let key: [u8; 32] = auth.body[66..98].try_into().unwrap();
            let mut login_body = pack_login(login, password, server);
            let sent = send_frame(&mut ws, &key, CMD_LOGIN, &login_body).await;
            login_body.fill(0);
            sent?;
            let response = receive_frame(&mut ws, &key).await?;
            if response.cmd_id != CMD_LOGIN || response.res_code != 0 {
                return Err(Error::Msg(format!("login refused: command {}, status {}", response.cmd_id, response.res_code)));
            }
            Ok(key)
        }).await.map_err(|_| Error::Timeout)??;
        let client = Self::attach(ws, key, login, server.to_string());
        // A usable client must have authenticated account data and routing.
        client.account().await?;
        client.request(CMD_SYMBOLS, &[]).await?;
        Ok(client)
    }

    fn attach<S>(ws: WebSocketStream<S>, key: [u8; 32], login: u64, server: String) -> Self
    where S: AsyncRead + AsyncWrite + Unpin + Send + 'static {
        let (tx, rx) = mpsc::channel(32);
        let cache = Arc::new(RwLock::new(Cache::default()));
        let changed = Arc::new(Notify::new());
        let closed = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(run_transport(ws, key, rx, cache.clone(), changed.clone(), closed.clone()));
        Self { inner: Arc::new(Inner { tx, cache, changed, closed, task, login, server }) }
    }

    pub fn is_connected(&self) -> bool {
        !self.inner.closed.load(Ordering::Acquire) && !self.inner.tx.is_closed()
    }

    async fn dispatch(&self, cmd: u16, payload: &[u8], expect_reply: bool) -> Result<Option<Frame>, Error> {
        if !self.is_connected() { return Err(Error::Closed); }
        if payload.len() > MAX_COMMAND_BYTES { return Err(Error::Msg("command exceeds size limit".into())); }
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        let (reply, rx) = oneshot::channel();
        timeout_at(deadline, self.inner.tx.send(Outbound {
            cmd, payload: payload.to_vec(), expect_reply, deadline, reply,
        })).await.map_err(|_| Error::Timeout)?.map_err(|_| Error::Closed)?;
        timeout_at(deadline, rx).await.map_err(|_| Error::Timeout)?.map_err(|_| Error::Closed)?
    }

    async fn send_cmd(&self, cmd: u16, payload: &[u8]) -> Result<(), Error> {
        self.dispatch(cmd, payload, false).await.map(|_| ())
    }

    /// RPCs are serialized because command IDs are not correlation IDs. A
    /// timeout/cancellation after transmission closes the transport, preventing
    /// a late reply from satisfying a subsequent request of the same command.
    pub async fn request(&self, cmd: u16, payload: &[u8]) -> Result<Frame, Error> {
        self.dispatch(cmd, payload, true).await?.ok_or(Error::Closed)
    }

    pub async fn account(&self) -> Result<Account, Error> {
        let frame = self.request(CMD_ACCOUNT, &[]).await?;
        let account = try_parse_account(&frame.body, self.inner.login, &self.inner.server)?;
        self.inner.cache.write().await.account = Some(account.clone());
        Ok(account)
    }

    pub async fn cached_account(&self) -> Option<Account> { self.inner.cache.read().await.account.clone() }
    pub async fn symbols(&self) -> HashMap<String, Symbol> { self.inner.cache.read().await.symbols.clone() }
    pub async fn symbol(&self, name: &str) -> Option<Symbol> { self.inner.cache.read().await.symbols.get(name).cloned() }

    pub async fn subscribe(&self, names: &[String]) -> Result<(), Error> {
        let mut ids = HashSet::new();
        let cache = self.inner.cache.read().await;
        for name in names {
            ids.insert(cache.symbols.get(name).ok_or_else(|| Error::Msg(format!("unknown symbol: {name}")))?.id);
        }
        drop(cache);
        if ids.is_empty() { return Ok(()); }
        let mut ids: Vec<_> = ids.into_iter().collect();
        ids.sort_unstable();
        let mut payload = Vec::with_capacity(4 + ids.len() * 4);
        payload.extend_from_slice(&(ids.len() as u32).to_le_bytes());
        for id in ids { payload.extend_from_slice(&id.to_le_bytes()); }
        self.send_cmd(CMD_SUBSCRIBE, &payload).await
    }

    /// Only complete, recently received two-sided quotes are exposed.
    pub async fn quote(&self, symbol: &str) -> Option<Quote> {
        if !self.is_connected() { return None; }
        self.inner.cache.read().await.quotes.get(symbol)
            .filter(|(q, received)| q.bid > 0.0 && q.ask > 0.0 && received.elapsed() <= QUOTE_MAX_AGE)
            .map(|(q, _)| q.clone())
    }

    pub(crate) fn quote_notifier(&self) -> Arc<Notify> { self.inner.changed.clone() }

    pub async fn wait_quote(&self, symbol: &str) -> Result<Quote, Error> {
        self.subscribe(&[symbol.to_string()]).await?;
        timeout(Duration::from_secs(8), async {
            loop {
                let changed = self.inner.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if let Some(quote) = self.quote(symbol).await { return Ok(quote); }
                if !self.is_connected() { return Err(Error::Closed); }
                changed.await;
            }
        }).await.map_err(|_| Error::Msg(format!("no fresh quote for {symbol}")))?
    }

    /// One coherent server reply supplies both position and pending-order sets.
    pub async fn positions_and_orders(&self) -> Result<(Vec<Position>, Vec<Order>), Error> {
        Ok(try_parse_positions_and_orders(&self.request(CMD_POSITIONS, &[]).await?.body)?)
    }
    pub async fn positions(&self) -> Result<Vec<Position>, Error> { Ok(self.positions_and_orders().await?.0) }
    pub async fn orders(&self) -> Result<Vec<Order>, Error> { Ok(self.positions_and_orders().await?.1) }

    pub async fn deals(&self, from: u32, to: u32) -> Result<Vec<Deal>, Error> {
        if from > to { return Err(Error::Msg("invalid deal range".into())); }
        let mut payload = Vec::with_capacity(8);
        payload.extend_from_slice(&from.to_le_bytes());
        payload.extend_from_slice(&to.to_le_bytes());
        Ok(try_parse_deals(&self.request(CMD_DEALS, &payload).await?.body)?)
    }

    pub async fn candles_range(&self, symbol: &str, tf: &str, from: i64, to: i64) -> Result<Vec<Candle>, Error> {
        timeframe_seconds(tf)?;
        validate_fixed_string(symbol, 32, "symbol")?;
        let from = i32::try_from(from).map_err(|_| "history start exceeds wire timestamp range".to_string())?;
        let to = i32::try_from(to).map_err(|_| "history end exceeds wire timestamp range".to_string())?;
        if from < 0 || from > to { return Err(Error::Msg("invalid history range".into())); }
        Ok(try_parse_candles(&self.request(CMD_RATES, &pack_rates_req(symbol, tf, from, to)).await?.body)?)
    }

    pub async fn candles(&self, symbol: &str, tf: &str, count: usize) -> Result<Vec<Candle>, Error> {
        if count == 0 { return Ok(Vec::new()); }
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system clock predates Unix epoch".to_string())?.as_secs();
        let now = i64::try_from(now).map_err(|_| "system clock exceeds timestamp range".to_string())?;
        let (from, to) = history_window(tf, count, now)?;
        let mut rows = self.candles_range(symbol, tf, from, to).await?;
        rows.retain(|r| r.time >= from && r.time <= to);
        rows.sort_by_key(|r| r.time);
        if rows.len() > count { rows.drain(..rows.len() - count); }
        Ok(rows)
    }

    pub async fn send_op(&self, op: &[u8]) -> Result<(u32, i64, i64, f64), Error> {
        if op.len() != OP_SIZE { return Err(Error::Msg("invalid trade record length".into())); }
        let frame = self.request(CMD_TRADE, op).await?;
        if let Some((ret, deal, order, _, price, _)) = parse_trade_event(&frame.body) {
            return Ok((ret, deal, order, price));
        }
        let code = frame.body.get(..4).ok_or_else(|| Error::Msg("trade outcome unknown: response has no result code".into()))?;
        Ok((u32::from_le_bytes(code.try_into().unwrap()), 0, 0, 0.0))
    }
}

async fn send_frame<S>(ws: &mut WebSocketStream<S>, key: &[u8], cmd: u16, body: &[u8]) -> Result<(), Error>
where S: AsyncRead + AsyncWrite + Unpin {
    let encrypted = aes_encrypt(key, &build_command(cmd, body))?;
    ws.send(Message::Binary(pack_wire(&encrypted))).await.map_err(|e| Error::Msg(e.to_string()))
}

async fn receive_frame<S>(ws: &mut WebSocketStream<S>, key: &[u8]) -> Result<Frame, Error>
where S: AsyncRead + AsyncWrite + Unpin {
    loop {
        match ws.next().await.ok_or(Error::Closed)?.map_err(|e| Error::Msg(e.to_string()))? {
            Message::Binary(raw) => {
                let plaintext = aes_decrypt(key, unpack_wire(&raw)?)?;
                return parse_response(&plaintext).ok_or_else(|| Error::Msg("truncated response".into()));
            }
            Message::Ping(_) => ws.flush().await.map_err(|e| Error::Msg(e.to_string()))?,
            Message::Pong(_) => {},
            Message::Close(_) => return Err(Error::Closed),
            _ => return Err(Error::Msg("unexpected non-binary WebTerminal message".into())),
        }
    }
}

async fn apply_frame(cache: &RwLock<Cache>, changed: &Notify, frame: &Frame) -> Result<(), Error> {
    if frame.res_code != 0 { return Ok(()); }
    match frame.cmd_id {
        CMD_SYMBOLS => {
            let symbols = try_parse_symbols(&frame.body)?;
            let decoder = QuoteDecoder::new(&symbols);
            let mut cache = cache.write().await;
            cache.symbols = symbols;
            cache.decoder = decoder;
            cache.quotes.clear();
        }
        CMD_QUOTES => {
            let mut cache = cache.write().await;
            for mut quote in cache.decoder.decode(&frame.body)? {
                if quote.bid == 0.0 && quote.ask == 0.0 { continue; }
                if let Some((previous, _)) = cache.quotes.get(&quote.symbol) {
                    if quote.bid == 0.0 { quote.bid = previous.bid; }
                    if quote.ask == 0.0 { quote.ask = previous.ask; }
                }
                cache.quotes.insert(quote.symbol.clone(), (quote, Instant::now()));
            }
            drop(cache);
            changed.notify_waiters();
        }
        _ => {},
    }
    Ok(())
}

struct TransportGuard { closed: Arc<AtomicBool>, changed: Arc<Notify> }
impl Drop for TransportGuard {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
}

async fn run_transport<S>(
    mut ws: WebSocketStream<S>, key: [u8; 32], mut inbound: mpsc::Receiver<Outbound>,
    cache: Arc<RwLock<Cache>>, changed: Arc<Notify>, closed: Arc<AtomicBool>,
) where S: AsyncRead + AsyncWrite + Unpin {
    let _guard = TransportGuard { closed, changed: changed.clone() };
    let mut heartbeat = tokio::time::interval_at(Instant::now() + Duration::from_secs(3), Duration::from_secs(3));
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            request = inbound.recv() => {
                let Some(mut request) = request else { return };
                if request.reply.is_closed() { continue; }
                if request.deadline <= Instant::now() {
                    let _ = request.reply.send(Err(Error::Timeout));
                    continue;
                }
                let result = tokio::select! {
                    _ = request.reply.closed() => return,
                    result = timeout_at(request.deadline, send_frame(&mut ws, &key, request.cmd, &request.payload)) =>
                        result.map_err(|_| Error::Timeout).and_then(|r| r),
                };
                if let Err(error) = result { let _ = request.reply.send(Err(error)); return; }
                if !request.expect_reply { let _ = request.reply.send(Ok(None)); continue; }
                loop {
                    tokio::select! {
                        _ = request.reply.closed() => return,
                        _ = tokio::time::sleep_until(request.deadline) => {
                            let _ = request.reply.send(Err(Error::Timeout)); return;
                        }
                        frame = receive_frame(&mut ws, &key) => {
                            let frame = match frame { Ok(frame) => frame, Err(error) => {
                                let _ = request.reply.send(Err(error)); return;
                            }};
                            if let Err(error) = apply_frame(&cache, &changed, &frame).await {
                                let _ = request.reply.send(Err(error)); return;
                            }
                            if frame.cmd_id == request.cmd {
                                let result = if frame.res_code == 0 { Ok(Some(frame)) }
                                    else { Err(Error::Msg(format!("command {} rejected with status {}", frame.cmd_id, frame.res_code))) };
                                let _ = request.reply.send(result);
                                break;
                            }
                        }
                        _ = heartbeat.tick() => {
                            if !matches!(timeout_at(request.deadline, send_frame(&mut ws, &key, CMD_HEARTBEAT, &[])).await, Ok(Ok(()))) {
                                let _ = request.reply.send(Err(Error::Timeout)); return;
                            }
                        }
                    }
                }
            }
            frame = receive_frame(&mut ws, &key) => {
                let Ok(frame) = frame else { return };
                if apply_frame(&cache, &changed, &frame).await.is_err() { return; }
            }
            _ = heartbeat.tick() => {
                if !matches!(timeout(REQUEST_TIMEOUT, send_frame(&mut ws, &key, CMD_HEARTBEAT, &[])).await, Ok(Ok(()))) { return; }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, DuplexStream};
    use tokio_tungstenite::tungstenite::protocol::Role;

    async fn pair() -> (Client, WebSocketStream<DuplexStream>) {
        let (a, b) = duplex(65536);
        let client = WebSocketStream::from_raw_socket(a, Role::Client, None).await;
        let server = WebSocketStream::from_raw_socket(b, Role::Server, None).await;
        (Client::attach(client, STATIC_KEY, 1, "mock".into()), server)
    }

    async fn command(server: &mut WebSocketStream<DuplexStream>) -> (u16, Vec<u8>) {
        loop {
            let Some(Ok(Message::Binary(raw))) = server.next().await else { panic!("no command") };
            let plain = aes_decrypt(&STATIC_KEY, unpack_wire(&raw).unwrap()).unwrap();
            let cmd = u16::from_le_bytes(plain[2..4].try_into().unwrap());
            if cmd != CMD_HEARTBEAT { return (cmd, plain[4..].to_vec()); }
        }
    }

    async fn reply(server: &mut WebSocketStream<DuplexStream>, cmd: u16, code: u8, body: &[u8]) {
        let mut response = vec![0, 0];
        response.extend_from_slice(&cmd.to_le_bytes());
        response.push(code);
        response.extend_from_slice(body);
        let encrypted = aes_encrypt(&STATIC_KEY, &response).unwrap();
        server.send(Message::Binary(pack_wire(&encrypted))).await.unwrap();
    }

    #[tokio::test]
    async fn simultaneous_identical_commands_cannot_overwrite_each_other() {
        let (client, mut server) = pair().await;
        let mock = tokio::spawn(async move {
            for _ in 0..2 {
                let (cmd, body) = command(&mut server).await;
                reply(&mut server, cmd, 0, &body).await;
            }
        });
        let (a, b) = tokio::join!(client.request(42, b"first"), client.request(42, b"second"));
        assert_eq!(a.unwrap().body, b"first");
        assert_eq!(b.unwrap().body, b"second");
        mock.await.unwrap();
    }

    #[tokio::test]
    async fn failure_codes_are_errors_not_empty_account_successes() {
        let (client, mut server) = pair().await;
        let mock = tokio::spawn(async move {
            let (cmd, _) = command(&mut server).await;
            reply(&mut server, cmd, 7, &[]).await;
        });
        assert!(client.account().await.is_err());
        assert!(client.cached_account().await.is_none());
        mock.await.unwrap();
    }

    #[tokio::test]
    async fn cancellation_after_send_invalidates_the_connection() {
        let (client, mut server) = pair().await;
        let caller = client.clone();
        let request = tokio::spawn(async move { caller.request(42, b"pending").await });
        command(&mut server).await;
        request.abort();
        let _ = request.await;
        tokio::task::yield_now().await;
        assert!(!client.is_connected());
        assert!(client.request(42, b"must not be sent").await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_closes_the_session_before_a_late_reply_can_be_reused() {
        let (client, mut server) = pair().await;
        let caller = client.clone();
        let request = tokio::spawn(async move { caller.request(42, b"pending").await });
        command(&mut server).await;
        tokio::time::advance(REQUEST_TIMEOUT + Duration::from_secs(1)).await;
        assert!(request.await.unwrap().is_err());
        tokio::task::yield_now().await;
        assert!(!client.is_connected());
    }

    #[tokio::test]
    async fn dropping_the_last_client_aborts_the_socket_owner() {
        let (client, mut server) = pair().await;
        let closed = client.inner.closed.clone();
        drop(client);
        assert!(closed.load(Ordering::Acquire));
        let result = timeout(Duration::from_secs(1), server.next()).await;
        assert!(result.is_ok());
        assert!(!matches!(result.unwrap(), Some(Ok(Message::Binary(_)))));
    }

    #[tokio::test]
    async fn malformed_wire_input_fails_pending_requests_without_panicking() {
        let (client, mut server) = pair().await;
        let mock = tokio::spawn(async move {
            command(&mut server).await;
            server.send(Message::Binary(vec![1, 2, 3])).await.unwrap();
        });
        assert!(client.request(42, &[]).await.is_err());
        mock.await.unwrap();
    }

    #[tokio::test]
    async fn complementary_initial_quote_updates_form_a_complete_book() {
        let symbol = Symbol { name: "TEST".into(), id: 7, digits: 0, ..Default::default() };
        let symbols = HashMap::from([(symbol.name.clone(), symbol)]);
        let cache = RwLock::new(Cache { decoder: QuoteDecoder::new(&symbols), symbols, ..Default::default() });
        let notify = Notify::new();
        for (bid, ask) in [(100.0f64, 0.0f64), (0.0, 101.0)] {
            let mut body = vec![0; QUOTE_SIZE];
            body[..4].copy_from_slice(&7u32.to_le_bytes());
            body[12..20].copy_from_slice(&bid.to_le_bytes());
            body[20..28].copy_from_slice(&ask.to_le_bytes());
            apply_frame(&cache, &notify, &Frame { tag: 0, cmd_id: CMD_QUOTES, res_code: 0, body }).await.unwrap();
        }
        let cache = cache.read().await;
        let quote = &cache.quotes["TEST"].0;
        assert_eq!((quote.bid, quote.ask), (100.0, 101.0));
    }
}
