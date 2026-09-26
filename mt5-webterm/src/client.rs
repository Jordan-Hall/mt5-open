//! Live web-terminal session.

use crate::crypto::{aes_decrypt, aes_encrypt, STATIC_KEY};
use crate::parse::{
    parse_account, parse_candles, parse_deals, parse_orders, parse_positions, parse_quotes, parse_symbol_info,
    parse_symbols, parse_tick_stats, parse_trade_event, Account, Candle, Deal, Order, Position, Quote, Symbol,
};
use crate::protocol::*;
use crate::search::find_web_terminal;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async_tls_with_config, Connector};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Msg(String),
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Msg(s)
    }
}

#[derive(Clone)]
pub struct Client {
    tx: mpsc::Sender<Vec<u8>>,
    pending: Arc<Mutex<HashMap<u16, oneshot::Sender<Frame>>>>,
    quotes: Arc<Mutex<HashMap<String, Quote>>>,
    symbols: Arc<Mutex<HashMap<String, Symbol>>>,
    account: Arc<Mutex<Option<Account>>>,
    frames: broadcast::Sender<Frame>,
    closed: Arc<AtomicBool>,
    tz_shift: Arc<AtomicI64>,
    login: u64,
    server: String,
}

impl Client {
    pub async fn connect(login: u64, password: &str, server: &str) -> Result<Self, Error> {
        let (host, port) = find_web_terminal(server).await?;
        Self::dial(&host, port, login, password, server).await
    }

    /// Connect through a named `host:port` rather than whichever endpoint the
    /// search picks first. Used to tell "this host refuses us" apart from
    /// "every host refuses us".
    pub async fn connect_via(endpoint: &str, login: u64, password: &str, server: &str) -> Result<Self, Error> {
        let (host, port_s) = endpoint.rsplit_once(':').ok_or_else(|| Error::Msg("bad endpoint".into()))?;
        let port: u16 = port_s.parse().map_err(|_| Error::Msg("bad port".into()))?;
        Self::dial(host, port, login, password, server).await
    }

    async fn dial(host: &str, port: u16, login: u64, password: &str, server: &str) -> Result<Self, Error> {
        let url = format!("wss://{host}:{port}/terminal");
        let mut req = url.into_client_request().map_err(|e| e.to_string())?;
        let origin = format!("https://{host}:{port}");
        req.headers_mut().insert("Origin", origin.parse().map_err(|e| format!("{e}"))?);
        let tls = crate::tls::client_config()?;
        let (ws, _) = connect_async_tls_with_config(req, None, false, Some(Connector::Rustls(tls)))
            .await
            .map_err(|e| e.to_string())?;
        let (mut write, mut read) = ws.split();

        let auth = aes_encrypt(&STATIC_KEY, &build_command(CMD_AUTH, &[0u8; 64]))?;
        write.send(Message::Binary(pack_wire(&auth))).await.map_err(|e| e.to_string())?;
        let raw = wait_bin(&mut read).await?;
        if raw.len() < 8 {
            return Err(Error::Msg("short auth frame".into()));
        }
        let pt = aes_decrypt(&STATIC_KEY, &raw[8..])?;
        let frame = parse_response(&pt).ok_or_else(|| "bad auth".to_string())?;
        if frame.res_code != 0 || frame.body.len() < 98 {
            return Err(Error::Msg(format!("auth code {}", frame.res_code)));
        }
        let session_key = frame.body[66..98].to_vec();

        let login_pl = pack_login(login, password, server);
        let enc = aes_encrypt(&session_key, &build_command(CMD_LOGIN, &login_pl))?;
        write.send(Message::Binary(pack_wire(&enc))).await.map_err(|e| e.to_string())?;
        let raw = wait_bin(&mut read).await?;
        let pt = aes_decrypt(&session_key, &raw[8..])?;
        let frame = parse_response(&pt).ok_or_else(|| "bad login".to_string())?;
        if frame.cmd_id != CMD_LOGIN || frame.res_code != 0 {
            return Err(Error::Msg(format!("login cmd={} code={}", frame.cmd_id, frame.res_code)));
        }

        let (tx, mut outbound) = mpsc::channel::<Vec<u8>>(32);
        let key_w = session_key.clone();
        tokio::spawn(async move {
            while let Some(payload) = outbound.recv().await {
                let Ok(enc) = aes_encrypt(&key_w, &payload) else { break };
                if write.send(Message::Binary(pack_wire(&enc))).await.is_err() {
                    break;
                }
            }
            // Every client handle is gone: close the socket rather than leave
            // the server holding a session nobody will use again.
            let _ = write.close().await;
        });

        let pending: Arc<Mutex<HashMap<u16, oneshot::Sender<Frame>>>> = Arc::new(Mutex::new(HashMap::new()));
        let quotes: Arc<Mutex<HashMap<String, Quote>>> = Arc::new(Mutex::new(HashMap::new()));
        let symbols = Arc::new(Mutex::new(HashMap::new()));
        let account = Arc::new(Mutex::new(None));
        let (frames, _) = broadcast::channel::<Frame>(256);
        let frames_r = frames.clone();
        let pending_r = pending.clone();
        let quotes_r = quotes.clone();
        let symbols_r = symbols.clone();
        let closed = Arc::new(AtomicBool::new(false));
        let closed_r = closed.clone();
        let tz_shift = Arc::new(AtomicI64::new(0));
        let tz_r = tz_shift.clone();
        tokio::spawn(async move {
            while let Some(msg) = read.next().await {
                let msg = match msg {
                    Ok(m) => m,
                    Err(_) => break,
                };
                if matches!(msg, Message::Close(_)) {
                    break;
                }
                let Message::Binary(raw) = msg else { continue };
                if raw.len() < 8 {
                    continue;
                }
                let Ok(pt) = aes_decrypt(&session_key, &raw[8..]) else { continue };
                let Some(frame) = parse_response(&pt) else { continue };
                if let Some(wait) = pending_r.lock().await.remove(&frame.cmd_id) {
                    let _ = wait.send(frame.clone());
                }
                let _ = frames_r.send(frame.clone());
                if frame.cmd_id == CMD_QUOTES {
                    let map = symbols_r.lock().await.clone();
                    for mut item in parse_quotes(&frame.body, &map) {
                        // A tick that moved only one side arrives with the
                        // other side zero. Overwriting wholesale publishes a
                        // bid of 0 -- which reads downstream as a half-dead
                        // feed, and prices a sell's exit at nothing. Carry the
                        // side that did not move; drop a record with neither.
                        let mut cache = quotes_r.lock().await;
                        if let Some(prev) = cache.get(&item.symbol) {
                            if item.bid <= 0.0 {
                                item.bid = prev.bid;
                            }
                            if item.ask <= 0.0 {
                                item.ask = prev.ask;
                            }
                        }
                        if item.bid <= 0.0 || item.ask <= 0.0 {
                            continue;
                        }
                        cache.insert(item.symbol.clone(), item);
                    }
                }
                if frame.cmd_id == CMD_TICK_STATS {
                    // The last quote and its server time, sent even when the
                    // market is closed and nothing will stream. It only fills
                    // a gap: a streamed quote is never older.
                    let map = symbols_r.lock().await.clone();
                    let shift_ms = tz_r.load(Ordering::Relaxed) * 1000;
                    let mut cache = quotes_r.lock().await;
                    for mut item in parse_tick_stats(&frame.body, &map) {
                        item.time_ms -= shift_ms;
                        cache.entry(item.symbol.clone()).or_insert(item);
                    }
                }
            }
            // The socket is gone. Pending requests would otherwise wait out
            // their full timeout, and a holder would keep using a dead client.
            closed_r.store(true, Ordering::Relaxed);
            pending_r.lock().await.clear();
        });

        let client = Client {
            tx,
            pending,
            quotes,
            symbols,
            account,
            frames,
            closed,
            tz_shift,
            login,
            server: server.to_string(),
        };
        // The heartbeat must not keep the session alive by itself: it holds
        // only a weak sender and stops once every client handle is dropped.
        let hb = client.tx.downgrade();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(3)).await;
                let Some(tx) = hb.upgrade() else { break };
                if tx.send(build_command(CMD_HEARTBEAT, &[])).await.is_err() {
                    break;
                }
            }
        });

        if let Ok(frame) = client.request(CMD_ACCOUNT, &[]).await {
            let acct = parse_account(&frame.body, login, server);
            client.tz_shift.store(acct.timezone_shift_seconds, Ordering::Relaxed);
            *client.account.lock().await = Some(acct);
        }
        if let Ok(frame) = client.request(CMD_SYMBOLS, &[]).await {
            *client.symbols.lock().await = parse_symbols(&frame.body);
        }
        Ok(client)
    }

    async fn send_cmd(&self, cmd: u16, payload: &[u8]) -> Result<(), Error> {
        self.tx.send(build_command(cmd, payload)).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn request(&self, cmd: u16, payload: &[u8]) -> Result<Frame, Error> {
        if self.is_closed() {
            return Err(Error::Msg("web-terminal session closed".into()));
        }
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(cmd, tx);
        self.send_cmd(cmd, payload).await?;
        Ok(tokio::time::timeout(Duration::from_secs(20), rx)
            .await
            .map_err(|_| "timeout".to_string())?
            .map_err(|_| "cancelled".to_string())?)
    }

    /// Every frame the server sends from now on, answers and pushes alike.
    /// A receiver that falls behind loses the oldest frames, not the session.
    pub fn frames(&self) -> broadcast::Receiver<Frame> {
        self.frames.subscribe()
    }

    /// True once the socket has closed or failed. A closed client never
    /// recovers; dial a new one.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// Seconds the server clock runs ahead of UTC, from the account frame.
    pub fn timezone_shift_seconds(&self) -> i64 {
        self.tz_shift.load(Ordering::Relaxed)
    }

    /// Read the full specification of `names` and keep it in the symbol
    /// cache. Names the server does not list are skipped.
    pub async fn symbol_info(&self, names: &[String]) -> Result<Vec<Symbol>, Error> {
        let ids: Vec<u32> = {
            let map = self.symbols.lock().await;
            names.iter().filter_map(|n| map.get(n).map(|s| s.id)).collect()
        };
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let mut payload = Vec::from((ids.len() as u32).to_le_bytes());
        for id in &ids {
            payload.extend_from_slice(&id.to_le_bytes());
        }
        let infos = parse_symbol_info(&self.request(CMD_SYMBOL_INFO, &payload).await?.body);
        let mut map = self.symbols.lock().await;
        for s in &infos {
            map.insert(s.name.clone(), s.clone());
        }
        Ok(infos)
    }

    pub async fn account(&self) -> Result<Account, Error> {
        let frame = self.request(CMD_ACCOUNT, &[]).await?;
        let acct = parse_account(&frame.body, self.login, &self.server);
        self.tz_shift.store(acct.timezone_shift_seconds, Ordering::Relaxed);
        *self.account.lock().await = Some(acct.clone());
        Ok(acct)
    }

    pub async fn cached_account(&self) -> Option<Account> {
        self.account.lock().await.clone()
    }

    pub async fn symbols(&self) -> HashMap<String, Symbol> {
        self.symbols.lock().await.clone()
    }

    pub async fn subscribe(&self, names: &[String]) -> Result<(), Error> {
        let map = self.symbols.lock().await.clone();
        let ids: Vec<u32> = names.iter().filter_map(|n| map.get(n).map(|s| s.id)).collect();
        if ids.is_empty() {
            return Ok(());
        }
        let mut payload = Vec::from((ids.len() as u32).to_le_bytes());
        for id in ids {
            payload.extend_from_slice(&id.to_le_bytes());
        }
        self.send_cmd(CMD_SUBSCRIBE, &payload).await
    }

    pub async fn quote(&self, symbol: &str) -> Option<Quote> {
        self.quotes.lock().await.get(symbol).cloned()
    }

    pub async fn wait_quote(&self, symbol: &str) -> Result<Quote, Error> {
        self.subscribe(&[symbol.to_string()]).await?;
        for _ in 0..40 {
            if let Some(q) = self.quote(symbol).await {
                return Ok(q);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Err(Error::Msg(format!("no quote for {symbol}")))
    }

    pub async fn positions(&self) -> Result<Vec<Position>, Error> {
        Ok(parse_positions(&self.request(CMD_POSITIONS, &[]).await?.body))
    }

    pub async fn orders(&self) -> Result<Vec<Order>, Error> {
        Ok(parse_orders(&self.request(CMD_POSITIONS, &[]).await?.body))
    }

    pub async fn deals(&self, from: u32, to: u32) -> Result<Vec<Deal>, Error> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&from.to_le_bytes());
        payload.extend_from_slice(&to.to_le_bytes());
        Ok(parse_deals(&self.request(CMD_DEALS, &payload).await?.body))
    }

    pub async fn candles(&self, symbol: &str, tf: &str, count: usize) -> Result<Vec<Candle>, Error> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i32)
            .unwrap_or(0);
        let sec = match tf {
            "M1" => 60,
            "M5" => 300,
            "M15" => 900,
            "M30" => 1800,
            "H1" => 3600,
            "H4" => 14400,
            "D1" => 86400,
            _ => 300,
        };
        let from = now - ((count as i32 + 10) * sec);
        self.candles_between(symbol, tf, from as i64, now as i64).await
    }

    /// Candles the server holds between `from` and `to` (seconds).
    pub async fn candles_between(&self, symbol: &str, tf: &str, from: i64, to: i64) -> Result<Vec<Candle>, Error> {
        let clamp = |t: i64| t.clamp(0, i32::MAX as i64) as i32;
        Ok(parse_candles(&self.request(CMD_RATES, &pack_rates_req(symbol, tf, clamp(from), clamp(to))).await?.body))
    }

    pub async fn send_op(&self, op: &[u8]) -> Result<(u32, i64, i64, f64), Error> {
        let frame = self.request(CMD_TRADE, op).await?;
        if let Some((ret, deal, order, _, price, _)) = parse_trade_event(&frame.body) {
            return Ok((ret, deal, order, price));
        }
        let ret = if frame.body.len() >= 4 {
            u32::from_le_bytes(frame.body[0..4].try_into().unwrap())
        } else {
            frame.res_code as u32
        };
        Ok((ret, 0, 0, 0.0))
    }

    pub fn symbol(&self, name: &str) -> impl std::future::Future<Output = Option<Symbol>> + Send {
        let symbols = self.symbols.clone();
        let name = name.to_string();
        async move { symbols.lock().await.get(&name).cloned() }
    }
}

async fn wait_bin<S>(read: &mut S) -> Result<Vec<u8>, Error>
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let msg = tokio::time::timeout(Duration::from_secs(20), read.next())
        .await
        .map_err(|_| "timeout".to_string())?
        .ok_or_else(|| "closed".to_string())?
        .map_err(|e| e.to_string())?;
    match msg {
        Message::Binary(b) => Ok(b),
        other => Err(Error::Msg(format!("unexpected {other}"))),
    }
}
