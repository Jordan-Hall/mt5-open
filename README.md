# mt5-open

Rust libraries for talking to MetaTrader 5 servers without the MT5 terminal.

| Crate | What it is | Status |
|---|---|---|
| `mt5-webterm` | Client for the MetaQuotes **web terminal** WebSocket: login, account, positions, orders, deals, candles, live quotes and trading. `session` adds a long-running account session (session refresh, login backoff, live tick stream, ticket resolution). `search` finds any broker's web-terminal servers through MetaQuotes' public directory. | Works against demo servers |
| `mt5-native` | Byte-in / byte-out codec for the MT5 application wire protocol (revision 3). No networking. | Conformance-tested offline |
| `mt5-session` | Socket and login for `mt5-native`, behind the `live` feature. | Connects and authenticates; the post-login derived values (tags 28 and 35) are open — help wanted |

Built with rustls only, so it cross-compiles for Android (`aarch64-linux-android`).

## Use

```rust
let session = mt5_webterm::Session::new(login, password, "BrokerName-Demo".into());
let snap = session.snapshot().await?;
println!("balance {} equity {}", snap.account.balance, snap.account.equity);
```

Probes in `mt5-webterm/src/bin` read `MT5_ACCOUNT`, `MT5_PASSWORD` and `MT5_SERVER` from the environment.

## Caution

This is not affiliated with or endorsed by MetaQuotes. Using unofficial clients may be against your broker's or MetaQuotes' terms. Test on demo accounts. Nothing here should be pointed at real money without your own review.
