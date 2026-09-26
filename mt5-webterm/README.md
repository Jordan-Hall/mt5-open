# mt5-webterm (Rust)

Native MetaQuotes web-terminal client. WebSocket to `wss://host:443/terminal`.
Server names resolve through the MetaQuotes directory; access ports
700–705 are rewritten to 443.

```powershell
# from the workspace root
$env:MT5_ACCOUNT=...; $env:MT5_PASSWORD=...; $env:MT5_SERVER=ExampleBroker-Demo
cargo run -p mt5_webterm --bin webterm-probe
```

An application embeds the client and talks to the broker in-process (a phone
or a server), with no terminal or Python process in between.

TLS is **rustls** only (no OpenSSL), so the crate builds for Android with the
NDK: `cargo ndk -t arm64-v8a --platform 26 check -p mt5_webterm`.

## Layers

`Client` is one connection and speaks the server's clock. `Session` is what a
host holds: it redials a stale or closed connection, backs off refused
logins, converts every time to UTC, loads full specifications for the
symbols in use and derives their tick value in the account currency.

## Verified against the native session

On 26 September 2026 one read-only web-terminal session and one native
session per demo account were compared record by record on the same
accounts.

| Area | Result |
|---|---|
| Deal history | 485 deals on two accounts matched on every field: ticket, order, position id, magic, deal type, entry (in, out, out-by), time to the millisecond, price, SL/TP, volume, profit and swap |
| Deal clock | Deal, candle and position times are the server clock; the account frame's offset (10800 s) equalled the native server time zone (180 min) |
| Specifications | `CMD_SYMBOL_INFO` (18) matched native contract size, tick size and value, volume min/max/step, currencies, calculation, trade and execution modes, filling and stop levels for 13 symbols with contract sizes 1, 100, 1000, 5000 and 100000 |
| USDX | 2,666 M1 candles matched the native bars exactly (OHLC and tick volume) on two accounts; the last quote arrives with tick statistics (17) on a closed market |

Not yet verified: the deal commission offset (commission was zero on every
deal compared), in/out reversal entries (a hedging account never produces
them), a nonzero daylight-saving mode, and quote timestamps of streamed
ticks (they carry the local receive time).
