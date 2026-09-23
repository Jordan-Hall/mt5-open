# mt5-webterm (Rust)

Native MetaQuotes web-terminal client. WebSocket to `wss://host:443/terminal`.
No `terminal64`, no loginid. Server names resolve via SearchMQ; access ports
700–705 are rewritten to 443.

```powershell
# from transports/rust
$env:MT5_ACCOUNT=...; $env:MT5_PASSWORD=...; $env:MT5_SERVER=ExampleBroker-Demo
cargo run -p mt5_webterm --bin webterm-probe
```

gd-core: `CORE_TRANSPORT=webterm` plus the same three env vars. The engine then
talks to the broker in-process (phone or VPS), not through Python.

TLS is **rustls** only (no OpenSSL). Android NDK builds of `gd-core --lib`
include this crate: `cargo ndk -t arm64-v8a --platform 26 check --lib -p gd-core`.
