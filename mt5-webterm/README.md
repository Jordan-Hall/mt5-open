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
