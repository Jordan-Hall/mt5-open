# mt5-webterm

Experimental Rust client for a broker's `wss://host:443/terminal` endpoint.
No installed terminal or remote login-calculation service is required by this
WebTerminal transport. It is a different protocol from the desktop codec.

See the [workspace README](../README.md) for connection examples, TLS policy,
uncertain trade outcomes, offline validation and remaining limitations.

Probe binaries read `MT5_ACCOUNT`, `MT5_PASSWORD` and `MT5_SERVER` explicitly.
They are not run by CI. The order probe is read-only and never places or cancels
an order. Do not use probe output as a production certification.
