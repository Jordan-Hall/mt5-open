# mt5-open

Rust clients and codecs for MetaTrader 5.

| Crate | Purpose | Verified support |
|---|---|---|
| `mt5-native` | Offline codecs for authentication, account records, quotes, history, depth and trade requests | Unit tests and protocol vectors |
| `mt5-session` | Native TCP account state, quotes, history and trading | Three Vantage demo accounts and one read-only Live 10 account, client 6182/server 5830, with locally computed challenge answers |
| `mt5-webterm` | Web-terminal sessions, quotes, history and trading | Existing demo-server support; broker lookup uses MetaQuotes' directory |

The native session does not require a running terminal or an external calculation
service. It requires a locally observed login profile. That profile matches both
challenge inputs by SHA-256 and rejects changed inputs or builds. The general
algorithms for arbitrary challenge inputs remain unimplemented. See
[`mt5-session/README.md`](mt5-session/README.md).

Native quotes, bar/deal history and a demo order lifecycle have been verified.
The desk adapter also passed a bounded demo trade lifecycle with balance and
margin comparisons. Broader execution and margin modes still need validation. See the detailed
[research matrix](NATIVE_RESEARCH.md). The web-terminal crate remains separate.

## Native login

```rust,no_run
let profile = mt5_session::LoginProfile::from_json(&profile_json)?;
let mut session = mt5_session::Session::connect(address)?;
session.authenticate(login, &password, profile.client_build)?;
let sync = session.synchronize(&profile)?;
println!("balance {}", sync.account.balance);
```

Enable `mt5-session/live` explicitly. The default build performs no native TCP
connections. Credentials and observed profiles belong in local configuration,
never in source control.

## Verification

```powershell
cargo test --locked -p mt5_native -p mt5_session --features mt5_session/live -j1
cargo test --locked -p mt5_webterm --lib -j1
```

Protocol vectors are included. `MT5_PROTOCOL_FIXTURES` optionally selects an
external fixture directory. Tests use synthetic credentials and loopback sockets.

This project is not affiliated with MetaQuotes. Native live verification included
bounded demo trades, three demo accounts and one real account used only for reads. This is limited observed
compatibility, not universal MT5 support. See [provenance](PROVENANCE.md) before redistribution.
