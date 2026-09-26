# Native sessions

`Session` owns TCP framing, authentication, directional ciphers and message
reassembly. `client::Client` maintains synchronized account state, subscriptions,
quotes and request/result correlation. `mt5-native` contains the offline codecs.

The native path connects directly to a broker. It has no web-terminal, HTTP
calculator, vendor DLL or running-terminal dependency. Build 6182 computes both
challenge programs locally. A connection profile supplies expected account/server
identity and compatibility metadata. It is not a complete replacement for terminal64.

## Verified behavior

Demo verification on 24–25 September 2026 used VantageMarkets-Demo, client build
6182 and server/record build 5830. Independent native sessions authenticated and
parsed the requested account, account terms and 1,230 symbols.

- Native EURUSD, XAUUSD and BTCUSD quotes reached the desk adapter.
- 17,242 M1 bars matched the official terminal's OHLC, volumes and spreads.
- 453 historical deals matched the official terminal's identifiers, execution
  prices, times, volumes, profit, commission, swap and comments.
- The native session submitted, modified and cancelled a demo pending order.
- The native session opened 0.02 EURUSD, modified SL/TP, closed 0.01, then closed
  the remainder. Authoritative updates reflected each position change.
- The desk adapter returned account state, quotes, 200 M5 bars and deal history.
  It also completed pending place/modify/cancel and market open/SLTP/partial/full
  close on a newly supplied demo account. Official comparisons matched order and
  position counts, balance and margin. Open-position equity differed by at most
  0.05 account-currency units as quotes moved between reads. Final equity and
  free margin matched, with no remaining exposure.

An early demo test confused a deal ticket with a position ticket. The broker
rejected the attempted modification/close; the probe recovered its own position
with the correct ticket. The decoder and request mapping were corrected. The last
verified terminal state after the native trade tests had no positions or orders.
The complete adapter lifecycle reduced that demo balance by 0.28 account-currency
units. These are demo results, not production or cross-broker certification.

The expanded SDK comparison verified 140,601 historical ticks, including sparse
price updates and recent packed ticks. Order-history checks caught and corrected
swapped initial/remaining volumes. All six pending types passed placement,
modification and cancellation with specified expiry. Buy/sell hedging and close-by
passed through the public client, including removal of both positions. These SDK
checks now include partial hedge closure and a close-by remainder. Margin
matched the comparison terminal at all 24 checkpoints. `Client::margin()` owns
the retail calculations used by the desk. Nonzero hedge/pending amounts and
larger-leg results still need broker validation; netting pending orders,
exchange portfolios and floating tiers remain unsupported.

## Authentication boundary

`mt5_native::challenge` interprets tag-28 and tag-35 programs for client build
6182. It computes fresh answers for each response; there is no captured-answer
lookup, challenge-hash enrollment, zero fallback or remote calculation service.
Both interpreters matched 2,048 generated composed programs each against the
isolated terminal. The shipped test corpus contains 1,280 synthetic reference
cases, including every instruction selector and the special tag-35 footer operand.

Profile JSON contains `client_build`, `server_build`, `environment`, and a required
`account` object with `login`, `mode` and the exact `server` name. Mode is `demo`,
`contest` or `real` and must be independently verified. Optional
`account.read_only: true` restricts the session to heartbeat, history and market
subscriptions. Old `f28`, `f35` and challenge-hash fields are rejected, not used.
Migrate local profiles by removing those four obsolete fields; keep the identity
and compatibility metadata. Profiles and credentials belong in ignored storage.

The login must match before dialing. The server response must contain exactly one
matching UTF-16 server name; missing, duplicate, malformed challenge programs and
unsupported client/server builds stop synchronization. The synchronized account
must match the requested login. A later account update for a different login
invalidates the session before any further request. Read-only broker updates
immediately restrict mutations. The desk also compares its configured server
with the profile before connecting or reconnecting.

These checks prevent a wrong challenge from silently selecting another account.
They do not determine whether a user intended to select a different, valid account
configuration. Challenge computation for other client versions, other brokers and
additional authentication methods still requires verification.

The server required the observed terminal environment metadata in tag 127. A
reduced application-identity string did not work. Certificate/OTP serializers
exist in the codec; their full socket flows and passkeys remain unimplemented.

## Read-only login checks

`MT5_ADDRESS` accepts comma-separated `host:port` or `[IPv6]:port` seeds. The
client learns public access points from authenticated synchronization; the desk
worker retains them across reconnects. A live fault test removed the bootstrap
and verified account identity and quotes after reconnection through an advertised
route. A failed authentication does not pin that endpoint as the preferred peer.

Set `MT5_ADDRESS`, `MT5_LOGIN`, `MT5_PASSWORD`, `MT5_SERVER` and `MT5_LOGIN_PROFILE` in the process
environment. `MT5_BUILD` defaults to the profile's client build.

```powershell
cargo run --locked -p mt5_session --features live --example auth_probe -j1 -- --json
```

The report distinguishes password acceptance, challenge computation, synchronization
and account/server identity. `--auth-only` explicitly stops before synchronization and
cannot prove that a usable account session exists.

`scripts/probe-native.ps1` reads an existing environment file using `-ConfigPath`,
`-LoginProfilePath` and `-Address`. `-Executable` selects a built probe.

For several explicitly selected accounts, create a local JSON manifest:

```json
{"accounts":[
  {"name":"demo-a","config_path":"a.env","profile_path":"a-profile.json","address":"broker-a:701"},
  {"name":"demo-b","config_path":"b.env","profile_path":"b-profile.json","address":"broker-b:701"}
]}
```

Paths are relative to the manifest. Each config supplies `MT5_LOGIN` or
`MT5_ACCOUNT`, plus `MT5_PASSWORD` and `MT5_SERVER`. Each child gets an isolated environment.

```powershell
py scripts/login-matrix.py .local/accounts.json --executable target/debug/examples/auth_probe.exe --output .local/login-results.json
```

The default is two rounds with at most two simultaneous sessions. A failed round
stops further attempts. Reports omit credentials, profiles and account numbers.
Passing twice with one account proves repeated sessions, not multiple accounts.
Use `--hold-seconds 300` to observe quotes and heartbeats for five minutes per
session. An observation window is not a guarantee of indefinite availability.

## Runtime behavior and limits

The client sends a keepalive after 10 seconds without a send, and the broker
answers it. On a closed market the answers arrived at most 20 seconds apart.
After 45 seconds with nothing received (`RECEIVE_DEADLINE`) the client fails
like any other broken connection, so a peer that vanished without closing
the socket is noticed rather than polled forever. A reconnecting host must
synchronize again and subscribe once; the desk adapter does both.

Authentication runs once per connection. Account readiness requires validated
synchronization and the requested login. TCP fragments survive idle polls;
decryption precedes decompression. Malformed incoming application state requires
a new connection and full synchronization.

`Session::account()` is the latest verified account record. `Client::state` receives subsequent
account, order, position and symbol updates. `Client::quotes` receives native
quote messages and can supply currency conversion routes.

History returns broker-clock seconds. The desk adapter converts them to UTC and
aggregates M1 bars using broker period boundaries. Unsupported inner history
compression and record variants return errors. `Client::orders` filters on
execution/cancellation time. `Client::ticks` returns broker-clock milliseconds,
retains duplicate timestamps and bounds requests to 31 days and one million ticks.
Cache continuation preserves the server's opaque tokens; status 14 still needs a
live comparison. Unknown column encodings are retained as opaque data.
`subscribe_depth` and `take_depth_updates` expose ordered wire deltas. The supplied
broker returned an empty-book reset, also observed in the terminal. A complete
book reducer is not yet verified.

Trade submission never retries after transmission begins. Request IDs correlate
responses; they do not make broker submission idempotent. Timeouts, disconnects
and partial fills require authoritative reconciliation. Result ordering, netting,
exchange execution and reconnect during execution need further broker testing.

See [research and remaining work](../NATIVE_RESEARCH.md) and
[provenance](../PROVENANCE.md). The running desk transport was not switched.

## Additional local probes

`history_probe` uses `MT5_FROM` and `MT5_TO` in broker-clock seconds, `MT5_SYMBOL`
and `MT5_PROBE_OUTPUT`. It reads orders, ticks and depth without sending trades.
`reconnect_probe` removes a bootstrap proxy and checks broker-route recovery.

`advanced_trade_probe` requires a bound demo profile, matching
`MT5_DEMO_TEST_LOGIN`, an empty account and a supervising process. Each checkpoint
writes a private snapshot and waits for `continue` on stdin. The supervisor must
verify the terminal and recover only the probe's marked exposure on failure.
It tests all pending types, specified expiry, hedge margin, partial closure,
close-by with unequal volumes and final closure. Broker timeouts require
reconciliation even when a pending order is already visible.
