# mt5-open

Rust libraries for MT5 broker protocols, without an installed trading terminal.

| Crate | Purpose | Evidence boundary |
|---|---|---|
| `mt5-webterm` | WebSocket client, official-directory discovery, account snapshots, quotes, history and trade requests | Experimental reconstructed layouts; offline transport/parser tests. Broker interoperability must be established for each deployment. |
| `mt5-native` | Networking-free desktop-protocol codec | Synthetic revision-3 conformance tests. |
| `mt5-session` | Optional desktop-protocol TCP transport | `live` feature required. Additional-login calculations for records 28/35 remain unimplemented. |

## Connect

```rust,no_run
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let session = mt5_webterm::Session::new(
    12345678,
    std::env::var("MT5_PASSWORD")?,
    "ExampleBroker-Demo".into(),
);
let snapshot = session.snapshot().await?;
println!("balance {} equity {}", snapshot.account.balance, snapshot.account.equity);
# Ok(())
# }
```

Discovery contacts only the MetaQuotes HTTPS directory. `Client::connect_via`
accepts an explicit broker endpoint and bypasses discovery. Published desktop
access points are WebTerminal **candidates**, not proof of support.

TLS verifies the certificate chain, hostname and handshake signatures by default.
Use the broker's certificate-matching DNS name. For private CAs, build a verified
`rustls::ClientConfig` and pass it to `Client::connect_via_with_tls`; do not disable
certificate verification. No built-in accept-any verifier is provided.

## Session behaviour

One task owns each WebSocket and serializes requests because command IDs are not
unique correlation IDs. A request that is cancelled or times out after sending
invalidates that connection, preventing a late reply from satisfying a subsequent
request. The last client handle shuts down the owner task and heartbeats.

Quotes use a precomputed symbol index and change notifications, not periodic
polling. The stream reports latest cached changes, not a lossless tick archive;
lagging consumers can miss intermediate ticks. Stale quotes are not used for
market requests. Account errors are not replaced with empty positions or zero
balances. Positions and pending orders share a single book request.

An uncertain trade response is reported as `SessionError::Uncertain`. Never retry
such a request without reconciliation. Missing tickets are left unresolved,
not guessed from unrelated changes to the account. Volume limits and several
record fields still need independently verified broker-specific schemas; see
[REVIEW.md](REVIEW.md).

## Native authentication

The desktop socket accepts a caller-supplied `LoginIdResolver` that executes
locally. `UnsupportedLoginResolver` fails explicitly. There is no built-in HTTP
calculation adapter, external licensing key or invented modern solver.
The `auth_probe` example stops at authentication diagnostics; it does not replace
required additional-login values with zero.

## Validate offline

```sh
cargo test --workspace --locked
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked
cargo run --release -p mt5_native --example bitpack_bench --locked
cargo run --release -p mt5_webterm --example quote_bench --locked
```

Tests and benchmarks do not need credentials or a broker. Probe binaries require
explicit credentials and are not run by CI. `webterm-order-probe` is now read-only;
it is a book-readiness diagnostic, not an automatic order-placement experiment.

The network stack uses rustls without OpenSSL. Android cross-compilation and live
multi-broker behaviour were not validated by this review.

## Caution

This project is not affiliated with MetaQuotes. Protocol descriptions are
reconstructed, not official specifications. Establish provenance and reuse rights
for any third-party reference material. Test with accounts you are authorized to
use, starting with demos; these changes are not a production-trading certification.
