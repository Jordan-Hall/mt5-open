# mt5-open

Experimental Rust clients and codecs for MetaTrader 5.

| Crate | Role | Boundary |
|---|---|---|
| `mt5-native` | Offline native wire codec, authentication, compression, reassembly, and record parsers | Fixture-tested; reconstructed rather than an official specification |
| `mt5-session` | Direct native TCP client behind the `live` feature | OTP/certificate continuation, local resolver integration, bounded sync transport; inner login derivation still unverified |
| `mt5-webterm` | Separate WebTerminal implementation | Not used by the native client |

## Direct native client

The native path connects to your broker's supplied native host and port. It does
not depend on the WebTerminal crate, a container, a terminal bridge, or a hosted
login-calculation service. `MT5_BUILD` must be chosen explicitly; no universal
compatible build is assumed.

```sh
cargo test --locked -p mt5_native
cargo test --locked -p mt5_session --features live
cargo run --locked -p mt5_session --features live --example auth_probe
```

The probe reads `MT5_ADDRESS`, `MT5_LOGIN`, `MT5_PASSWORD`, `MT5_BUILD`, and optional
`MT5_OTP`. It reports authentication structure without logging credentials and
stops before synchronization when there is no verified local derivation.

**The missing tag-28/tag-35 algorithms have not been implemented.**
`LoginIdResolver` permits a caller-owned, build-validated implementation; it is
not a substitute for that algorithm. The implemented wrapper is applied to the
current session challenge, with no guessed or zeroed fallback. See
[authentication details](mt5-native/AUTH.md) for implemented behavior, tests, and
remaining limitations, including full account/symbol synchronization parsing.

## Existing WebTerminal client

This remains a separate crate for existing users. Its server search now uses
only the first-party directory. The native client never calls this directory
and never rewrites a broker's native port to 443.

## Caution

Not affiliated with or endorsed by MetaQuotes. Review applicable broker and
software terms. Validate authorized demo sessions before considering live use.
Synthetic tests are not proof of broker interoperability or production readiness.
