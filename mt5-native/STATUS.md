# Status

`mt5_native` is a byte-in / byte-out codec for the MetaTrader 5 application
wire protocol (revision 3). It has no socket, no connection and no order-send
path: `LIVE_ENABLED` is `false`, and `ensure_live_allowed()` fails unless the
crate is deliberately built with `--features live`. Every test here is a
statement about bytes, checked offline against recorded conformance vectors.

Networking lives in `mt5-session`, which depends on this crate and is itself
off unless its `live` feature is on.

## Where it stands

1. Connect and stay connected — done.
2. Authenticate (MD5 challenge/response) — done against a demo server.
3. The derived values the server asks for after login (tags 28 and 35) — open.
   This is the part where help is most welcome; see `mt5-session`.

Nothing here should be pointed at a real-money account.
