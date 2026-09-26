# Native codec status

The offline codec supports native authentication, synchronization, quotes,
subscriptions, depth, bar/tick history, order/deal records and signed trade
requests. Networking and account-state integration live in `mt5-session`.

Live demo checks established quote streaming, M1 history, deal history and a
pending/market order lifecycle for Vantage client 6182/server 5830. The native
challenge module now interprets arbitrary bounded programs for that client build;
other client versions and authentication methods remain unverified.

The old host-specific `orders` shim and standalone `intent` model were removed.
The desk owns durable execution intent and reconciliation; `trade` remains the
wire request codec and `records::TradeResult` separates order and deal tickets.

Tick history has live comparisons for daily/hourly columns and recent packed
ticks. Order records distinguish initial and remaining volume. Close-by arrays
are decoded and live-verified. Depth signed volumes match a fixed wire fixture;
an empty-book reset matches the broker. Certificate, OTP and nonempty depth
books remain outside complete live verification.

Bar history: replies for symbols with a gap inside the trading session (stock
CFDs) carry an empty run before the skip over the gap. It is skipped, and every
container of 33 live replies across eleven symbols then decoded to exactly its
declared bar count and bit length. Other inner compression flags and anchor
flag 4 still return explicit errors, as does a reply status other than the
ones listed in `bars.rs`.

Full evidence and open work are in [the session guide](../mt5-session/README.md)
and [the research matrix](../NATIVE_RESEARCH.md).
