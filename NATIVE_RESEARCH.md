# Native MT5 research and verification

Research checked 25 September 2026. The target is a client speaking the desktop
terminal's broker protocol directly. A local terminal bridge, WebSocket client or
broker Manager API does not satisfy that target merely because it uses TCP.

## Current coverage

| Area | Evidence in this workspace | Remaining work |
|---|---|---|
| Password, LoginId and synchronization | Three Vantage demo accounts and one real account on Live 10 passed simultaneous native synchronization and quotes; account and exact server identity checked | Other brokers/builds, compatibility metadata and additional authentication methods |
| Account and symbols | Balance/credit/leverage comparison; account terms and 1,230 symbols parsed | Broader record versions; complete dynamic broker/group configuration |
| Quotes | Native commands 50/51; EURUSD/XAUUSD/BTCUSD delivered through desk; conversion subscriptions and live reconnection through an advertised access point | Quote clearing, stale conversion rates and session transitions |
| Bars | 17,242 M1 bars matched terminal fields; desk returned 200 M5 bars, with 199 closed bars matching and the forming bar changing between reads; stock-CFD replies with in-session gaps now decode (33 live replies, eleven symbols, every container exact to its declared count and bit length); USDX M1 matched the web terminal on 2,666 bars | Other inner compression flags; long-range gaps, DST transitions and other brokers |
| Order/deal history | 453 historical deals matched terminal fields; native order-history client added with completion-time filtering and corrected initial/remaining volumes | Older schemas, corrections and large history ranges |
| Trading | Desk adapter passed pending/market/SLTP/partial/full close; SDK also passed all six pending types with specified expiry, buy/sell hedge and close-by at 24 terminal checkpoints, including an unequal hedge and close-by remainder | Netting, exchange flows, expiry execution and disconnect during submission |
| Updates | Execution and position records separated; close-by additional execution and position arrays handled and live-verified | Reversed event ordering, other collection variants, corrections and reconnect mid-trade |
| Margin and profit | Retail hedge methods and pending-order formulas implemented; broker margin matched at 24 demo checkpoints; larger-leg wire flag isolated using custom symbols | Nonzero hedged/pending margin and larger-leg broker comparisons; netting, exchange, floating tiers, spread discounts and component rounding need validation |
| Recovery | Broker access-point discovery, DNS/multiple bootstrap endpoints, retained routes and bounded dial attempts; bootstrap removal test reauthenticated and resumed quotes; 45 s receive deadline catches a silent peer; 31-minute soak through a fault proxy with two cuts and a blackhole: quotes resumed within 9 s of a cut and 50 s of a blackhole, one subscription per connection, no trade frames | Fault tests with execution in flight, persistent routing cache and broader reconciliation |
| Additional authentication | Certificate and OTP codecs present | Socket integration, enrollment, passkeys and independent test accounts |
| Tick history | Daily columns, hourly batches and recent packed ticks; public range API matched 140,601 terminal ticks in order, timestamps, flags and prices within 1e-12 | Live continuation status 14, nonzero exchange volumes and additional metadata encodings |
| Depth | Subscription and ordered delta API; signed-magnitude volume corrected against a wire fixture; empty-book reset matched the terminal | Nonempty broker books, reset/merge semantics and exchange liquidity |

The original terminal temporarily reported `Invalid account`. It later logged in
again. The shared terminal was also being returned to the original login by a
running bridge, so verification moved to an isolated terminal instance. Both new
accounts independently verified as demo and passed full native synchronization.

One broker access point timed out before TCP connection on repeat attempts. Using
the access point observed in the connected official terminal, both accounts
completed two 60-second quote sessions. These failures occurred before password
authentication; they do not establish a short-lived LoginId. Synchronization now
retains advertised access points. A live test removed a loopback bootstrap, then
reauthenticated through an advertised route and resumed quotes.
The adapter trade test then passed on the latest
demo account, ending with no positions or orders and a 0.28 demo balance decrease.

Both new accounts then completed simultaneous five-minute native sessions,
receiving 189 and 190 quote records. No authentication loss occurred in those
windows. The isolated comparison terminal was closed during that observation;
native sessions continued independently. This does not establish indefinite
session lifetime or support for changed server challenges.

The earlier baseline passed 103 native/session tests, 22 desk transport tests,
seven existing web-terminal tests and an Android ARM64 native-session check.
The expanded codec/session suite passes 115 tests. The latest desk adapter lifecycle again matched
balance and margin at all checkpoints; transient equity differed by at most 0.01.
Both additional demos also passed two fresh logins through DNS bootstrap routes.
Latest checks passed 115 native/session tests, 23 desk transport tests and the
Android ARM64 native-session build. The final demo account had zero orders and
positions. The original terminal, bridge and desk processes remained running.
Credential files, bound profiles and detailed local captures remain ignored.

## Four-account and margin verification

The fourth account was independently identified as real, zero balance, retail
hedging on VantageMarkets-Live 10. It supplied different tag-28/tag-35 challenges
from the demo server: 984/696 bytes versus 624/456 bytes. Its separate enrolled
profile completed two simultaneous 30-second sessions alongside all three demos.
After adding exact server binding and read-only enforcement, all four passed a
further simultaneous 15-second check. No live trading request was sent.

The live profile rejects trade, password-change and unknown commands before
transmission. Server-name matching requires exactly one matching UTF-16 field;
wrong or missing names and different logins fail closed. The original runs used
exact challenge hashes and cached answers. Those have now been replaced by the
interpreters described below; other broker modes still need verification.

An isolated custom-symbol experiment changed only SYMBOL_MARGIN_HEDGED_USE_LEG.
Comparing native records identified bit 4 at group offset 832. The SDK now owns
retail margin calculations; the desk no longer duplicates these formulas.
The supervised demo test matched native and official margin at all 24 checkpoints:
4.30 with a 0.02-lot buy, 0.00 with an equal hedge, 2.15 after partial closure,
2.15 with the close-by remainder, then 0.00 after closing it. The account ended
with zero orders and positions. Demo balance changed by 0.33 in this sequence.
All pending order ratios and hedged margin on this broker were zero, so that test
does not establish nonzero pending or covered-margin parity.

An earlier pending submission timed out after broker acceptance. The supervisor
found and cancelled that exact test order through the comparison terminal. The
native client did not resubmit it. A later instrumented run confirmed correctly
correlated acknowledgements, including delayed final results. The original
missed confirmation's cause is not established; reconciliation remains necessary.
The isolated terminal's Algo Trading toggle had also been reset after restart;
the supervisor now requires it to be enabled before starting a trading test.

The native/session suite passes 122 tests after the margin and profile changes.
The desk transport suite passes 23 tests, and the native session passes an Android
ARM64 compile check. The saved desk manifest also passed a final simultaneous
30-second login/quote run: 40 quote records per demo and 57 on the read-only
live account.
Private captures and enrolled profiles remain ignored; terminal binaries and
instrumentation output are not runtime dependencies or distributed code.

## Computed challenges and account isolation

The build-6182 tag-28 and tag-35 interpreters now compute each response without
cached answers. Local calculator comparisons matched 2,048 composed programs
per interpreter and all 256 instruction selectors per interpreter. Arithmetic
comparisons covered 405 cases per interpreter. One tag-35 footer selector treats
its left operand as zero; all 256 selectors on both footer operands were checked.
The runtime is ordinary bounded Rust arithmetic. No terminal code, instrumented
process, binary blob or reference-output table is part of authentication.

All four supplied accounts passed simultaneous computed-challenge authentication,
identity verification and 15 seconds of quotes. A second round passed on all three
demos; the live bootstrap TCP connection timed out before authentication. A
subsequent read-only fault test authenticated the live account, removed its local
bootstrap proxy, then reauthenticated through a broker-advertised route and
verified quotes in 2.44 seconds. No orders were sent in these login tests.

The native/session suite now passes 130 tests, including account-change and
read-only-update refusal. The Android ARM64 session check and all 24 desk transport tests also pass.

The shipped conformance corpus contains 1,280 synthetic reference cases. Profile
identity is mandatory. Wrong login/server configuration is rejected, and a
foreign account update invalidates the session. Local fake-broker tests check
that no request follows an identity mismatch or read-only restriction.

## Web terminal parity, stock-CFD bars and fault soak, 26 September

One read-only web-terminal session and one native session per demo account
were compared record by record. 485 web-terminal deals on two accounts
matched native deal history on every field, including position id, magic,
deal type and entry (in, out and out-by), with times on the server clock.
Full web-terminal symbol records (command 18) matched native contract size,
tick size and value, volume limits, currencies and trade modes for 13
symbols with five contract sizes. Through the desk adapters, tick values in
the account currency agreed to six decimals for eight symbols, including
JPY-quoted pairs converted to GBP.

USDX: native M1 history loaded (2,666 bars over three days) and matched the
web terminal's candles exactly. On the weekend both transports returned the
Friday-close quote (100.758/100.793, 23:59:59 server time); live streaming
of USDX awaits an open market.

Stock-CFD bar replies (DXC, DXYZ) failed with "bar run exceeds declared
count". They carry an empty run before the skip over an in-session gap;
skipping it decodes all 33 dumped replies exactly.

A closed-market session showed keepalive answers at most 20 seconds apart;
the client now fails after 45 seconds of silence. The desk adapter soaked
for 31 minutes on a demo account through a local proxy that cut the
connection at 300 s and 1200 s and blackholed it at 720 s: 2,789 crypto
quotes, 124 of 124 snapshots, the quote stream open throughout, gaps of
6.1 s and 8.7 s after the cuts and 50.2 s across the blackhole (45 s to
detect it), one subscription per connection despite a resubscribe request
every second, and no trade frame sent. No silence was reported outside the
blackhole.

## Sources that help

MetaQuotes documents execution semantics without documenting the desktop wire
challenge algorithm. Its [OrderSend reference](https://www.mql5.com/en/docs/trading/ordersend)
distinguishes acceptance from execution. [Trade transaction documentation](https://www.mql5.com/en/docs/event_handlers/ontradetransaction)
warns that event arrival order is not guaranteed. These support separate request,
order, deal and position identifiers, plus reconciliation after uncertainty.

[OrderCheck](https://www.mql5.com/en/docs/trading/ordercheck) provides an official
behavior reference for pre-trade funds checks; the native adapter does not yet
implement an equivalent broker-validated check. [Margin documentation](https://www.metatrader5.com/en/terminal/help/trading_advanced/margin_forex)
describes instrument formulas, fixed-margin leverage, currency conversion,
pending orders and both hedging methods. The SDK calculates both retail hedge methods, including weighted prices, currency
rates and pending orders. The desk calls the same implementation. Unknown flags
and unimplemented portfolio models return errors. Nonzero hedge and pending
amounts, component rounding and larger-leg results still need broker comparisons.

[CopyTicksRange](https://www.mql5.com/en/docs/series/copyticksrange) specifies tick
range and flag semantics used in the native comparison. Sparse prices are carried
forward; distinct ticks sharing a timestamp are preserved. [2FA/TOTP documentation](https://www.metatrader5.com/en/terminal/help/start_advanced/otp)
establishes that some accounts need an additional code on each connection.
[Platform startup documentation](https://www.metatrader5.com/en/terminal/help/start_advanced/start)
describes certificate-related terminal configuration. Password-only success is
therefore insufficient evidence for all account types.

## External implementation search

| Source | What its primary documentation/source shows | Use for this project |
|---|---|---|
| [mtapi.online](https://mtapi.online/) and [source product](https://mtapi.online/product/mt5-net-client-api-sources/) | Commercial provider advertises direct terminal-protocol emulation and source licensing | Potential licensed reference, not adopted; marketing is not a compatibility test |
| [Provider trial/trading example](https://mtapi.online/2018/09/19/mt5-order-send-async/) | Trading is disabled in the trial | Trial availability does not supply an independently usable complete trading client |
| [Provider class documentation](https://www.mtapi.online/mt5-api-doc/html/2c8b6e85-82b9-0af0-992e-bddaf69d322b.htm) | Quotes, history, order updates and margin-related methods | Helps enumerate intended API behavior, not recover the general challenge algorithm |
| [go-mt5](https://github.com/mukbeast4/go-mt5) | Windows terminal IPC | Possible comparison tool; requires terminal |
| [metatrader-terminal](https://github.com/nodalytics/metatrader-terminal) | Terminal/Wine integration | Operational reference; requires terminal |
| [MT5WebAPIGO](https://github.com/iamocap/MT5WebAPIGO) | Manager Web API with dealer/admin operations | Different authentication and permission model |
| [fnklabs/mt5-client](https://github.com/fnklabs/mt5-client) | Calls itself RAW API, but [command source](https://github.com/fnklabs/mt5-client/blob/master/mt5-client-raw/src/main/java/com/fnklabs/mt5/client/Command.java) uses textual RETCODE/CLI_RAND_ANSWER commands | Does not provide the terminal64 binary login challenge flow |
| [mt5_api bridge](https://github.com/huy-bui-tech/mt5_api) | Python socket server with MT5 EA client | Useful feature comparison; requires terminal/EA |

No reviewed public repository supplied a verified, general native F28/F35 solver
or a complete replacement satisfying this project's requirements. This describes
the search result, not proof that no such implementation exists. No discovered
WebSocket or Manager API code was added to the native path.

## Verification sequence

1. Extend `scripts/login-matrix.py` checks to other brokers/builds and longer
   observation windows. Keep password, profile, synchronization and identity
   results separate. Extend the passed access-point fault test to mid-session failures.
2. Extend the passed desk-adapter lifecycle comparison to unsupported execution
   and margin cases, using official terminal checkpoints.
3. Exercise supported order variants and fault cases on demo, including delayed
   results, disconnect after send, reconnection and subscription recovery.
4. Expand observed schemas and authentication support only with matching evidence.
   Keep unsupported cases explicit. Resolve inherited provenance before publishing.

The code supports `CORE_TRANSPORT=mt5-native`, comma-separated `MT5_ADDRESS`
seeds, `MT5_LOGIN` or `MT5_ACCOUNT`, and `MT5_LOGIN_PROFILE`. History pagination
has its own module. The worker uses one reconnection path for requests and quotes.
No hosted API or web-terminal dependency was added to the native implementation.

The running desk has not been switched to this native adapter. Local verification
uses the official terminal as a comparison tool; it is not a dependency of native
broker sessions.
