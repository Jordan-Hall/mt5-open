# Protocol and session review

Review base: `d7da63729994cacc43ba7479669bb709a37ec2d2`.
Scope: the three workspace crates, their transport/codec/trading interfaces,
fixtures, probe binaries, manifests and documentation. Static inspection and
credential-free CI were performed; this is not an exhaustive security audit or
a certification of live broker compatibility.

## Fixed in this PR

| Area | Finding and change |
|---|---|
| External dependencies | Removed the third-party broker-directory fallback, HTTP additional-login adapter, its service-key interface and optional `ureq` dependency. Removed the now-unused HTTP-envelope codec and its three fixtures, retaining the MT5 wire fixtures and integrity checks. |
| TLS | Replaced acceptance of arbitrary certificates and handshake signatures with cached public-PKI verification. Explicit `connect_via_with_tls` supports a caller-configured private CA without adding an accept-any switch. |
| WebSocket ownership | A single task now owns the socket. A bounded request queue serializes RPCs because command IDs are not unique correlation IDs. Dropping the final client aborts the socket owner and heartbeat. |
| Cancellation | A cancelled or timed-out request after transmission invalidates the connection; a late reply cannot satisfy the next same-command request. |
| Parser safety | Validate outer lengths, version and CBC alignment before slicing. Account, symbol, deal and book decoders check complete records; counts are checked before allocation. DEFLATE rejects truncation, trailing bytes and excess output. |
| Native state | General authentication-challenge access is separate from certificate-only access. Operating-system entropy replaces time-derived nonces. Startup command/flags, socket deadlines, synchronization size/fragments and state transitions are checked. |
| Trading correctness | Nonzero response statuses are errors, absent trade results are uncertain, and retcode zero is not an execution success. Missing tickets are not inferred from unrelated account changes. Session writes are serialized and never automatically retried. |
| Account data | Preserve reported zero equity rather than inventing balance-based equity. Read positions and pending orders from one reply and propagate errors rather than returning empty success. |
| Quote path | Build symbol routing and price scales once. Replace 200 ms polling with notifications. Cache freshness is tracked independently for bid and ask, so one side cannot keep the other side artificially fresh. |
| Performance and bounds | Byte-chunk bit packing replaces per-bit processing. Fix `BitWriter::default()` radix zero, which could loop indefinitely. Session ciphers avoid modulo per byte and preserve phase on counter overflow. Reassembly shares an aggregate memory budget and limits empty fragments. Segmented reads copy chunks and reject oversized reads before consuming state or allocating. |
| Discovery and diagnostics | Pool and bound the official HTTPS directory client, encode form parameters safely and normalize IPv6 endpoints. Published access points remain candidates, not support guarantees. The order probe is read-only; no diagnostic places or cancels orders. |

## Remaining blockers and risks

**Native desktop authentication is still incomplete.** The modern inner mappings
for additional-login records 28 and 35 are not implemented. `LoginIdResolver`
is an in-process extension point, not a solver; `UnsupportedLoginResolver`
returns an explicit error. No guessed zero, cached answer or remote fallback
is supplied. See [AUTH.md](mt5-native/AUTH.md).

**Wire layouts need broker-specific verification.** The WebTerminal and desktop
codecs are different reconstructed protocols. Symbol contract and volume
constraints are unknown rather than guessed; tick-size equivalence to point
size is not universally established. Some pending-order/deal fields remain
unmapped, including timestamps and pending-order protection fields. The existing
pending-order volume width and numeric validation across all record types need
further independent fixtures. High-level native close/modify serialization also
needs end-to-end verification before execution use.

**Uncertain execution requires reconciliation.** A socket write followed by a
lost acknowledgement cannot establish whether a broker executed an order.
`SessionError::Uncertain` and absent receipt tickets are not retry permission.
The intent model is not durable exactly-once execution. Low-level raw-frame and
trade-record APIs remain the caller's responsibility.

**Transport limits are not full operational guarantees.** Native DNS resolution
is blocking and currently selects the first resolved address. Per-frame limits
do not create one wall-clock deadline across every multi-frame operation.
Compressed startup/synchronization variants are explicitly unsupported in the
socket path rather than incorrectly decoded. Quote notifications expose latest
cached changes, not a lossless tick archive; timestamps/freshness reflect local
receipt, not an independently verified exchange clock. Application secrets are
not guaranteed to be zeroized across all copies and lifetimes.

No live login, order, broker-wide compatibility matrix, Android cross-build,
long-running reconnect soak, passkey flow, certificate enrollment, full fuzz
campaign or external penetration test was performed. Private/self-signed broker
certificates now need an explicitly trusted CA and matching hostname. Removing
runtime dependencies does not establish reuse rights for reference material;
no licence or copyright notice is removed and Git history is preserved.

## Migration

Replace the removed network resolver with a verified local `LoginIdResolver`.
Handle the new `SessionError::Uncertain` case. Use certificate-matching broker
DNS names or an explicit verified TLS configuration. Do not depend on guessed
symbol constraints, synthesized equity, automatic ticket recovery, or the old
order probe's side effects. Legacy lenient parsing helpers remain for API
compatibility; network-facing client paths use strict `try_parse_*` functions.

## Validation and measurements

CI runs default and all-feature workspace tests with `--locked`, Clippy for all
targets/features and two release-mode synthetic benchmarks. Tests use byte
fixtures and in-memory mock sockets, not broker credentials. The fixture count
changes only because three removed service-envelope cases are not MT5 wire
conformance cases.

The completed [benchmark run](https://github.com/Jordan-Hall/mt5-open/actions/runs/36071508932)
for commit `38d28c6ce57df8dede7311ecba781576939bfad5` measured:

| CPU-only workload, median of five | Reference | Improved | Ratio |
|---|---:|---:|---:|
| Bit-field reads | 7.340 ms | 2.069 ms | 3.55x |
| Quote decode, 512 symbols / 64 ticks | 24.423 ms | 7.230 ms | 3.38x |

These are same-run microbenchmarks, not broker latency, throughput guarantees or
an end-to-end comparison with any commercial product. Clippy completed with
style warnings; it was not run as a warning-free gate. The PR checks are the
source of truth for the final commit. No test success is a trading certification.
