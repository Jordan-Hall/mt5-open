# MT5 authentication and session establishment

A reference for the authentication path implemented (offline, inert) in this
crate. It describes how a client would establish an authenticated MT5 session
against a broker account it holds, mapped to the modules that build and parse
each message. **Nothing here is wired to a socket**; the crate is `DISABLED` by
policy (see [DISABLED.md](DISABLED.md)) and every function below is byte-in /
byte-out only. Going live is a separate, deliberate decision.

The existing wire primitives are compared with the local `mt5_protocol/`
revision-3 conformance vectors by [`tests/conformance.rs`](tests/conformance.rs).
New state-transition tests use synthetic replies, and certificate continuation
tests establish byte ordering and cipher continuity, not certificate validity.
The reference package is untracked; portable unit tests require no such package.

---

## 0. Driving the whole flow

[`handshake::Handshake`](src/handshake.rs) is a pure state machine that sequences
every step below and holds the derived keys — bytes in, bytes out, no I/O:

```
Init ─hello()─▶ HelloSent ─on_challenge()─▶ ChallengeReceived
     ─auth()─▶ AuthSent ─on_auth_result(status=0)─▶ SessionKeysReady
                       └─ status=1003 ─▶ CertificateRequired
                           └─ certificate_continuation() ─▶ SessionKeysReady
SessionKeysReady ─sync()─▶ SyncSent
Rejected status / malformed reply ─▶ Failed
```

`on_auth_result` validates status before deriving session and optional trade
keys. It processes repeated key tags in wire order and retains all ordered tags,
including 28/35, for the caller. `sync()` emits the session-encoded command-12
request once. `SyncSent` is not account readiness: there is no full incoming
account/symbol synchronization parser in this driver. Its
test drives the flow end to end, reproducing the `hello`/`auth` conformance
frames byte-for-byte and the documented session/trade keys, then round-tripping
the sync body through the session cipher. Steps out of order are rejected.
Failed sessions must be discarded. Missing tag 27 leaves the signing key absent.
`authentication_result()` contains sensitive material; use its `summary()` for
structural diagnostics instead of logging the original result.

## 1. The shape of the handshake

```
TCP connect
  → HELLO            command 0   (handshake cipher)      auth::make_hello
  ← challenge reply  32 bytes plaintext                  auth::parse_challenge
  → AUTH             command 1   (handshake cipher)      auth::make_auth
  ← auth result      44-byte head + TLVs                 auth::parse_auth_result
        ├─ TLV 7   → session key   (AES-128-CBC)          keys::derive_session_key*
        └─ TLV 27  → trade key     (SHA-256)              keys::derive_trade_key*
  → SYNC (cmd 12)    login values + tags (session cipher) login::make_sync_request
  ← sync stream      status + records (§9)                sync::SegmentedReader
  = account/session validation still required; not implemented by this driver
```

Two ciphers are in play and they are **not** the same (see
[`cipher`](src/cipher.rs)):

- **Handshake cipher** — a byte-feedback XOR stream whose feedback is the
  *ciphertext* byte and whose key index restarts at 0 for every message. Used
  for the HELLO and AUTH request bodies. `startup_encrypt` / `startup_decrypt`.
- **Session cipher** — a byte-feedback XOR stream whose feedback is the
  *plaintext* byte and whose key position **persists for the life of the
  connection** (state crosses packet boundaries, and an empty PING does not
  advance it). Used once the session key is derived. `SessionCipher`.

Framing is `<B i H H>` = command (u8), **signed** i32 length, sequence (u16),
flags (u16: `COMPRESSED=1`, `FINAL=2`) — see [`frame`](src/frame.rs).

---

## 2. Credential material

All in [`crypto`](src/crypto.rs), built on a parameterized MD5
([`md5`](src/md5.rs)):

| Value | Definition |
|---|---|
| `password_hash(login, pw)` | `MD5( u64le(login) ‖ utf16le(pw, first 16 code units) ‖ "M\0Q\0" )` |
| `challenge_response(login, pw, challenge)` | `MD5` of the 16-byte server challenge **continued from `password_hash` as the initial state** |
| `hardware_id(login)` | 256-byte LCG stream (`state = state*214013 + 2531011`) → `MD5`, then byte 0 replaced by the checksum of bytes 1..15 |

`utf16le(pw, 16)` truncates to 16 UTF-16 code units; a truncation that splits a
surrogate pair yields U+FFFD.

---

## 3. Request frames

### HELLO — command 0 (`auth::make_hello`)

34-byte handshake-enciphered payload:

```
u8  nonce_byte
u8  0
u16 build
u16 0x514D                 ("MQ")
u64 login
[16] device_id            defaults to hardware_id(login)
u32 random_word
```

### AUTH — command 1 (`auth::make_auth`)

Handshake-enciphered payload:

```
u16 nonce_word
[16] challenge_response(login, pw, challenge)
[16] client_challenge
( optional TLV 18: OTP, enciphered under
  MD5(password_hash ‖ challenge ‖ OTP_SALT ‖ 0x00) )
```

The 44-byte auth-result head and its trailing TLVs are parsed by
`auth::parse_auth_result`; the plaintext 32-byte challenge reply by
`auth::parse_challenge`.

---

## 4. Key derivation ([`keys`](src/keys.rs))

Both consume the 16-byte credential digest (the password hash):

- **Session key** (from auth-result **TLV 7**): AES-128-CBC encrypt of the
  zero-padded TLV value, key = digest, IV = zero, no padding.
  `derive_session_key_from_digest`.
- **Trade key** (from **TLV 27**): `SHA-256( startup_decrypt(tag27, digest) ‖
  digest )` → the 32-byte HMAC key used to sign trade requests.
  `derive_trade_key_from_digest`.

After this point, frames use the session cipher.

---

## 5. Command-12 synchronization login ([`login`](src/login.rs))

The initial synchronization request (command 12) is an **ordered TLV list with
no leading count** (`login::make_sync_request`). It carries, among fixed tags,
tag 88 (and, in the modern profile, tag 134) derived from the **login-value
wrapper**. In the modern profile it also carries tag 127, whose environment
metadata is generated deterministically from the device id and client build by
[`metadata`](src/metadata.rs) — the tab-separated `key=value` string, with the
computer name produced by the fully specified §8.2 legacy subtractive PRNG
(seeded from the first four hardware-id bytes). This has no conformance fixture
(the sample request is non-modern); the PRNG is cross-checked against a reference
port and the output is deterministic.

`login::login_value_wrapper` combines the external `F28`/`F35` results into
`login_id`, `extended_login_id`, and the two tag values by the documented mod-2⁶⁴
arithmetic (constants `K`, `J`; the server challenge and builds mix in). Verified
against the `login_value_wrapper_only` fixture.

### The completion boundary — F28 / F35

`F28` and `F35` are **external HTTP calculations**, not present in the analyzed
executable. This crate implements only the request/response **adapter contract**
(`subscription::additional_login_http_contract`: POST target, the
`loginidnew5`-prefixed Base64 body for modern builds, `application/text`, decimal
integer response) and treats the returned integers as **inputs** to the wrapper.
Their inner mappings are not defined here, and no value for them is invented,
zeroed, or substituted. A self-contained login for a path that requires them
still needs those definitions and an equivalent permitted calculation service.

The certificate-continuation path (command 2) is provisioning-driven: the
PFX/private key are external inputs, not embedded enrollment. On status 1003,
`certificate_challenge()` exposes the original challenge for an external signer.
`certificate_continuation()` takes that signer's RSA PKCS#1 v1.5 SHA-1 signature
and DER certificate, reverses the signature for the wire, and sends the encoded
command-2 body before command 12 on the same TX cipher. These functions do not
parse PFX, perform RSA signing or validate certificate ownership. Empty inputs
are rejected before cipher state changes. The covered profile does not require
a command-2 acknowledgement before command 12. Modern sync requests generate
environment metadata when no explicit override is supplied.

---

## 6. What is proven, and what is not

**Proven offline** (conformance vectors, byte-for-byte unless noted):
`hello_frame`, `authentication_frame` (with and without OTP), the plaintext
challenge/result parsers, `credential_digest_and_challenge_response`,
`deterministic_hardware_id`, `password_truncation_and_hash`, both
`session_key_derivation` and `trade_key_derivation`, `startup_transform`, the
stateful multi-frame session-cipher continuity, `synchronization_request`, and
`login_value_wrapper_only`.

**Not established** (and deliberately not faked): the inner `F28`/`F35`
functions; live-server acceptance of any authentication profile; certificate
enrollment; and whether a given server requires the additional login TLVs. A
passing offline round trip is not a successful session — see the
`IMPLEMENTATION_GAPS.md` in the spec package.

**Policy:** the crate stays inert. `ensure_live_allowed()` hard-fails and both
policy tests assert the disabled state; there is no socket in the tree. Any
future live use must additionally pass the host application's demo reconciliation /
idempotency / uncertainty / risk / soak gates.

## 7. Research update — 18 September 2026

The operator identified **the MTAPI trial** as the source of the local reference.
This is a reconstructed client profile, not an official MetaQuotes wire
specification. [MTAPI's product description](https://mtapi.online/product/mt5-net-client-api-binaries/)
says its trial uses vendor servers for trial checks and its full version can be
independent. [Its published FAQ](https://mtapi.online/) makes the same distinction.
That supports investigating a vendor dependency; it does **not** establish that
F28/F35 are merely removable license checks, or that their outputs can be omitted
from the MT5 wire. The local reference describes outputs incorporated into sync
fields, so a guessed constant is not a substitute for an established mapping.

Public documentation and the supplied reference do not provide either inner
mapping. The native hello/password response, OTP payload, key derivation and
certificate-continuation serialization are testable now. Independent F28/F35
implementation still needs an algorithm or independent input/output evidence for
the appropriate server/client builds. A licensed implementation with the needed
rights is one possible source of that evidence; no purchase or service access was
performed. The vendor's statements do not establish license terms for porting.

MetaQuotes documents [certificate authentication](https://www.metatrader5.com/en/terminal/help/start_advanced/extended_authorization)
and [OTP as an additional account factor](https://www.metatrader5.com/en/terminal/help/start_advanced/otp).
Its [build 6060 release notes](https://www.metatrader5.com/en/releasenotes/terminal/2447)
also describe broker-enabled passkeys as an additional factor. This reconstructed
profile does not implement passkeys, and unknown authentication statuses fail
instead of being interpreted as successful password authentication.

### Offline tools and checks

From `transports/rust`:

```powershell
cargo test --locked -p mt5_native --lib -j1
# Optional: the independently supplied reference package is required for these.
$env:MT5_PROTOCOL_FIXTURES = 'C:/path/to/mt5_protocol'
cargo test --locked -p mt5_native --test conformance -j1
# Input is a startup-decoded command-1 body, not a TCP capture or encrypted frame.
cargo run --locked -p mt5_native --example auth_inspect -- C:/path/to/auth-result.bin
# Or inspect one complete, uncompressed command-1 wire frame:
cargo run --locked -p mt5_native --example auth_inspect -- --frame C:/path/to/auth-frame.bin
```

The inspector prints only status, server/record builds, certificate requirement,
and ordered tag IDs/lengths. No passwords, challenge bytes, tag values, session
keys or trading keys are printed. It rejects files above the frame-size limit.
`--frame` performs startup decoding and rejects unrelated, compressed, partial,
or multiple frames. It is not a PCAP reader or a TCP stream reassembler.
Input captures themselves may contain secrets and must remain local. No broker
or auxiliary HTTP endpoint is contacted by this tool or its tests.

### Evidence still required for a specific broker

The exact server/build and authentication profile are unverified. A
permitted demo session must establish the requested factors and tag presence,
then successful synchronization and account identity. The inspector can summarize
an available decoded reply, but does not obtain one or prove acceptance. Nonces
and client challenges in any real transport must come from a cryptographically
secure random source; fixture constants are for offline tests only. Connection
management, separate receive-cipher state, complete sync parsing, reconciliation
and broker execution remain outside this authentication patch.

### Validation of this change

87 unit tests, 7 external-fixture conformance tests and 2 inspector tests passed.
The inspector was also run on a synthetic decoded result and printed only its
structural summary. `cargo check --locked -p mt5_native --lib --target
aarch64-linux-android -j1` passed. The conformance package was supplied locally
through `MT5_PROTOCOL_FIXTURES`; it has not been added to version control. These
checks establish offline behavior and cross-compilation, not broker acceptance.
