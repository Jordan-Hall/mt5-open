# Native authentication

`mt5_native` is a byte-in/byte-out codec. `mt5_session`, with its explicit
`live` feature, connects directly to a broker-provided native TCP host and port.
Neither needs a terminal, WebTerminal, container, nor hosted login service.
This is an experimental reconstructed profile, not an official wire specification.

## Implemented flow

1. `Session::connect` resolves the supplied native address and attempts its
   resolved addresses within a connect deadline. It does not discover brokers
   through any directory. DNS lookup itself is synchronous.
2. `authenticate_with_otp` obtains client nonces and the client challenge from
   the operating system through `getrandom`, sends command 0, parses the server
   challenge, and sends command 1. An optional OTP is encoded as tag 18.
3. The transport validates startup command/sequence and requires a final,
   uncompressed startup reply. Other startup profiles are explicitly rejected.
   The codec derives session keys from tag 7 and an optional trade key from
   tag 27. A structural `AuthSummary` remains available after a parsed rejection;
   it contains status, builds, and tag lengths, not credentials or raw material.
4. Status 1003 requires a provisioned certificate. `certificate_challenge`
   exposes the bytes to sign. `certificate_continuation` sends the caller's
   RSA PKCS#1 v1.5 SHA-1 signature and DER certificate as command 2. The signature
   is reversed for the wire. This does not perform signing, key enrollment,
   PFX parsing, certificate validation, or passkey authentication. The covered
   profile sends command 12 next without a command-2 acknowledgement.
5. `login_context` exposes the authenticated connection's challenge and ordered
   tags to a caller-owned `LoginIdResolver`. Unlike the certificate accessor,
   this accessor works in the normal session-keys-ready state. The resolver
   supplies F28/F35 results, and the existing wrapper derives the command-12
   values. `synchronize_with` sends them on this same connection.
6. Incoming session frames are decrypted in order with a persistent RX cipher,
   decompressed when flagged, and reassembled by sequence. Interleaved complete
   messages are bounded and retained while waiting for the matching sync reply.
   Nonzero sync status is an error that closes the session. Account updates
   are matched to the authenticated account rather than taking the first record.

A status-zero sync reply is not full account readiness. The full command-12
account/symbol stream parser remains incomplete; `read_account_state` reads the
separate command-55 subtype-19 update profile. No broker acceptance has been
established by these tests. The low-level raw `send` API can send arbitrary
frames and must not be confused with an execution safety boundary.

## The remaining LoginId boundary

The numeric account login belongs to the broker account. The separate
`LoginValues.login_id` and `extended_login_id` are fields in the reconstructed
command-12 profile, not account numbers or independently discoverable tokens.
The wrapper is implemented and fixture-tested, including build thresholds 4852
and 5409. The inner mappings from opaque tag-28/tag-35 inputs to F28/F35 outputs
are **not established by the repository's evidence**.

`LoginIdResolver` is an in-process extension point, not a completed derivation
algorithm. `UnsupportedLoginProfile` deliberately returns an error. No values
are guessed, replaced with zero, scraped from a terminal, or requested over
HTTP. Absence of input tags does not establish that zero values are valid.
A real implementation requires independent, authorized input/output evidence or
an algorithm for the relevant client/server builds. Removing a vendor adapter
alone does not prove what a broker will accept.

Contexts include the client build, server build, record build, original challenge,
and ordered auth tags. `input(28)` and `input(35)` reject empty or duplicate inputs
rather than choosing a precedence without evidence. Resolvers must validate the
profile they implement; they must not cache values across different challenges.
The current code does not sandbox a caller-supplied resolver.

## Local validation

From the workspace root:

```sh
cargo test --locked -p mt5_native
cargo test --locked -p mt5_session --features live
cargo test --locked -p mt5_webterm --lib
```

Native conformance fixtures are under `mt5-native/tests/fixtures`.
`MT5_PROTOCOL_FIXTURES` may override that directory with a compatible fixture set.
Historical HTTP adapter cases were removed with that adapter; remaining wire
vectors are unchanged. Loopback tests use synthetic server replies and synthetic
F28/F35 outputs. They validate transport/state transitions and wrapper wiring,
not the unknown derivation, a real certificate, or successful broker login.

## Read-only diagnostic probe

Set `MT5_ADDRESS` to the broker's native `host:port`, `MT5_LOGIN`, `MT5_PASSWORD`,
and an explicitly selected `MT5_BUILD`; optionally set `MT5_OTP`. Use an account
you are authorized to access, preferably demo or investor access. The probe
prints only structural diagnostics and exits nonzero when continuation or an
unsupported derivation prevents completion. It never sends a guessed sync.

```sh
cargo run --locked -p mt5_session --features live --example auth_probe
```

Do not publish credentials, certificates/private keys, challenges, auth captures,
or tag contents. Tests do not contact a broker. This change does not rewrite Git
history, claim a clean-room provenance, grant rights to reference materials,
or establish compatibility with every broker or client build.
