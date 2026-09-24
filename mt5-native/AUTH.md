# Native authentication: profile and evidence boundary

This crate is a networking-free codec for a reconstructed MT5 desktop-client
profile. The sibling `mt5-session` crate adds TCP only with the optional `live`
feature. Enabling that feature does not establish complete authentication or
production readiness.

## Credential and transport stages

`crypto` encodes account/password material and derives the credential digest.
`md5` implements the state-preserving reset needed by the reconstructed challenge
proof. `auth` builds and parses the hello, password-proof and result bodies;
`frame` supplies the nine-byte outer envelope. Startup payload transformation and
stateful session ciphers are separate; neither is a substitute for verifying the
remote party.

`Handshake` progresses through hello, challenge, authentication, session-key
installation, optional certificate continuation and synchronization. Callers
must check command, status, framing and state rather than equating a received
response with successful authentication. The socket transport validates expected
hello/authentication commands and rejects unsupported compressed startup replies.

Client nonces in `mt5-session` come from the operating system random source.
Hardware identifiers are profile fields, not a source of cryptographic entropy.

## Additional-login records 28 and 35

The `F28` and `F35` mappings are **not implemented**. These are the inner
calculations associated with additional-login records 28 (`0x1c`) and 35
(`0x23`); they are not the password hash itself.

`login::login_value_wrapper` mixes independently obtained inner results with the
account, challenge and build values using the reconstructed integer arithmetic.
That wrapper has synthetic fixtures. Those fixtures do not establish the missing
inner mappings or demonstrate acceptance by a broker.

`mt5-session::LoginIdResolver` is the local integration boundary. Supply an
implementation backed by verified, permitted code for the specific record and
build. The provided `UnsupportedLoginResolver` returns an error and never
substitutes zero, a cached answer, a guessed constant or a network service.
The optional socket transport fails before synchronization when required values
are unresolved. No remote calculation request builder is retained in the codec.

An older interpreter is not evidence that modern records have the same format.
The prior research identified a build-dependent distinction at 4852 in one
reference implementation; this is not a universal compatibility guarantee.

## Certificate continuation

On status 1003, `certificate_challenge()` exposes the original server challenge
for an external signer. `authentication_challenge()` also supports the normal
(non-certificate) additional-login path. Keeping these accessors distinct avoids
requiring certificate authentication just to resolve ordinary login records.

`certificate_continuation()` accepts RSA PKCS#1 v1.5 SHA-1 signature bytes and a
DER certificate, reverses the signature for the reconstructed wire format and
serializes command 2 before synchronization. It does not parse PFX, enroll a
certificate, verify ownership, or implement a signing service. Unknown statuses
must fail explicitly. OTP serialization is present; passkey authentication is
not implemented.

## Limits and validation

Network reads, writes, frame sizes, synchronization fragments and decompression
outputs are bounded. Malformed or incomplete input must fail before advancing
state or allocating from an untrusted count. Complete encrypted synchronization
requires the correct per-direction cipher state and all required login values.

Offline conformance covers framing, startup transformation, credential proofs,
key derivations, stateful cipher continuity, record layouts and login-value
wrapping. Inputs are synthetic and are not captured successful broker sessions.
Three historical HTTP-envelope fixtures were removed with the network adapter;
MT5 wire fixtures and their integrity checks remain.

The reference material originated from analysis of a third-party client rather
than an official protocol specification. Removing a runtime service dependency
changes neither that provenance nor the need to establish reuse rights. Git
history preserves the earlier research notes. No licence or copyright notice is
removed or replaced by this document.

## Offline commands

Run from the workspace root:

```sh
cargo test --locked -p mt5_native
cargo test --locked -p mt5_native --all-features
cargo test --locked -p mt5_session --all-features
```

A passing round trip is not a successful session. No live broker login, order,
certificate provisioning or newer-build inner calculation is certified here.
