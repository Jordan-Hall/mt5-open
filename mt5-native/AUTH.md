# Native authentication

The offline `Handshake` state machine produces hello, password authentication,
optional certificate continuation and synchronization frames. `mt5-session`
provides the TCP connection and verifies the resulting account.

| Step | Module | Result |
|---|---|---|
| Hello and password challenge | `auth`, `crypto`, `handshake` | Password accepted or an error |
| Session and trade keys | `keys`, `cipher` | Independent directional cipher state and optional signing key |
| Additional login values | `challenge`, `login` | Interpreted tag-28/tag-35 programs bound to this connection |
| Synchronization | `sync::parse_sync_account` | Complete structural parse and account identity check |

Password hashes use the protocol's 16-code-unit UTF-16 limit and MD5 challenge
construction. These wire encodings remain compatible with the included vectors.
OS randomness supplies live nonces and client challenges.

Authentication input tags 28 and 35 produce synchronization fields 88 and 134.
`Handshake::login_values` accesses the authenticated connection's challenge
directly. The certificate-only accessor is reserved for certificate signing.

The build-6182 session interprets both challenge programs locally, then computes
the per-connection wrapper. Configuration contains identity and compatibility
metadata, not cached answers. The implementation was compared with synthetic
terminal-calculator reference cases, including all instruction selectors. Other
client versions and authentication methods remain outside this verified path.
Full evidence and configuration requirements are in
[`mt5-session/README.md`](../mt5-session/README.md).

Each synchronization frame is decrypted and then decompressed if flagged. The
decoder consumes the concatenated response, including records that cross frame
boundaries. It returns no account until the complete response validates and the
account number matches the requested login. The receive cipher continues at its
current position for later messages.

Certificate and OTP serialization remain in the codec. Certificate enrollment,
passkeys and live certificate authentication are outside the verified socket path.
Raw authentication captures contain key material and must remain local.
