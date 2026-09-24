# Status

The native codec has no network I/O. The separate `mt5-session` crate provides an
explicitly feature-gated direct TCP transport. See [AUTH.md](AUTH.md).

Implemented and tested offline: authentication message codecs, credential/key
operations, OTP encoding, certificate-continuation serialization, login wrapper,
compression/reassembly, transport state checks, and matching account updates.

Still unverified or incomplete: inner tag-28/tag-35 login calculations, real
broker acceptance, full initial account/symbol synchronization parsing,
certificate provisioning/signing, passkeys, and execution lifecycle management.
There is no hosted login fallback or automatic zero-value synchronization.
