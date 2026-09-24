# Status

`mt5_native` is a networking-free codec for a reconstructed MT5 application
protocol. Synthetic revision-3 fixtures cover byte-level behaviour, not
successful broker sessions. The `live` feature is disabled by default.

`mt5-session` supplies optional TCP transport and a caller-owned local
`LoginIdResolver` interface. Modern additional-login mappings for records 28
and 35 remain unimplemented. The default resolver fails explicitly; there is
no remote-service fallback or fabricated result.

Earlier development notes reported a demo password-authentication exchange.
This review did not reproduce that exchange and does not establish complete
synchronization, trading or multi-broker compatibility. See [AUTH.md](AUTH.md)
and the workspace [review](../REVIEW.md).
