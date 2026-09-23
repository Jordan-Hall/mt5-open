//! The loginid service, done exactly the way the terminal does it.
//!
//! The specification is precise that the terminal does not compute these two
//! values -- it "contains request construction and response parsing, not the
//! service's computation". So the terminal is not self-contained here either:
//! it POSTs the tag material to a configured service and reads back a decimal
//! integer. This module does the same POST.
//!
//! **The base address and the guid are configuration inputs**, exactly as the
//! specification frames them: "neither is a value derived from the broker
//! frame." They are supplied by the caller, like the account password. This
//! module does not discover them, and it does not compute what the service
//! computes -- there is no way to, and pretending otherwise is what the codec's
//! conformance tests refuse to do.

#![cfg(feature = "live")]

use std::time::Duration;

use mt5_native::error::{ProtocolError, Result};
use mt5_native::subscription::additional_login_http_contract;

/// Where the loginid values come from, and the key that admits us.
///
/// `base` is the service root (`https://host[:port]`); the module appends the
/// contract's own relative path and the guid. `guid` is the configured service
/// key. Both are the terminal's configuration, provided here rather than
/// discovered.
pub struct LoginIdService {
    base: String,
    guid: String,
    timeout: Duration,
}

impl LoginIdService {
    pub fn new(base: impl Into<String>, guid: impl Into<String>) -> LoginIdService {
        LoginIdService { base: base.into(), guid: guid.into(), timeout: Duration::from_secs(20) }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> LoginIdService {
        self.timeout = timeout;
        self
    }

    /// Resolve one input tag (28 or 35) to its integer, by the documented
    /// contract: POST the exact body to `{base}{relative_path}{guid}`,
    /// `application/text`, and read the reply as a decimal `u64`.
    ///
    /// The specification's own rules are honoured: HTTP 201 is an error
    /// carrying its text, and an unparsable body is a failure -- a wrong number
    /// here is worse than none, because it becomes a silently wrong login id.
    pub fn resolve_tag(&self, tag: u8, value: &[u8], server_build: i32) -> Result<u64> {
        let contract = additional_login_http_contract(tag, value, server_build)?;
        let url = format!("{}{}{}", self.base.trim_end_matches('/'), contract.relative_path, self.guid);

        let response = ureq::post(&url)
            .timeout(self.timeout)
            .set("Content-Type", contract.content_type)
            .send_bytes(&contract.body);

        let text = match response {
            Ok(ok) => {
                // 201 is an error in this contract even though it is a 2xx.
                if ok.status() == 201 {
                    let body = ok.into_string().unwrap_or_default();
                    return Err(ProtocolError::new(format!("loginid service returned 201: {body}")));
                }
                ok.into_string().map_err(|e| ProtocolError::new(format!("loginid response not text: {e}")))?
            }
            Err(ureq::Error::Status(code, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                return Err(ProtocolError::new(format!("loginid service returned {code}: {body}")));
            }
            Err(e) => return Err(ProtocolError::new(format!("loginid request failed: {e}"))),
        };

        text.trim()
            .parse::<u64>()
            .map_err(|_| ProtocolError::new(format!("loginid reply was not a decimal integer: {:?}", text.trim())))
    }
}
