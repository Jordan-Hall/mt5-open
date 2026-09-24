//! Resolve MT5 server names through the MetaQuotes HTTPS directory.
//!
//! Published desktop access points are normalized to port 443 for WebTerminal
//! probes. Discovery alone does not prove that an endpoint supports WebTerminal
//! or that its certificate is valid for that hostname.

use md5::{Digest, Md5};
use serde_json::Value;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SIGNATURE_KEY: [u8; 32] = [
    61, 123, 21, 22, 214, 234, 187, 52, 217, 214, 99, 227, 98, 62, 27, 215, 251, 220, 174, 244, 87,
    59, 223, 53, 127, 168, 207, 11, 190, 173, 146, 127,
];
const DIRECTORY_URL: &str = "https://updates.metaquotes.net/public/mt5/network";
const WEB_PORT: u16 = 443;
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
static HTTP: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct ServerHit {
    pub name: String,
    pub access: Vec<String>,
}

fn http_client() -> Result<&'static reqwest::Client, String> {
    HTTP.get_or_init(|| {
        reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(12))
            .build()
            .map_err(|e| format!("directory client: {e}"))
    })
    .as_ref()
    .map_err(Clone::clone)
}

/// Parse a hostname/IP and optional port, without accepting URLs, userinfo,
/// paths, queries, or fragments. IPv6 hosts are returned in brackets.
pub(crate) fn parse_endpoint(endpoint: &str) -> Result<(String, u16), String> {
    if endpoint.is_empty()
        || endpoint.chars().any(char::is_whitespace)
        || endpoint.contains(['/', '\\', '@', '?', '#'])
    {
        return Err("invalid access endpoint".into());
    }
    if let Ok(ip) = endpoint.parse::<IpAddr>() {
        return Ok((match ip {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        }, WEB_PORT));
    }
    let parsed = url::Url::parse(&format!("https://{endpoint}"))
        .map_err(|_| "invalid access endpoint".to_string())?;
    let host = parsed.host_str().ok_or("missing access hostname")?;
    let port = parsed.port_or_known_default().ok_or("missing access port")?;
    if host.is_empty() || port == 0 || endpoint.ends_with(':') {
        return Err("invalid access endpoint".into());
    }
    Ok((host.to_string(), port))
}

pub fn pick_web_terminal(access: &[String]) -> Result<String, String> {
    let mut first = None;
    for item in access {
        let Ok((host, port)) = parse_endpoint(item) else { continue };
        let endpoint = format!("{host}:{WEB_PORT}");
        if port == WEB_PORT {
            return Ok(endpoint);
        }
        if first.is_none() {
            first = Some(endpoint);
        }
    }
    first.ok_or_else(|| "no valid access endpoints".into())
}

fn signature(body: &str) -> String {
    let body_hash = Md5::digest(body.as_bytes());
    let mut hash = Md5::new();
    hash.update(body_hash);
    hash.update(SIGNATURE_KEY);
    format!("{:x}", hash.finalize())
}

fn request_body(company: &str) -> String {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("company", company)
        .append_pair("code", "mt5")
        .finish();
    format!("{body}&signature={}&ver=2", signature(&body))
}

fn cookie() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let val = timestamp.saturating_sub(1_420_070_400) | 0x4200_0000_0000_0000;
    format!("_fz_uniq={val};uniq={val};age={};tid=0", timestamp.saturating_sub(86400))
}

fn parse_directory_response(body: &[u8]) -> Result<Vec<Value>, String> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err("directory response exceeds size limit".into());
    }
    let start = body.iter().position(|&b| b == b'{').ok_or("directory response is not JSON")?;
    let mut value: Value = serde_json::from_slice(&body[start..])
        .map_err(|e| format!("invalid directory response: {e}"))?;
    match value.get_mut("result").map(Value::take) {
        Some(Value::Array(results)) => Ok(results),
        _ => Err("directory response has no result array".into()),
    }
}

/// Search the official directory, preserving HTTP, transport and decoding errors.
pub async fn try_search_mq(company: &str) -> Result<Vec<Value>, String> {
    if company.trim().is_empty() || company.len() > 1024 || company.contains('\0') {
        return Err("company must contain 1..=1024 bytes without NUL".into());
    }
    let mut response = http_client()?
        .post(DIRECTORY_URL)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("User-Agent", "MetaTrader 5 Terminal/5.5830 (Windows NT 10.0.22621; x64)")
        .header("Cookie", cookie())
        .body(request_body(company))
        .send()
        .await
        .map_err(|e| format!("directory request: {e}"))?
        .error_for_status()
        .map_err(|e| format!("directory HTTP status: {e}"))?;
    if response.content_length().is_some_and(|n| n > MAX_RESPONSE_BYTES as u64) {
        return Err("directory response exceeds size limit".into());
    }
    let mut body = Vec::with_capacity(4096);
    while let Some(chunk) = response.chunk().await.map_err(|e| format!("directory body: {e}"))? {
        if chunk.len() > MAX_RESPONSE_BYTES - body.len() {
            return Err("directory response exceeds size limit".into());
        }
        body.extend_from_slice(&chunk);
    }
    parse_directory_response(&body)
}

/// Compatibility helper. Prefer `try_search_mq` when callers need diagnostics.
pub async fn search_mq(company: &str) -> Vec<Value> {
    try_search_mq(company).await.unwrap_or_default()
}

/// Compatibility alias using the same official directory and no fallback service.
pub async fn search_company(company: &str) -> Vec<Value> {
    search_mq(company).await
}

fn hits_named(payload: &[Value], server_name: &str) -> Vec<ServerHit> {
    let target = server_name.to_lowercase();
    let mut out = Vec::new();
    for company in payload {
        let Some(results) = company.get("results").and_then(Value::as_array) else { continue };
        for result in results {
            let Some(name) = result.get("name").and_then(Value::as_str) else { continue };
            if name.to_lowercase() != target {
                continue;
            }
            let access = result.get("access").and_then(Value::as_array)
                .map(|items| items.iter().filter_map(Value::as_str).map(str::to_owned).collect())
                .unwrap_or_default();
            out.push(ServerHit { name: name.to_string(), access });
        }
    }
    out
}

async fn find_access(server_name: &str) -> Result<Vec<String>, String> {
    let hits = hits_named(&try_search_mq(server_name).await?, server_name);
    if hits.is_empty() {
        return Err(format!("server not found: {server_name}"));
    }
    Ok(hits.into_iter().flat_map(|hit| hit.access).collect())
}

pub async fn find_web_terminal(server_name: &str) -> Result<(String, u16), String> {
    parse_endpoint(&pick_web_terminal(&find_access(server_name).await?)?)
}

/// Unique normalized WebTerminal candidates in their published order.
pub async fn access_points(server_name: &str) -> Result<Vec<String>, String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for item in find_access(server_name).await? {
        let Ok((host, _)) = parse_endpoint(&item) else { continue };
        let endpoint = format!("{host}:{WEB_PORT}");
        if seen.insert(endpoint.clone()) {
            out.push(endpoint);
        }
    }
    if out.is_empty() {
        return Err("no valid access endpoints".into());
    }
    Ok(out)
}

/// Sorted unique server names from one official-directory request.
pub async fn list_servers(company: &str) -> Result<Vec<String>, String> {
    let mut names = HashSet::new();
    for entry in try_search_mq(company).await? {
        let Some(results) = entry.get("results").and_then(Value::as_array) else { continue };
        for result in results {
            if let Some(name) = result.get("name").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                names.insert(name.to_string());
            }
        }
    }
    if names.is_empty() {
        return Err(format!("no servers found for {company}"));
    }
    let mut names: Vec<_> = names.into_iter().collect();
    names.sort_unstable();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_443() {
        assert_eq!(pick_web_terminal(&["acc.example:701".into(), "edge.example:443".into()]).unwrap(), "edge.example:443");
    }

    #[test]
    fn rewrites_desktop_port() {
        assert_eq!(pick_web_terminal(&["acc.example:701".into(), "acc.example:702".into()]).unwrap(), "acc.example:443");
    }

    #[test]
    fn ipv6_and_bare_hosts_are_supported() {
        for (input, expected) in [
            ("example.test", "example.test:443"),
            ("127.0.0.1:701", "127.0.0.1:443"),
            ("[2001:db8::1]:701", "[2001:db8::1]:443"),
            ("2001:db8::1", "[2001:db8::1]:443"),
        ] {
            assert_eq!(pick_web_terminal(&[input.into()]).unwrap(), expected);
        }
    }

    #[test]
    fn rejects_urls_userinfo_and_invalid_ports() {
        for input in ["", "host:0", "host:65536", "host:abc", "host:", " user", "https://host", "u@host", "host/path", "host?x", "host#x", "host\\path"] {
            assert!(parse_endpoint(input).is_err(), "accepted {input:?}");
        }
    }

    #[test]
    fn form_encoding_cannot_inject_parameters() {
        let body = request_body("A&B + Partners=Demo");
        let pairs: Vec<_> = url::form_urlencoded::parse(body.as_bytes()).collect();
        assert_eq!(pairs.len(), 4);
        assert_eq!(pairs[0].0, "company");
        assert_eq!(pairs[0].1, "A&B + Partners=Demo");
        let unsigned = body.split("&signature=").next().unwrap();
        assert_eq!(pairs[2].1, signature(unsigned));
    }

    #[test]
    fn directory_decoding_rejects_bad_shapes() {
        assert!(parse_directory_response(b"garbage").is_err());
        assert!(parse_directory_response(b"{}").is_err());
        assert!(parse_directory_response(b"{\"result\":null}").is_err());
        assert!(parse_directory_response(b"prefix{\"result\":[]}").unwrap().is_empty());
        assert!(parse_directory_response(&vec![b' '; MAX_RESPONSE_BYTES + 1]).is_err());
    }

    #[test]
    fn directory_transport_is_https_only() {
        let url = url::Url::parse(DIRECTORY_URL).unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("updates.metaquotes.net"));
    }
}
