//! Resolve MT5 server names to web-terminal hosts (always port 443).

use md5::{Digest, Md5};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

const HMAC_KEY: [u8; 32] = [
    61, 123, 21, 22, 214, 234, 187, 52, 217, 214, 99, 227, 98, 62, 27, 215, 251, 220, 174, 244, 87,
    59, 223, 53, 127, 168, 207, 11, 190, 173, 146, 127,
];
const SEARCHMQ_URL: &str = "https://updates.metaquotes.net/public/mt5/network";
const WEB_PORT: u16 = 443;

#[derive(Debug, Clone)]
pub struct ServerHit {
    pub name: String,
    pub access: Vec<String>,
}

pub fn pick_web_terminal(access: &[String]) -> Result<String, String> {
    let mut parsed = Vec::new();
    for item in access {
        if let Some((host, port_s)) = item.rsplit_once(':') {
            if let Ok(port) = port_s.parse::<u16>() {
                if !host.is_empty() {
                    parsed.push((host.to_string(), port));
                }
            }
        } else if !item.is_empty() {
            parsed.push((item.clone(), WEB_PORT));
        }
    }
    if let Some((host, _)) = parsed.iter().find(|(_, p)| *p == WEB_PORT) {
        return Ok(format!("{host}:{WEB_PORT}"));
    }
    if let Some((host, _)) = parsed.first() {
        return Ok(format!("{host}:{WEB_PORT}"));
    }
    Err("no access endpoints".into())
}

fn signature(body: &str) -> String {
    let mut h = Md5::new();
    h.update(body.as_bytes());
    let body_hash = h.finalize();
    let mut h2 = Md5::new();
    h2.update(body_hash);
    h2.update(HMAC_KEY);
    format!("{:x}", h2.finalize())
}

fn cookie() -> String {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let val = ((timestamp.saturating_sub(1_420_070_400)) as u64) | 0x4200_0000_0000_0000;
    format!("_fz_uniq={val};uniq={val};age={};tid=0", timestamp.saturating_sub(86400))
}

/// Compatibility alias for the first-party directory lookup.
pub async fn search_company(company: &str) -> Vec<Value> {
    search_mq(company).await
}

pub async fn search_mq(company: &str) -> Vec<Value> {
    let body = format!("company={}&code=mt5", urlencoding_lite(company));
    let full = format!("{body}&signature={}&ver=2", signature(&body));
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(12)).build();
    let Ok(client) = client else { return vec![] };
    let Ok(resp) = client
        .post(SEARCHMQ_URL)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("User-Agent", "MetaTrader 5 Terminal/5.5830 (Windows NT 10.0.22621; x64)")
        .header("Cookie", cookie())
        .body(full)
        .send()
        .await
    else {
        return vec![];
    };
    let Ok(text) = resp.text().await else { return vec![] };
    let Some(idx) = text.find('{') else { return vec![] };
    let Ok(v) = serde_json::from_str::<Value>(&text[idx..]) else { return vec![] };
    v.get("result").and_then(|x| x.as_array()).cloned().unwrap_or_default()
}

fn hits_named(payload: &[Value], server_name: &str) -> Vec<ServerHit> {
    let target = server_name.to_lowercase();
    let mut out = Vec::new();
    for company in payload {
        let Some(results) = company.get("results").and_then(|x| x.as_array()) else { continue };
        for result in results {
            let name = result.get("name").and_then(|x| x.as_str()).unwrap_or("");
            if name.to_lowercase() != target {
                continue;
            }
            let access = result
                .get("access")
                .and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            out.push(ServerHit { name: name.to_string(), access });
        }
    }
    out
}

pub async fn find_web_terminal(server_name: &str) -> Result<(String, u16), String> {
    let mq = search_mq(server_name).await;
    let hits = hits_named(&mq, server_name);
    let access = hits.first().map(|h| h.access.clone()).ok_or_else(|| format!("server not found: {server_name}"))?;
    let endpoint = pick_web_terminal(&access)?;
    let (host, port_s) = endpoint.rsplit_once(':').ok_or("bad endpoint")?;
    Ok((host.to_string(), port_s.parse().unwrap_or(WEB_PORT)))
}

/// Every endpoint the broker publishes for this server, in the order given.
///
/// `find_web_terminal` commits to the first one. When a login is refused it
/// matters whether that host alone is refusing us or all of them are, and
/// that question cannot be asked without the full list.
pub async fn access_points(server_name: &str) -> Result<Vec<String>, String> {
    let mq = search_mq(server_name).await;
    let hits = hits_named(&mq, server_name);
    let access = hits.first().map(|h| h.access.clone()).ok_or_else(|| format!("server not found: {server_name}"))?;
    let mut out = Vec::new();
    for item in access {
        let ep = match item.rsplit_once(':') {
            Some((host, port)) if port.parse::<u16>().is_ok() && !host.is_empty() => format!("{host}:{WEB_PORT}"),
            _ if !item.is_empty() => format!("{item}:{WEB_PORT}"),
            _ => continue,
        };
        if !out.contains(&ep) {
            out.push(ep);
        }
    }
    Ok(out)
}

/// Every server name MetaQuotes lists for a broker, so the app can offer a
/// list instead of asking someone to type "ExampleBroker-Demo" exactly right.
///
/// One wrong character in a server name is indistinguishable from a wrong
/// password: the login is simply refused. Typing it should not be part of
/// signing in.
pub async fn list_servers(company: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for payload in [search_mq(company).await] {
        for entry in &payload {
            let Some(results) = entry.get("results").and_then(|x| x.as_array()) else { continue };
            for result in results {
                if let Some(name) = result.get("name").and_then(|x| x.as_str()) {
                    if !name.is_empty() && !names.iter().any(|n: &String| n == name) {
                        names.push(name.to_string());
                    }
                }
            }
        }
    }
    names.sort();
    if names.is_empty() {
        return Err(format!("no servers found for {company}"));
    }
    Ok(names)
}

fn urlencoding_lite(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_443() {
        let access = vec![
            "acc.example:701".into(),
            "edge.example:443".into(),
        ];
        assert_eq!(pick_web_terminal(&access).unwrap(), "edge.example:443");
    }

    #[test]
    fn rewrites_desktop_port() {
        let access = vec!["acc.example:701".into(), "acc.example:702".into()];
        assert_eq!(pick_web_terminal(&access).unwrap(), "acc.example:443");
    }
}
