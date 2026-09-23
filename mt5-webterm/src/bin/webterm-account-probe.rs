//! Locate the account frame's fields by value, not by guessing offsets.
//!
//! The schema walk in `parse_account` reads margin at one offset and the live
//! bridge disagrees with it. Rather than shift offsets until something looks
//! right, this dumps every 8-byte float in the frame and flags the ones that
//! equal values we already know to be true (passed in the environment).
//!
//!     MT5_ACCOUNT=.. MT5_PASSWORD=.. MT5_SERVER=.. \
//!     BALANCE=155.16 MARGIN=9.05 EQUITY=151.0 webterm-account-probe

use mt5_webterm::protocol::CMD_ACCOUNT;
use mt5_webterm::Client;

fn f64_at(b: &[u8]) -> f64 {
    f64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

#[tokio::main]
async fn main() {
    let login: u64 = std::env::var("MT5_ACCOUNT").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let password = std::env::var("MT5_PASSWORD").unwrap_or_default();
    let server = std::env::var("MT5_SERVER").unwrap_or_default();
    let want: Vec<(String, f64)> = ["BALANCE", "MARGIN", "EQUITY", "FREE", "PROFIT"]
        .iter()
        .filter_map(|k| std::env::var(k).ok().and_then(|v| v.parse::<f64>().ok()).map(|v| (k.to_string(), v)))
        .collect();
    if login == 0 || password.is_empty() || server.is_empty() {
        eprintln!("set MT5_ACCOUNT MT5_PASSWORD MT5_SERVER and any of BALANCE/MARGIN/EQUITY/FREE/PROFIT");
        std::process::exit(2);
    }
    let c = match Client::connect(login, &password, &server).await {
        Ok(c) => c,
        Err(e) => { eprintln!("connect FAILED: {e}"); std::process::exit(1); }
    };
    let frame = c.request(CMD_ACCOUNT, &[]).await.expect("account frame");
    let body = &frame.body;
    println!("account frame: {} bytes; looking for {:?}", body.len(), want);

    // Every byte offset, so a misaligned schema cannot hide a field.
    for off in 0..body.len().saturating_sub(8) {
        let v = f64_at(&body[off..]);
        if !v.is_finite() || v == 0.0 || v.abs() > 1e12 || v.abs() < 1e-6 {
            continue;
        }
        let mut labels = Vec::new();
        for (name, target) in &want {
            if (v - target).abs() < 0.005 {
                labels.push(name.as_str());
            }
        }
        if !labels.is_empty() {
            println!("  off {off:>4}: {v:<16} <== {}", labels.join(" / "));
        }
    }
    println!("--- plausible money-like values, for context ---");
    for off in 0..body.len().saturating_sub(8) {
        let v = f64_at(&body[off..]);
        if v.is_finite() && v > 0.01 && v < 1e7 {
            println!("  off {off:>4}: {v}");
        }
    }
}
