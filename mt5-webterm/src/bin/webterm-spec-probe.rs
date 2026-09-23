//! Ask the web terminal for one symbol's full specification (CMD_SPEC).
//!
//! The symbols list carries only a name, digits and an id -- which is why
//! tick_value arrived as 0 and the app would not size a trade. The numbers
//! that decide risk per lot should come from the terminal, not from a
//! conversion done by hand here.
//!
//!     MT5_ACCOUNT=.. MT5_PASSWORD=.. MT5_SERVER=.. SYMBOL=XAUUSD \
//!     CONTRACT=100 TICK_VALUE=0.7486430844095078 webterm-spec-probe

use mt5_webterm::protocol::CMD_SPEC;
use mt5_webterm::Client;

fn u32_at(b: &[u8]) -> u32 { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) }
fn f64_at(b: &[u8]) -> f64 { f64::from_le_bytes([b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7]]) }

fn utf16_le(s: &str, width: usize) -> Vec<u8> {
    let mut out = vec![0u8; width];
    for (i, u) in s.encode_utf16().enumerate() {
        if i * 2 + 1 >= width { break; }
        out[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
    }
    out
}

#[tokio::main]
async fn main() {
    let login: u64 = std::env::var("MT5_ACCOUNT").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let password = std::env::var("MT5_PASSWORD").unwrap_or_default();
    let server = std::env::var("MT5_SERVER").unwrap_or_default();
    let symbol = std::env::var("SYMBOL").unwrap_or_else(|_| "XAUUSD".into());
    let wants: Vec<(String, f64)> = ["CONTRACT","TICK_VALUE","POINT","TICK_SIZE","VOLUME_MIN","VOLUME_MAX","MARGIN"]
        .iter()
        .filter_map(|k| std::env::var(k).ok().and_then(|v| v.parse::<f64>().ok()).map(|v| (k.to_string(), v)))
        .collect();

    let c = match Client::connect(login, &password, &server).await {
        Ok(c) => c, Err(e) => { eprintln!("connect FAILED: {e}"); std::process::exit(1); }
    };
    // Try a few plausible payloads: the symbol name, and the name plus a
    // trailing id, since the shape is not documented here.
    for (label, payload) in [
        ("name only (64 bytes)", utf16_le(&symbol, 64)),
        ("name padded to 128", utf16_le(&symbol, 128)),
    ] {
        match c.request(CMD_SPEC, &payload).await {
            Ok(frame) => {
                println!("\n{label}: {} bytes back", frame.body.len());
                if frame.body.is_empty() { continue; }
                for off in 0..frame.body.len().saturating_sub(8) {
                    let v = f64_at(&frame.body[off..]);
                    if !v.is_finite() || v == 0.0 { continue; }
                    let hits: Vec<&str> = wants.iter()
                        .filter(|(_, t)| (v - t).abs() <= t.abs() * 1e-9 + 1e-12)
                        .map(|(k, _)| k.as_str()).collect();
                    if !hits.is_empty() {
                        println!("  f64 @ {off:>4}: {v:<24} <== {}", hits.join(" / "));
                    }
                }
                println!("  -- plausible f64s --");
                for off in (0..frame.body.len().saturating_sub(8)).step_by(8) {
                    let v = f64_at(&frame.body[off..]);
                    if v.is_finite() && v.abs() > 1e-9 && v.abs() < 1e9 {
                        println!("     @ {off:>4}: {v}");
                    }
                }
                println!("  -- small u32s --");
                for off in (0..frame.body.len().saturating_sub(4)).step_by(4) {
                    let v = u32_at(&frame.body[off..]);
                    if v > 0 && v < 1_000_000 { println!("     u32 @ {off:>4}: {v}"); }
                }
            }
            Err(e) => println!("\n{label}: FAILED {e}"),
        }
    }
}
