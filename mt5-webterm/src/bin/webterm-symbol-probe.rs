//! Locate the fields in a symbol record that position sizing depends on.
//!
//! `parse_symbols` reads a name, digits and an id, and defaults everything
//! else -- so `tick_value` arrives as 0 and the app refuses to size a trade
//! ("Waiting for broker specifications"). Those numbers decide risk per lot,
//! so they are found against values already known to be true rather than
//! guessed.
//!
//! Pass what the bridge reports for one symbol and this reports every offset
//! in that symbol's record holding it:
//!
//!     MT5_ACCOUNT=.. MT5_PASSWORD=.. MT5_SERVER=.. SYMBOL=XAUUSD \
//!     CONTRACT=100 TICK_VALUE=0.7486430844095078 POINT=0.01 \
//!     webterm-symbol-probe

use flate2::read::ZlibDecoder;
use mt5_webterm::protocol::CMD_SYMBOLS;
use mt5_webterm::Client;
use std::io::Read;

fn u32_at(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn f64_at(b: &[u8]) -> f64 {
    f64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}
fn utf16(b: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i + 1 < b.len() {
        let c = u16::from_le_bytes([b[i], b[i + 1]]);
        if c == 0 {
            break;
        }
        out.push(char::from_u32(c as u32).unwrap_or('?'));
        i += 2;
    }
    out
}

#[tokio::main]
async fn main() {
    let login: u64 = std::env::var("MT5_ACCOUNT").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let password = std::env::var("MT5_PASSWORD").unwrap_or_default();
    let server = std::env::var("MT5_SERVER").unwrap_or_default();
    let symbol = std::env::var("SYMBOL").unwrap_or_else(|_| "XAUUSD".into());
    let wants: Vec<(String, f64)> = ["CONTRACT", "TICK_VALUE", "POINT", "TICK_SIZE", "VOLUME_MIN", "VOLUME_MAX"]
        .iter()
        .filter_map(|k| std::env::var(k).ok().and_then(|v| v.parse::<f64>().ok()).map(|v| (k.to_string(), v)))
        .collect();
    if login == 0 || password.is_empty() || server.is_empty() {
        eprintln!("set MT5_ACCOUNT MT5_PASSWORD MT5_SERVER [SYMBOL] and known values");
        std::process::exit(2);
    }

    let c = match Client::connect(login, &password, &server).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("connect FAILED: {e}");
            std::process::exit(1);
        }
    };
    let frame = c.request(CMD_SYMBOLS, &[]).await.expect("symbols frame");
    let compressed = &frame.body[4..];
    let mut raw = Vec::new();
    if ZlibDecoder::new(compressed).read_to_end(&mut raw).is_err() {
        eprintln!("could not inflate the symbols frame");
        std::process::exit(1);
    }
    let count = u32_at(&raw[0..4]) as usize;
    println!("{count} symbols, {} bytes inflated; looking for {symbol} and {wants:?}", raw.len());

    // The record length is not declared, so find our symbol's name and then
    // report a generous window after it.
    let stride_guess = if count > 1 { (raw.len() - 4) / count } else { raw.len() - 4 };
    println!("record stride looks like {stride_guess} bytes");

    let mut o = 4usize;
    for n in 0..count {
        if o + stride_guess > raw.len() {
            break;
        }
        let name = utf16(&raw[o..o + 64]);
        if name.eq_ignore_ascii_case(&symbol) {
            println!("\n{symbol} is record {n} at offset {o}");
            let rec = &raw[o..(o + stride_guess).min(raw.len())];
            for off in 0..rec.len().saturating_sub(8) {
                let v = f64_at(&rec[off..]);
                if !v.is_finite() || v == 0.0 {
                    continue;
                }
                let hits: Vec<&str> = wants
                    .iter()
                    .filter(|(_, target)| (v - target).abs() <= target.abs() * 1e-9 + 1e-12)
                    .map(|(k, _)| k.as_str())
                    .collect();
                if !hits.is_empty() {
                    println!("  f64 @ {off:>4}: {v:<24} <== {}", hits.join(" / "));
                }
            }
            // The protocol stores prices as integers scaled by a power of
            // ten (parse_quotes already divides by 10^digits), so the spec
            // fields are very likely integers too.
            println!("  -- integer matches, allowing a power-of-ten scale --");
            for off in 0..rec.len().saturating_sub(8) {
                let u64v = u64::from_le_bytes(rec[off..off + 8].try_into().unwrap());
                let u32v = u32_at(&rec[off..]) as u64;
                for (name, target) in &wants {
                    for scale in 0..12u32 {
                        let factor = 10f64.powi(scale as i32);
                        let scaled = target * factor;
                        if scaled.fract().abs() > 1e-6 || scaled <= 0.0 || scaled > 1e18 {
                            continue;
                        }
                        let want = scaled.round() as u64;
                        if u64v == want {
                            println!("  u64 @ {off:>4}: {u64v} = {name} x 10^{scale}");
                        }
                        if u32v == want && want <= u32::MAX as u64 {
                            println!("  u32 @ {off:>4}: {u32v} = {name} x 10^{scale}");
                        }
                    }
                }
            }
            println!("  -- small non-zero integers, for context --");
            for off in (0..rec.len().saturating_sub(4)).step_by(4) {
                let v = u32_at(&rec[off..]);
                if v > 0 && v < 10_000_000 {
                    println!("     u32 @ {off:>4}: {v}");
                }
            }
            return;
        }
        o += stride_guess;
    }
    println!("{symbol} not found with that stride; the record layout is not fixed-width");
}
