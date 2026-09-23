//! Locate the magic-number field in the web terminal's position/order records.
//!
//! The desks tell their trades apart by MT5's `magic`, and the web-terminal
//! parse does not decode it yet. Rather than guess an offset, this reads the
//! raw frame and reports every offset whose value equals a magic we already
//! know from the bridge (`MAGIC=` in the environment). One offset will match on
//! every record — that is the field.
//!
//!     MT5_ACCOUNT=.. MT5_PASSWORD=.. MT5_SERVER=.. MAGIC=770077 webterm-magic-probe

use mt5_webterm::parse::pos_size;
use mt5_webterm::protocol::ORDER_REC_SIZE;
use mt5_webterm::protocol::CMD_POSITIONS;
use mt5_webterm::Client;

fn u32_at(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn u64_at(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}
fn i64_at(b: &[u8]) -> i64 {
    u64_at(b) as i64
}

#[tokio::main]
async fn main() {
    let login: u64 = std::env::var("MT5_ACCOUNT").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let password = std::env::var("MT5_PASSWORD").unwrap_or_default();
    let server = std::env::var("MT5_SERVER").unwrap_or_default();
    let magic: u64 = std::env::var("MAGIC").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    if login == 0 || password.is_empty() || server.is_empty() {
        eprintln!("set MT5_ACCOUNT MT5_PASSWORD MT5_SERVER [MAGIC]");
        std::process::exit(2);
    }
    let c = match Client::connect(login, &password, &server).await {
        Ok(c) => c,
        Err(e) => { eprintln!("connect FAILED: {e}"); std::process::exit(1); }
    };
    let frame = c.request(CMD_POSITIONS, &[]).await.expect("positions frame");
    let body = &frame.body;
    if body.len() < 4 {
        eprintln!("empty positions frame");
        return;
    }
    let count = u32_at(body) as usize;
    let size = pos_size();
    println!("positions: {count}, record size {size}, body {} bytes, looking for magic {magic}", body.len());

    let mut o = 4usize;
    for n in 0..count {
        if o + size > body.len() {
            break;
        }
        let rec = &body[o..o + size];
        let ticket = i64_at(rec);
        print!("record {n} ticket {ticket}: ");
        let mut hits = Vec::new();
        // Every 4-byte-aligned offset, read both widths.
        for off in (0..size.saturating_sub(8)).step_by(4) {
            if magic != 0 {
                if u32_at(&rec[off..]) as u64 == magic {
                    hits.push(format!("u32@{off}"));
                }
                if u64_at(&rec[off..]) == magic {
                    hits.push(format!("u64@{off}"));
                }
            }
        }
        if hits.is_empty() {
            println!("no offset holds {magic}");
            // Show the unmapped integer fields so a human can eyeball them.
            for off in [8usize, 20, 100, 140, 148, 172, 180, 252, 260, 264, 268, 336, 340] {
                if off + 8 <= size {
                    println!("    off {off:>3}: u32 {:<12} u64 {}", u32_at(&rec[off..]), u64_at(&rec[off..]));
                }
            }
        } else {
            println!("{}", hits.join(", "));
        }
        o += size;
    }

    // ---- orders ---------------------------------------------------------
    let mut oo = 4 + count * size;
    if oo + 4 <= body.len() {
        let ocnt = u32_at(&body[oo..]) as usize;
        oo += 4;
        println!("orders: {ocnt}, record size {ORDER_REC_SIZE}");
        for n in 0..ocnt {
            if oo + ORDER_REC_SIZE > body.len() {
                break;
            }
            let rec = &body[oo..oo + ORDER_REC_SIZE];
            let ticket = i64_at(rec);
            let mut hits = Vec::new();
            for off in (0..ORDER_REC_SIZE.saturating_sub(8)).step_by(4) {
                if magic != 0 {
                    if u32_at(&rec[off..]) as u64 == magic {
                        hits.push(format!("u32@{off}"));
                    }
                    if u64_at(&rec[off..]) == magic {
                        hits.push(format!("u64@{off}"));
                    }
                }
            }
            println!("order {n} ticket {ticket}: {}", if hits.is_empty() { "no match".to_string() } else { hits.join(", ") });
            oo += ORDER_REC_SIZE;
        }
    }
}
