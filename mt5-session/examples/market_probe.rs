//! Read-only native market-data probe. Uses the same environment as auth_probe.
use mt5_native::{
    quotes::decode_quotes, requests::make_trade_history_request, subscription::bar_month_request,
};
use mt5_session::{LoginProfile, Session};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let profile = LoginProfile::from_json(&std::fs::read_to_string(std::env::var(
        "MT5_LOGIN_PROFILE",
    )?)?)?;
    let mut session = Session::connect(std::env::var("MT5_ADDRESS")?)?;
    session.authenticate(
        std::env::var("MT5_LOGIN")?.parse()?,
        &std::env::var("MT5_PASSWORD")?,
        profile.client_build,
    )?;
    let sync = session.synchronize(&profile)?;
    println!(
        "symbols={} orders={} positions={} terms={:?}",
        sync.state.symbols.len(),
        sync.state.orders.len(),
        sync.state.positions.len(),
        sync.state.terms
    );
    let symbol = std::env::var("MT5_SYMBOL").unwrap_or_else(|_| "EURUSD".into());
    let info = sync
        .state
        .symbols
        .iter()
        .find(|s| s.name == symbol)
        .ok_or("symbol not found")?;
    println!("symbol={info:?}");
    let q = session.subscribe(&[info.id])?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let d = session.send_request(101, &make_trade_history_request(33, now - 7 * 86400, now))?;
    let year = std::env::var("MT5_YEAR")?.parse()?;
    let month = std::env::var("MT5_MONTH")?.parse()?;
    let h = session.send_request(102, &bar_month_request(&symbol, year, month, 1)?)?;
    println!("requests quotes={q} deals={d} bars={h}");
    let mut seen = [false; 3];
    for index in 0..200 {
        let m = session.next_message()?;
        println!(
            "message cmd={} seq={} bytes={}",
            m.command,
            m.sequence,
            m.payload.len()
        );
        if let Ok(dir) = std::env::var("MT5_PROBE_OUTPUT") {
            std::fs::write(
                std::path::Path::new(&dir)
                    .join(format!("{index}-{}-{}.bin", m.command, m.sequence)),
                &m.payload,
            )?;
        }
        match m.command {
            50 | 51 => {
                for row in decode_quotes(&m.payload, m.command)? {
                    println!("quote={row:?}");
                }
                seen[0] = true;
            }
            101 if m.sequence == d => seen[1] = true,
            102 if m.sequence == h => seen[2] = true,
            _ => (),
        }
        if seen.iter().all(|v| *v) {
            return Ok(());
        }
    }
    Err("not all requested data arrived".into())
}
