//! Print the full specification the web terminal holds for some symbols.
//!
//! The symbol list carries only a name, digits, an id and the calculation
//! mode; contract size, tick size and volume limits come from
//! `CMD_SYMBOL_INFO`. Read-only: one login, no trading.
//!
//!     MT5_ACCOUNT=.. MT5_PASSWORD=.. MT5_SERVER=.. SYMBOLS=XAUUSD,EURUSD webterm-spec-probe

use mt5_webterm::Client;

#[tokio::main]
async fn main() {
    let login: u64 = std::env::var("MT5_ACCOUNT").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let password = std::env::var("MT5_PASSWORD").unwrap_or_default();
    let server = std::env::var("MT5_SERVER").unwrap_or_default();
    let names: Vec<String> = std::env::var("SYMBOLS")
        .unwrap_or_else(|_| "XAUUSD,EURUSD".into())
        .split(',')
        .map(str::to_string)
        .collect();
    let c = match Client::connect(login, &password, &server).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("connect FAILED: {e}");
            std::process::exit(1);
        }
    };
    match c.symbol_info(&names).await {
        Ok(v) => {
            for s in v {
                println!(
                    "{} digits={} point={} contract={} tick_size={} tick_value={} calc={} volume={}..{} step {} \
                     currencies={}/{}/{} trade_mode={} execution={} filling={} stops={} freeze={}",
                    s.name, s.digits, s.point, s.contract_size, s.tick_size, s.tick_value, s.calc_mode, s.min_volume,
                    s.max_volume, s.volume_step, s.base_currency, s.profit_currency, s.margin_currency, s.trade_mode,
                    s.execution_mode, s.filling_flags, s.stops_level, s.freeze_level
                );
            }
        }
        Err(e) => eprintln!("symbol info FAILED: {e}"),
    }
    drop(c);
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
}
