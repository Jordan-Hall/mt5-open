//! Login + account + symbol count + one quote. Credentials from the environment.

use mt5_webterm::Client;

#[tokio::main]
async fn main() {
    let login: u64 = std::env::var("MT5_ACCOUNT").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let password = std::env::var("MT5_PASSWORD").unwrap_or_default();
    let server = std::env::var("MT5_SERVER").unwrap_or_default();
    if login == 0 || password.is_empty() || server.is_empty() {
        eprintln!("set MT5_ACCOUNT MT5_PASSWORD MT5_SERVER");
        std::process::exit(2);
    }
    match Client::connect(login, &password, &server).await {
        Ok(c) => {
            match c.account().await {
                Ok(a) => println!(
                    "READY login={} server={} balance={:.2} equity={:.2} currency={} symbols={}",
                    a.login,
                    a.server,
                    a.balance,
                    a.equity,
                    a.currency,
                    c.symbols().await.len()
                ),
                Err(e) => {
                    eprintln!("account: {e}");
                    std::process::exit(1);
                }
            }
            if let Ok(q) = c.wait_quote("XAUUSD").await {
                println!("quote XAUUSD {}/{}", q.bid, q.ask);
            }
        }
        Err(e) => {
            eprintln!("FAILED {e}");
            std::process::exit(1);
        }
    }
}
