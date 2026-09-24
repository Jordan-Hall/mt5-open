//! Read-only account/book readiness probe. It never places or cancels orders.
//!
//! A distant limit order can still fill, so automatic placement is not a safe
//! diagnostic. Exercise writes separately with explicit demo-account controls.

use mt5_webterm::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os("CANCEL_TICKET").is_some() {
        return Err("this probe is read-only; cancellation must be an explicit application operation".into());
    }
    let login: u64 = std::env::var("MT5_ACCOUNT")?.parse()?;
    let password = std::env::var("MT5_PASSWORD")?;
    let server = std::env::var("MT5_SERVER")?;
    if login == 0 || password.is_empty() || server.is_empty() {
        return Err("set MT5_ACCOUNT, MT5_PASSWORD and MT5_SERVER".into());
    }
    let client = Client::connect(login, &password, &server).await?;
    let account = client.account().await?;
    let (positions, orders) = client.positions_and_orders().await?;
    println!("READ-ONLY: balance={} currency={} positions={} orders={}",
        account.balance, account.currency, positions.len(), orders.len());
    println!("Book retrieval succeeded. Order placement and cancellation were not tested.");
    Ok(())
}
