//! Read-only public-client history check. Dates use broker-clock Unix seconds.
use mt5_session::{
    LoginProfile,
    client::{Client, Config},
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let profile = LoginProfile::from_json(&std::fs::read_to_string(std::env::var(
        "MT5_LOGIN_PROFILE",
    )?)?)?;
    let mut client = Client::connect(&Config {
        address: std::env::var("MT5_ADDRESS")?,
        login: std::env::var("MT5_LOGIN")?.parse()?,
        password: std::env::var("MT5_PASSWORD")?,
        client_build: profile.client_build,
        profile,
    })?;
    let from: i64 = std::env::var("MT5_FROM")?.parse()?;
    let to: i64 = std::env::var("MT5_TO")?.parse()?;
    let symbol = std::env::var("MT5_SYMBOL").unwrap_or_else(|_| "EURUSD".into());
    let output = std::path::PathBuf::from(std::env::var("MT5_PROBE_OUTPUT")?);
    std::fs::create_dir_all(&output)?;
    let orders = client.orders(from, to)?;
    let order_json:Vec<_>=orders.iter().map(|r|serde_json::json!({"ticket":r.ticket,"symbol":r.symbol,"kind":r.kind,"state":r.state,"time":r.time,"history_stamp":r.history_stamp,"time_done":r.time_done,"price":r.price,"volume":r.volume,"volume_initial":r.volume_initial,"stop_limit":r.stop_limit,"expiration":r.expiration})).collect();
    std::fs::write(
        output.join("client-orders.json"),
        serde_json::to_vec(&order_json)?,
    )?;
    println!("order history rows={}", orders.len());
    let ticks = client.ticks(&symbol, from * 1000, to * 1000)?;
    let tick_json:Vec<_>=ticks.iter().map(|r|serde_json::json!({"time_ms":r.time_ms,"bid":r.bid,"ask":r.ask,"last":r.last,"volume":r.volume_units,"flags":r.flags})).collect();
    std::fs::write(
        output.join("client-ticks.json"),
        serde_json::to_vec(&tick_json)?,
    )?;
    println!("tick history symbol={symbol} rows={}", ticks.len());
    client.subscribe_depth(&[symbol.clone()])?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        client.poll(std::time::Duration::from_millis(100))?;
        let depth = client.take_depth_updates();
        if !depth.is_empty() {
            println!(
                "depth records={} entries={}",
                depth.len(),
                depth.iter().map(|r| r.entries.len()).sum::<usize>()
            );
            return Ok(());
        }
    }
    Err("depth subscription produced no response".into())
}
