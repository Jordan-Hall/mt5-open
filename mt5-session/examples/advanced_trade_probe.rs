//! Demo-only, externally supervised interoperability checks. Every checkpoint
//! waits for stdin so an independent terminal can verify state before proceeding.
use mt5_session::{
    LoginProfile,
    client::{Client, Config, TradeOutcome},
    protocol::{
        records::TradeResult,
        trade::{MarketTradeFields, build_trade_record},
    },
};
use std::{
    io::{self, Write},
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn submit(client: &mut Client, fields: &mut MarketTradeFields) -> Result<TradeResult> {
    fields.request_id += 1;
    let result = match client.trade(&build_trade_record(fields)?)? {
        TradeOutcome::Confirmed(r) => r,
        TradeOutcome::Uncertain(reason) => {
            return Err(format!("uncertain trade, supervisor must reconcile: {reason}").into());
        }
    };
    println!(
        "RESULT request={} status={} ticket={}",
        fields.request_id, result.status, result.ticket
    );
    if !result.is_success() {
        return Err(format!("broker rejected request: {}", result.status).into());
    }
    let deadline = Instant::now() + Duration::from_millis(300);
    while Instant::now() < deadline {
        client.poll(Duration::from_millis(25))?;
    }
    Ok(result)
}

fn checkpoint(client: &Client, name: &str) -> Result<()> {
    let out = std::path::PathBuf::from(std::env::var("MT5_PROBE_OUTPUT")?);
    let orders:Vec<_>=client.state.orders.iter().map(|o|serde_json::json!({"ticket":o.ticket,"kind":o.kind,"price":o.price,"stop_limit":o.stop_limit,"expiry":o.expiration,"volume":o.volume,"state":o.state})).collect();
    let positions:Vec<_>=client.state.positions.iter().map(|p|serde_json::json!({"ticket":p.ticket,"position":p.position,"kind":p.kind,"volume":p.volume,"price":p.price_open,"margin_rate":p.margin_rate})).collect();
    std::fs::write(
        out.join(format!("advanced-{name}.json")),
        serde_json::to_vec(
            &serde_json::json!({"orders":orders,"positions":positions,"balance":client.state.account.balance,"margin":client.margin()?}),
        )?,
    )?;
    println!("CHECKPOINT {name}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    if line.trim() != "continue" {
        return Err("supervisor did not verify checkpoint".into());
    }
    Ok(())
}

fn main() -> Result<()> {
    let login: u64 = std::env::var("MT5_LOGIN")?.parse()?;
    if std::env::var("MT5_DEMO_TEST_LOGIN")?.parse::<u64>()? != login {
        return Err("demo opt-in mismatch".into());
    }
    let profile = LoginProfile::from_json(&std::fs::read_to_string(std::env::var(
        "MT5_LOGIN_PROFILE",
    )?)?)?;
    if profile.account_mode(login)? != "demo" {
        return Err("verified demo enrollment required".into());
    }
    let config = Config {
        address: std::env::var("MT5_ADDRESS")?,
        login,
        password: std::env::var("MT5_PASSWORD")?,
        client_build: profile.client_build,
        profile,
    };
    let mut client = Client::connect(&config)?;
    if !client.state.orders.is_empty() || !client.state.positions.is_empty() {
        return Err("empty demo account required".into());
    }
    let symbol = client.symbol("EURUSD")?.clone();
    if symbol.volume_min != 1_000_000 {
        return Err("probe only supports 0.01-lot minimum".into());
    }
    client.subscribe(&[symbol.name.clone()])?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !client.quotes.contains_key(&symbol.name) {
        if Instant::now() > deadline {
            return Err("quote unavailable".into());
        }
        client.poll(Duration::from_millis(100))?;
    }
    let quote = client.quotes[&symbol.name].clone();
    let grid = 10f64.powi(symbol.digits);
    let round = |p: f64| (p * grid).round() / grid;
    let mut f = MarketTradeFields {
        request_id: 481000,
        login,
        symbol: symbol.name.clone(),
        digits: symbol.digits,
        comment: "native-advanced-check".into(),
        ..Default::default()
    };
    checkpoint(&client, "initial")?;
    for kind in 2..=7 {
        let flag = if kind <= 3 {
            2
        } else if kind <= 5 {
            4
        } else {
            8
        };
        if symbol.order_flags & flag == 0 {
            println!("UNSUPPORTED pending type={kind} broker symbol flags");
            continue;
        }
        f.trade_type = 5;
        f.order_type = kind;
        f.fill_policy = 2;
        f.order_ticket = 0;
        f.volume_units = symbol.volume_min;
        let above = matches!(kind, 3 | 4 | 6);
        f.price = round(if above {
            quote.ask + 0.05
        } else {
            quote.bid - 0.05
        });
        f.stop_limit_price = if kind == 6 {
            round(f.price - 0.01)
        } else if kind == 7 {
            round(f.price + 0.01)
        } else {
            0.0
        };
        f.expiration_type = 2;
        f.expiration_time = quote.time_ms / 1000 + 3600;
        let placed = submit(&mut client, &mut f)?;
        checkpoint(&client, &format!("pending-{kind}"))?;
        f.order_ticket = placed.ticket as i64;
        f.trade_type = 7;
        f.price = round(f.price + if above { 0.01 } else { -0.01 });
        submit(&mut client, &mut f)?;
        checkpoint(&client, &format!("modified-{kind}"))?;
        f.trade_type = 8;
        submit(&mut client, &mut f)?;
        checkpoint(&client, &format!("cancelled-{kind}"))?;
    }
    f.volume_units = symbol
        .volume_min
        .checked_mul(2)
        .ok_or("probe volume overflow")?;
    if f.volume_units > symbol.volume_max {
        return Err("probe volume exceeds symbol maximum".into());
    }
    f.order_ticket = 0;
    f.price = 0.0;
    f.stop_limit_price = 0.0;
    f.expiration_type = 0;
    f.expiration_time = 0;
    f.fill_policy = 1;
    let mut positions = Vec::new();
    for side in 0..=1 {
        f.trade_type = symbol.execution_mode + 1;
        f.order_type = side;
        let opened = submit(&mut client, &mut f)?;
        positions.push(opened.ticket);
        checkpoint(&client, &format!("market-{side}"))?;
    }
    f.order_type = 0;
    f.position_ticket = positions[1] as i64;
    f.volume_units = symbol.volume_min;
    submit(&mut client, &mut f)?;
    checkpoint(&client, "partial-hedge")?;
    f.trade_type = 10;
    f.order_type = 0;
    f.position_ticket = positions[0] as i64;
    f.opposite_position_ticket = positions[1] as i64;
    submit(&mut client, &mut f)?;
    checkpoint(&client, "closed-by")?;
    let remaining = client
        .state
        .positions
        .first()
        .ok_or("expected close-by remainder")?
        .clone();
    if client.state.positions.len() != 1 || remaining.volume != symbol.volume_min {
        return Err("unexpected close-by remainder".into());
    }
    f.trade_type = symbol.execution_mode + 1;
    f.order_type = 1 - remaining.kind;
    f.position_ticket = remaining.ticket as i64;
    f.opposite_position_ticket = 0;
    f.volume_units = remaining.volume;
    submit(&mut client, &mut f)?;
    checkpoint(&client, "closed-remainder")?;
    if !client.state.orders.is_empty() || !client.state.positions.is_empty() {
        return Err("native state still reports exposure".into());
    }
    println!(
        "PASS pending types, specified expiry, hedge margin, partial close and close-by remainder"
    );
    Ok(())
}
