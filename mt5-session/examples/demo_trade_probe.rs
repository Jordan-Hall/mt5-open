//! Explicit demo-only interoperability probe. A pending order is cancelled
//! before success is reported. Use MT5_DEMO_TEST_LOGIN to opt in per account.
use mt5_native::{
    records::TradeResult,
    trade::{MarketTradeFields, build_trade_record},
};
use mt5_session::{LoginProfile, Session};

fn result(session: &mut Session, request: i32) -> Result<TradeResult, Box<dyn std::error::Error>> {
    for _ in 0..200 {
        let m = session.next_message()?;
        println!(
            "event cmd={} seq={} bytes={} subtype={:?}",
            m.command,
            m.sequence,
            m.payload.len(),
            if m.command == 55 {
                m.payload.first()
            } else {
                None
            }
        );
        if let Ok(dir) = std::env::var("MT5_PROBE_OUTPUT") {
            std::fs::write(
                std::path::Path::new(&dir)
                    .join(format!("trade-{request}-{}-{}.bin", m.command, m.sequence)),
                &m.payload,
            )?;
        }
        if m.command == 55 && m.payload.first() == Some(&35) {
            for r in TradeResult::decode_update(&m.payload)? {
                println!("result={r:?}");
                if r.request_id == request && r.is_final() {
                    return Ok(r);
                }
            }
        }
        if m.command == 55 && matches!(m.payload.first(), Some(31 | 33)) {
            println!(
                "update={:?}",
                mt5_native::updates::decode_update(&m.payload)?
            );
        }
    }
    Err("no definitive trade result".into())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let login: u64 = std::env::var("MT5_LOGIN")?.parse()?;
    if std::env::var("MT5_DEMO_TEST_LOGIN")?.parse::<u64>()? != login {
        return Err("demo opt-in does not match login".into());
    }
    let profile = LoginProfile::from_json(&std::fs::read_to_string(std::env::var(
        "MT5_LOGIN_PROFILE",
    )?)?)?;
    let mut s = Session::connect(std::env::var("MT5_ADDRESS")?)?;
    s.authenticate(login, &std::env::var("MT5_PASSWORD")?, profile.client_build)?;
    let state = s.synchronize(&profile)?.state;
    let symbol = state
        .symbols
        .iter()
        .find(|s| s.name == "EURUSD")
        .ok_or("EURUSD absent")?;
    let action = std::env::var("MT5_TRADE_TEST_ACTION")?;
    if action == "recover" {
        let ticket: i64 =
            std::fs::read_to_string(std::env::var("MT5_TEST_TICKET_FILE")?)?.parse()?;
        let p = state
            .positions
            .iter()
            .find(|p| p.position == ticket as u64 || p.ticket == ticket as u64)
            .ok_or("test position not found")?;
        if p.comment != "native-protocol-check" {
            return Err("not the test position".into());
        }
        println!("recovering own test position, volume={}", p.volume);
        let trade = MarketTradeFields {
            request_id: 272000,
            trade_type: symbol.execution_mode + 1,
            login,
            symbol: symbol.name.clone(),
            digits: symbol.digits,
            volume_units: p.volume,
            order_type: 1 - p.kind,
            fill_policy: 1,
            position_ticket: ticket,
            ..Default::default()
        };
        s.send_trade(&build_trade_record(&trade)?)?;
        let close = result(&mut s, trade.request_id)?;
        if !close.is_success() {
            return Err(format!("recovery failed {}", close.status).into());
        }
        println!("PASS: own test position closed natively");
        return Ok(());
    }
    if !state.positions.is_empty() || !state.orders.is_empty() {
        return Err("demo probe requires an empty account".into());
    }
    println!("timezone={:?}", state.server_timezone_minutes);
    let pending = action == "pending";
    let market = action == "market";
    let mut trade = MarketTradeFields {
        request_id: 271001,
        trade_type: 5,
        login,
        symbol: symbol.name.clone(),
        digits: symbol.digits,
        volume_units: if market {
            symbol.volume_min * 2
        } else if pending {
            symbol.volume_min
        } else {
            0
        },
        order_type: 2,
        fill_policy: 2,
        price: 0.9,
        comment: "native-protocol-check".into(),
        ..Default::default()
    };
    if market {
        trade.trade_type = symbol.execution_mode + 1;
        trade.order_type = 0;
        trade.fill_policy = 1;
        trade.price = 0.0;
    }
    s.send_trade(&build_trade_record(&trade)?)?;
    let r = result(&mut s, trade.request_id)?;
    if !pending && !market {
        if r.status != 10014 {
            return Err(format!("expected invalid-volume rejection, got {}", r.status).into());
        }
        println!("PASS: signed native request rejected with invalid volume as expected");
        return Ok(());
    }
    if !r.is_success() || r.ticket == 0 {
        return Err(format!("pending test failed: {}", r.status).into());
    }
    if let Ok(path) = std::env::var("MT5_TEST_TICKET_FILE") {
        std::fs::write(path, r.ticket.to_string())?;
    }
    if market {
        trade.position_ticket = r.ticket as i64;
        let mut verify = Session::connect(std::env::var("MT5_ADDRESS")?)?;
        verify.authenticate(login, &std::env::var("MT5_PASSWORD")?, profile.client_build)?;
        let observed = verify.synchronize(&profile)?.state;
        println!(
            "synchronized_positions={:?} account={:?}",
            observed.positions, observed.account
        );
        trade.request_id += 1;
        trade.trade_type = 6;
        trade.stop_loss = 0.8;
        trade.take_profit = 1.5;
        s.send_trade(&build_trade_record(&trade)?)?;
        let modify = result(&mut s, trade.request_id)?;
        println!("modify_status={}", modify.status);
        trade.trade_type = symbol.execution_mode + 1;
        trade.order_type = 1;
        trade.stop_loss = 0.0;
        trade.take_profit = 0.0;
        trade.volume_units = symbol.volume_min;
        for _ in 0..2 {
            trade.request_id += 1;
            s.send_trade(&build_trade_record(&trade)?)?;
            let close = result(&mut s, trade.request_id)?;
            if !close.is_success() {
                return Err(format!("close failed {}", close.status).into());
            }
        }
        if !modify.is_success() {
            return Err("position modification failed".into());
        }
        println!("PASS: native market open, modify, partial close, full close");
        return Ok(());
    }
    trade.request_id += 1;
    trade.trade_type = 7;
    trade.order_ticket = r.ticket as i64;
    trade.price = 0.89;
    s.send_trade(&build_trade_record(&trade)?)?;
    let modify = result(&mut s, trade.request_id)?;
    trade.request_id += 1;
    trade.trade_type = 8;
    trade.order_ticket = r.ticket as i64;
    trade.volume_units = 0;
    s.send_trade(&build_trade_record(&trade)?)?;
    let cancel = result(&mut s, trade.request_id)?;
    if !cancel.is_success() {
        return Err(format!("cancel failed: {}", cancel.status).into());
    }
    if !modify.is_success() {
        return Err(format!("modify failed: {}", modify.status).into());
    }
    println!("PASS: native pending order placed and cancelled");
    Ok(())
}
