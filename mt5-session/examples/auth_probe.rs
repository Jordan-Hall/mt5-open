//! Verify native authentication and synchronization without sending orders.
//! Credentials stay in the environment. --json emits a sanitized result;
//! --auth-only stops after the password exchange and cannot prove login readiness.
use mt5_session::{LoginProfile, endpoints::EndpointPool};
use serde_json::{Value, json};

fn var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is not set"))
}

fn probe(report: &mut Value) -> Result<(), String> {
    let auth_only = std::env::args().any(|arg| arg == "--auth-only");
    let args: Vec<_> = std::env::args().collect();
    let hold = if let Some(index) = args.iter().position(|a| a == "--hold-seconds") {
        args.get(index + 1)
            .ok_or("missing hold duration")?
            .parse::<u64>()
            .map_err(|_| "invalid hold duration")?
    } else {
        0
    };
    if hold > 300 || auth_only && hold > 0 {
        return Err("hold duration must be 0..300 and requires synchronization".into());
    }
    let profile = if auth_only {
        None
    } else {
        let input = std::fs::read_to_string(var("MT5_LOGIN_PROFILE")?)
            .map_err(|_| "cannot read MT5_LOGIN_PROFILE")?;
        Some(LoginProfile::from_json(&input).map_err(|e| e.to_string())?)
    };
    let login: u64 = var("MT5_LOGIN")?.parse().map_err(|_| "invalid MT5_LOGIN")?;
    // Reject an enrolled profile for another account before contacting the broker.
    if let Some(p) = &profile {
        p.account_mode(login).map_err(|e| e.to_string())?;
        if let Ok(server) = std::env::var("MT5_SERVER") {
            p.validate_account(login, &server)
                .map_err(|e| e.to_string())?;
        }
    }
    let build = match std::env::var("MT5_BUILD") {
        Ok(value) => value.parse::<u16>().map_err(|_| "invalid MT5_BUILD")?,
        Err(_) => profile.as_ref().map(|p| p.client_build).unwrap_or(6182),
    };
    report["client_build"] = json!(build);
    report["stage"] = json!("connect");
    let mut endpoints = EndpointPool::new(&var("MT5_ADDRESS")?).map_err(|e| e.to_string())?;
    let mut session = endpoints.connect().map_err(|e| e.to_string())?;
    report["stage"] = json!("authenticate");
    let server_build = session
        .authenticate(login, &var("MT5_PASSWORD")?, build)
        .map_err(|e| e.to_string())?;
    report["password_accepted"] = json!(true);
    report["server_build"] = json!(server_build);
    if let Some(summary) = session.auth_summary() {
        report["record_build"] = json!(summary.record_build);
        report["authentication_tag_sizes"] = json!(summary.tags);
    }
    if let Some(profile) = profile {
        report["stage"] = json!("synchronize");
        let sync = session.synchronize(&profile).map_err(|e| e.to_string())?;
        report["challenge_computed"] = json!(true);
        report["server_identity_verified"] = json!(true);
        report["synchronized"] = json!(true);
        report["account_identity_verified"] = json!(sync.account.login == login);
        report["read_only"] = json!(session.is_read_only().map_err(|e| e.to_string())?);
        report["synchronization_bytes"] = json!(sync.payload.len());
        report["symbols"] = json!(sync.state.symbols.len());
        report["access_points"] = json!(sync.state.access_points.len());
        if hold > 0 {
            use std::time::{Duration, Instant};
            let symbol = sync
                .state
                .symbols
                .iter()
                .find(|s| s.name == "EURUSD")
                .ok_or("EURUSD unavailable for quote observation")?;
            session.subscribe(&[symbol.id]).map_err(|e| e.to_string())?;
            report["stage"] = json!("observe");
            let start = Instant::now();
            let mut ping = Instant::now();
            let mut quotes = 0usize;
            while start.elapsed() < Duration::from_secs(hold) {
                if ping.elapsed() >= Duration::from_secs(10) {
                    session.send_request(10, &[]).map_err(|e| e.to_string())?;
                    ping = Instant::now();
                }
                if let Some(message) = session
                    .poll_message(Duration::from_secs(1))
                    .map_err(|e| e.to_string())?
                {
                    if matches!(message.command, 50 | 51) {
                        quotes += mt5_session::protocol::quotes::decode_quotes(
                            &message.payload,
                            message.command,
                        )
                        .map_err(|e| e.to_string())?
                        .len();
                    }
                }
                report["held_seconds"] = json!(start.elapsed().as_secs());
                report["quote_records"] = json!(quotes);
            }
            if quotes == 0 {
                return Err("no quotes received during observation".into());
            }
        }
    }
    report["stage"] = json!("complete");
    report["success"] = json!(true);
    Ok(())
}

fn main() {
    let mut report = json!({"success":false,"stage":"configuration",
        "password_accepted":false,"challenge_computed":false,"server_identity_verified":false,
        "synchronized":false,"account_identity_verified":false});
    if let Err(error) = probe(&mut report) {
        report["error"] = json!(error);
    }
    if std::env::args().any(|arg| arg == "--json") {
        println!("{report}");
    } else {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    }
    if report["success"] != true {
        std::process::exit(1);
    }
}
