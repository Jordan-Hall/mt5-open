//! Stage 2: does a real access server accept what the codec builds, and what
//! does it then ask us for?
//!
//! Connect, hello, challenge, auth, and stop. **No order is built, signed or
//! sent**, and nothing here can reach the codec's execution modules.
//!
//! Beyond pass/fail this answers the question that decides whether a
//! terminal-free client is possible at all. The specification says the
//! presence of the tag-28/tag-35 TLVs, and whether a server requires the
//! values derived from them, "must be evaluated for that connection". This is
//! how that connection gets evaluated.
//!
//! Credentials come from the environment so they stay out of the shell history
//! and out of this file. Nothing they contain is ever printed:
//!
//!   MT5_ADDRESS   host:port of the access server
//!   MT5_LOGIN     account number
//!   MT5_PASSWORD  password for that account
//!   MT5_BUILD     client build to announce (default 6182)
//!
//! Run it against a demo account. Authentication changes nothing, but a failed
//! handshake against a live account is still a failed login on a live account.

use std::time::Instant;

use mt5_native::login::LoginValues;
use mt5_session::{LoginIdService, Session};

fn var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is not set"))
}

fn main() {
    if let Err(message) = probe() {
        eprintln!("\n  FAILED: {message}");
        std::process::exit(1);
    }
}

fn probe() -> Result<(), String> {
    let address = var("MT5_ADDRESS")?;
    let login: u64 = var("MT5_LOGIN")?
        .trim()
        .parse()
        .map_err(|_| "MT5_LOGIN is not a number".to_string())?;
    let password = var("MT5_PASSWORD")?;
    let build: u16 = std::env::var("MT5_BUILD")
        .ok()
        .and_then(|b| b.trim().parse().ok())
        .unwrap_or(6182);

    // The login is shown because a wrong account is the likeliest cause of a
    // confusing rejection. The password is not shown, here or anywhere.
    println!("  server  {address}");
    println!("  login   {login}");
    println!("  build   {build}");
    println!("  (no order is sent by this program)\n");

    let started = Instant::now();
    let mut session = Session::connect(&address).map_err(|e| format!("could not connect: {e}"))?;
    println!("  connected in {} ms", started.elapsed().as_millis());

    let started = Instant::now();
    let server_build = session
        .authenticate(login, &password, build)
        .map_err(|e| format!("handshake rejected: {e}"))?;

    println!("  authenticated in {} ms", started.elapsed().as_millis());
    println!("  server build {server_build}");
    println!("\n  Stage 2 passed: a real server accepted the handshake this codec builds.");

    // Only tag numbers and lengths are printed. AuthSummary exists precisely to
    // carry no login, challenge, credential, key or tag values.
    let summary = session
        .auth_summary()
        .ok_or("authenticated, but no authentication result was retained")?;

    println!("\n  --- what this server asks for ---");
    println!(
        "  status {}   server build {}   record build {}",
        summary.status, summary.server_build, summary.record_build
    );
    println!("  certificate required: {}", summary.certificate_required);
    if summary.tags.is_empty() {
        println!("  tags returned: none");
    } else {
        let listed: Vec<String> = summary
            .tags
            .iter()
            .map(|(tag, len)| format!("{tag} ({len} bytes)"))
            .collect();
        println!("  tags returned: {}", listed.join(", "));
    }

    let wants_28 = summary.tags.iter().any(|(tag, _)| *tag == 28);
    let wants_35 = summary.tags.iter().any(|(tag, _)| *tag == 35);
    println!();
    if wants_28 || wants_35 {
        let which = match (wants_28, wants_35) {
            (true, true) => "tag 28 and tag 35",
            (true, false) => "tag 28",
            _ => "tag 35",
        };
        println!("  VERDICT: this server sent {which}.");
        println!("  Synchronization needs values derived from it, and that derivation is an");
        println!("  external calculation this codec does not contain.");
    } else {
        println!("  VERDICT: this server sent neither tag 28 nor tag 35.");
        println!("  The external calculation may not be needed here.");
    }

    // If a loginid service is configured, do exactly what the terminal does:
    // POST the tag material, get the two integers, synchronize with real login
    // values, and read account state. The base URL and guid are the terminal's
    // configuration inputs, supplied here rather than discovered.
    //
    //   MT5_LOGINID_BASE   e.g. https://host[:port]
    //   MT5_LOGINID_GUID   the configured service key
    //
    // Still no order: the command-12 reply is account state, which is a read.
    match (std::env::var("MT5_LOGINID_BASE"), std::env::var("MT5_LOGINID_GUID")) {
        (Ok(base), Ok(guid)) => {
            println!("
  --- command-12 synchronization via the loginid service ---");
            println!("  loginid base {base}");
            let service = LoginIdService::new(base, guid);
            match session.synchronize_via_service(&service) {
                Ok((status, stream)) => {
                    println!("  reply status {status}, {} bytes decoded", stream.len());
                    if status == 0 {
                        println!("
  READY. Reading account state...");
                        match session.read_account_state() {
                            Ok(acct) => {
                                println!("  login {}   balance {:.2}   credit {:.2}   blocked {:.2}   leverage 1:{}",
                                    acct.login, acct.balance, acct.credit, acct.blocked, acct.leverage);
                                println!("  read-only (investor): {}", acct.is_read_only());
                                println!("
  Balance read natively. The phone can do what the terminal does.");
                            }
                            Err(e) => println!("  account state not read: {e}"),
                        }
                    } else {
                        println!("
  Synchronization returned status {status}. Login values reached the");
                        println!("  server but were not accepted; check the base URL and guid.");
                    }
                }
                Err(e) => println!("  synchronization failed: {e}"),
            }
        }
        _ => {
            println!("
  --- no loginid service configured; trying zeroed login values ---");
            let zeroed = LoginValues { login_id: 0, extended_login_id: 0, tag88_value: [0; 8], tag134_value: [0; 8] };
            match session.synchronize(&zeroed) {
                Ok((status, stream)) => println!("  reply status {status}, {} bytes decoded", stream.len()),
                Err(e) => println!("  synchronization failed: {e}"),
            }
            println!("  Set MT5_LOGINID_BASE and MT5_LOGINID_GUID to synchronize for real.");
        }
    }
    Ok(())
}
