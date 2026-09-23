//! List the broker's published access points and try a login against each.
//!
//! `pick_web_terminal` takes the first endpoint on the standard port and never
//! reconsiders. If the broker rotates that list, or the first host stops
//! serving the web terminal, every login fails identically with no way to tell
//! "wrong host" from "account refused". This tries them all and says which
//! answer each one gives.
//!
//!     MT5_ACCOUNT=.. MT5_PASSWORD=.. MT5_SERVER=.. webterm-access-probe

use mt5_webterm::search;
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

    match search::find_web_terminal(&server).await {
        Ok((host, port)) => println!("chosen by pick_web_terminal: {host}:{port}"),
        Err(e) => println!("pick_web_terminal FAILED: {e}"),
    }

    // The one the transport would use, tried on its own so the result is
    // unambiguous.
    match Client::connect(login, &password, &server).await {
        Ok(_) => println!("login via chosen endpoint: OK"),
        Err(e) => println!("login via chosen endpoint: FAILED {e}"),
    }

    // Every endpoint the broker publishes, so "one bad host" can be told apart
    // from "this client is refused everywhere".
    match search::access_points(&server).await {
        Ok(list) => {
            println!("broker publishes {} access point(s)", list.len());
            for ep in list {
                match Client::connect_via(&ep, login, &password, &server).await {
                    Ok(_) => println!("  {ep}: LOGIN OK"),
                    Err(e) => println!("  {ep}: {e}"),
                }
            }
        }
        Err(e) => println!("could not list access points: {e}"),
    }
}
