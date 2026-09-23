//! List a broker's MT5 server names, so the app can offer them rather than
//! asking anyone to type one exactly right.
//!
//!     BROKER=ExampleBroker webterm-servers

#[tokio::main]
async fn main() {
    let company = std::env::var("BROKER").unwrap_or_else(|_| "ExampleBroker".into());
    match mt5_webterm::search::list_servers(&company).await {
        Ok(names) => {
            println!("{} server(s) for {company}:", names.len());
            for n in names {
                println!("  {n}");
            }
        }
        Err(e) => {
            eprintln!("FAILED {e}");
            std::process::exit(1);
        }
    }
}
