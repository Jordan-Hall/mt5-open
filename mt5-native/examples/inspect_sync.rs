//! Print routing and selected symbol/account terms, never raw authentication data.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("provide decoded synchronization file")?;
    let build: i16 = std::env::args()
        .nth(2)
        .ok_or("provide record build")?
        .parse()?;
    let state = mt5_native::sync::parse_synchronized_state(&std::fs::read(path)?, build)?;
    println!(
        "timezone={:?} terms={:?} access_points={:?}",
        state.server_timezone_minutes, state.terms, state.access_points
    );
    for name in ["EURUSD", "XAUUSD", "BTCUSD"] {
        if let Some(s) = state.symbols.iter().find(|s| s.name == name) {
            println!("{s:?}");
        }
    }
    Ok(())
}
