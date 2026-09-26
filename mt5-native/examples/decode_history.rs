//! Decode a privately saved native history response into JSON lines.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let kind = args.next().ok_or("expected bars or deals")?;
    let bytes = std::fs::read(args.next().ok_or("expected input file")?)?;
    let path = args.next().ok_or("expected output file")?;
    let mut rows = Vec::new();
    match kind.as_str() {
        "bars" => {
            for history in mt5_native::bars::decode_bar_history(&bytes)? {
                for b in history.bars {
                    rows.push(serde_json::json!({"symbol":history.symbol,"time":b.time,"open":b.open,"high":b.high,"low":b.low,"close":b.close,"tick_volume":b.tick_volume,"spread":b.spread,"real_volume":b.real_volume}));
                }
            }
        }
        "deals" => {
            if let mt5_native::trade_history::TradeHistory::Deals(deals) =
                mt5_native::trade_history::decode_trade_history(&bytes)?
            {
                for d in deals {
                    rows.push(serde_json::json!({"ticket":d.ticket,"order":d.order,"position_id":d.position,"symbol":d.symbol,"time":d.time,"time_msc":d.time_ms,"type":d.kind,"entry":d.entry,"price":d.price_open,"volume":d.volume as f64/1e8,"profit":d.profit,"commission":d.commission,"swap":d.swap,"comment":d.comment}));
                }
            }
        }
        _ => return Err("unknown history type".into()),
    }
    println!("Decoded {} {kind} records", rows.len());
    std::fs::write(path, serde_json::to_vec(&rows)?)?;
    Ok(())
}
