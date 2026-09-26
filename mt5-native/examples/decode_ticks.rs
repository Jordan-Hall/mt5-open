fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input = std::env::args().nth(1).ok_or("provide input")?;
    let output = std::env::args().nth(2).ok_or("provide output")?;
    let decoded = mt5_native::tick_history::decode_tick_history(&std::fs::read(input)?)?;
    let normalized = mt5_native::tick_history::materialize_ticks(
        decoded
            .containers
            .iter()
            .chain(&decoded.trailing)
            .flat_map(|c| &c.ticks),
    )?;
    let rows:Vec<_>=normalized.iter().map(|r|serde_json::json!({
        "time_ms":r.time_ms,"bid":r.bid,"ask":r.ask,"last":r.last,"volume":r.volume_units,"raw_flags":r.flags
    })).collect();
    println!(
        "symbol={} more={} containers={} trailing_rows={} total={}",
        decoded.symbol,
        decoded.more,
        decoded.containers.len(),
        decoded.trailing.len(),
        rows.len()
    );
    std::fs::write(output, serde_json::to_vec(&rows)?)?;
    Ok(())
}
