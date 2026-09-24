use mt5_webterm::parse::{Quote, QuoteDecoder, Symbol};
use std::collections::HashMap;
use std::hint::black_box;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn reference(body: &[u8], symbols: &HashMap<String, Symbol>) -> Vec<Quote> {
    let by_id: HashMap<u32, &Symbol> = symbols.values().map(|s| (s.id, s)).collect();
    let mut output = Vec::new();
    for record in body.chunks_exact(50) {
        let id = u32::from_le_bytes(record[..4].try_into().unwrap());
        let Some(symbol) = by_id.get(&id) else { continue };
        let scale = 10f64.powi(symbol.digits as i32);
        output.push(Quote {
            symbol: symbol.name.clone(), symbol_id: id,
            bid: f64::from_le_bytes(record[12..20].try_into().unwrap()) / scale,
            ask: f64::from_le_bytes(record[20..28].try_into().unwrap()) / scale,
            time_ms: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64,
        });
    }
    output
}

fn measure(mut f: impl FnMut() -> Vec<Quote>) -> Duration {
    let mut runs = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        for _ in 0..2000 { black_box(f()); }
        runs.push(start.elapsed());
    }
    runs.sort_unstable();
    runs[2]
}

fn main() {
    let symbols: HashMap<_, _> = (0..512).map(|id| {
        let name = format!("symbol-{id}");
        (name.clone(), Symbol { name, id, digits: 5, ..Default::default() })
    }).collect();
    let mut body = vec![0u8; 64 * 50];
    for (id, record) in body.chunks_exact_mut(50).enumerate() {
        record[..4].copy_from_slice(&(id as u32).to_le_bytes());
        record[12..20].copy_from_slice(&123450f64.to_le_bytes());
        record[20..28].copy_from_slice(&123460f64.to_le_bytes());
    }
    let decoder = QuoteDecoder::new(&symbols);
    let expected = reference(&body, &symbols);
    let actual = decoder.decode(&body).unwrap();
    assert_eq!(actual.len(), expected.len());
    for (a, b) in actual.iter().zip(&expected) {
        assert_eq!((&a.symbol, a.symbol_id, a.bid, a.ask), (&b.symbol, b.symbol_id, b.bid, b.ask));
    }
    let old = measure(|| reference(black_box(&body), black_box(&symbols)));
    let new = measure(|| decoder.decode(black_box(&body)).unwrap());
    println!("quotes: rebuilt-index={old:?}, cached-index={new:?}, ratio={:.2}x (512 symbols/64 ticks, median of 5; CPU-only)", old.as_secs_f64() / new.as_secs_f64());
}
