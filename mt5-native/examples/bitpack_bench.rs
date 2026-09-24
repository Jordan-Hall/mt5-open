use mt5_native::bitpack::BitReader;
use std::hint::black_box;
use std::time::{Duration, Instant};

fn reference(data: &[u8], position: usize, width: usize) -> u64 {
    assert!(position + width <= data.len() * 8);
    let mut value = 0;
    for i in 0..width {
        value |= (((data[(position + i) / 8] >> ((position + i) % 8)) & 1) as u64) << i;
    }
    value
}

fn measure(mut f: impl FnMut() -> u64) -> Duration {
    let mut runs = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        black_box(f());
        runs.push(start.elapsed());
    }
    runs.sort_unstable();
    runs[2]
}

fn main() {
    let data: Vec<u8> = (0..4096).map(|i| (i * 37 + 11) as u8).collect();
    let cases: Vec<_> = (0..1000).map(|i| (i * 17, [13, 21, 32, 47, 64][i % 5])).collect();
    for &(position, width) in &cases {
        assert_eq!(reference(&data, position, width), BitReader::with_position(&data, position).bits(width).unwrap());
    }
    let old = measure(|| {
        let mut total = 0;
        for _ in 0..200 {
            for &(position, width) in black_box(&cases) {
                total ^= black_box(reference(black_box(&data), position, width));
            }
        }
        total
    });
    let new = measure(|| {
        let mut total = 0;
        for _ in 0..200 {
            for &(position, width) in black_box(&cases) {
                total ^= black_box(BitReader::with_position(black_box(&data), position).bits(width).unwrap());
            }
        }
        total
    });
    println!("bit fields: per-bit={old:?}, byte-chunk={new:?}, ratio={:.2}x (median of 5; synthetic CPU-only)", old.as_secs_f64() / new.as_secs_f64());
}
