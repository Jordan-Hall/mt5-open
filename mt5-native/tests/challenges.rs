use mt5_native::challenge::{Version, solve};

#[test]
fn synthetic_programs_match_terminal_6182_reference_results() {
    for (index, line) in include_str!("fixtures/challenges-6182.tsv")
        .lines()
        .enumerate()
        .skip(1)
    {
        let fields: Vec<_> = line.split('\t').collect();
        let version = match fields[0] {
            "3" => Version::Tag35,
            "4" => Version::Tag28,
            other => panic!("unexpected version {other}"),
        };
        let seed = u64::from_str_radix(fields[1], 16).unwrap();
        let program = mt5_native::hexutil::decode(fields[2]);
        let expected = u64::from_str_radix(fields[3], 16).unwrap();
        assert_eq!(
            solve(version, &program, seed).unwrap(),
            expected,
            "fixture line {}",
            index + 1
        );
    }
}

#[test]
fn halt_does_not_execute_trailing_instructions() {
    for (version, halt, shift) in [(Version::Tag28, 106u64, 11), (Version::Tag35, 114, 17)] {
        let mut program: Vec<_> = [halt << shift, 1, 2]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let expected = solve(version, &program, 123).unwrap();
        program.extend([u64::MAX; 3].into_iter().flat_map(u64::to_le_bytes));
        assert_eq!(solve(version, &program, 123).unwrap(), expected);
    }
}
