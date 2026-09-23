//! Environment metadata for the command-12 synchronization request (tag 127,
//! modern profile).
//!
//! This completes the previously-deferred part of the sync request: the
//! tab-separated `key=value` metadata string, whose only variable pieces are
//! derived deterministically from the device hardware id and the client build.
//! The computer name comes from a fully specified legacy subtractive
//! pseudo-random generator (a .NET `Random` reimplementation) seeded from the
//! first four hardware-id bytes. No network or host inspection occurs — this is
//! an observed construction profile, and a server may accept other truthful
//! metadata.

/// Legacy subtractive PRNG (unchecked signed 32-bit arithmetic).
struct LegacyRandom {
    a: [i32; 56],
    p: usize,
    q: usize,
}

const M: i32 = 2147483647;

impl LegacyRandom {
    fn new(seed: i32) -> Self {
        let s = if seed == i32::MIN { 2147483647 } else { seed.abs() };
        let mut a = [0i32; 56];
        let mut mj = 161803398i32.wrapping_sub(s);
        let mut mk = 1i32;
        a[55] = mj;
        for i in 1..=54usize {
            let j = (21 * i) % 55;
            a[j] = mk;
            mk = mj.wrapping_sub(mk);
            if mk < 0 {
                mk = mk.wrapping_add(M);
            }
            mj = a[j];
        }
        for _ in 0..4 {
            for i in 1..=55usize {
                a[i] = a[i].wrapping_sub(a[1 + ((i + 30) % 55)]);
                if a[i] < 0 {
                    a[i] = a[i].wrapping_add(M);
                }
            }
        }
        LegacyRandom { a, p: 0, q: 21 }
    }

    /// Return `trunc(sample * n)`, `sample` in `[0, 1)`.
    fn next_index(&mut self, n: usize) -> usize {
        self.p += 1;
        if self.p >= 56 {
            self.p = 1;
        }
        self.q += 1;
        if self.q >= 56 {
            self.q = 1;
        }
        let mut r = self.a[self.p].wrapping_sub(self.a[self.q]);
        if r == M {
            r -= 1;
        }
        if r < 0 {
            r = r.wrapping_add(M);
        }
        self.a[self.p] = r;
        ((r as f64) * (1.0 / M as f64) * n as f64).trunc() as usize
    }
}

const CONSONANTS: &[u8] = b"BCDFGHJKLMNPQRSTVWXYZ";
const VOWELS: &[u8] = b"AEIOU";
const SUFFIXES: [&str; 5] = ["-PC", "-DESKTOP", "-LAPTOP", "-HOME", "-OFFICE"];

/// Deterministic computer name: two consonant/vowel pairs and a suffix chosen by
/// `hardware_id[15] mod 5`.
pub fn computer_name(hardware_id: &[u8; 16]) -> String {
    let seed = i32::from_le_bytes([hardware_id[0], hardware_id[1], hardware_id[2], hardware_id[3]]);
    let mut rng = LegacyRandom::new(seed);
    let c1 = CONSONANTS[rng.next_index(CONSONANTS.len())] as char;
    let v1 = VOWELS[rng.next_index(VOWELS.len())] as char;
    let c2 = CONSONANTS[rng.next_index(CONSONANTS.len())] as char;
    let v2 = VOWELS[rng.next_index(VOWELS.len())] as char;
    let suffix = SUFFIXES[(hardware_id[15] % 5) as usize];
    format!("{c1}{v1}{c2}{v2}{suffix}")
}

fn upper_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Build the tab-separated environment metadata string (tag-127 text, before its
/// UTF-16LE encoding and trailing NUL).
pub fn environment_metadata(hardware_id: &[u8; 16], client_build: u32) -> String {
    let h = upper_hex(hardware_id); // 32 uppercase hex chars
    let computer = computer_name(hardware_id);
    [
        "file=terminal64.exe".to_string(),
        format!("version={client_build}"),
        "cert_company=MetaQuotes Ltd".to_string(),
        "cert_issuer=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1".to_string(),
        "cert_serial=04390a4c5f8906a1d7052c1768d45047".to_string(),
        format!("os_ver=Windows 11 build 22{}", &h[0..3]),
        format!("os_id={}-{}-{}-AAOEM", &h[3..7], &h[7..11], &h[11..15]),
        format!("computer={computer}"),
    ]
    .join("\t")
        + "\t"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hardware_id;

    #[test]
    fn computer_name_is_deterministic_and_well_formed() {
        let hw = hardware_id(12345678);
        let a = computer_name(&hw);
        assert_eq!(a, computer_name(&hw), "deterministic");
        assert_eq!(a, "NIMO-DESKTOP"); // ground truth from the §8.2 generator
        let (name, suffix) = a.split_once('-').map(|(n, s)| (n.to_string(), format!("-{s}"))).unwrap();
        assert_eq!(name.len(), 4, "four letters before the suffix");
        assert!(name.chars().all(|c| c.is_ascii_uppercase()));
        assert_eq!(&suffix, SUFFIXES[(hw[15] % 5) as usize]);
    }

    #[test]
    fn metadata_has_the_eight_documented_fields() {
        let hw = hardware_id(12345678);
        let meta = environment_metadata(&hw, 5500);
        assert!(meta.ends_with('\t'));
        let fields: Vec<&str> = meta.trim_end_matches('\t').split('\t').collect();
        assert_eq!(fields.len(), 8);
        assert_eq!(fields[0], "file=terminal64.exe");
        assert_eq!(fields[1], "version=5500");
        assert!(fields[5].starts_with("os_ver=Windows 11 build 22"));
        assert!(fields[6].starts_with("os_id=") && fields[6].ends_with("-AAOEM"));
        assert!(fields[7].starts_with("computer="));
        // os_id embeds hardware-id hex slices.
        let h = upper_hex(&hw);
        assert_eq!(fields[6], format!("os_id={}-{}-{}-AAOEM", &h[3..7], &h[7..11], &h[11..15]));
    }

    #[test]
    fn legacy_random_matches_dotnet_reference_seed() {
        // The .NET Random(seed) subtractive generator produces a fixed sequence.
        // For seed 0 the first three Next(1000) values are a stable reference of
        // the algorithm's wiring; regenerating them here guards against drift.
        let mut r = LegacyRandom::new(0);
        let seq: Vec<usize> = (0..3).map(|_| r.next_index(1000)).collect();
        assert_eq!(seq, vec![726, 817, 768]);
    }
}
