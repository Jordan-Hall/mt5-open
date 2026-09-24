//! Experimental local evaluator for the legacy tag-28 instruction format.
//!
//! This is not the build-4852+ evaluator and does not implement tag 35.
//! There is no network I/O, native-code execution, or profile autodetection.
//! Tests establish the reconstructed arithmetic, not acceptance by a broker.

use crate::error::{ProtocolError, Result};
use std::fmt;

const FIRST_NEW_BUILD: u16 = 4852;
const MAX_INSTRUCTIONS: usize = 4096;
const MAX_PROGRAM_BYTES: usize = MAX_INSTRUCTIONS * 24 + 24;
const HALT: u8 = 0xd8;
const ACCUMULATOR: u8 = 0xf5;

fn selector(word: u64) -> u8 {
    ((word >> 21) & 0xff) as u8
}

fn require_legacy_build(server_build: u16) -> Result<()> {
    if server_build == 0 || server_build >= FIRST_NEW_BUILD {
        return Err(ProtocolError::new(format!(
            "legacy tag-28 evaluator does not support server build {server_build}"
        )));
    }
    Ok(())
}

/// Evaluate raw tag-28 bytes using the reconstructed pre-4852 grammar.
///
/// Instructions are three little-endian u64 words: opcode, lhs, rhs. The
/// selector occupies bits 21..28. A lhs selector of 0xf5 selects the previous
/// accumulator; rhs is always literal. Arithmetic wraps modulo 2^64. Shifts
/// use rhs modulo 24. Opcode 0xd8 returns before fetching operand words;
/// aligned words after that terminator are ignored by this legacy grammar.
/// Unknown instructions fail rather than being interpreted as another profile.
pub fn decode_tag28(server_build: u16, program: &[u8]) -> Result<u64> {
    require_legacy_build(server_build)?;
    if program.is_empty() || program.len() % 8 != 0 {
        return Err(ProtocolError::new(
            "legacy tag-28 program must contain complete u64 words",
        ));
    }
    if program.len() > MAX_PROGRAM_BYTES {
        return Err(ProtocolError::new("legacy tag-28 program exceeds size limit"));
    }
    let mut words = program.chunks_exact(8).map(|chunk| {
        u64::from_le_bytes(chunk.try_into().expect("chunks_exact yields eight bytes"))
    });
    let mut accumulator = 0u64;
    let mut executed = 0usize;
    loop {
        let instruction = words
            .next()
            .ok_or_else(|| ProtocolError::new("legacy tag-28 program has no terminator"))?;
        let opcode = selector(instruction);
        if opcode == HALT {
            return Ok(accumulator);
        }
        if executed == MAX_INSTRUCTIONS {
            return Err(ProtocolError::new("legacy tag-28 instruction limit exceeded"));
        }
        if !matches!(opcode, 0x54 | 0x70 | 0x91 | 0xab | 0xa9 | 0xb1 | 0xc8) {
            return Err(ProtocolError::new(format!(
                "unsupported legacy opcode 0x{opcode:02x} at instruction {executed}"
            )));
        }
        let lhs = words
            .next()
            .ok_or_else(|| ProtocolError::new("truncated legacy tag-28 operands"))?;
        let rhs = words
            .next()
            .ok_or_else(|| ProtocolError::new("truncated legacy tag-28 operands"))?;
        let lhs = if selector(lhs) == ACCUMULATOR { accumulator } else { lhs };
        accumulator = match opcode {
            0x54 => lhs & rhs,
            0x70 => lhs | rhs,
            0x91 => lhs ^ rhs,
            0xab => lhs.wrapping_add(rhs),
            0xa9 => lhs.wrapping_sub(rhs),
            0xb1 => lhs << (rhs % 24),
            0xc8 => lhs >> (rhs % 24),
            _ => unreachable!("opcode validated above"),
        };
        executed += 1;
    }
}

/// The legacy primary login value only. No extended value is fabricated.
#[derive(Clone, PartialEq, Eq)]
pub struct LegacyLoginId {
    pub login_id: u64,
    pub tag88_value: [u8; 8],
}

impl fmt::Debug for LegacyLoginId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LegacyLoginId").finish_non_exhaustive()
    }
}

/// Compute F28 locally and apply the legacy primary-login wrapper.
/// This result alone cannot satisfy a profile that also requires tag 134.
pub fn derive_login_id(
    login: u64,
    client_build: u16,
    server_build: u16,
    challenge: &[u8; 16],
    tag28: &[u8],
) -> Result<LegacyLoginId> {
    if client_build == 0 {
        return Err(ProtocolError::new("client build must be positive"));
    }
    let f28 = decode_tag28(server_build, tag28)?;
    let wire_value = f28 ^ login ^ u64::from(client_build) ^ super::q_of(challenge);
    Ok(LegacyLoginId {
        login_id: wire_value ^ super::K,
        tag88_value: wire_value.to_le_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(words: &[u64]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    fn op(code: u8) -> u64 {
        u64::from(code) << 21
    }

    fn eval(code: u8, lhs: u64, rhs: u64) -> u64 {
        decode_tag28(4851, &bytes(&[op(code), lhs, rhs, op(HALT)])).unwrap()
    }

    #[test]
    fn all_seven_operations_have_explicit_vectors() {
        assert_eq!(eval(0x54, 0xf0, 0x3c), 0x30);
        assert_eq!(eval(0x70, 0xf0, 0x3c), 0xfc);
        assert_eq!(eval(0x91, 0xf0, 0x3c), 0xcc);
        assert_eq!(eval(0xab, 30, 12), 42);
        assert_eq!(eval(0xa9, 30, 12), 18);
        assert_eq!(eval(0xb1, 3, 4), 48);
        assert_eq!(eval(0xc8, 48, 4), 3);
    }

    #[test]
    fn addition_subtraction_and_shifts_wrap_as_u64() {
        assert_eq!(eval(0xab, u64::MAX, 1), 0);
        assert_eq!(eval(0xa9, 0, 2), u64::MAX - 1);
        assert_eq!(eval(0xb1, u64::MAX, 1), u64::MAX - 1);
        assert_eq!(eval(0xc8, 1 << 63, 23), 1 << 40);
    }

    #[test]
    fn shifts_reduce_modulo_24_not_64() {
        for count in [0, 23, 24, 25, 47, 48, 63, 64, u64::MAX] {
            assert_eq!(eval(0xb1, 1, count), 1 << (count % 24));
            assert_eq!(eval(0xc8, 1 << 63, count), (1 << 63) >> (count % 24));
        }
    }

    #[test]
    fn accumulator_marker_applies_only_to_left_operand() {
        let marker = op(ACCUMULATOR) | 123;
        let program = bytes(&[
            op(0xab), 40, 2,
            op(0x91), marker, marker,
            op(HALT),
        ]);
        assert_eq!(decode_tag28(4199, &program).unwrap(), 42 ^ marker);
    }

    #[test]
    fn selector_ignores_bits_outside_21_through_28() {
        let noise = !(0xffu64 << 21);
        let program = bytes(&[op(0xab) | noise, 17, 25, op(HALT) | noise]);
        assert_eq!(decode_tag28(4199, &program).unwrap(), 42);
    }

    #[test]
    fn halt_does_not_read_operands_and_ignores_aligned_trailer() {
        assert_eq!(decode_tag28(4199, &bytes(&[op(HALT)])).unwrap(), 0);
        let program = bytes(&[op(0xab), 1, 2, op(HALT), u64::MAX, 0]);
        assert_eq!(decode_tag28(4199, &program).unwrap(), 3);
    }

    #[test]
    fn malformed_programs_are_errors_not_panics() {
        for invalid in [
            vec![], vec![0], vec![0; 7], vec![0; 9], bytes(&[op(0xab)]),
            bytes(&[op(0xab), 1]), bytes(&[op(0xab), 1, 2]),
            bytes(&[op(0x00), 1, 2, op(HALT)]),
        ] {
            assert!(decode_tag28(4199, &invalid).is_err());
        }
    }

    #[test]
    fn modern_and_invalid_builds_are_not_downgraded() {
        let program = bytes(&[op(HALT)]);
        for build in [0, 4852, 5409, 6180, u16::MAX] {
            assert!(decode_tag28(build, &program).is_err());
        }
        for build in [1, 4199, 4200, 4851] {
            assert_eq!(decode_tag28(build, &program).unwrap(), 0);
        }
    }

    #[test]
    fn instruction_and_input_limits_are_enforced() {
        let mut words = Vec::new();
        for _ in 0..MAX_INSTRUCTIONS {
            words.extend([op(0xab), op(ACCUMULATOR), 1]);
        }
        words.push(op(HALT));
        assert_eq!(decode_tag28(4199, &bytes(&words)).unwrap(), MAX_INSTRUCTIONS as u64);
        words.pop();
        words.extend([op(0xab), 0, 1]);
        assert!(decode_tag28(4199, &bytes(&words)).is_err());
        assert!(decode_tag28(4199, &vec![0; MAX_PROGRAM_BYTES + 8]).is_err());
    }

    #[test]
    fn known_outer_fixture_can_be_reached_without_external_f28() {
        let challenge = std::array::from_fn(|index| index as u8);
        let program = bytes(&[op(0xa9), 0, 2, op(HALT)]);
        let values = derive_login_id(12345678, 5500, 4199, &challenge, &program).unwrap();
        assert_eq!(values.login_id, 18289557989361181670);
        assert_eq!(values.tag88_value, [0xcc, 0x8a, 0x41, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8]);
        assert_eq!(format!("{values:?}"), "LegacyLoginId { .. }");
        assert!(derive_login_id(1, 0, 4199, &challenge, &program).is_err());
    }

    #[test]
    fn randomized_programs_match_bitwise_arithmetic_model() {
        fn add_bits(a: u64, b: u64) -> u64 {
            let mut carry = 0;
            let mut result = 0;
            for bit in 0..64 {
                let x = (a >> bit) & 1;
                let y = (b >> bit) & 1;
                result |= (x ^ y ^ carry) << bit;
                carry = (x & y) | (x & carry) | (y & carry);
            }
            result
        }
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut random = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let codes = [0x54, 0x70, 0x91, 0xab, 0xa9, 0xb1, 0xc8];
        for _ in 0..512 {
            let mut expected = 0u64;
            let mut program = Vec::new();
            for index in 0..32 {
                let code = codes[(random() % 7) as usize];
                let raw_lhs = if index % 2 == 0 { random() } else { op(ACCUMULATOR) };
                let rhs = random();
                let lhs = if selector(raw_lhs) == ACCUMULATOR { expected } else { raw_lhs };
                expected = match code {
                    0x54 => lhs & rhs,
                    0x70 => lhs | rhs,
                    0x91 => lhs ^ rhs,
                    0xab => add_bits(lhs, rhs),
                    0xa9 => add_bits(lhs, add_bits(!rhs, 1)),
                    0xb1 => (0..rhs % 24).fold(lhs, |value, _| add_bits(value, value)),
                    0xc8 => (0..64).fold(0, |value, bit| {
                        if bit >= rhs % 24 && lhs & (1u64 << bit) != 0 {
                            value | (1u64 << (bit - rhs % 24))
                        } else { value }
                    }),
                    _ => unreachable!(),
                };
                program.extend([op(code), raw_lhs, rhs]);
            }
            program.push(op(HALT));
            assert_eq!(decode_tag28(4851, &bytes(&program)).unwrap(), expected);
        }
    }
}
