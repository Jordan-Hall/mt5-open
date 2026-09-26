//! Native build-6182 interpreters for authentication tags 28 and 35.
//!
//! Programs contain little-endian triples: instruction, left operand, right
//! operand. Arithmetic wraps at 64 bits. These functions do not access a
//! terminal, network service, captured answer or account credential.

use crate::error::{ProtocolError, Result};

pub const CLIENT_BUILD: u16 = 6182;
pub const LOGIN_SEED: u64 = 0xc9d1_c265_16d7;
const MAX_PROGRAM_BYTES: usize = 64 * 1024;
const FINAL_XOR: u64 = 0xc9d1_4005_0011;

#[derive(Debug, Clone, Copy)]
pub enum Version {
    Tag28,
    Tag35,
}

/// Execute a bounded challenge program, with an explicit seed for conformance
/// testing. Login callers use [`LOGIN_SEED`]. A halt returns immediately;
/// programs without a halt return their last accumulator value.
pub fn solve(version: Version, program: &[u8], seed: u64) -> Result<u64> {
    if program.is_empty() || program.len() > MAX_PROGRAM_BYTES || program.len() % 24 != 0 {
        return Err(ProtocolError::new(
            "invalid native challenge program length",
        ));
    }
    let (shift, accumulator_operand, mut value) = match version {
        Version::Tag28 => (11, 252, seed ^ 0x16_bbb9_5687_7806),
        Version::Tag35 => (17, 242, seed ^ 0x67_4af6_c786_2323),
    };
    for instruction in program.chunks_exact(24) {
        let word = |offset| u64::from_le_bytes(instruction[offset..offset + 8].try_into().unwrap());
        let opcode = ((word(0) >> shift) & 255) as u8;
        let left = word(8);
        let right = word(16);
        let a = if (left >> shift) & 255 == accumulator_operand {
            value
        } else {
            left
        };
        value = match version {
            Version::Tag28 => match opcode {
                39 => (a & right) ^ 5,
                98 => a | right,
                214 => a ^ right ^ 5,
                113 => a.wrapping_add(right),
                63 => a.wrapping_sub(right) ^ 5,
                51 => a << (right % 16),
                205 => (a >> (right % 16)) ^ 5,
                88 => a ^ right,
                25 => ((a | 200) & right) ^ 5,
                80 => a | right | 0x2800_0000,
                118 => (a ^ 0x7600_0000_0000).wrapping_add(right ^ 0x3b0) ^ 5,
                74 => (a ^ 0x1_2800).wrapping_sub(right),
                220 => (a & 0xf732_6732_1127_9323) ^ right ^ 5,
                237 => (a / 237) ^ right,
                7 => a ^ (right / 7) ^ 5,
                106 => return Ok(value ^ seed ^ FINAL_XOR),
                _ => value,
            },
            Version::Tag35 => match opcode {
                34 => a & right,
                147 => a | right,
                194 => a ^ right,
                127 => a.wrapping_add(right),
                78 => a.wrapping_sub(right),
                56 => a << (right % 24),
                171 => a >> (right % 24),
                50 => (a | (50 << 37)) ^ (right | 50),
                17 => (a | (17 << 43)) & (right | (17 << 12)),
                95 => a | right | (95 << 52) | (95 << 18),
                154 => (a ^ (154 << 35)).wrapping_add(right ^ (154 << 7)),
                39 => (a ^ (39 << 40)).wrapping_sub(right ^ (39 << 21)),
                226 => ((a ^ (226 << 40)) % 226) ^ right,
                206 => (a / 206) ^ right,
                134 => a ^ (right / 134),
                114 => {
                    // The footer's nested operand encoding has its own selector.
                    let low = if (left >> 14) & 255 == 83 {
                        0
                    } else {
                        left & 0xffff_ffff
                    };
                    return Ok(value ^ seed ^ FINAL_XOR ^ low ^ (right & 0xffff_ffff_0000_0000));
                }
                _ => value,
            },
        };
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_programs_are_rejected() {
        for bytes in [vec![], vec![0; 8], vec![0; 25], vec![0; 65544]] {
            for version in [Version::Tag28, Version::Tag35] {
                assert!(solve(version, &bytes, LOGIN_SEED).is_err());
            }
        }
    }
}
