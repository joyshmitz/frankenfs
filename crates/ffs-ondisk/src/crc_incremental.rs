//! Incremental CRC32C update for in-place changes to a fixed-length buffer.
//!
//! Re-checksumming a whole 4 KiB group bitmap on every allocation (a single-bit
//! or short-range change) is O(buffer); after the bit-loop→range wins made the
//! bitmap marking O(N/8), that full crc32c recompute is the dominant per-create
//! serial CPU cost (bench `bitmap_csum_recompute`: ~648 ns for a 4 KiB block
//! bitmap). CRC is linear, so changing bytes `[start, start+len)` from `old` to
//! `new` shifts the checksum by exactly `crc32c_shift(raw_crc(old XOR new), suffix)`
//! where `suffix` is the number of unchanged bytes after the change. With the
//! per-power operator matrices precomputed once, that shift is O(log suffix) 32×32
//! GF(2) matrix-vector products — far cheaper than re-scanning the whole buffer.
//!
//! Standard reflected CRC32C (`crc32c` crate) is affine: for two SAME-LENGTH
//! buffers `std(a) XOR std(b) = raw(a XOR b)` (the init/final terms cancel), so a
//! cached *standard* crc updates correctly with this raw-CRC delta.

use std::sync::OnceLock;

/// Reflected CRC32C polynomial (Castagnoli, bit-reversed form).
const POLY: u32 = 0x82F6_3B78;

/// Byte-indexed CRC32C table for the reflected polynomial, built once.
fn crc32c_byte_table() -> &'static [u32; 256] {
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        let mut i = 0usize;
        while i < 256 {
            let mut c = i as u32;
            let mut b = 0;
            while b < 8 {
                c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
                b += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    })
}

/// Raw reflected CRC32C: init 0, no final XOR. Linear in its input, unlike the
/// standard crc (init/final make it affine). Table-driven (one lookup per byte)
/// so it stays cheap even on a larger changed region, keeping the incremental
/// win over the SIMD full recompute across a wider delta range.
fn raw_crc32c(data: &[u8]) -> u32 {
    let table = crc32c_byte_table();
    let mut crc = 0u32;
    for &b in data {
        crc = table[((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

/// Multiply a GF(2) 32×32 matrix (stored column-major as 32 u32s) by a vector.
fn gf2_matrix_times(mat: &[u32; 32], mut vec: u32) -> u32 {
    let mut sum = 0u32;
    let mut i = 0usize;
    while vec != 0 {
        if vec & 1 != 0 {
            sum ^= mat[i];
        }
        vec >>= 1;
        i += 1;
    }
    sum
}

fn gf2_matrix_square(square: &mut [u32; 32], mat: &[u32; 32]) {
    for n in 0..32 {
        square[n] = gf2_matrix_times(mat, mat[n]);
    }
}

/// Operator matrices for shifting a CRC by `2^k` zero *bits*, precomputed once.
/// `ops[k]` advances a CRC as if `2^k` zero bits were appended.
fn shift_operators() -> &'static [[u32; 32]; 40] {
    static OPS: OnceLock<[[u32; 32]; 40]> = OnceLock::new();
    OPS.get_or_init(|| {
        let mut ops = [[0u32; 32]; 40];
        // ops[0] = operator for one zero bit.
        ops[0][0] = POLY;
        let mut row = 1u32;
        for n in 1..32 {
            ops[0][n] = row;
            row <<= 1;
        }
        // ops[k+1] = ops[k]^2 (doubles the number of zero bits).
        for k in 1..40 {
            let prev = ops[k - 1];
            gf2_matrix_square(&mut ops[k], &prev);
        }
        ops
    })
}

/// Advance `crc` as if `zero_bits` zero bits were appended (multiply by x^zero_bits).
fn crc32c_shift_bits(crc: u32, mut zero_bits: u64) -> u32 {
    let ops = shift_operators();
    let mut c = crc;
    let mut k = 0usize;
    while zero_bits != 0 {
        if zero_bits & 1 != 0 {
            c = gf2_matrix_times(&ops[k], c);
        }
        zero_bits >>= 1;
        k += 1;
    }
    c
}

/// Incrementally update a standard CRC32C after an in-place change.
///
/// `old_crc` is `crc32c(buffer_before)`. The change replaced `buffer[start..start+delta.len()]`
/// such that `delta[i] = before[start+i] XOR after[start+i]`. `suffix_bytes` is the
/// number of bytes AFTER the changed region (`buffer.len() - start - delta.len()`).
/// Returns `crc32c(buffer_after)`. Result-identical to a full recompute.
#[must_use]
pub fn crc32c_update_region(old_crc: u32, delta: &[u8], suffix_bytes: usize) -> u32 {
    let raw = raw_crc32c(delta);
    old_crc ^ crc32c_shift_bits(raw, (suffix_bytes as u64) * 8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(orig: &[u8], start: usize, new_bytes: &[u8]) -> Vec<u8> {
        let mut b = orig.to_vec();
        b[start..start + new_bytes.len()].copy_from_slice(new_bytes);
        b
    }

    fn check(orig: &[u8], start: usize, new_bytes: &[u8]) {
        let after = apply(orig, start, new_bytes);
        let old_crc = crc32c::crc32c(orig);
        let delta: Vec<u8> = new_bytes
            .iter()
            .zip(&orig[start..start + new_bytes.len()])
            .map(|(n, o)| n ^ o)
            .collect();
        let suffix = orig.len() - start - new_bytes.len();
        let got = crc32c_update_region(old_crc, &delta, suffix);
        assert_eq!(got, crc32c::crc32c(&after), "start={start} len={}", new_bytes.len());
    }

    #[test]
    fn incremental_matches_full_recompute_cases() {
        let base: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(37) & 0xFF) as u8).collect();
        // single-byte, short-range, and boundary changes at various positions.
        check(&base, 0, &[0xFF]);
        check(&base, 4095, &[0x01]);
        check(&base, 40, &[0xFF; 8]);
        check(&base, 2000, &[0x5A; 32]);
        check(&base, 4064, &[0xAB; 32]);
        check(&base, 1, &[0u8; 100]);
    }

    #[test]
    fn incremental_matches_full_recompute_prop() {
        // Deterministic pseudo-random sweep (proptest-style).
        let mut state = 0x1234_5678u32;
        let mut next = || {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state
        };
        let base: Vec<u8> = (0..8192u32).map(|i| (i.wrapping_mul(101) & 0xFF) as u8).collect();
        for _ in 0..500 {
            let len = 1 + (next() as usize % 64);
            let start = (next() as usize) % (base.len() - len);
            let new_bytes: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();
            check(&base, start, &new_bytes);
        }
    }
}
