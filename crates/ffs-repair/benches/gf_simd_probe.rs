#![forbid(unsafe_code)]
#![feature(portable_simd)]
#![allow(clippy::cast_possible_truncation)]

//! Probe: does an SSSE3 (x86-64-v2) baseline let portable-SIMD `swizzle_dyn`
//! beat the scalar GF(256) LUT gather? (bd-5htg1 / bd-79fp8 evidence)
//!
//! Run twice:
//!   rch exec -- cargo bench -p ffs-repair --bench gf_simd_probe
//!   RUSTFLAGS="-C target-cpu=x86-64-v2" rch exec -- cargo bench -p ffs-repair --bench gf_simd_probe
//!
//! On generic x86-64 (no SSSE3) `swizzle_dyn` lowers to a scalar emulation and
//! the SIMD path LOSES (bd-79fp8: 4.6x slower). If SSSE3 makes PSHUFB available,
//! the SIMD path should win — evidence the v2 baseline unlocks the GF/scan/string
//! SIMD kernel class. Self-contained; touches no production code.

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::simd::Simd;

const BLOCK: usize = 4096;
// 16 lanes == native SSSE3/SSE4.2 PSHUFB width (x86-64-v2); 32 needs AVX2 (v3).
const LANES: usize = 16;
type U8s = Simd<u8, LANES>;

// GF(256) multiply table row for a fixed coefficient (AES poly 0x11B, gen 0x03).
fn mul_row(coeff: u8) -> [u8; 256] {
    // log/exp tables
    let mut log = [0u8; 256];
    let mut exp = [0u8; 512];
    let mut val = 1u32;
    let mut i = 0usize;
    while i < 512 {
        exp[i] = val as u8;
        if i < 255 {
            log[val as usize] = i as u8;
        }
        val = (val << 1) ^ val;
        if val >= 256 {
            val ^= 0x11B;
        }
        i += 1;
    }
    let mut row = [0u8; 256];
    let mut s = 0usize;
    while s < 256 {
        row[s] = if coeff == 0 || s == 0 {
            0
        } else {
            exp[log[coeff as usize] as usize + log[s] as usize]
        };
        s += 1;
    }
    row
}

fn scalar_mul_xor(dst: &mut [u8], src: &[u8], row: &[u8; 256]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= row[*s as usize];
    }
}

fn simd_mul_xor(dst: &mut [u8], src: &[u8], row: &[u8; 256]) {
    let lo = U8s::from_array(std::array::from_fn(|i| row[i % 16]));
    let hi = U8s::from_array(std::array::from_fn(|i| row[(i % 16) << 4]));
    let mask = U8s::splat(0x0F);
    let n = dst.len().min(src.len());
    let simd_len = n - (n % LANES);
    let mut off = 0;
    while off < simd_len {
        let s = U8s::from_slice(&src[off..off + LANES]);
        let d = U8s::from_slice(&dst[off..off + LANES]);
        let prod = lo.swizzle_dyn(s & mask) ^ hi.swizzle_dyn(s >> Simd::splat(4));
        (d ^ prod).copy_to_slice(&mut dst[off..off + LANES]);
        off += LANES;
    }
    for (d, s) in dst[simd_len..].iter_mut().zip(src[simd_len..].iter()) {
        *d ^= row[*s as usize];
    }
}

fn bench_gf(c: &mut Criterion) {
    let src: Vec<u8> = (0..BLOCK).map(|i| (i * 31 + 7) as u8).collect();
    let row = mul_row(0xB7);

    // Equivalence sanity (both paths byte-identical).
    let mut a = vec![0u8; BLOCK];
    let mut b = vec![0u8; BLOCK];
    scalar_mul_xor(&mut a, &src, &row);
    simd_mul_xor(&mut b, &src, &row);
    assert_eq!(a, b, "SIMD and scalar GF mul-xor must match");

    let mut g = c.benchmark_group("gf256_mul_xor_4k");
    g.bench_function("scalar_lut", |bch| {
        bch.iter(|| {
            let mut dst = vec![0u8; BLOCK];
            scalar_mul_xor(black_box(&mut dst), black_box(&src), black_box(&row));
            black_box(dst[0]);
        });
    });
    g.bench_function("simd_swizzle", |bch| {
        bch.iter(|| {
            let mut dst = vec![0u8; BLOCK];
            simd_mul_xor(black_box(&mut dst), black_box(&src), black_box(&row));
            black_box(dst[0]);
        });
    });
    g.finish();
}

criterion_group!(benches, bench_gf);
criterion_main!(benches);
