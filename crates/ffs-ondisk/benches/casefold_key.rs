#![forbid(unsafe_code)]

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::ext4_casefold_key;
use ffs_types::all_zero_bytes;
use std::hint::black_box;

const ZERO_SCAN_BLOCK_LEN: usize = 4096;

fn scalar_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&byte| byte == 0)
}

fn bench_ext4_casefold_key_ascii(c: &mut Criterion) {
    let names: Vec<&[u8]> = vec![
        b"README.md",
        b"src",
        b"main.rs",
        b"Cargo.toml",
        b"DOCUMENTATION_AND_NOTES.txt",
        b"a",
        b"some_quite_long_filename_with_many_characters_to_exercise.dat",
    ];

    c.bench_function("ext4_casefold_key_ascii", |b| {
        b.iter(|| {
            for name in &names {
                black_box(ext4_casefold_key(black_box(name)));
            }
        });
    });
}

fn bench_ext4_casefold_key_mixed_utf8(c: &mut Criterion) {
    let names: Vec<&[u8]> = vec![
        "Straße.txt".as_bytes(),
        "GROẞBUCHSTABEN.md".as_bytes(),
        "café_passé.csv".as_bytes(),
        "MüllerStraße_Düsseldorf.log".as_bytes(),
        "naïve_façade_ßtest.dat".as_bytes(),
    ];

    c.bench_function("ext4_casefold_key_mixed_utf8", |b| {
        b.iter(|| {
            for name in &names {
                black_box(ext4_casefold_key(black_box(name)));
            }
        });
    });
}

fn bench_ext4_casefold_key_long_utf8(c: &mut Criterion) {
    let names: Vec<Vec<u8>> = vec![
        "ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ".repeat(4).into_bytes(),
        "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ".repeat(2).into_bytes(),
        "你好世界这是一个长的中文文件名".repeat(3).into_bytes(),
        "אבגדהוזחטיכלמנסעפצקרשת".repeat(4).into_bytes(),
    ];

    c.bench_function("ext4_casefold_key_long_utf8", |b| {
        b.iter(|| {
            for name in &names {
                black_box(ext4_casefold_key(black_box(name.as_slice())));
            }
        });
    });
}

fn bench_ext4_casefold_key_invalid_utf8(c: &mut Criterion) {
    let names: Vec<Vec<u8>> = vec![
        b"FILE\xff\xfe\xfd.bin".to_vec(),
        b"\x80\x81\x82SomeAsciiTail.dat".to_vec(),
        b"prefix\xc3middle\xc3suffix".to_vec(),
        b"\xff".repeat(64),
    ];

    c.bench_function("ext4_casefold_key_invalid_utf8", |b| {
        b.iter(|| {
            for name in &names {
                black_box(ext4_casefold_key(black_box(name.as_slice())));
            }
        });
    });
}

fn bench_zero_scan_scalar_all_zero_4k(c: &mut Criterion) {
    let block = vec![0_u8; ZERO_SCAN_BLOCK_LEN];

    c.bench_function("zero_scan_scalar_all_zero_4k", |b| {
        b.iter(|| black_box(scalar_all_zero(black_box(&block))));
    });
}

fn bench_zero_scan_chunked_all_zero_4k(c: &mut Criterion) {
    let block = vec![0_u8; ZERO_SCAN_BLOCK_LEN];

    c.bench_function("zero_scan_chunked_all_zero_4k", |b| {
        b.iter(|| black_box(all_zero_bytes(black_box(&block))));
    });
}

fn bench_zero_scan_scalar_late_nonzero_4k(c: &mut Criterion) {
    let mut block = vec![0_u8; ZERO_SCAN_BLOCK_LEN];
    *block.last_mut().expect("non-empty block") = 1;

    c.bench_function("zero_scan_scalar_late_nonzero_4k", |b| {
        b.iter(|| black_box(scalar_all_zero(black_box(&block))));
    });
}

fn bench_zero_scan_chunked_late_nonzero_4k(c: &mut Criterion) {
    let mut block = vec![0_u8; ZERO_SCAN_BLOCK_LEN];
    *block.last_mut().expect("non-empty block") = 1;

    c.bench_function("zero_scan_chunked_late_nonzero_4k", |b| {
        b.iter(|| black_box(all_zero_bytes(black_box(&block))));
    });
}

criterion_group!(
    casefold,
    bench_ext4_casefold_key_ascii,
    bench_ext4_casefold_key_mixed_utf8,
    bench_ext4_casefold_key_long_utf8,
    bench_ext4_casefold_key_invalid_utf8,
    bench_zero_scan_scalar_all_zero_4k,
    bench_zero_scan_chunked_all_zero_4k,
    bench_zero_scan_scalar_late_nonzero_4k,
    bench_zero_scan_chunked_late_nonzero_4k,
);
criterion_main!(casefold);
