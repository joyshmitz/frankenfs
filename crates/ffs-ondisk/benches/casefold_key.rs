#![forbid(unsafe_code)]

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::ext4_casefold_key;
use std::hint::black_box;

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

criterion_group!(
    casefold,
    bench_ext4_casefold_key_ascii,
    bench_ext4_casefold_key_mixed_utf8,
    bench_ext4_casefold_key_long_utf8,
    bench_ext4_casefold_key_invalid_utf8,
);
criterion_main!(casefold);
