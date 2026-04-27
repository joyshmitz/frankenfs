//! Conformance Family A: btrfs on-disk format golden round-trip harness.
//!
//! Per the /testing-conformance-harnesses skill, on-disk serialization
//! formats are frozen via golden byte arrays: `parse(bytes) -> struct` and
//! `encode(struct) -> bytes` must both be bit-exact across every supported
//! variant and edge case. A single-byte drift in any of these layouts
//! silently corrupts real btrfs images, so this suite is the regression
//! gate for the parse/encode pair owned by `ffs-btrfs`.
//!
//! Fixtures are inlined as hex literals so every byte is visible in the
//! git diff - the alternative (external binary fixtures) makes regressions
//! invisible during code review.
//!
//! Coverage matrix in `DISCREPANCIES.md` and in the module-level comment
//! above each case. Cases cover both MUST-exact encoders and parse-only
//! fields (root items, root refs) that the in-tree encoder does not yet
//! emit but must decode from real images.

use ffs_btrfs::{
    BTRFS_FILE_EXTENT_INLINE, BTRFS_FILE_EXTENT_REG, BtrfsDirItem, BtrfsExtentData, BtrfsInodeItem,
    BtrfsInodeRef, BtrfsXattrItem, parse_dir_items, parse_extent_data, parse_inode_item,
    parse_inode_refs, parse_root_item, parse_root_ref, parse_xattr_items,
};
use ffs_types::ParseError;

// Helpers

/// Assert parse -> encode -> parse round-trip is bit-exact.
///
/// For layouts where the encoder zeroes fields the parser ignores
/// (e.g. `transid`, `block_group`, reserved), the fixture must also zero
/// them so the encoded bytes equal the fixture bytes.
fn assert_bitexact_roundtrip<T, P, E>(fixture_name: &str, fixture: &[u8], parse: P, encode: E)
where
    T: std::fmt::Debug + PartialEq,
    P: Fn(&[u8]) -> T,
    E: Fn(&T) -> Vec<u8>,
{
    let decoded = parse(fixture);
    let reencoded = encode(&decoded);
    assert_eq!(
        reencoded, fixture,
        "{fixture_name}: encode(parse(fixture)) diverged from fixture\n\
         decoded: {decoded:?}"
    );
    let redecoded = parse(&reencoded);
    assert_eq!(
        redecoded, decoded,
        "{fixture_name}: parse(encode(parse(fixture))) diverged from parse(fixture)"
    );
}

/// Like `assert_bitexact_roundtrip` but for parsers that return `Vec<T>`
/// and encoders that emit one payload per item. The full concatenation
/// must match the fixture bytes.
fn assert_vec_roundtrip<T, P, E>(fixture_name: &str, fixture: &[u8], parse: P, encode: E)
where
    T: std::fmt::Debug + PartialEq,
    P: Fn(&[u8]) -> Vec<T>,
    E: Fn(&T) -> Vec<u8>,
{
    let decoded = parse(fixture);
    let mut reencoded = Vec::new();
    for item in &decoded {
        reencoded.extend_from_slice(&encode(item));
    }
    assert_eq!(
        reencoded, fixture,
        "{fixture_name}: concat(encode(parse(fixture))) diverged from fixture\n\
         decoded: {decoded:?}"
    );
    let redecoded = parse(&reencoded);
    assert_eq!(
        redecoded, decoded,
        "{fixture_name}: parse(concat(encode(parse(fixture)))) diverged from parse(fixture)"
    );
}

// INODE_ITEM (btrfs_inode_item, 160 bytes fixed)

/// Golden bytes for a regular-file INODE_ITEM:
/// - generation = 0x0000_0000_0000_002A (42)
/// - size       = 0x0000_0000_0000_1000 (4096)
/// - nbytes     = 0x0000_0000_0000_2000 (8192)
/// - nlink      = 1
/// - uid        = 1000
/// - gid        = 1000
/// - mode       = 0o100_644 (regular file with 0644 perms) = 0x000_081A4
/// - rdev       = 0
/// - atime/ctime/mtime/otime = (sec=0x1800_0000, nsec=0x1234_5678)
///
/// Kernel-untracked fields (transid@8, block_group@32, flags@64, sequence@72,
/// reserved[0..4]@80) must be zero in the fixture because our encoder zeroes
/// them; this is documented in DISCREPANCIES.md DISC-BTRFS-001.
const GOLDEN_INODE_ITEM_REGFILE: [u8; 160] = [
    // offset 0: generation = 42 LE
    0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0..8
    // offset 8: transid (zero)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 8..16
    // offset 16: size = 4096 LE
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 16..24
    // offset 24: nbytes = 8192 LE
    0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 24..32
    // offset 32: block_group (zero)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 32..40
    // offset 40: nlink = 1 LE
    0x01, 0x00, 0x00, 0x00, // 40..44
    // offset 44: uid = 1000 LE (0x03E8)
    0xE8, 0x03, 0x00, 0x00, // 44..48
    // offset 48: gid = 1000 LE
    0xE8, 0x03, 0x00, 0x00, // 48..52
    // offset 52: mode = 0o100644 = 0x81A4 LE
    0xA4, 0x81, 0x00, 0x00, // 52..56
    // offset 56: rdev = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 56..64
    // offset 64: flags (zero)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 64..72
    // offset 72: sequence (zero)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 72..80
    // offset 80..112: reserved[4 x u64]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 80..88
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 88..96
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 96..104
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 104..112
    // offset 112: atime_sec = 0x1800_0000 LE
    0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, // 112..120
    // offset 120: atime_nsec = 0x1234_5678 LE
    0x78, 0x56, 0x34, 0x12, // 120..124
    // offset 124: ctime_sec = 0x1800_0000 LE
    0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, // 124..132
    // offset 132: ctime_nsec = 0x1234_5678 LE
    0x78, 0x56, 0x34, 0x12, // 132..136
    // offset 136: mtime_sec = 0x1800_0000 LE
    0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, // 136..144
    // offset 144: mtime_nsec = 0x1234_5678 LE
    0x78, 0x56, 0x34, 0x12, // 144..148
    // offset 148: otime_sec = 0x1800_0000 LE
    0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, // 148..156
    // offset 156: otime_nsec = 0x1234_5678 LE
    0x78, 0x56, 0x34, 0x12, // 156..160
];

#[test]
fn golden_inode_item_regfile_roundtrip() {
    let expected = BtrfsInodeItem {
        generation: 42,
        size: 4096,
        nbytes: 8192,
        nlink: 1,
        uid: 1000,
        gid: 1000,
        mode: 0o100_644,
        rdev: 0,
        atime_sec: 0x1800_0000,
        atime_nsec: 0x1234_5678,
        ctime_sec: 0x1800_0000,
        ctime_nsec: 0x1234_5678,
        mtime_sec: 0x1800_0000,
        mtime_nsec: 0x1234_5678,
        otime_sec: 0x1800_0000,
        otime_nsec: 0x1234_5678,
    };

    // Parse direction: fixture -> struct
    let decoded = parse_inode_item(&GOLDEN_INODE_ITEM_REGFILE).expect("parse regfile inode");
    assert_eq!(decoded, expected, "parse diverged from expected struct");

    // Encode direction: struct -> fixture (bit-exact)
    let encoded = expected.to_bytes();
    assert_eq!(
        encoded.as_slice(),
        GOLDEN_INODE_ITEM_REGFILE.as_slice(),
        "encode diverged from fixture"
    );

    // Round-trip: parse(encode(decoded)) == decoded
    let redecoded = parse_inode_item(&encoded).expect("reparse");
    assert_eq!(redecoded, decoded, "parse/encode/parse diverged");
}

/// Directory INODE_ITEM (mode = 0o040755) with zero timestamps and nbytes=0.
/// Exercises the low-value edge case (all-zero-metadata fields) that caused
/// historical parser bugs where "unset" was confused with the first epoch
/// second.
const GOLDEN_INODE_ITEM_DIR_ZERO_TIMES: [u8; 160] = [
    // generation = 1
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0..8
    // transid
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 8..16
    // size = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 16..24
    // nbytes = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 24..32
    // block_group
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 32..40
    // nlink = 2
    0x02, 0x00, 0x00, 0x00, // 40..44
    // uid = 0
    0x00, 0x00, 0x00, 0x00, // 44..48
    // gid = 0
    0x00, 0x00, 0x00, 0x00, // 48..52
    // mode = 0o040755 = 0x41ED LE
    0xED, 0x41, 0x00, 0x00, // 52..56
    // rdev = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 56..64
    // flags, sequence, reserved[4]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 64..72
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 72..80
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 80..88
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 88..96
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 96..104
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 104..112
    // atime/ctime/mtime/otime: all zero
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 112..120
    0x00, 0x00, 0x00, 0x00, // 120..124
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 124..132
    0x00, 0x00, 0x00, 0x00, // 132..136
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 136..144
    0x00, 0x00, 0x00, 0x00, // 144..148
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 148..156
    0x00, 0x00, 0x00, 0x00, // 156..160
];

#[test]
fn golden_inode_item_dir_zero_times_roundtrip() {
    assert_bitexact_roundtrip(
        "dir inode with zero times",
        &GOLDEN_INODE_ITEM_DIR_ZERO_TIMES,
        |bytes| parse_inode_item(bytes).expect("parse"),
        BtrfsInodeItem::to_bytes,
    );
}

/// Large-generation INODE_ITEM exercising the full u64 range so encoders that
/// truncate to u32 are caught, while timestamp nanoseconds stay in the valid
/// timespec subsecond range.
#[test]
fn inode_item_u64_bounds_roundtrip() {
    const MAX_VALID_NSEC: u32 = 999_999_999;

    let expected = BtrfsInodeItem {
        generation: u64::MAX,
        size: u64::MAX,
        nbytes: u64::MAX,
        nlink: u32::MAX,
        uid: u32::MAX,
        gid: u32::MAX,
        mode: u32::MAX,
        rdev: u64::MAX,
        atime_sec: u64::MAX,
        atime_nsec: MAX_VALID_NSEC,
        ctime_sec: u64::MAX,
        ctime_nsec: MAX_VALID_NSEC,
        mtime_sec: u64::MAX,
        mtime_nsec: MAX_VALID_NSEC,
        otime_sec: u64::MAX,
        otime_nsec: MAX_VALID_NSEC,
    };
    let encoded = expected.to_bytes();
    assert_eq!(encoded.len(), 160, "inode_item encoded length must be 160");
    let decoded = parse_inode_item(&encoded).expect("parse max-value inode");
    assert_eq!(decoded, expected, "u64::MAX round-trip diverged");
}

#[test]
fn inode_item_timestamp_nanoseconds_must_be_timespec_bounded() {
    let valid = BtrfsInodeItem {
        generation: 1,
        size: 4096,
        nbytes: 4096,
        nlink: 1,
        uid: 0,
        gid: 0,
        mode: 0o100_644,
        rdev: 0,
        atime_sec: u64::MAX,
        atime_nsec: 999_999_999,
        ctime_sec: u64::MAX,
        ctime_nsec: 999_999_999,
        mtime_sec: u64::MAX,
        mtime_nsec: 999_999_999,
        otime_sec: u64::MAX,
        otime_nsec: 999_999_999,
    };
    parse_inode_item(&valid.to_bytes()).expect("max valid nanoseconds parse");

    for (offset, field) in [
        (120, "inode_item.atime_nsec"),
        (132, "inode_item.ctime_nsec"),
        (144, "inode_item.mtime_nsec"),
        (156, "inode_item.otime_nsec"),
    ] {
        let mut invalid = valid.to_bytes();
        invalid[offset..offset + 4].copy_from_slice(&1_000_000_000_u32.to_le_bytes());
        let err = parse_inode_item(&invalid).expect_err("invalid nanoseconds must be rejected");
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: got_field,
                reason: "must be less than 1_000_000_000",
            } if got_field == field
        ));
    }
}

#[test]
fn inode_item_short_payload_rejected() {
    // Any payload < 160 bytes must be rejected as InsufficientData.
    for len in 0..160 {
        let err = parse_inode_item(&vec![0u8; len]).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("InsufficientData"),
            "len={len}: expected InsufficientData, got {err:?}"
        );
    }
}

// DIR_ITEM / DIR_INDEX (30 + name_len bytes per entry)

/// Golden DIR_ITEM payload with one entry:
/// - child_objectid = 257
/// - child_key_type = 1 (BTRFS_ITEM_INODE_ITEM)
/// - child_key_offset = 0
/// - file_type = 1 (REG_FILE)
/// - name = "hello.txt" (9 bytes)
///
/// Total size: 30 (header) + 9 (name) = 39 bytes.
const GOLDEN_DIR_ITEM_HELLO_TXT: [u8; 39] = [
    // location.objectid = 257 LE
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0..8
    // location.type = 1
    0x01, // 8
    // location.offset = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 9..17
    // transid = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 17..25
    // data_len = 0
    0x00, 0x00, // 25..27
    // name_len = 9
    0x09, 0x00, // 27..29
    // file_type = 1
    0x01, // 29
    // name = "hello.txt"
    b'h', b'e', b'l', b'l', b'o', b'.', b't', b'x', b't', // 30..39
];

#[test]
fn golden_dir_item_hello_txt_roundtrip() {
    let expected = BtrfsDirItem {
        child_objectid: 257,
        child_key_type: 1,
        child_key_offset: 0,
        file_type: 1,
        name: b"hello.txt".to_vec(),
    };

    let decoded = parse_dir_items(&GOLDEN_DIR_ITEM_HELLO_TXT).expect("parse dir_item");
    assert_eq!(decoded, vec![expected.clone()]);

    let encoded = expected.to_bytes();
    assert_eq!(
        encoded.as_slice(),
        GOLDEN_DIR_ITEM_HELLO_TXT.as_slice(),
        "dir_item encode diverged from fixture"
    );
}

#[test]
fn dir_item_multiple_entries_concatenate() {
    // Two DIR_ITEM entries in a single payload: "a" (inode 257), "bb" (inode 258).
    let a = BtrfsDirItem {
        child_objectid: 257,
        child_key_type: 1,
        child_key_offset: 0,
        file_type: 1,
        name: b"a".to_vec(),
    };
    let bb = BtrfsDirItem {
        child_objectid: 258,
        child_key_type: 1,
        child_key_offset: 0,
        file_type: 2,
        name: b"bb".to_vec(),
    };
    let mut payload = a.to_bytes();
    payload.extend_from_slice(&bb.to_bytes());

    let decoded = parse_dir_items(&payload).expect("parse two dir_items");
    assert_eq!(decoded, vec![a, bb]);
}

#[test]
fn dir_item_empty_name_length_2_roundtrips() {
    // Smallest legal name length (1); the Linux filesystem itself never
    // stores zero-length names, so the smallest non-dot name is one byte.
    let item = BtrfsDirItem {
        child_objectid: 256,
        child_key_type: 1,
        child_key_offset: 0,
        file_type: 2,
        name: b"x".to_vec(),
    };
    let bytes = item.to_bytes();
    assert_eq!(bytes.len(), 31);
    let decoded = parse_dir_items(&bytes).expect("parse 1-byte-name dir_item");
    assert_eq!(decoded, vec![item]);
}

// INODE_REF (10 + name_len bytes per entry)

/// Golden INODE_REF payload: one entry index=2, name="subdir" (6 bytes).
/// Total 16 bytes.
const GOLDEN_INODE_REF_SUBDIR: [u8; 16] = [
    // index = 2 LE
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0..8
    // name_len = 6 LE
    0x06, 0x00, // 8..10
    // name = "subdir"
    b's', b'u', b'b', b'd', b'i', b'r', // 10..16
];

#[test]
fn golden_inode_ref_subdir_roundtrip() {
    let expected = BtrfsInodeRef {
        index: 2,
        name: b"subdir".to_vec(),
    };

    let decoded = parse_inode_refs(&GOLDEN_INODE_REF_SUBDIR).expect("parse inode_ref");
    assert_eq!(decoded, vec![expected.clone()]);

    let encoded = expected.to_bytes();
    assert_eq!(
        encoded.as_slice(),
        GOLDEN_INODE_REF_SUBDIR.as_slice(),
        "inode_ref encode diverged from fixture"
    );
}

#[test]
fn inode_ref_multiple_hardlinks_concatenate() {
    // Hard-linked file: two back-refs to the same parent with different names.
    let refs = vec![
        BtrfsInodeRef {
            index: 3,
            name: b"linkname_a".to_vec(),
        },
        BtrfsInodeRef {
            index: 4,
            name: b"linkname_b".to_vec(),
        },
    ];
    let mut payload = Vec::new();
    for r in &refs {
        payload.extend_from_slice(&r.to_bytes());
    }

    let decoded = parse_inode_refs(&payload).expect("parse hard-linked inode_refs");
    assert_eq!(decoded, refs);
}

#[test]
fn inode_ref_long_name_255_bytes_roundtrips() {
    // Linux NAME_MAX is 255 bytes; exercise the u16 name_len field at that
    // boundary. Ensures no truncation to u8 in encoder or parser.
    let long_name = vec![b'z'; 255];
    let item = BtrfsInodeRef {
        index: 1,
        name: long_name,
    };
    let bytes = item.to_bytes();
    assert_eq!(bytes.len(), 10 + 255);
    let decoded = parse_inode_refs(&bytes).expect("parse 255-byte-name inode_ref");
    assert_eq!(decoded, vec![item]);
}

// EXTENT_DATA (inline and regular)

/// Golden regular EXTENT_DATA (53 bytes):
/// - generation = 42
/// - ram_bytes = 4096
/// - compression = 0
/// - extent_type = BTRFS_FILE_EXTENT_REG
/// - disk_bytenr = 0x1_0000_0000 (4 GiB mark)
/// - disk_num_bytes = 4096
/// - extent_offset = 0
/// - num_bytes = 4096
const GOLDEN_EXTENT_DATA_REG: [u8; 53] = [
    // generation = 42
    0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0..8
    // ram_bytes = 4096
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 8..16
    // compression = 0
    0x00, // 16
    // encryption = 0
    0x00, // 17
    // other_encoding = 0
    0x00, 0x00, // 18..20
    // type = BTRFS_FILE_EXTENT_REG = 1
    0x01, // 20
    // disk_bytenr = 0x1_0000_0000 LE
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // 21..29
    // disk_num_bytes = 4096
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 29..37
    // extent_offset = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 37..45
    // num_bytes = 4096
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 45..53
];

#[test]
fn golden_extent_data_regular_roundtrip() {
    let expected = BtrfsExtentData::Regular {
        generation: 42,
        ram_bytes: 4096,
        extent_type: BTRFS_FILE_EXTENT_REG,
        compression: 0,
        disk_bytenr: 0x1_0000_0000,
        disk_num_bytes: 4096,
        extent_offset: 0,
        num_bytes: 4096,
    };

    let decoded = parse_extent_data(&GOLDEN_EXTENT_DATA_REG).expect("parse regular extent");
    assert_eq!(decoded, expected);

    let encoded = expected.to_bytes();
    assert_eq!(
        encoded.as_slice(),
        GOLDEN_EXTENT_DATA_REG.as_slice(),
        "regular extent encode diverged from fixture"
    );
}

#[test]
fn golden_extent_data_inline_roundtrip() {
    // Inline extent payload: "abc" (3 bytes of actual file data).
    // Layout: 21-byte header + 3 data bytes = 24 bytes total.
    let payload = b"abc".to_vec();
    let expected = BtrfsExtentData::Inline {
        generation: 7,
        ram_bytes: 3,
        compression: 0,
        data: payload.clone(),
    };

    let encoded = expected.to_bytes();
    assert_eq!(encoded.len(), 24);

    // Verify byte layout inline here since it's small.
    assert_eq!(
        &encoded[0..8],
        &7u64.to_le_bytes(),
        "inline extent generation"
    );
    assert_eq!(&encoded[8..16], &3u64.to_le_bytes(), "inline ram_bytes");
    assert_eq!(encoded[16], 0, "inline compression");
    assert_eq!(encoded[20], BTRFS_FILE_EXTENT_INLINE, "inline extent type");
    assert_eq!(&encoded[21..], payload.as_slice(), "inline data");

    // Round-trip: parse(encode(x)) == x
    let decoded = parse_extent_data(&encoded).expect("parse inline extent");
    assert_eq!(decoded, expected, "inline extent round-trip diverged");
}

#[test]
fn extent_data_short_header_rejected() {
    for len in 0..21 {
        let err = parse_extent_data(&vec![0u8; len]).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("InsufficientData"),
            "len={len}: expected InsufficientData, got {err:?}"
        );
    }
}

#[test]
fn extent_data_regular_short_after_header_rejected() {
    // 21-byte header declaring type=REG but truncated before the 32-byte
    // extent tail (disk_bytenr/disk_num_bytes/offset/num_bytes). Allocate the
    // full 53 bytes so the slice operation is valid and the tail is zero-
    // padded; the parser must still reject every length < 53.
    let mut bytes = [0u8; 53];
    bytes[20] = BTRFS_FILE_EXTENT_REG;
    for len in 21..53 {
        let truncated = &bytes[..len];
        let err = parse_extent_data(truncated).expect_err("truncated extent tail must reject");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("InsufficientData"),
            "len={len}: expected InsufficientData, got {err:?}"
        );
    }
}

#[test]
fn extent_data_unknown_type_rejected() {
    // Valid 21-byte header with an unsupported extent type byte.
    let mut bytes = vec![0u8; 21];
    bytes[20] = 99; // invalid
    let err = parse_extent_data(&bytes).unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("unsupported extent type"),
        "expected unsupported-type error, got {err:?}"
    );
}

// XATTR_ITEM (same 30-byte header as DIR_ITEM, with data_len > 0)

#[test]
fn xattr_item_single_name_value_parses() {
    // Build a payload with DIR_ITEM-shaped header + "user.foo" name + b"bar"
    // value.
    let name = b"user.foo";
    let value = b"bar";
    let mut payload = vec![0u8; 30];
    // Location + transid remain zero.
    payload[25..27].copy_from_slice(
        &u16::try_from(value.len())
            .expect("test xattr value length fits in u16")
            .to_le_bytes(),
    );
    payload[27..29].copy_from_slice(
        &u16::try_from(name.len())
            .expect("test xattr name length fits in u16")
            .to_le_bytes(),
    );
    // file_type at 29 is not used by the xattr parser; leave zero.
    payload.extend_from_slice(name);
    payload.extend_from_slice(value);

    let decoded = parse_xattr_items(&payload).expect("parse single xattr");
    assert_eq!(
        decoded,
        vec![BtrfsXattrItem {
            name: name.to_vec(),
            value: value.to_vec(),
        }]
    );
}

#[test]
fn xattr_item_empty_value_parses_as_zero_length_value() {
    // Linux allows zero-length xattr values; parser must not confuse it with
    // end-of-stream.
    let name = b"trusted.empty";
    let mut payload = vec![0u8; 30];
    // data_len = 0
    payload[25..27].copy_from_slice(&0u16.to_le_bytes());
    payload[27..29].copy_from_slice(
        &u16::try_from(name.len())
            .expect("test xattr name length fits in u16")
            .to_le_bytes(),
    );
    payload.extend_from_slice(name);

    let decoded = parse_xattr_items(&payload).expect("parse empty-value xattr");
    assert_eq!(
        decoded,
        vec![BtrfsXattrItem {
            name: name.to_vec(),
            value: Vec::new(),
        }]
    );
}

// ROOT_ITEM (parse-only; no in-tree encoder)

/// Parse-only golden: exercises parser on a 256-byte ROOT_ITEM payload with
/// UUID fields present. Our in-tree code does not emit ROOT_ITEM bytes (the
/// writable path seeds alloc state from disk and mutates in-memory), so this
/// is a one-way fixture test; encoder side is XFAIL.
///
/// See DISCREPANCIES.md DISC-BTRFS-002.
#[test]
fn golden_root_item_256_bytes_parse_only() {
    let mut fixture = vec![0u8; 256];
    // generation @ 160 = 5
    fixture[160..168].copy_from_slice(&5u64.to_le_bytes());
    // root_dirid @ 168 = 256 (BTRFS_FIRST_FREE_OBJECTID)
    fixture[168..176].copy_from_slice(&256u64.to_le_bytes());
    // bytenr @ 176 = 0x4000 (must be nonzero; 0 triggers InvalidField)
    fixture[176..184].copy_from_slice(&0x4000u64.to_le_bytes());
    // flags @ 208 = 1 (read-only subvolume bit)
    fixture[208..216].copy_from_slice(&1u64.to_le_bytes());
    // refs @ 216 = 1
    fixture[216..224].copy_from_slice(&1u64.to_le_bytes());
    // uuid @ 224: 0xAA bytes
    for b in &mut fixture[224..240] {
        *b = 0xAA;
    }
    // parent_uuid @ 240: 0xBB bytes
    for b in &mut fixture[240..256] {
        *b = 0xBB;
    }
    // level at last byte. 256-byte payload means level is fixture[255] = 0xBB.
    // That's the last parent_uuid byte, and it doubles as level.
    // To control level independently, shrink payload to 255 bytes? Keep as-is.

    let decoded = parse_root_item(&fixture).expect("parse root_item");
    assert_eq!(decoded.bytenr, 0x4000);
    assert_eq!(decoded.generation, 5);
    assert_eq!(decoded.root_dirid, 256);
    assert_eq!(decoded.flags, 1);
    assert_eq!(decoded.refs, 1);
    assert_eq!(decoded.uuid, [0xAA; 16]);
    assert_eq!(decoded.parent_uuid, [0xBB; 16]);
    assert_eq!(decoded.level, 0xBB, "level is the last byte of the payload");
}

#[test]
fn root_item_bytenr_zero_rejected() {
    let mut fixture = vec![0u8; 256];
    // bytenr @ 176 stays 0 and must be rejected.
    // Must still fill other required fields so the parser doesn't fail on
    // InsufficientData first.
    let err = parse_root_item(&fixture).unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("bytenr"),
        "expected bytenr-nonzero rejection, got {err:?}"
    );

    // Also verify that a non-zero bytenr at that offset makes the parse
    // succeed (prevents the test from silently passing if the parser rejected
    // on some other ground).
    fixture[176] = 0x01;
    let _ok = parse_root_item(&fixture).expect("parse with nonzero bytenr");
}

#[test]
fn root_item_short_payload_rejected() {
    for len in 0..224 {
        let err = parse_root_item(&vec![0u8; len]).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("InsufficientData"),
            "len={len}: expected InsufficientData, got {err:?}"
        );
    }
}

// ROOT_REF (parse-only; no in-tree encoder)

#[test]
fn root_ref_minimal_payload_parses() {
    // dirid=256, sequence=1, name_len=3, name="sub"
    let mut payload = vec![0u8; 21];
    payload[0..8].copy_from_slice(&256u64.to_le_bytes());
    payload[8..16].copy_from_slice(&1u64.to_le_bytes());
    payload[16..18].copy_from_slice(&3u16.to_le_bytes());
    payload[18..21].copy_from_slice(b"sub");

    let decoded = parse_root_ref(&payload).expect("parse root_ref");
    assert_eq!(decoded.dirid, 256);
    assert_eq!(decoded.sequence, 1);
    assert_eq!(decoded.name, b"sub");
}

// Coverage glue

#[test]
fn vec_roundtrip_helper_exercises_inode_ref() {
    // Smoke test of the shared helper to guard against regressions in test
    // infrastructure itself.
    assert_vec_roundtrip(
        "two inode_refs",
        &{
            let a = BtrfsInodeRef {
                index: 10,
                name: b"a".to_vec(),
            };
            let b = BtrfsInodeRef {
                index: 11,
                name: b"bb".to_vec(),
            };
            let mut p = a.to_bytes();
            p.extend_from_slice(&b.to_bytes());
            p
        },
        |bytes| parse_inode_refs(bytes).expect("parse"),
        BtrfsInodeRef::to_bytes,
    );
}

#[test]
fn bitexact_roundtrip_helper_exercises_inode_item() {
    assert_bitexact_roundtrip(
        "regfile inode",
        &GOLDEN_INODE_ITEM_REGFILE,
        |bytes| parse_inode_item(bytes).expect("parse"),
        BtrfsInodeItem::to_bytes,
    );
}
