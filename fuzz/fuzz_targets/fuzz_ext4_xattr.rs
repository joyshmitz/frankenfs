#![no_main]
use ffs_ondisk::{parse_ibody_xattrs, parse_xattr_block, Ext4Inode, Ext4Xattr};
use ffs_types::{
    EXT4_XATTR_INDEX_POSIX_ACL_ACCESS, EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT,
    EXT4_XATTR_INDEX_RICHACL, EXT4_XATTR_INDEX_SECURITY, EXT4_XATTR_INDEX_SYSTEM,
    EXT4_XATTR_INDEX_TRUSTED, EXT4_XATTR_INDEX_USER, EXT4_XATTR_MAGIC, S_IFREG,
};
use libfuzzer_sys::fuzz_target;

const EXTERNAL_BLOCK_SIZE: usize = 256;
const EXTERNAL_ENTRY_OFFSET: usize = 32;
const EXTERNAL_VALUE_OFFSET: usize = 160;
const INODE_SIZE: usize = 256;
const INODE_EXTRA_ISIZE: u16 = 32;
const INODE_EXTRA_ISIZE_USIZE: usize = 32;
const INODE_IBODY_START: usize = 128 + INODE_EXTRA_ISIZE_USIZE;
const IBODY_ENTRY_OFFSET: usize = INODE_IBODY_START + 4;
const IBODY_VALUE_OFFSET: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
enum XattrOutcome {
    Xattrs(Vec<XattrSig>),
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct XattrSig {
    name_index: u8,
    name: Vec<u8>,
    value: Vec<u8>,
    full_name: String,
}

fn normalize_xattrs(result: Result<Vec<Ext4Xattr>, impl ToString>) -> XattrOutcome {
    match result {
        Ok(xattrs) => XattrOutcome::Xattrs(xattrs.iter().map(xattr_sig).collect()),
        Err(err) => XattrOutcome::Error(err.to_string()),
    }
}

fn xattr_sig(xattr: &Ext4Xattr) -> XattrSig {
    XattrSig {
        name_index: xattr.name_index,
        name: xattr.name.clone(),
        value: xattr.value.clone(),
        full_name: xattr.full_name(),
    }
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn bounded_bytes(data: &[u8], offset: usize, len: usize, fallback_seed: u8) -> Vec<u8> {
    (0..len)
        .map(|idx| {
            data.get(offset.saturating_add(idx))
                .copied()
                .unwrap_or(fallback_seed.wrapping_add(u8::try_from(idx).unwrap_or(0)))
        })
        .collect()
}

fn synthetic_name(data: &[u8], offset: usize) -> Vec<u8> {
    let len = usize::from(data.get(offset).copied().unwrap_or(3) % 16) + 1;
    bounded_bytes(data, offset.saturating_add(1), len, b'a')
}

fn synthetic_value(data: &[u8], offset: usize) -> Vec<u8> {
    synthetic_value_with_max(data, offset, 32)
}

fn synthetic_value_with_max(data: &[u8], offset: usize, max_len: u8) -> Vec<u8> {
    let len = usize::from(data.get(offset).copied().unwrap_or(5) % max_len);
    bounded_bytes(data, offset.saturating_add(1), len, b'v')
}

fn synthetic_name_index(data: &[u8], offset: usize) -> u8 {
    match data.get(offset).copied().unwrap_or(0) % 7 {
        0 => EXT4_XATTR_INDEX_USER,
        1 => EXT4_XATTR_INDEX_POSIX_ACL_ACCESS,
        2 => EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT,
        3 => EXT4_XATTR_INDEX_TRUSTED,
        4 => EXT4_XATTR_INDEX_SECURITY,
        5 => EXT4_XATTR_INDEX_SYSTEM,
        _ => EXT4_XATTR_INDEX_RICHACL,
    }
}

fn assert_full_name_prefix(sig: &XattrSig) {
    let prefixes = [
        "user.",
        "system.posix_acl_access",
        "system.posix_acl_default",
        "trusted.",
        "security.",
        "system.",
        "system.richacl",
        "unknown.",
    ];
    assert!(
        prefixes
            .iter()
            .any(|prefix| sig.full_name.starts_with(prefix)),
        "xattr full name must use a known namespace prefix"
    );
}

fn assert_xattr_shape(outcome: &XattrOutcome) {
    let XattrOutcome::Xattrs(xattrs) = outcome else {
        return;
    };

    for sig in xattrs {
        assert_full_name_prefix(sig);
        assert!(
            sig.name.len() <= u8::MAX as usize,
            "xattr names are length-prefixed by one byte"
        );
    }
}

fn write_entry(
    bytes: &mut [u8],
    entry_offset: usize,
    name_index: u8,
    name: &[u8],
    value_offset: u16,
    value: &[u8],
) -> usize {
    bytes[entry_offset] = u8::try_from(name.len()).unwrap_or(u8::MAX);
    bytes[entry_offset + 1] = name_index;
    bytes[entry_offset + 2..entry_offset + 4].copy_from_slice(&value_offset.to_le_bytes());
    bytes[entry_offset + 8..entry_offset + 12]
        .copy_from_slice(&u32::try_from(value.len()).unwrap_or(0).to_le_bytes());
    bytes[entry_offset + 16..entry_offset + 16 + name.len()].copy_from_slice(name);
    align4(entry_offset + 16 + name.len())
}

fn synthetic_external_block(data: &[u8]) -> (Vec<u8>, u8, Vec<u8>, Vec<u8>) {
    let mut block = vec![0_u8; EXTERNAL_BLOCK_SIZE];
    block[0..4].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());
    let name_index = synthetic_name_index(data, 0);
    let name = synthetic_name(data, 1);
    let value = synthetic_value(data, 24);
    let terminator = write_entry(
        &mut block,
        EXTERNAL_ENTRY_OFFSET,
        name_index,
        &name,
        u16::try_from(EXTERNAL_VALUE_OFFSET).unwrap_or(0),
        &value,
    );
    block[terminator] = 0;
    block[terminator + 1] = 0;
    block[EXTERNAL_VALUE_OFFSET..EXTERNAL_VALUE_OFFSET + value.len()].copy_from_slice(&value);
    (block, name_index, name, value)
}

fn synthetic_inode_bytes(data: &[u8]) -> (Vec<u8>, u8, Vec<u8>, Vec<u8>) {
    let mut bytes = vec![0_u8; INODE_SIZE];
    bytes[0x00..0x02].copy_from_slice(&(S_IFREG | 0o644).to_le_bytes());
    bytes[0x80..0x82].copy_from_slice(&INODE_EXTRA_ISIZE.to_le_bytes());
    bytes[INODE_IBODY_START..INODE_IBODY_START + 4]
        .copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());

    let name_index = synthetic_name_index(data, 56);
    let name = synthetic_name(data, 57);
    let value = synthetic_value_with_max(data, 80, 24);
    let terminator = write_entry(
        &mut bytes,
        IBODY_ENTRY_OFFSET,
        name_index,
        &name,
        u16::try_from(IBODY_VALUE_OFFSET).unwrap_or(0),
        &value,
    );
    bytes[terminator] = 0;
    bytes[terminator + 1] = 0;

    let value_start = IBODY_ENTRY_OFFSET + IBODY_VALUE_OFFSET;
    bytes[value_start..value_start + value.len()].copy_from_slice(&value);

    (bytes, name_index, name, value)
}

fn assert_arbitrary_external_block(data: &[u8]) {
    let parsed = normalize_xattrs(parse_xattr_block(data));
    assert_eq!(
        parsed,
        normalize_xattrs(parse_xattr_block(data)),
        "external xattr block parsing must be deterministic"
    );
    assert_xattr_shape(&parsed);

    if data.len() < EXTERNAL_ENTRY_OFFSET {
        assert!(
            matches!(parsed, XattrOutcome::Error(_)),
            "short external xattr blocks must reject"
        );
    }
}

fn assert_arbitrary_ibody(data: &[u8]) {
    let Ok(inode) = Ext4Inode::parse_from_bytes(data) else {
        return;
    };
    let parsed = normalize_xattrs(parse_ibody_xattrs(&inode));
    assert_eq!(
        parsed,
        normalize_xattrs(parse_ibody_xattrs(&inode)),
        "inline xattr parsing must be deterministic"
    );
    assert_xattr_shape(&parsed);
}

fn assert_synthetic_external_block(data: &[u8]) {
    let (block, name_index, name, value) = synthetic_external_block(data);
    let parsed = parse_xattr_block(&block);
    assert!(parsed.is_ok(), "synthetic external xattr block must parse");
    let Ok(xattrs) = parsed else {
        return;
    };
    assert_eq!(xattrs.len(), 1);
    assert_eq!(xattrs[0].name_index, name_index);
    assert_eq!(xattrs[0].name, name);
    assert_eq!(xattrs[0].value, value);

    let mut mutated_hash = block;
    mutated_hash[EXTERNAL_ENTRY_OFFSET + 12..EXTERNAL_ENTRY_OFFSET + 16]
        .copy_from_slice(&0xA5A5_5A5A_u32.to_le_bytes());
    assert_eq!(
        normalize_xattrs(parse_xattr_block(&mutated_hash)),
        XattrOutcome::Xattrs(xattrs.iter().map(xattr_sig).collect()),
        "unused external xattr entry hash must not affect the logical parse"
    );
}

fn assert_synthetic_ibody(data: &[u8]) {
    let (bytes, name_index, name, value) = synthetic_inode_bytes(data);
    let inode = Ext4Inode::parse_from_bytes(&bytes);
    assert!(inode.is_ok(), "synthetic inode must parse");
    let Ok(inode) = inode else {
        return;
    };
    let parsed = parse_ibody_xattrs(&inode);
    assert!(parsed.is_ok(), "synthetic ibody xattr must parse");
    let Ok(xattrs) = parsed else {
        return;
    };
    assert_eq!(xattrs.len(), 1);
    assert_eq!(xattrs[0].name_index, name_index);
    assert_eq!(xattrs[0].name, name);
    assert_eq!(xattrs[0].value, value);
}

fuzz_target!(|data: &[u8]| {
    assert_arbitrary_external_block(data);
    assert_arbitrary_ibody(data);
    assert_synthetic_external_block(data);
    assert_synthetic_ibody(data);
});
