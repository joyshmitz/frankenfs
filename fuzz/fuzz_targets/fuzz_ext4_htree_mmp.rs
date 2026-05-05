#![no_main]
use ffs_ondisk::ext4::{
    ext4_chksum, parse_dx_root_with_large_dir, EXT4_MMP_MAGIC, EXT4_MMP_SEQ_CLEAN,
    EXT4_MMP_SEQ_FSCK, EXT4_MMP_SEQ_MAX,
};
use ffs_ondisk::{parse_dx_root, Ext4DxRoot, Ext4MmpBlock, Ext4MmpStatus};
use ffs_types::{trim_nul_padded, EXT4_SUPERBLOCK_SIZE};
use libfuzzer_sys::fuzz_target;

const DX_COUNT_LIMIT_OFFSET: usize = 0x20;
const DX_ENTRY_ARRAY_OFFSET: usize = 0x28;
const MMP_CHECKSUM_OFFSET: usize = 0x3FC;

#[derive(Debug, Clone, PartialEq, Eq)]
enum DxOutcome {
    Root {
        hash_version: u8,
        indirect_levels: u8,
        entries: Vec<(u32, u32)>,
    },
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MmpOutcome {
    Block {
        magic: u32,
        seq: u32,
        time: u64,
        nodename: String,
        bdevname: String,
        check_interval: u16,
        checksum: u32,
        status: Ext4MmpStatus,
    },
    Error(String),
}

fn le_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

fn le_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn raw_u16(data: &[u8], offset: usize) -> u16 {
    le_u16(data, offset).unwrap_or(0)
}

fn raw_u32(data: &[u8], offset: usize) -> u32 {
    le_u32(data, offset).unwrap_or(0)
}

fn raw_u64_from_u32_pair(data: &[u8], offset: usize) -> u64 {
    u64::from(raw_u32(data, offset)) | (u64::from(raw_u32(data, offset.saturating_add(4))) << 32)
}

fn normalize_dx_root(data: &[u8], large_dir: bool) -> DxOutcome {
    match parse_dx_root_with_large_dir(data, large_dir) {
        Ok(root) => dx_signature(&root),
        Err(err) => DxOutcome::Error(err.to_string()),
    }
}

fn dx_signature(root: &Ext4DxRoot) -> DxOutcome {
    DxOutcome::Root {
        hash_version: root.hash_version,
        indirect_levels: root.indirect_levels,
        entries: root
            .entries
            .iter()
            .map(|entry| (entry.hash, entry.block))
            .collect(),
    }
}

fn normalize_mmp(data: &[u8]) -> MmpOutcome {
    match Ext4MmpBlock::parse_from_bytes(data) {
        Ok(block) => {
            let status = block.status();
            MmpOutcome::Block {
                magic: block.magic,
                seq: block.seq,
                time: block.time,
                nodename: block.nodename,
                bdevname: block.bdevname,
                check_interval: block.check_interval,
                checksum: block.checksum,
                status,
            }
        }
        Err(err) => MmpOutcome::Error(err.to_string()),
    }
}

fn expected_status(seq: u32) -> Ext4MmpStatus {
    match seq {
        EXT4_MMP_SEQ_CLEAN => Ext4MmpStatus::Clean,
        EXT4_MMP_SEQ_FSCK => Ext4MmpStatus::Fsck,
        1..=EXT4_MMP_SEQ_MAX => Ext4MmpStatus::Active(seq),
        other => Ext4MmpStatus::UnsafeUnknown(other),
    }
}

fn declared_dx_count(data: &[u8]) -> usize {
    usize::from(raw_u16(data, DX_COUNT_LIMIT_OFFSET + 2))
}

fn max_dx_entries_fitting(data: &[u8]) -> usize {
    if data.len() < DX_ENTRY_ARRAY_OFFSET {
        0
    } else {
        1 + data.len().saturating_sub(DX_ENTRY_ARRAY_OFFSET) / 8
    }
}

fn assert_dx_root_invariants(data: &[u8]) {
    let normal = normalize_dx_root(data, false);
    let large_dir = normalize_dx_root(data, true);

    assert_eq!(
        normal,
        normalize_dx_root(data, false),
        "normal DX root parsing must be deterministic"
    );
    assert_eq!(
        large_dir,
        normalize_dx_root(data, true),
        "LARGEDIR DX root parsing must be deterministic"
    );

    if let DxOutcome::Root { entries, .. } = &normal {
        assert_eq!(
            &normal, &large_dir,
            "normal DX roots must also be accepted identically in LARGEDIR mode"
        );
        assert_dx_entry_shape(entries, data);
    }

    if let DxOutcome::Root {
        indirect_levels,
        entries,
        ..
    } = &large_dir
    {
        assert!(*indirect_levels <= 3);
        assert_dx_entry_shape(entries, data);
        if *indirect_levels <= 2 {
            assert_eq!(
                &large_dir, &normal,
                "LARGEDIR roots at normal depth must parse identically without LARGEDIR"
            );
        } else {
            assert!(matches!(normal, DxOutcome::Error(_)));
        }
    }

    let public_normal = parse_dx_root(data).map(|root| dx_signature(&root));
    let normalized_public = match public_normal {
        Ok(root) => root,
        Err(err) => DxOutcome::Error(err.to_string()),
    };
    assert_eq!(
        normalized_public, normal,
        "public parse_dx_root wrapper must match non-LARGEDIR parsing"
    );
}

fn assert_dx_entry_shape(entries: &[(u32, u32)], data: &[u8]) {
    let declared_count = declared_dx_count(data);
    assert!(
        entries.len() <= declared_count,
        "DX parser must not return more entries than declared"
    );
    assert!(
        entries.len() <= max_dx_entries_fitting(data),
        "DX parser must not synthesize entries beyond the source bytes"
    );

    if declared_count == 0 {
        assert!(
            entries.is_empty(),
            "zero declared DX count must produce no entries"
        );
    }
    if let Some((hash, _block)) = entries.first() {
        assert_eq!(*hash, 0, "DX entry 0 has an implicit zero hash");
    }
}

fn assert_arbitrary_mmp_invariants(data: &[u8]) {
    let parsed = normalize_mmp(data);
    assert_eq!(
        parsed,
        normalize_mmp(data),
        "MMP parsing must be deterministic"
    );

    let MmpOutcome::Block {
        magic,
        seq,
        time,
        nodename,
        bdevname,
        check_interval,
        checksum,
        status,
    } = parsed
    else {
        return;
    };

    assert_eq!(magic, EXT4_MMP_MAGIC);
    assert_eq!(seq, raw_u32(data, 0x04));
    assert_eq!(time, raw_u64_from_u32_pair(data, 0x08));
    assert_eq!(
        nodename,
        trim_nul_padded(data.get(0x10..0x50).unwrap_or(&[]))
    );
    assert_eq!(
        bdevname,
        trim_nul_padded(data.get(0x50..0x70).unwrap_or(&[]))
    );
    assert_eq!(check_interval, raw_u16(data, 0x70));
    assert_eq!(checksum, raw_u32(data, MMP_CHECKSUM_OFFSET));
    assert_eq!(status, expected_status(seq));
}

fn synthetic_mmp_block(data: &[u8]) -> ([u8; EXT4_SUPERBLOCK_SIZE], u32) {
    let mut block = [0_u8; EXT4_SUPERBLOCK_SIZE];
    block[0x00..0x04].copy_from_slice(&EXT4_MMP_MAGIC.to_le_bytes());

    let seq = match data.first().copied().unwrap_or(0) % 4 {
        0 => EXT4_MMP_SEQ_CLEAN,
        1 => EXT4_MMP_SEQ_FSCK,
        2 => raw_u32(data, 1) % EXT4_MMP_SEQ_MAX.max(1) + 1,
        _ => EXT4_MMP_SEQ_MAX.saturating_add(raw_u32(data, 1).max(1)),
    };
    block[0x04..0x08].copy_from_slice(&seq.to_le_bytes());
    block[0x08..0x0C].copy_from_slice(&raw_u32(data, 5).to_le_bytes());
    block[0x0C..0x10].copy_from_slice(&raw_u32(data, 9).to_le_bytes());

    for (idx, byte) in data.iter().skip(13).take(64).enumerate() {
        block[0x10 + idx] = *byte;
    }
    for (idx, byte) in data.iter().skip(77).take(32).enumerate() {
        block[0x50 + idx] = *byte;
    }
    block[0x70..0x72].copy_from_slice(&raw_u16(data, 109).to_le_bytes());

    let csum_seed = raw_u32(data, 111);
    let checksum = ext4_chksum(csum_seed, &block[..MMP_CHECKSUM_OFFSET]);
    block[MMP_CHECKSUM_OFFSET..MMP_CHECKSUM_OFFSET + 4].copy_from_slice(&checksum.to_le_bytes());
    (block, csum_seed)
}

fn assert_synthetic_mmp_invariants(data: &[u8]) {
    let (block, csum_seed) = synthetic_mmp_block(data);
    let parsed_result = Ext4MmpBlock::parse_from_bytes(&block);
    assert!(parsed_result.is_ok(), "synthetic MMP block must parse");
    let Ok(parsed) = parsed_result else {
        return;
    };

    assert_eq!(parsed.magic, EXT4_MMP_MAGIC);
    assert_eq!(parsed.status(), expected_status(parsed.seq));
    assert!(
        parsed.validate_checksum(&block, csum_seed).is_ok(),
        "synthetic MMP checksum must validate against its seed"
    );

    let mut corrupted = block;
    corrupted[0x10] ^= 1;
    assert!(
        parsed.validate_checksum(&corrupted, csum_seed).is_err(),
        "single-byte MMP payload corruption must invalidate the checksum"
    );
}

fuzz_target!(|data: &[u8]| {
    assert_dx_root_invariants(data);
    assert_arbitrary_mmp_invariants(data);
    assert_synthetic_mmp_invariants(data);
});
