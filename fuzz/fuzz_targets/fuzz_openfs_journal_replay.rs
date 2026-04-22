#![no_main]

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_core::{
    Ext4JournalReplayMode, ExternalJournalInfo, Ext4FastCommitReplayEvidence, OpenFs, OpenOptions,
};
use ffs_error::{FfsError, Result};
use ffs_journal::ReplayOutcome as JournalReplayOutcome;
use ffs_mvcc::persist::WalRecoveryReport;
use ffs_mvcc::wal::{self, WalCommit, WalHeader, WalWrite, HEADER_SIZE as WAL_HEADER_SIZE};
use ffs_mvcc::wal_replay::ReplayOutcome as WalReplayOutcome;
use ffs_ondisk::{EXT4_ORPHAN_FS, EXT4_VALID_FS};
use ffs_types::{ByteOffset, CommitSeq, InodeNumber, TxnId, EXT4_SUPERBLOCK_OFFSET, EXT4_SUPER_MAGIC};
use libfuzzer_sys::fuzz_target;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

const MAX_INPUT_BYTES: usize = 1024;
const BLOCK_SIZE: usize = 4096;
const IMAGE_SIZE: usize = 256 * 1024;
const INODE_SIZE: usize = 256;
const ROOT_INODE_TABLE_OFFSET: usize = 4 * BLOCK_SIZE;

const EXT4_STATE_OFFSET: usize = EXT4_SUPERBLOCK_OFFSET + 0x3A;
const EXT4_COMPAT_OFFSET: usize = EXT4_SUPERBLOCK_OFFSET + 0x5C;
const EXT4_JOURNAL_UUID_OFFSET: usize = EXT4_SUPERBLOCK_OFFSET + 0xD0;
const EXT4_JOURNAL_INUM_OFFSET: usize = EXT4_SUPERBLOCK_OFFSET + 0xE0;
const EXT4_JOURNAL_DEV_OFFSET: usize = EXT4_SUPERBLOCK_OFFSET + 0xE4;
const EXT4_LAST_ORPHAN_OFFSET: usize = EXT4_SUPERBLOCK_OFFSET + 0xE8;

const JOURNAL_SUPERBLOCK_BLOCK: usize = 20;
const JOURNAL_DESCRIPTOR_BLOCK: usize = 21;
const JOURNAL_DATA_BLOCK: usize = 22;
const JOURNAL_COMMIT_BLOCK: usize = 23;
const JOURNAL_FAST_COMMIT_BLOCK: usize = 24;

const EXT4_INTERESTING_OFFSETS: [usize; 14] = [
    EXT4_SUPERBLOCK_OFFSET + 0x04,
    EXT4_STATE_OFFSET,
    EXT4_COMPAT_OFFSET,
    EXT4_JOURNAL_UUID_OFFSET,
    EXT4_JOURNAL_UUID_OFFSET + 8,
    EXT4_JOURNAL_INUM_OFFSET,
    EXT4_JOURNAL_DEV_OFFSET,
    EXT4_LAST_ORPHAN_OFFSET,
    JOURNAL_SUPERBLOCK_BLOCK * BLOCK_SIZE + 12,
    JOURNAL_SUPERBLOCK_BLOCK * BLOCK_SIZE + 40,
    JOURNAL_SUPERBLOCK_BLOCK * BLOCK_SIZE + 84,
    JOURNAL_DESCRIPTOR_BLOCK * BLOCK_SIZE + 12,
    JOURNAL_DESCRIPTOR_BLOCK * BLOCK_SIZE + 16,
    JOURNAL_FAST_COMMIT_BLOCK * BLOCK_SIZE,
];

const EXTERNAL_JOURNAL_INTERESTING_OFFSETS: [usize; 8] = [
    12,
    16,
    20,
    40,
    48,
    BLOCK_SIZE + 12,
    BLOCK_SIZE + 16,
    2 * BLOCK_SIZE,
];

const WAL_INTERESTING_OFFSETS: [usize; 10] = [
    0,
    4,
    8,
    WAL_HEADER_SIZE,
    WAL_HEADER_SIZE + 8,
    WAL_HEADER_SIZE + 16,
    WAL_HEADER_SIZE + 32,
    WAL_HEADER_SIZE + 48,
    WAL_HEADER_SIZE + 64,
    WAL_HEADER_SIZE + 96,
];

const JOURNAL_UUID: [u8; 16] = *b"fuzz-journal-000";

#[derive(Clone, Copy)]
enum SeedCase {
    InternalJournal,
    FastCommit,
    ExternalJournalClean,
    ExternalJournalDirty,
    WalOnly,
}

impl SeedCase {
    fn from_selector(selector: u8) -> Self {
        match selector % 5 {
            0 => Self::InternalJournal,
            1 => Self::FastCommit,
            2 => Self::ExternalJournalClean,
            3 => Self::ExternalJournalDirty,
            _ => Self::WalOnly,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WalOutcomeClass {
    Clean,
    EmptyLog,
    TruncatedTail { discarded: u64 },
    CorruptTail { discarded: u64, first_corrupt_offset: u64 },
    MonotonicityViolation { violating_seq: u64, expected_after: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JournalClass {
    committed_sequences: usize,
    replayed_blocks: u64,
    incomplete_transactions: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FastCommitClass {
    reserved_fc_blocks: u32,
    transactions_found: u64,
    incomplete_transactions: u64,
    verified_operations: u64,
    fallback_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WalClass {
    outcome: WalOutcomeClass,
    commits_replayed: u64,
    records_discarded: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExternalJournalClass {
    uuid_match: bool,
    journal_block_size: u32,
    journal_max_len: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OutcomeClass {
    Open {
        block_size: u32,
        dirty_recovery: bool,
        journal: Option<JournalClass>,
        fast_commit: Option<FastCommitClass>,
        wal: Option<WalClass>,
        external_journal: Option<ExternalJournalClass>,
    },
    Err {
        errno: i32,
        detail: String,
    },
}

#[derive(Debug)]
struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        let byte = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        byte
    }

    fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 == 1
    }

    fn next_u16(&mut self) -> u16 {
        u16::from_le_bytes([self.next_u8(), self.next_u8()])
    }

    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    fn next_index(&mut self, len: usize) -> usize {
        if len == 0 {
            0
        } else {
            usize::from(self.next_u16()) % len
        }
    }
}

#[derive(Debug)]
struct MemByteDevice {
    data: Arc<Mutex<Vec<u8>>>,
}

impl MemByteDevice {
    fn from_vec(data: Vec<u8>) -> Self {
        Self {
            data: Arc::new(Mutex::new(data)),
        }
    }
}

impl ByteDevice for MemByteDevice {
    fn len_bytes(&self) -> u64 {
        let data = self
            .data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        u64::try_from(data.len()).unwrap_or(u64::MAX)
    }

    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        let off = usize::try_from(offset.0)
            .map_err(|_| FfsError::Format("offset does not fit usize".to_owned()))?;
        let data = self
            .data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let end = off
            .checked_add(buf.len())
            .ok_or_else(|| FfsError::Format("read offset overflow".to_owned()))?;
        if end > data.len() {
            return Err(FfsError::Format(format!(
                "read out of bounds: {off}..{end} > {}",
                data.len()
            )));
        }
        buf.copy_from_slice(&data[off..end]);
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        let off = usize::try_from(offset.0)
            .map_err(|_| FfsError::Format("offset does not fit usize".to_owned()))?;
        let mut data = self
            .data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let end = off
            .checked_add(buf.len())
            .ok_or_else(|| FfsError::Format("write offset overflow".to_owned()))?;
        if end > data.len() {
            return Err(FfsError::Format(format!(
                "write out of bounds: {off}..{end} > {}",
                data.len()
            )));
        }
        data[off..end].copy_from_slice(buf);
        Ok(())
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct JournalReplayCase {
    image: Vec<u8>,
    external_journal: Option<Vec<u8>>,
    wal_bytes: Option<Vec<u8>>,
}

fn build_ext4_image_with_inode() -> Vec<u8> {
    let mut image = vec![0_u8; IMAGE_SIZE];
    let sb_off = EXT4_SUPERBLOCK_OFFSET;

    image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
    image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&2_u32.to_le_bytes());
    let blocks_count = u32::try_from(IMAGE_SIZE / BLOCK_SIZE).unwrap_or(u32::MAX);
    image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&0_u32.to_le_bytes());
    image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&(INODE_SIZE as u16).to_le_bytes());
    image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes());
    image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes());
    image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&(0x0002_u32 | 0x0040_u32).to_le_bytes());
    image[sb_off + 0x3A..sb_off + 0x3C].copy_from_slice(&EXT4_VALID_FS.to_le_bytes());

    let gd_off = BLOCK_SIZE;
    image[gd_off..gd_off + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[gd_off + 4..gd_off + 8].copy_from_slice(&3_u32.to_le_bytes());
    image[gd_off + 8..gd_off + 12].copy_from_slice(&4_u32.to_le_bytes());

    let ino_off = ROOT_INODE_TABLE_OFFSET + INODE_SIZE;
    image[ino_off..ino_off + 2].copy_from_slice(&0o040_755_u16.to_le_bytes());
    image[ino_off + 4..ino_off + 8].copy_from_slice(&(BLOCK_SIZE as u32).to_le_bytes());
    image[ino_off + 0x1A..ino_off + 0x1C].copy_from_slice(&2_u16.to_le_bytes());
    image[ino_off + 0x80..ino_off + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    image
}

fn write_jbd2_header(block: &mut [u8], block_type: u32, sequence: u32) {
    const JBD2_MAGIC: u32 = 0xC03B_3998;
    block[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
    block[4..8].copy_from_slice(&block_type.to_be_bytes());
    block[8..12].copy_from_slice(&sequence.to_be_bytes());
}

fn write_jbd2_superblock_v2(
    block: &mut [u8],
    block_size: u32,
    max_len: u32,
    first_log_block: u32,
    start_sequence: u32,
    start_block: u32,
    num_fc_blocks: u32,
    feature_incompat: u32,
) {
    write_jbd2_header(block, 4, 0);
    block[12..16].copy_from_slice(&block_size.to_be_bytes());
    block[16..20].copy_from_slice(&max_len.to_be_bytes());
    block[20..24].copy_from_slice(&first_log_block.to_be_bytes());
    block[24..28].copy_from_slice(&start_sequence.to_be_bytes());
    block[28..32].copy_from_slice(&start_block.to_be_bytes());
    block[40..44].copy_from_slice(&feature_incompat.to_be_bytes());
    block[84..88].copy_from_slice(&num_fc_blocks.to_be_bytes());
}

fn build_fc_tag(tag_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4 + payload.len());
    bytes.extend_from_slice(&tag_type.to_le_bytes());
    bytes.extend_from_slice(
        &u16::try_from(payload.len())
            .expect("fast-commit payload length should fit")
            .to_le_bytes(),
    );
    bytes.extend_from_slice(payload);
    bytes
}

fn build_fc_inode_update_transaction(ino: u32, tid: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(build_fc_tag(0x0A, &[0; 16]));
    bytes.extend(build_fc_tag(0x07, &ino.to_le_bytes()));
    let mut tail = [0_u8; 8];
    tail[..4].copy_from_slice(&tid.to_le_bytes());
    bytes.extend(build_fc_tag(0x09, &tail));
    bytes
}

fn pad_fc_stream_to_block_boundary(bytes: &mut Vec<u8>, block_len: usize) {
    let used = bytes.len() % block_len;
    if used == 0 {
        return;
    }

    let remaining = block_len - used;
    let pad_tag = build_fc_tag(0x08, &[]);
    for _ in 0..(remaining / pad_tag.len()) {
        bytes.extend_from_slice(&pad_tag);
    }
}

fn set_test_journal_uuid(image: &mut [u8], uuid: [u8; 16]) {
    image[EXT4_JOURNAL_UUID_OFFSET..EXT4_JOURNAL_UUID_OFFSET + 16].copy_from_slice(&uuid);
}

fn build_external_journal_image(
    block_size: usize,
    uuid: [u8; 16],
    target_block: u32,
    payload: &[u8],
) -> Vec<u8> {
    let blocks = 8usize;
    let mut image = vec![0_u8; block_size * blocks];
    write_jbd2_superblock_v2(
        &mut image[..block_size],
        u32::try_from(block_size).expect("block_size fits u32"),
        u32::try_from(blocks).expect("block count fits u32"),
        1,
        1,
        1,
        0,
        0,
    );
    image[48..64].copy_from_slice(&uuid);

    let desc = block_size;
    write_jbd2_header(&mut image[desc..desc + block_size], 1, 1);
    image[desc + 12..desc + 16].copy_from_slice(&target_block.to_be_bytes());
    image[desc + 16..desc + 20].copy_from_slice(&0x0000_0008_u32.to_be_bytes());

    let data = 2 * block_size;
    image[data..data + payload.len()].copy_from_slice(payload);

    let commit = 3 * block_size;
    write_jbd2_header(&mut image[commit..commit + block_size], 2, 1);

    image
}

fn journal_inode_offset() -> usize {
    ROOT_INODE_TABLE_OFFSET + 7 * INODE_SIZE
}

fn build_ext4_image_with_internal_journal() -> Vec<u8> {
    let mut image = build_ext4_image_with_inode();
    let compat = u32::from_le_bytes(
        image[EXT4_COMPAT_OFFSET..EXT4_COMPAT_OFFSET + 4]
            .try_into()
            .expect("compat bytes"),
    );
    image[EXT4_COMPAT_OFFSET..EXT4_COMPAT_OFFSET + 4]
        .copy_from_slice(&(compat | 0x0004).to_le_bytes());
    image[EXT4_JOURNAL_INUM_OFFSET..EXT4_JOURNAL_INUM_OFFSET + 4]
        .copy_from_slice(&8_u32.to_le_bytes());

    let ino8_off = journal_inode_offset();
    image[ino8_off..ino8_off + 2].copy_from_slice(&0o100_600_u16.to_le_bytes());
    image[ino8_off + 4..ino8_off + 8].copy_from_slice(&(3_u32 * BLOCK_SIZE as u32).to_le_bytes());
    image[ino8_off + 0x1A..ino8_off + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
    image[ino8_off + 0x20..ino8_off + 0x24].copy_from_slice(&0x0008_0000_u32.to_le_bytes());
    image[ino8_off + 0x80..ino8_off + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let extent = ino8_off + 0x28;
    image[extent..extent + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[extent + 2..extent + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[extent + 4..extent + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[extent + 6..extent + 8].copy_from_slice(&0_u16.to_le_bytes());
    image[extent + 12..extent + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[extent + 16..extent + 18].copy_from_slice(&3_u16.to_le_bytes());
    image[extent + 18..extent + 20].copy_from_slice(&0_u16.to_le_bytes());
    image[extent + 20..extent + 24]
        .copy_from_slice(&(JOURNAL_SUPERBLOCK_BLOCK as u32).to_le_bytes());

    let j_desc = JOURNAL_DESCRIPTOR_BLOCK * BLOCK_SIZE;
    write_jbd2_header(&mut image[j_desc..j_desc + BLOCK_SIZE], 1, 1);
    image[j_desc + 12..j_desc + 16].copy_from_slice(&15_u32.to_be_bytes());
    image[j_desc + 16..j_desc + 20].copy_from_slice(&0x0000_0008_u32.to_be_bytes());

    let j_data = JOURNAL_DATA_BLOCK * BLOCK_SIZE;
    image[j_data..j_data + 16].copy_from_slice(b"JBD2-REPLAY-TEST");

    let j_commit = JOURNAL_COMMIT_BLOCK * BLOCK_SIZE;
    write_jbd2_header(&mut image[j_commit..j_commit + BLOCK_SIZE], 2, 1);

    image
}

fn build_ext4_image_with_fast_commit_evidence() -> Vec<u8> {
    const JBD2_FEATURE_INCOMPAT_FAST_COMMIT: u32 = 0x0000_0020;
    const EXT4_COMPAT_FAST_COMMIT: u32 = 0x0000_0400;

    let mut image = build_ext4_image_with_internal_journal();
    let compat = u32::from_le_bytes(
        image[EXT4_COMPAT_OFFSET..EXT4_COMPAT_OFFSET + 4]
            .try_into()
            .expect("compat bytes"),
    );
    image[EXT4_COMPAT_OFFSET..EXT4_COMPAT_OFFSET + 4]
        .copy_from_slice(&(compat | EXT4_COMPAT_FAST_COMMIT).to_le_bytes());

    let ino8_off = journal_inode_offset();
    image[ino8_off + 4..ino8_off + 8].copy_from_slice(&(6_u32 * BLOCK_SIZE as u32).to_le_bytes());
    let extent = ino8_off + 0x28;
    image[extent + 16..extent + 18].copy_from_slice(&6_u16.to_le_bytes());

    let journal_sb = JOURNAL_SUPERBLOCK_BLOCK * BLOCK_SIZE;
    write_jbd2_superblock_v2(
        &mut image[journal_sb..journal_sb + BLOCK_SIZE],
        BLOCK_SIZE as u32,
        6,
        1,
        1,
        1,
        2,
        JBD2_FEATURE_INCOMPAT_FAST_COMMIT,
    );

    let mut fc_payload = build_fc_inode_update_transaction(42, 1);
    pad_fc_stream_to_block_boundary(&mut fc_payload, BLOCK_SIZE);
    let fc_block = JOURNAL_FAST_COMMIT_BLOCK * BLOCK_SIZE;
    image[fc_block..fc_block + fc_payload.len()].copy_from_slice(&fc_payload);

    image
}

fn build_ext4_image_with_external_journal(dirty_recovery: bool) -> (Vec<u8>, Vec<u8>) {
    let mut image = build_ext4_image_with_inode();
    let compat = u32::from_le_bytes(
        image[EXT4_COMPAT_OFFSET..EXT4_COMPAT_OFFSET + 4]
            .try_into()
            .expect("compat bytes"),
    );
    image[EXT4_COMPAT_OFFSET..EXT4_COMPAT_OFFSET + 4]
        .copy_from_slice(&(compat | 0x0004).to_le_bytes());
    image[EXT4_JOURNAL_DEV_OFFSET..EXT4_JOURNAL_DEV_OFFSET + 4].copy_from_slice(&1_u32.to_le_bytes());
    set_test_journal_uuid(&mut image, JOURNAL_UUID);
    let state = if dirty_recovery { 0 } else { EXT4_VALID_FS };
    image[EXT4_STATE_OFFSET..EXT4_STATE_OFFSET + 2].copy_from_slice(&state.to_le_bytes());
    let external = build_external_journal_image(BLOCK_SIZE, JOURNAL_UUID, 15, b"EXT-JBD2-REPLAY!");
    (image, external)
}

fn build_wal_bytes() -> Vec<u8> {
    let c1 = WalCommit {
        commit_seq: CommitSeq(1),
        txn_id: TxnId(1),
        writes: vec![WalWrite {
            block: ffs_types::BlockNumber(10),
            data: vec![0xAA; 16],
        }],
    };
    let c2 = WalCommit {
        commit_seq: CommitSeq(2),
        txn_id: TxnId(2),
        writes: vec![WalWrite {
            block: ffs_types::BlockNumber(20),
            data: vec![0xBB; 16],
        }],
    };
    let mut bytes = Vec::from(wal::encode_header(&WalHeader::default()));
    bytes.extend_from_slice(&wal::encode_commit(&c1).expect("encode commit"));
    bytes.extend_from_slice(&wal::encode_commit(&c2).expect("encode commit"));
    bytes
}

fn mutate_byte(bytes: &mut [u8], offset: usize, value: u8) {
    if let Some(slot) = bytes.get_mut(offset) {
        *slot = value;
    }
}

fn xor_byte(bytes: &mut [u8], offset: usize, value: u8) {
    if let Some(slot) = bytes.get_mut(offset) {
        *slot ^= value;
    }
}

fn write_u16_le(bytes: &mut [u8], offset: usize, value: u16) {
    let end = offset.saturating_add(2);
    if end <= bytes.len() {
        bytes[offset..end].copy_from_slice(&value.to_le_bytes());
    }
}

fn write_u32_le(bytes: &mut [u8], offset: usize, value: u32) {
    let end = offset.saturating_add(4);
    if end <= bytes.len() {
        bytes[offset..end].copy_from_slice(&value.to_le_bytes());
    }
}

fn overwrite_range(bytes: &mut [u8], offset: usize, len: usize, cursor: &mut ByteCursor<'_>) {
    let start = offset.min(bytes.len());
    let end = start.saturating_add(len).min(bytes.len());
    for byte in &mut bytes[start..end] {
        *byte = cursor.next_u8();
    }
}

fn zero_range(bytes: &mut [u8], offset: usize, len: usize) {
    let start = offset.min(bytes.len());
    let end = start.saturating_add(len).min(bytes.len());
    bytes[start..end].fill(0);
}

fn mutate_bytes(bytes: &mut [u8], cursor: &mut ByteCursor<'_>, interesting_offsets: &[usize]) {
    let focused_rounds = usize::from(cursor.next_u8() % 16);
    for _ in 0..focused_rounds {
        let base = interesting_offsets[cursor.next_index(interesting_offsets.len())];
        match cursor.next_u8() % 6 {
            0 => mutate_byte(bytes, base, cursor.next_u8()),
            1 => xor_byte(bytes, base, cursor.next_u8()),
            2 => write_u16_le(bytes, base, cursor.next_u16()),
            3 => write_u32_le(bytes, base, cursor.next_u32()),
            4 => overwrite_range(bytes, base, 1 + usize::from(cursor.next_u8() % 32), cursor),
            _ => zero_range(bytes, base, 1 + usize::from(cursor.next_u8() % 32)),
        }
    }

    let wide_rounds = usize::from(cursor.next_u8() % 4);
    for _ in 0..wide_rounds {
        let base = cursor.next_index(bytes.len());
        overwrite_range(bytes, base, 1 + usize::from(cursor.next_u8() % 64), cursor);
    }
}

fn mutate_wal_bytes(bytes: &mut Vec<u8>, cursor: &mut ByteCursor<'_>) {
    mutate_bytes(bytes, cursor, &WAL_INTERESTING_OFFSETS);
    if cursor.next_bool() && !bytes.is_empty() {
        let keep = cursor.next_index(bytes.len());
        bytes.truncate(keep);
    }
}

fn build_case(seed: SeedCase, cursor: &mut ByteCursor<'_>) -> JournalReplayCase {
    let mut case = match seed {
        SeedCase::InternalJournal => JournalReplayCase {
            image: build_ext4_image_with_internal_journal(),
            external_journal: None,
            wal_bytes: None,
        },
        SeedCase::FastCommit => JournalReplayCase {
            image: build_ext4_image_with_fast_commit_evidence(),
            external_journal: None,
            wal_bytes: None,
        },
        SeedCase::ExternalJournalClean => {
            let (image, external_journal) = build_ext4_image_with_external_journal(false);
            JournalReplayCase {
                image,
                external_journal: Some(external_journal),
                wal_bytes: None,
            }
        }
        SeedCase::ExternalJournalDirty => {
            let (mut image, external_journal) = build_ext4_image_with_external_journal(true);
            image[EXT4_LAST_ORPHAN_OFFSET..EXT4_LAST_ORPHAN_OFFSET + 4]
                .copy_from_slice(&u32::from(InodeNumber(11).0 as u32).to_le_bytes());
            JournalReplayCase {
                image,
                external_journal: Some(external_journal),
                wal_bytes: None,
            }
        }
        SeedCase::WalOnly => JournalReplayCase {
            image: build_ext4_image_with_inode(),
            external_journal: None,
            wal_bytes: Some(build_wal_bytes()),
        },
    };

    if cursor.next_bool() {
        case.wal_bytes.get_or_insert_with(build_wal_bytes);
    }
    if cursor.next_bool() && case.external_journal.is_none() && matches!(seed, SeedCase::InternalJournal | SeedCase::FastCommit) {
        let (_, external_journal) = build_ext4_image_with_external_journal(cursor.next_bool());
        case.external_journal = Some(external_journal);
        case.image[EXT4_JOURNAL_DEV_OFFSET..EXT4_JOURNAL_DEV_OFFSET + 4]
            .copy_from_slice(&1_u32.to_le_bytes());
        set_test_journal_uuid(&mut case.image, JOURNAL_UUID);
    }

    mutate_bytes(&mut case.image, cursor, &EXT4_INTERESTING_OFFSETS);
    if let Some(external) = &mut case.external_journal {
        mutate_bytes(external, cursor, &EXTERNAL_JOURNAL_INTERESTING_OFFSETS);
    }
    if let Some(wal_bytes) = &mut case.wal_bytes {
        mutate_wal_bytes(wal_bytes, cursor);
    }

    if cursor.next_bool() {
        case.image[EXT4_STATE_OFFSET..EXT4_STATE_OFFSET + 2]
            .copy_from_slice(&(EXT4_VALID_FS | EXT4_ORPHAN_FS).to_le_bytes());
    }

    case
}

fn pick_options(
    seed: SeedCase,
    case: &JournalReplayCase,
    cursor: &mut ByteCursor<'_>,
) -> OpenOptions {
    let ext4_journal_replay_mode = match cursor.next_u8() % 3 {
        0 => Ext4JournalReplayMode::Apply,
        1 => Ext4JournalReplayMode::SimulateOverlay,
        _ => Ext4JournalReplayMode::Skip,
    };

    let external_journal_path = if case.external_journal.is_some()
        && (!matches!(seed, SeedCase::ExternalJournalDirty) || cursor.next_bool())
    {
        Some(persistent_path("external_journal.img"))
    } else {
        None
    };

    let mvcc_wal_path = if case.wal_bytes.is_some() && cursor.next_bool() {
        Some(persistent_path("openfs_replay.wal"))
    } else {
        None
    };

    OpenOptions {
        skip_validation: cursor.next_bool(),
        ext4_journal_replay_mode,
        mvcc_wal_path,
        mvcc_replay_policy: if cursor.next_bool() {
            ffs_mvcc::wal_replay::TailPolicy::FailFast
        } else {
            ffs_mvcc::wal_replay::TailPolicy::TruncateToLastGood
        },
        external_journal_path,
        ext4_verify_journal_checksums: cursor.next_bool(),
        ..OpenOptions::default()
    }
}

fn persistent_dir() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!(
            "frankenfs-fuzz-bd-p8c4q-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        dir
    })
}

fn persistent_path(name: &str) -> PathBuf {
    persistent_dir().join(name)
}

fn write_persistent_bytes(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, bytes);
}

fn classify_journal(outcome: &JournalReplayOutcome) -> JournalClass {
    JournalClass {
        committed_sequences: outcome.committed_sequences.len(),
        replayed_blocks: outcome.stats.replayed_blocks,
        incomplete_transactions: outcome.stats.incomplete_transactions,
    }
}

fn classify_fast_commit(evidence: &Ext4FastCommitReplayEvidence) -> FastCommitClass {
    FastCommitClass {
        reserved_fc_blocks: evidence.reserved_fc_blocks,
        transactions_found: evidence.replay.transactions_found,
        incomplete_transactions: evidence.replay.incomplete_transactions,
        verified_operations: evidence.verified_operations,
        fallback_required: evidence.replay.fallback_required,
    }
}

fn classify_wal(report: &WalRecoveryReport) -> WalClass {
    let outcome = match &report.outcome {
        WalReplayOutcome::Clean => WalOutcomeClass::Clean,
        WalReplayOutcome::EmptyLog => WalOutcomeClass::EmptyLog,
        WalReplayOutcome::TruncatedTail { records_discarded } => {
            WalOutcomeClass::TruncatedTail {
                discarded: *records_discarded,
            }
        }
        WalReplayOutcome::CorruptTail {
            records_discarded,
            first_corrupt_offset,
        } => WalOutcomeClass::CorruptTail {
            discarded: *records_discarded,
            first_corrupt_offset: *first_corrupt_offset,
        },
        WalReplayOutcome::MonotonicityViolation {
            violating_seq,
            expected_after,
        } => WalOutcomeClass::MonotonicityViolation {
            violating_seq: *violating_seq,
            expected_after: *expected_after,
        },
    };

    WalClass {
        outcome,
        commits_replayed: report.commits_replayed,
        records_discarded: report.records_discarded,
    }
}

fn classify_external(info: &ExternalJournalInfo) -> ExternalJournalClass {
    ExternalJournalClass {
        uuid_match: info.uuid_match,
        journal_block_size: info.journal_block_size,
        journal_max_len: info.journal_max_len,
    }
}

fn classify_open(case: &JournalReplayCase, options: &OpenOptions) -> OutcomeClass {
    if let (Some(path), Some(bytes)) = (&options.external_journal_path, &case.external_journal) {
        write_persistent_bytes(path, bytes);
    }
    if let (Some(path), Some(bytes)) = (&options.mvcc_wal_path, &case.wal_bytes) {
        write_persistent_bytes(path, bytes);
    }

    let cx = Cx::for_testing();
    let dev = MemByteDevice::from_vec(case.image.clone());
    match OpenFs::from_device(&cx, Box::new(dev), options) {
        Ok(fs) => {
            assert!(fs.is_ext4(), "journal replay fuzz target should stay on ext4");
            assert!(fs.ext4_superblock().is_some(), "ext4 open should expose a superblock");

            let journal = fs.ext4_journal_replay().map(classify_journal);
            let fast_commit = fs.ext4_fast_commit_replay().map(classify_fast_commit);
            let wal = fs.mvcc_wal_recovery().map(classify_wal);
            let external_journal = fs.external_journal_info.as_ref().map(classify_external);
            let dirty_recovery = fs.crash_recovery().is_some_and(|recovery| !recovery.was_clean);

            if let Some(journal) = &journal {
                assert!(
                    journal.replayed_blocks <= u64::try_from(journal.committed_sequences).unwrap_or(u64::MAX).saturating_mul(8),
                    "replayed block count should stay bounded by committed sequences"
                );
            }
            if let Some(fast_commit) = &fast_commit {
                assert!(
                    journal.is_some(),
                    "fast-commit evidence should only appear when journal replay info exists"
                );
                assert!(
                    fast_commit.verified_operations
                        <= fast_commit.transactions_found.saturating_add(1),
                    "verified fast-commit operations should stay near committed transaction count"
                );
            }
            if let Some(wal) = &wal {
                assert!(
                    wal.records_discarded <= 2,
                    "seed WAL harness should only discard a small bounded number of records"
                );
            }

            OutcomeClass::Open {
                block_size: fs.block_size(),
                dirty_recovery,
                journal,
                fast_commit,
                wal,
                external_journal,
            }
        }
        Err(err) => OutcomeClass::Err {
            errno: err.to_errno(),
            detail: err.to_string(),
        },
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut cursor = ByteCursor::new(data);
    let seed = SeedCase::from_selector(cursor.next_u8());
    let case = build_case(seed, &mut cursor);
    let options = pick_options(seed, &case, &mut cursor);

    let first = classify_open(&case, &options);
    let second = classify_open(&case, &options);
    assert_eq!(
        first, second,
        "journal replay open classification must be deterministic for identical inputs"
    );
});
