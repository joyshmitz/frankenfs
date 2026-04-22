#![no_main]

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_core::{Ext4JournalReplayMode, OpenFs, OpenOptions};
use ffs_error::{FfsError, Result};
use ffs_ondisk::{EXT4_ORPHAN_FS, EXT4_VALID_FS};
use ffs_types::{
    crc32c, ByteOffset, BTRFS_CSUM_TYPE_CRC32C, BTRFS_MAGIC, BTRFS_SUPER_INFO_OFFSET,
    EXT4_SUPERBLOCK_OFFSET, EXT4_SUPER_MAGIC,
};
use libfuzzer_sys::fuzz_target;
use std::sync::{Arc, Mutex};

const MAX_INPUT_BYTES: usize = 512;

const EXT4_IMAGE_SIZE: usize = 128 * 1024;
const EXT4_BLOCK_SIZE_LOG: u32 = 2;
const EXT4_STATE_OFFSET: usize = EXT4_SUPERBLOCK_OFFSET + 0x3A;
const EXT4_JOURNAL_INUM_OFFSET: usize = EXT4_SUPERBLOCK_OFFSET + 0xE0;
const EXT4_LAST_ORPHAN_OFFSET: usize = EXT4_SUPERBLOCK_OFFSET + 0xE8;
const EXT4_INTERESTING_OFFSETS: [usize; 8] = [
    EXT4_SUPERBLOCK_OFFSET + 0x04,
    EXT4_SUPERBLOCK_OFFSET + 0x18,
    EXT4_STATE_OFFSET,
    EXT4_SUPERBLOCK_OFFSET + 0x58,
    EXT4_SUPERBLOCK_OFFSET + 0x60,
    EXT4_JOURNAL_INUM_OFFSET,
    EXT4_LAST_ORPHAN_OFFSET,
    EXT4_SUPERBLOCK_OFFSET + 0x166,
];

const BTRFS_IMAGE_SIZE: usize = 256 * 1024;
const BTRFS_ROOT_LOGICAL: usize = 0x4_000;
const BTRFS_NODESIZE: usize = 4_096;
const BTRFS_LOGICAL_OFFSET: usize = BTRFS_SUPER_INFO_OFFSET + 0x30;
const BTRFS_LOG_ROOT_OFFSET: usize = BTRFS_SUPER_INFO_OFFSET + 0x60;
const BTRFS_CSUM_TYPE_OFFSET: usize = BTRFS_SUPER_INFO_OFFSET + 0xC4;
const BTRFS_LOG_ROOT_LEVEL_OFFSET: usize = BTRFS_SUPER_INFO_OFFSET + 0xC8;
const BTRFS_INTERESTING_OFFSETS: [usize; 12] = [
    BTRFS_LOGICAL_OFFSET,
    BTRFS_SUPER_INFO_OFFSET + 0x40,
    BTRFS_SUPER_INFO_OFFSET + 0x48,
    BTRFS_SUPER_INFO_OFFSET + 0x50,
    BTRFS_LOG_ROOT_OFFSET,
    BTRFS_SUPER_INFO_OFFSET + 0x90,
    BTRFS_SUPER_INFO_OFFSET + 0x94,
    BTRFS_CSUM_TYPE_OFFSET,
    BTRFS_ROOT_LOGICAL + 0x30,
    BTRFS_ROOT_LOGICAL + 0x50,
    BTRFS_ROOT_LOGICAL + 0x60,
    BTRFS_ROOT_LOGICAL + 200,
];

#[derive(Clone, Copy)]
enum SeedImage {
    Ext4Clean,
    Ext4Dirty,
    BtrfsClean,
    BtrfsTreeLog,
}

impl SeedImage {
    fn from_selector(selector: u8) -> Self {
        match selector % 4 {
            0 => Self::Ext4Clean,
            1 => Self::Ext4Dirty,
            2 => Self::BtrfsClean,
            _ => Self::BtrfsTreeLog,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum OutcomeClass {
    Ext4 {
        block_size: u32,
        dirty_recovery: bool,
        has_journal_report: bool,
    },
    Btrfs {
        block_size: u32,
        chunk_count: usize,
        log_root_present: bool,
    },
    Err(String),
}

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

fn build_ext4_image(block_size_log: u32) -> Vec<u8> {
    let block_size = 1024_u32 << block_size_log;
    let mut image = vec![0_u8; EXT4_IMAGE_SIZE];
    let sb_off = EXT4_SUPERBLOCK_OFFSET;

    image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
    image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&block_size_log.to_le_bytes());

    let blocks_count = u32::try_from(EXT4_IMAGE_SIZE / usize::try_from(block_size).unwrap_or(1))
        .unwrap_or(u32::MAX);
    image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes());

    let first_data = u32::from(block_size == 1024);
    image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&first_data.to_le_bytes());
    image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes());
    image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes());
    image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes());

    let filetype = 0x0002_u32;
    let extents = 0x0040_u32;
    image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&(filetype | extents).to_le_bytes());
    image[sb_off + 0x3A..sb_off + 0x3C].copy_from_slice(&EXT4_VALID_FS.to_le_bytes());

    image
}

fn build_ext4_dirty_image() -> Vec<u8> {
    let mut image = build_ext4_image(EXT4_BLOCK_SIZE_LOG);
    image[EXT4_STATE_OFFSET..EXT4_STATE_OFFSET + 2]
        .copy_from_slice(&(EXT4_VALID_FS | EXT4_ORPHAN_FS).to_le_bytes());
    image[EXT4_LAST_ORPHAN_OFFSET..EXT4_LAST_ORPHAN_OFFSET + 4]
        .copy_from_slice(&2_u32.to_le_bytes());
    image
}

fn build_btrfs_image() -> Vec<u8> {
    let mut image = vec![0_u8; BTRFS_IMAGE_SIZE];
    let sb_off = BTRFS_SUPER_INFO_OFFSET;

    image[sb_off + 0x30..sb_off + 0x38]
        .copy_from_slice(&(BTRFS_SUPER_INFO_OFFSET as u64).to_le_bytes());
    image[sb_off + 0x40..sb_off + 0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
    image[sb_off + 0x48..sb_off + 0x50].copy_from_slice(&1_u64.to_le_bytes());
    image[sb_off + 0x50..sb_off + 0x58].copy_from_slice(&(BTRFS_ROOT_LOGICAL as u64).to_le_bytes());
    image[sb_off + 0x58..sb_off + 0x60].copy_from_slice(&0_u64.to_le_bytes());
    image[sb_off + 0x70..sb_off + 0x78].copy_from_slice(&(BTRFS_IMAGE_SIZE as u64).to_le_bytes());
    image[sb_off + 0x80..sb_off + 0x88].copy_from_slice(&256_u64.to_le_bytes());
    image[sb_off + 0x88..sb_off + 0x90].copy_from_slice(&1_u64.to_le_bytes());
    image[sb_off + 0x90..sb_off + 0x94].copy_from_slice(&4096_u32.to_le_bytes());
    image[sb_off + 0x94..sb_off + 0x98].copy_from_slice(&4096_u32.to_le_bytes());
    image[sb_off + 0x9C..sb_off + 0xA0].copy_from_slice(&4096_u32.to_le_bytes());
    image[BTRFS_CSUM_TYPE_OFFSET..BTRFS_CSUM_TYPE_OFFSET + 2]
        .copy_from_slice(&BTRFS_CSUM_TYPE_CRC32C.to_le_bytes());

    let mut chunk_array = Vec::new();
    chunk_array.extend_from_slice(&256_u64.to_le_bytes());
    chunk_array.push(228_u8);
    chunk_array.extend_from_slice(&0_u64.to_le_bytes());
    chunk_array.extend_from_slice(&(BTRFS_IMAGE_SIZE as u64).to_le_bytes());
    chunk_array.extend_from_slice(&2_u64.to_le_bytes());
    chunk_array.extend_from_slice(&0x1_0000_u64.to_le_bytes());
    chunk_array.extend_from_slice(&2_u64.to_le_bytes());
    chunk_array.extend_from_slice(&4096_u32.to_le_bytes());
    chunk_array.extend_from_slice(&4096_u32.to_le_bytes());
    chunk_array.extend_from_slice(&4096_u32.to_le_bytes());
    chunk_array.extend_from_slice(&1_u16.to_le_bytes());
    chunk_array.extend_from_slice(&0_u16.to_le_bytes());
    chunk_array.extend_from_slice(&1_u64.to_le_bytes());
    chunk_array.extend_from_slice(&0_u64.to_le_bytes());
    chunk_array.extend_from_slice(&[0_u8; 16]);

    let array_size = u32::try_from(chunk_array.len()).unwrap_or(u32::MAX);
    image[sb_off + 0xA0..sb_off + 0xA4].copy_from_slice(&array_size.to_le_bytes());
    let array_start = sb_off + 0x32B;
    image[array_start..array_start + chunk_array.len()].copy_from_slice(&chunk_array);
    image[sb_off + 0xC6] = 0;

    let leaf_off = BTRFS_ROOT_LOGICAL;
    image[leaf_off + 0x30..leaf_off + 0x38]
        .copy_from_slice(&(BTRFS_ROOT_LOGICAL as u64).to_le_bytes());
    image[leaf_off + 0x50..leaf_off + 0x58].copy_from_slice(&1_u64.to_le_bytes());
    image[leaf_off + 0x58..leaf_off + 0x60].copy_from_slice(&1_u64.to_le_bytes());
    image[leaf_off + 0x60..leaf_off + 0x64].copy_from_slice(&1_u32.to_le_bytes());
    image[leaf_off + 0x64] = 0;

    let item_off = leaf_off + 101;
    image[item_off..item_off + 8].copy_from_slice(&256_u64.to_le_bytes());
    image[item_off + 8] = 132;
    image[item_off + 9..item_off + 17].copy_from_slice(&0_u64.to_le_bytes());
    image[item_off + 17..item_off + 21].copy_from_slice(&(200_u32 - 101).to_le_bytes());
    image[item_off + 21..item_off + 25].copy_from_slice(&8_u32.to_le_bytes());
    image[leaf_off + 200..leaf_off + 208]
        .copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF]);

    stamp_btrfs_tree_block_checksum(&mut image, BTRFS_ROOT_LOGICAL);
    image
}

fn build_btrfs_tree_log_image() -> Vec<u8> {
    let mut image = build_btrfs_image();
    image[BTRFS_LOG_ROOT_OFFSET..BTRFS_LOG_ROOT_OFFSET + 8]
        .copy_from_slice(&(BTRFS_ROOT_LOGICAL as u64).to_le_bytes());
    image[BTRFS_LOG_ROOT_LEVEL_OFFSET] = 0;
    image
}

fn stamp_btrfs_tree_block_checksum(image: &mut [u8], logical: usize) {
    let block = &mut image[logical..logical + BTRFS_NODESIZE];
    block[..0x20].fill(0);
    let checksum = crc32c(&block[0x20..]);
    block[..4].copy_from_slice(&checksum.to_le_bytes());
}

fn mutate_bytes(image: &mut [u8], cursor: &mut ByteCursor<'_>, interesting_offsets: &[usize]) {
    let focused_rounds = usize::from(cursor.next_u8() % 16);
    for _ in 0..focused_rounds {
        let base = interesting_offsets[cursor.next_index(interesting_offsets.len())];
        match cursor.next_u8() % 6 {
            0 => mutate_byte(image, base, cursor.next_u8()),
            1 => xor_byte(image, base, cursor.next_u8()),
            2 => write_u16_le(image, base, cursor.next_u16()),
            3 => write_u32_le(image, base, cursor.next_u32()),
            4 => overwrite_range(image, base, 1 + usize::from(cursor.next_u8() % 32), cursor),
            _ => zero_range(image, base, 1 + usize::from(cursor.next_u8() % 32)),
        }
    }

    let wide_rounds = usize::from(cursor.next_u8() % 4);
    for _ in 0..wide_rounds {
        let base = cursor.next_index(image.len());
        overwrite_range(image, base, 1 + usize::from(cursor.next_u8() % 64), cursor);
    }
}

fn mutate_byte(image: &mut [u8], offset: usize, value: u8) {
    if let Some(slot) = image.get_mut(offset) {
        *slot = value;
    }
}

fn xor_byte(image: &mut [u8], offset: usize, value: u8) {
    if let Some(slot) = image.get_mut(offset) {
        *slot ^= value;
    }
}

fn write_u16_le(image: &mut [u8], offset: usize, value: u16) {
    let end = offset.saturating_add(2);
    if end <= image.len() {
        image[offset..end].copy_from_slice(&value.to_le_bytes());
    }
}

fn write_u32_le(image: &mut [u8], offset: usize, value: u32) {
    let end = offset.saturating_add(4);
    if end <= image.len() {
        image[offset..end].copy_from_slice(&value.to_le_bytes());
    }
}

fn overwrite_range(image: &mut [u8], offset: usize, len: usize, cursor: &mut ByteCursor<'_>) {
    let start = offset.min(image.len());
    let end = start.saturating_add(len).min(image.len());
    for byte in &mut image[start..end] {
        *byte = cursor.next_u8();
    }
}

fn zero_range(image: &mut [u8], offset: usize, len: usize) {
    let start = offset.min(image.len());
    let end = start.saturating_add(len).min(image.len());
    image[start..end].fill(0);
}

fn pick_options(cursor: &mut ByteCursor<'_>) -> OpenOptions {
    let ext4_journal_replay_mode = match cursor.next_u8() % 3 {
        0 => Ext4JournalReplayMode::Apply,
        1 => Ext4JournalReplayMode::SimulateOverlay,
        _ => Ext4JournalReplayMode::Skip,
    };

    OpenOptions {
        skip_validation: cursor.next_bool(),
        ext4_journal_replay_mode,
        ..OpenOptions::default()
    }
}

fn build_image(seed: SeedImage, cursor: &mut ByteCursor<'_>) -> Vec<u8> {
    let mut image = match seed {
        SeedImage::Ext4Clean => build_ext4_image(EXT4_BLOCK_SIZE_LOG),
        SeedImage::Ext4Dirty => build_ext4_dirty_image(),
        SeedImage::BtrfsClean => build_btrfs_image(),
        SeedImage::BtrfsTreeLog => build_btrfs_tree_log_image(),
    };

    match seed {
        SeedImage::Ext4Clean | SeedImage::Ext4Dirty => {
            mutate_bytes(&mut image, cursor, &EXT4_INTERESTING_OFFSETS);
            if matches!(seed, SeedImage::Ext4Dirty) && cursor.next_bool() {
                image[EXT4_STATE_OFFSET..EXT4_STATE_OFFSET + 2]
                    .copy_from_slice(&(EXT4_VALID_FS | EXT4_ORPHAN_FS).to_le_bytes());
                let orphan_head = 2_u32 + u32::from(cursor.next_u8() % 8);
                image[EXT4_LAST_ORPHAN_OFFSET..EXT4_LAST_ORPHAN_OFFSET + 4]
                    .copy_from_slice(&orphan_head.to_le_bytes());
            }
        }
        SeedImage::BtrfsClean | SeedImage::BtrfsTreeLog => {
            mutate_bytes(&mut image, cursor, &BTRFS_INTERESTING_OFFSETS);
            if matches!(seed, SeedImage::BtrfsTreeLog) && cursor.next_bool() {
                image[BTRFS_LOG_ROOT_OFFSET..BTRFS_LOG_ROOT_OFFSET + 8]
                    .copy_from_slice(&(BTRFS_ROOT_LOGICAL as u64).to_le_bytes());
                image[BTRFS_LOG_ROOT_LEVEL_OFFSET] = 0;
            }
            if cursor.next_bool() {
                stamp_btrfs_tree_block_checksum(&mut image, BTRFS_ROOT_LOGICAL);
            }
        }
    }

    image
}

fn classify_open(image: &[u8], options: &OpenOptions) -> OutcomeClass {
    let cx = Cx::for_testing();
    let dev = MemByteDevice::from_vec(image.to_vec());
    match OpenFs::from_device(&cx, Box::new(dev), options) {
        Ok(fs) if fs.is_ext4() => {
            assert!(
                fs.ext4_superblock().is_some(),
                "ext4 opens must expose a superblock"
            );
            assert!(!fs.is_btrfs(), "ext4 opens must not also report btrfs");
            let dirty_recovery = fs
                .crash_recovery()
                .is_some_and(|recovery| !recovery.was_clean);
            OutcomeClass::Ext4 {
                block_size: fs.block_size(),
                dirty_recovery,
                has_journal_report: fs.ext4_journal_replay().is_some(),
            }
        }
        Ok(fs) => {
            assert!(
                fs.is_btrfs(),
                "non-ext4 opens in this harness must be btrfs"
            );
            assert!(
                fs.btrfs_superblock().is_some(),
                "btrfs opens must expose a superblock"
            );
            let superblock = fs.btrfs_superblock().expect("btrfs superblock");
            let context = fs.btrfs_context().expect("btrfs context");
            OutcomeClass::Btrfs {
                block_size: fs.block_size(),
                chunk_count: context.chunks.len(),
                log_root_present: superblock.log_root != 0,
            }
        }
        Err(err) => OutcomeClass::Err(err.to_string()),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut cursor = ByteCursor::new(data);
    let seed = SeedImage::from_selector(cursor.next_u8());
    let image = build_image(seed, &mut cursor);
    let options = pick_options(&mut cursor);

    let first = classify_open(&image, &options);
    let second = classify_open(&image, &options);
    assert_eq!(
        first, second,
        "open/recovery classification must be deterministic for the same mutated image"
    );
});
