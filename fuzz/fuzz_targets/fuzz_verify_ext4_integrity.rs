#![no_main]

use ffs_core::{verify_ext4_integrity, CheckVerdict, IntegrityReport};
use ffs_ondisk::{Ext4Superblock, EXT4_ORPHAN_FS, EXT4_VALID_FS};
use ffs_types::{GroupNumber, EXT4_SUPERBLOCK_OFFSET, EXT4_SUPER_MAGIC};
use libfuzzer_sys::fuzz_target;

const MAX_RAW_BYTES: usize = 256 * 1024;
const IMAGE_SIZE: usize = 128 * 1024;
const EXT4_BLOCK_SIZE_LOG: u32 = 2;
const EXT4_STATE_OFFSET: usize = EXT4_SUPERBLOCK_OFFSET + 0x3A;
const EXT4_LAST_ORPHAN_OFFSET: usize = EXT4_SUPERBLOCK_OFFSET + 0xE8;
const EXT4_INTERESTING_OFFSETS: [usize; 8] = [
    EXT4_SUPERBLOCK_OFFSET + 0x04,
    EXT4_SUPERBLOCK_OFFSET + 0x18,
    EXT4_STATE_OFFSET,
    EXT4_SUPERBLOCK_OFFSET + 0x28,
    EXT4_SUPERBLOCK_OFFSET + 0x58,
    EXT4_SUPERBLOCK_OFFSET + 0x60,
    EXT4_SUPERBLOCK_OFFSET + 0xE0,
    EXT4_LAST_ORPHAN_OFFSET,
];

#[derive(Clone, Copy)]
enum SeedImage {
    Raw,
    Clean,
    Dirty,
    CorruptSuperblock,
    CorruptGroupDesc,
    Truncated,
}

impl SeedImage {
    fn from_selector(selector: u8) -> Self {
        match selector % 6 {
            0 => Self::Raw,
            1 => Self::Clean,
            2 => Self::Dirty,
            3 => Self::CorruptSuperblock,
            4 => Self::CorruptGroupDesc,
            _ => Self::Truncated,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct NormalizedReport {
    verdicts: Vec<(String, bool, String)>,
    passed: u64,
    failed: u64,
    posterior_alpha: f64,
    posterior_beta: f64,
    expected_corruption_rate: f64,
    upper_bound_corruption_rate: f64,
    healthy: bool,
    prob_healthy: f64,
    log_bayes_factor: f64,
}

#[derive(Debug, Clone, PartialEq)]
enum OutcomeClass {
    Report(NormalizedReport),
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

    fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 == 1
    }

    fn next_index(&mut self, len: usize) -> usize {
        if len == 0 {
            0
        } else {
            usize::from(self.next_u16()) % len
        }
    }
}

fn build_ext4_image(block_size_log: u32) -> Vec<u8> {
    let block_size = 1024_u32 << block_size_log;
    let mut image = vec![0_u8; IMAGE_SIZE];
    let sb_off = EXT4_SUPERBLOCK_OFFSET;

    image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
    image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&block_size_log.to_le_bytes());

    let blocks_count =
        u32::try_from(IMAGE_SIZE / usize::try_from(block_size).unwrap_or(1)).unwrap_or(u32::MAX);
    image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off + 0x14..sb_off + 0x18]
        .copy_from_slice(&u32::from(block_size == 1024).to_le_bytes());
    image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes());
    image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes());
    image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes());
    image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&(0x0002_u32 | 0x0040_u32).to_le_bytes());
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

fn build_corrupt_superblock_image() -> Vec<u8> {
    let mut image = build_ext4_image(EXT4_BLOCK_SIZE_LOG);
    let tamper_off = EXT4_SUPERBLOCK_OFFSET + 0x60;
    image[tamper_off] ^= 0xFF;
    image
}

fn build_corrupt_group_desc_image() -> Vec<u8> {
    let mut image = build_ext4_image(EXT4_BLOCK_SIZE_LOG);
    if let Ok(sb) = Ext4Superblock::parse_from_image(&image) {
        if let Some(gd_off) = sb.group_desc_offset(GroupNumber(0)) {
            if let Ok(offset) = usize::try_from(gd_off) {
                if offset.saturating_add(4) < image.len() {
                    image[offset + 4] ^= 0xFF;
                }
            }
        }
    }
    image
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

fn mutate_ext4_image(image: &mut [u8], cursor: &mut ByteCursor<'_>) {
    let focused_rounds = usize::from(cursor.next_u8() % 16);
    for _ in 0..focused_rounds {
        let base = EXT4_INTERESTING_OFFSETS[cursor.next_index(EXT4_INTERESTING_OFFSETS.len())];
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

fn truncate_image(image: &mut Vec<u8>, cursor: &mut ByteCursor<'_>) {
    let new_len = cursor.next_index(image.len().saturating_add(1));
    image.truncate(new_len);
}

fn build_image(mode: SeedImage, data: &[u8], cursor: &mut ByteCursor<'_>) -> Vec<u8> {
    match mode {
        SeedImage::Raw => data[..data.len().min(MAX_RAW_BYTES)].to_vec(),
        SeedImage::Clean => {
            let mut image = build_ext4_image(EXT4_BLOCK_SIZE_LOG);
            mutate_ext4_image(&mut image, cursor);
            image
        }
        SeedImage::Dirty => {
            let mut image = build_ext4_dirty_image();
            mutate_ext4_image(&mut image, cursor);
            if cursor.next_bool() {
                image[EXT4_STATE_OFFSET..EXT4_STATE_OFFSET + 2]
                    .copy_from_slice(&(EXT4_VALID_FS | EXT4_ORPHAN_FS).to_le_bytes());
            }
            image
        }
        SeedImage::CorruptSuperblock => {
            let mut image = build_corrupt_superblock_image();
            mutate_ext4_image(&mut image, cursor);
            image
        }
        SeedImage::CorruptGroupDesc => {
            let mut image = build_corrupt_group_desc_image();
            mutate_ext4_image(&mut image, cursor);
            image
        }
        SeedImage::Truncated => {
            let mut image = build_ext4_image(EXT4_BLOCK_SIZE_LOG);
            mutate_ext4_image(&mut image, cursor);
            truncate_image(&mut image, cursor);
            image
        }
    }
}

fn normalize_verdicts(verdicts: &[CheckVerdict]) -> Vec<(String, bool, String)> {
    verdicts
        .iter()
        .map(|verdict| {
            (
                verdict.component.clone(),
                verdict.passed,
                verdict.detail.clone(),
            )
        })
        .collect()
}

fn assert_report_invariants(report: &IntegrityReport) {
    let passed_verdicts = report
        .verdicts
        .iter()
        .filter(|verdict| verdict.passed)
        .count();
    let failed_verdicts = report
        .verdicts
        .iter()
        .filter(|verdict| !verdict.passed)
        .count();
    assert!(
        report.passed >= u64::try_from(passed_verdicts).unwrap_or(u64::MAX),
        "pass count must cover every passing verdict"
    );
    assert!(
        report.failed >= u64::try_from(failed_verdicts).unwrap_or(u64::MAX),
        "failure count must cover every failing verdict"
    );
    for verdict in &report.verdicts {
        assert!(
            !verdict.component.is_empty(),
            "verdict component must not be empty"
        );
    }

    assert!(report.posterior_alpha.is_finite());
    assert!(report.posterior_beta.is_finite());
    assert!(report.expected_corruption_rate.is_finite());
    assert!(report.upper_bound_corruption_rate.is_finite());

    assert!(
        (report.posterior_alpha - (1.0 + report.failed as f64)).abs() < 1e-9,
        "posterior alpha must track failures"
    );
    assert!(
        (report.posterior_beta - (1.0 + report.passed as f64)).abs() < 1e-9,
        "posterior beta must track passes"
    );
    assert!(
        (0.0..=1.0).contains(&report.expected_corruption_rate),
        "expected corruption rate must stay within probability bounds"
    );
    assert!(
        (0.0..=1.0).contains(&report.upper_bound_corruption_rate),
        "upper corruption bound must stay within probability bounds"
    );
    assert!(
        report.upper_bound_corruption_rate >= report.expected_corruption_rate,
        "upper corruption bound must dominate the posterior mean"
    );
    assert_eq!(
        report.healthy,
        report.upper_bound_corruption_rate < 0.01,
        "health verdict must align with the public threshold"
    );

    let prob_healthy = report.prob_healthy(0.01);
    assert!(prob_healthy.is_finite());
    assert!(
        (0.0..=1.0).contains(&prob_healthy),
        "prob_healthy must stay within probability bounds"
    );
    assert!(
        report.log_bayes_factor().is_finite(),
        "log Bayes factor must remain finite"
    );
}

fn normalize_outcome(image: &[u8], max_inodes: u32) -> OutcomeClass {
    match verify_ext4_integrity(image, max_inodes) {
        Ok(report) => {
            assert_report_invariants(&report);
            OutcomeClass::Report(NormalizedReport {
                verdicts: normalize_verdicts(&report.verdicts),
                passed: report.passed,
                failed: report.failed,
                posterior_alpha: report.posterior_alpha,
                posterior_beta: report.posterior_beta,
                expected_corruption_rate: report.expected_corruption_rate,
                upper_bound_corruption_rate: report.upper_bound_corruption_rate,
                healthy: report.healthy,
                prob_healthy: report.prob_healthy(0.01),
                log_bayes_factor: report.log_bayes_factor(),
            })
        }
        Err(err) => OutcomeClass::Err(err.to_string()),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_RAW_BYTES {
        return;
    }

    let mut cursor = ByteCursor::new(data);
    let mode = SeedImage::from_selector(cursor.next_u8());
    let image = build_image(mode, data, &mut cursor);
    let max_inodes = match cursor.next_u8() % 4 {
        0 => 0,
        1 => 1 + u32::from(cursor.next_u8() % 8),
        2 => 1 + u32::from(cursor.next_u8() % 32),
        _ => cursor.next_u32(),
    };

    let first = normalize_outcome(&image, max_inodes);
    let second = normalize_outcome(&image, max_inodes);
    assert_eq!(
        first, second,
        "verify_ext4_integrity classification must be deterministic for identical inputs"
    );
});
