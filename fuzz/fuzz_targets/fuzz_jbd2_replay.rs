#![no_main]

use asupersync::Cx;
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_journal::{
    replay_jbd2, replay_jbd2_segments, Jbd2Superblock, JournalRegion, JournalSegment, ReplayOutcome,
};
use ffs_types::BlockNumber;
use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::RwLock;

const BLOCK_SIZE: usize = 512;
const MIN_BLOCK_COUNT: u64 = 4_096;
const MAX_JOURNAL_BYTES: usize = 128 * BLOCK_SIZE;

#[derive(Debug)]
struct MemBlockDevice {
    blocks: RwLock<BTreeMap<BlockNumber, Vec<u8>>>,
    block_size: u32,
    block_count: u64,
}

impl MemBlockDevice {
    fn from_journal_blocks(journal_blocks: &[Vec<u8>]) -> Self {
        let block_count =
            MIN_BLOCK_COUNT.max(u64::try_from(journal_blocks.len()).unwrap_or(u64::MAX));
        let device = Self {
            blocks: RwLock::new(BTreeMap::new()),
            block_size: u32::try_from(BLOCK_SIZE).expect("block size fits u32"),
            block_count,
        };
        for (index, block) in journal_blocks.iter().enumerate() {
            device.raw_write(
                BlockNumber(u64::try_from(index).expect("block index fits u64")),
                block.clone(),
            );
        }
        device
    }

    fn raw_write(&self, block: BlockNumber, data: Vec<u8>) {
        self.blocks
            .write()
            .expect("lock poisoned")
            .insert(block, data);
    }

    fn snapshot(&self) -> BTreeMap<u64, Vec<u8>> {
        self.blocks
            .read()
            .expect("lock poisoned")
            .iter()
            .map(|(block, bytes)| (block.0, bytes.clone()))
            .collect()
    }
}

impl BlockDevice for MemBlockDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        if block.0 >= self.block_count {
            return Err(FfsError::Format(format!(
                "block out of range: {} >= {}",
                block.0, self.block_count
            )));
        }
        let data = self
            .blocks
            .read()
            .expect("lock poisoned")
            .get(&block)
            .cloned()
            .unwrap_or_else(|| vec![0_u8; BLOCK_SIZE]);
        Ok(BlockBuf::new(data))
    }

    fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        if block.0 >= self.block_count {
            return Err(FfsError::Format(format!(
                "block out of range: {} >= {}",
                block.0, self.block_count
            )));
        }
        if data.len() != BLOCK_SIZE {
            return Err(FfsError::Format(format!(
                "size mismatch: got {} expected {}",
                data.len(),
                BLOCK_SIZE
            )));
        }
        self.blocks
            .write()
            .expect("lock poisoned")
            .insert(block, data.to_vec());
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        self.block_count
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

fn journal_blocks(data: &[u8]) -> Vec<Vec<u8>> {
    data.chunks(BLOCK_SIZE)
        .map(|chunk| {
            let mut block = vec![0_u8; BLOCK_SIZE];
            block[..chunk.len()].copy_from_slice(chunk);
            block
        })
        .collect()
}

fn region_for(block_count: usize) -> JournalRegion {
    JournalRegion {
        start: BlockNumber(0),
        blocks: u64::try_from(block_count).unwrap_or(u64::MAX),
    }
}

fn equivalent_segments(total_blocks: u64, selector: u8) -> Vec<JournalSegment> {
    if total_blocks == 0 {
        return Vec::new();
    }
    if total_blocks == 1 {
        return vec![JournalSegment {
            start: BlockNumber(0),
            blocks: 1,
        }];
    }
    let split = 1 + (u64::from(selector) % (total_blocks - 1));
    vec![
        JournalSegment {
            start: BlockNumber(0),
            blocks: split,
        },
        JournalSegment {
            start: BlockNumber(split),
            blocks: total_blocks - split,
        },
    ]
}

fn assert_superblock_invariants(block: &[u8]) {
    let first = Jbd2Superblock::parse(block);
    let second = Jbd2Superblock::parse(block);
    assert_eq!(
        first, second,
        "JBD2 superblock parsing should be deterministic"
    );
    if let Some(superblock) = first {
        let segment = superblock.external_journal_segment();
        let expected_start = if superblock.first_log_block > 0 {
            u64::from(superblock.first_log_block)
        } else {
            1
        };
        assert_eq!(
            segment.start,
            BlockNumber(expected_start),
            "external journal segment start should follow first_log_block semantics"
        );
        assert_eq!(
            segment.blocks,
            u64::from(superblock.max_len).saturating_sub(expected_start),
            "external journal segment length should be max_len minus the superblock block"
        );
    }
}

fn assert_replay_invariants(outcome: &ReplayOutcome) {
    let unique_sequences: BTreeSet<_> = outcome.committed_sequences.iter().copied().collect();
    assert_eq!(
        unique_sequences.len(),
        outcome.committed_sequences.len(),
        "committed sequence list must not contain duplicates"
    );
    assert!(
        outcome.stats.descriptor_blocks <= outcome.stats.scanned_blocks,
        "descriptor block count cannot exceed scanned block count"
    );
    assert!(
        outcome.stats.commit_blocks <= outcome.stats.scanned_blocks,
        "commit block count cannot exceed scanned block count"
    );
    assert!(
        outcome.stats.revoke_blocks <= outcome.stats.scanned_blocks,
        "revoke block count cannot exceed scanned block count"
    );
    assert!(
        outcome.stats.replayed_blocks <= outcome.stats.descriptor_tags,
        "replayed blocks must come from descriptor tags"
    );
    assert!(
        outcome.stats.skipped_revoked_blocks <= outcome.stats.revoke_entries,
        "skipped revoked blocks cannot exceed revoke entry count"
    );
    assert!(
        outcome.stats.orphaned_commit_blocks <= outcome.stats.commit_blocks,
        "orphaned commit count cannot exceed commit block count"
    );
    assert!(
        u64::try_from(outcome.committed_sequences.len()).unwrap_or(u64::MAX)
            <= outcome.stats.commit_blocks,
        "every committed sequence must correspond to a commit block"
    );
    assert!(
        outcome
            .stats
            .replayed_blocks
            .saturating_add(outcome.stats.skipped_revoked_blocks)
            <= outcome.stats.descriptor_tags,
        "replayed and revoked writes together cannot exceed descriptor tags"
    );
}

fn assert_results_match(
    left: &std::result::Result<ReplayOutcome, FfsError>,
    right: &std::result::Result<ReplayOutcome, FfsError>,
    context: &str,
) {
    match (left, right) {
        (Ok(left), Ok(right)) => {
            assert_eq!(
                left, right,
                "{context} should produce identical replay outcomes"
            );
            assert_replay_invariants(left);
        }
        (Err(left), Err(right)) => {
            assert_eq!(
                left.to_string(),
                right.to_string(),
                "{context} should deterministically reject the same malformed journal"
            );
        }
        (left, right) => {
            panic!("{context} changed success/failure mode: left={left:?} right={right:?}");
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_JOURNAL_BYTES {
        return;
    }

    let journal = journal_blocks(data);
    let region = region_for(journal.len());
    let cx = Cx::for_testing();

    if let Some(first_block) = journal.first() {
        assert_superblock_invariants(first_block);
    }

    let direct_left = MemBlockDevice::from_journal_blocks(&journal);
    let direct_right = MemBlockDevice::from_journal_blocks(&journal);
    let direct_first = replay_jbd2(&cx, &direct_left, region);
    let direct_second = replay_jbd2(&cx, &direct_right, region);
    assert_results_match(&direct_first, &direct_second, "replay_jbd2");
    assert_eq!(
        direct_left.snapshot(),
        direct_right.snapshot(),
        "replay_jbd2 should apply the same device mutations on repeated runs"
    );

    if region.blocks > 0 {
        let segmented = MemBlockDevice::from_journal_blocks(&journal);
        let segments = equivalent_segments(region.blocks, data.first().copied().unwrap_or(0));
        let segmented_result = replay_jbd2_segments(&cx, &segmented, &segments);
        assert_results_match(&direct_first, &segmented_result, "replay_jbd2_segments");
        assert_eq!(
            direct_left.snapshot(),
            segmented.snapshot(),
            "segment-based replay should produce the same final device image as region-based replay"
        );
    }
});
