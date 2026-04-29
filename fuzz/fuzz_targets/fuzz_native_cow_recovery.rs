#![no_main]

use asupersync::Cx;
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_journal::{
    recover_native_cow, replay_native_cow, CowWrite, JournalRegion, RecoveredCommit,
};
use ffs_types::{BlockNumber, CommitSeq};
use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

const COW_MAGIC: u32 = 0x4A53_4646;
const COW_VERSION: u16 = 1;
const COW_RECORD_WRITE: u16 = 1;
const COW_RECORD_COMMIT: u16 = 2;
const COW_HEADER_SIZE: usize = 32;
const BLOCK_SIZE_CHOICES: [u32; 4] = [64, 128, 256, 512];
const MAX_SYNTHETIC_COMMITS: usize = 4;
const MAX_WRITES_PER_COMMIT: usize = 3;
const MAX_RAW_BLOCKS: usize = 16;

type NormalizedWrite = (u64, Vec<u8>);
type NormalizedCommit = (u64, Vec<NormalizedWrite>);
type NormalizedRecover = Vec<NormalizedCommit>;
type NormalizedSnapshot = Vec<(u64, Vec<u8>)>;

struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        let value = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        value
    }

    fn next_index(&mut self, len: usize) -> usize {
        if len == 0 {
            0
        } else {
            usize::from(self.next_u8()) % len
        }
    }
}

struct MemBlockDevice {
    blocks: Mutex<BTreeMap<u64, Vec<u8>>>,
    block_size: u32,
    block_count: u64,
}

impl MemBlockDevice {
    fn new(block_size: u32, block_count: u64) -> Self {
        Self {
            blocks: Mutex::new(BTreeMap::new()),
            block_size,
            block_count,
        }
    }

    fn with_journal(region: JournalRegion, blocks: &[Vec<u8>], block_size: u32) -> Self {
        let region_end = region.start.0.saturating_add(region.blocks);
        let block_count = region_end.saturating_add(32).max(128);
        let device = Self::new(block_size, block_count);
        for (index, block) in blocks.iter().enumerate() {
            let Ok(index_u64) = u64::try_from(index) else {
                break;
            };
            device.seed_block(
                BlockNumber(region.start.0.saturating_add(index_u64)),
                block.clone(),
            );
        }
        device
    }

    fn seed_block(&self, block: BlockNumber, data: Vec<u8>) {
        let mut blocks = match self.blocks.lock() {
            Ok(blocks) => blocks,
            Err(poisoned) => poisoned.into_inner(),
        };
        blocks.insert(block.0, data);
    }

    fn snapshot(&self) -> NormalizedSnapshot {
        let blocks = match self.blocks.lock() {
            Ok(blocks) => blocks,
            Err(poisoned) => poisoned.into_inner(),
        };
        blocks
            .iter()
            .map(|(block, data)| (*block, data.clone()))
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
        let block_size = match usize::try_from(self.block_size) {
            Ok(block_size) => block_size,
            Err(_) => return Err(FfsError::Format("block_size does not fit usize".to_owned())),
        };
        let blocks = match self.blocks.lock() {
            Ok(blocks) => blocks,
            Err(poisoned) => poisoned.into_inner(),
        };
        let data = blocks
            .get(&block.0)
            .cloned()
            .unwrap_or_else(|| vec![0_u8; block_size]);
        Ok(BlockBuf::new(data))
    }

    fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        if block.0 >= self.block_count {
            return Err(FfsError::Format(format!(
                "block out of range: {} >= {}",
                block.0, self.block_count
            )));
        }
        let expected = match usize::try_from(self.block_size) {
            Ok(expected) => expected,
            Err(_) => return Err(FfsError::Format("block_size does not fit usize".to_owned())),
        };
        if data.len() != expected {
            return Err(FfsError::Format(format!(
                "size mismatch: got {} expected {expected}",
                data.len()
            )));
        }
        let mut blocks = match self.blocks.lock() {
            Ok(blocks) => blocks,
            Err(poisoned) => poisoned.into_inner(),
        };
        blocks.insert(block.0, data.to_vec());
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

fn encode_write_record(
    block_size: usize,
    commit_seq: u64,
    block: BlockNumber,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = vec![0_u8; block_size];
    out[0..4].copy_from_slice(&COW_MAGIC.to_le_bytes());
    out[4..6].copy_from_slice(&COW_VERSION.to_le_bytes());
    out[6..8].copy_from_slice(&COW_RECORD_WRITE.to_le_bytes());
    out[8..16].copy_from_slice(&commit_seq.to_le_bytes());
    out[16..24].copy_from_slice(&block.0.to_le_bytes());
    out[24..28].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    out[28..32].copy_from_slice(&crc32c::crc32c(payload).to_le_bytes());
    let payload_end = COW_HEADER_SIZE.saturating_add(payload.len());
    out[COW_HEADER_SIZE..payload_end].copy_from_slice(payload);
    out
}

fn encode_commit_record(block_size: usize, commit_seq: u64) -> Vec<u8> {
    let mut out = vec![0_u8; block_size];
    out[0..4].copy_from_slice(&COW_MAGIC.to_le_bytes());
    out[4..6].copy_from_slice(&COW_VERSION.to_le_bytes());
    out[6..8].copy_from_slice(&COW_RECORD_COMMIT.to_le_bytes());
    out[8..16].copy_from_slice(&commit_seq.to_le_bytes());
    out
}

fn payload_from_cursor(cursor: &mut ByteCursor<'_>, payload_len: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(payload_len);
    for i in 0..payload_len {
        let salt = u8::try_from(i & 0xff).unwrap_or_default();
        payload.push(cursor.next_u8().wrapping_add(salt));
    }
    payload
}

fn raw_journal_blocks(data: &[u8], block_size: usize) -> Vec<Vec<u8>> {
    data.chunks(block_size)
        .take(MAX_RAW_BLOCKS)
        .map(|chunk| {
            let mut block = vec![0_u8; block_size];
            block[..chunk.len()].copy_from_slice(chunk);
            block
        })
        .collect()
}

fn synthetic_journal_blocks(cursor: &mut ByteCursor<'_>, block_size: usize) -> Vec<Vec<u8>> {
    let payload_capacity = block_size.saturating_sub(COW_HEADER_SIZE);
    if payload_capacity == 0 {
        return vec![vec![0_u8; block_size]];
    }

    let commit_count = 1 + cursor.next_index(MAX_SYNTHETIC_COMMITS);
    let mut blocks = Vec::new();
    for commit_index in 0..commit_count {
        let commit_seq = 1_u64
            .saturating_add(u64::try_from(commit_index).unwrap_or_default())
            .saturating_add(u64::from(cursor.next_u8()));
        let write_count = 1 + cursor.next_index(MAX_WRITES_PER_COMMIT);
        for _ in 0..write_count {
            let block = BlockNumber(u64::from(cursor.next_u8()));
            let payload_len = cursor.next_index(payload_capacity + 1);
            let payload = payload_from_cursor(cursor, payload_len);
            blocks.push(encode_write_record(block_size, commit_seq, block, &payload));
        }
        blocks.push(encode_commit_record(block_size, commit_seq));
    }

    match cursor.next_u8() % 4 {
        0 => {}
        1 => {
            if let Some(first) = blocks.first_mut() {
                first[28..32].copy_from_slice(&0_u32.to_le_bytes());
            }
        }
        2 => {
            if let Some(first) = blocks.first_mut() {
                let oversized = u32::try_from(block_size.saturating_add(1)).unwrap_or(u32::MAX);
                first[24..28].copy_from_slice(&oversized.to_le_bytes());
            }
        }
        _ => blocks.push(vec![0_u8; block_size]),
    }

    blocks
}

fn normalize_recover(
    result: Result<Vec<RecoveredCommit>>,
) -> std::result::Result<NormalizedRecover, String> {
    result
        .map(|commits| {
            commits
                .into_iter()
                .map(|commit| {
                    let writes = commit
                        .writes
                        .into_iter()
                        .map(|write| (write.block.0, write.bytes))
                        .collect();
                    (commit.commit_seq.0, writes)
                })
                .collect()
        })
        .map_err(|err| err.to_string())
}

fn assert_recovered_invariants(commits: &NormalizedRecover, block_size: usize) {
    let unique_sequences: BTreeSet<_> = commits.iter().map(|(seq, _)| *seq).collect();
    assert_eq!(
        unique_sequences.len(),
        commits.len(),
        "recovered commit sequence list must be unique"
    );
    for (_, writes) in commits {
        for (_, payload) in writes {
            assert!(
                payload.len() <= block_size,
                "recovered payload must fit a single block"
            );
        }
    }
}

fn mutate_commits(
    cursor: &mut ByteCursor<'_>,
    commits: &[RecoveredCommit],
    block_size: usize,
) -> Vec<RecoveredCommit> {
    let mut mutated = commits.to_vec();
    if mutated.is_empty() {
        return mutated;
    }

    match cursor.next_u8() % 4 {
        0 => {}
        1 => {
            if let Some(first_write) = mutated
                .first_mut()
                .and_then(|commit| commit.writes.first_mut())
            {
                first_write
                    .bytes
                    .resize(block_size.saturating_add(1), cursor.next_u8());
            }
        }
        2 => {
            if let Some(first_write) = mutated
                .first_mut()
                .and_then(|commit| commit.writes.first_mut())
            {
                let new_len = cursor.next_index(first_write.bytes.len().saturating_add(1));
                first_write.bytes.truncate(new_len);
            }
        }
        _ => mutated.reverse(),
    }

    mutated
}

fn expected_snapshot(commits: &[RecoveredCommit], block_size: usize) -> NormalizedSnapshot {
    let mut expected = BTreeMap::new();
    for commit in commits {
        for write in &commit.writes {
            if write.bytes.len() > block_size {
                return Vec::new();
            }
            let mut full = vec![0_u8; block_size];
            full[..write.bytes.len()].copy_from_slice(&write.bytes);
            expected.insert(write.block.0, full);
        }
    }
    expected.into_iter().collect()
}

fn replay_device_size(region: JournalRegion, commits: &[RecoveredCommit]) -> u64 {
    let mut max_block = region.start.0.saturating_add(region.blocks);
    for commit in commits {
        for write in &commit.writes {
            max_block = max_block.max(write.block.0);
        }
    }
    max_block.saturating_add(32).max(128)
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = ByteCursor::new(data);
    let block_size = BLOCK_SIZE_CHOICES[cursor.next_index(BLOCK_SIZE_CHOICES.len())];
    let block_size_usize = match usize::try_from(block_size) {
        Ok(block_size_usize) => block_size_usize,
        Err(_) => return,
    };

    let region = JournalRegion {
        start: BlockNumber(u64::from(cursor.next_u8())),
        blocks: 0,
    };
    let journal_blocks = if cursor.next_u8().is_multiple_of(2) {
        raw_journal_blocks(data, block_size_usize)
    } else {
        synthetic_journal_blocks(&mut cursor, block_size_usize)
    };
    let region = JournalRegion {
        start: region.start,
        blocks: u64::try_from(journal_blocks.len()).unwrap_or(u64::MAX),
    };

    let dev = MemBlockDevice::with_journal(region, &journal_blocks, block_size);
    let cx = Cx::for_testing();

    let recovered_first = normalize_recover(recover_native_cow(&cx, &dev, region));
    let recovered_second = normalize_recover(recover_native_cow(&cx, &dev, region));
    assert_eq!(
        recovered_first, recovered_second,
        "native COW recovery must be deterministic"
    );

    let Ok(normalized_commits) = &recovered_first else {
        return;
    };
    assert_recovered_invariants(normalized_commits, block_size_usize);

    let commits: Vec<RecoveredCommit> = normalized_commits
        .iter()
        .map(|(commit_seq, writes)| RecoveredCommit {
            commit_seq: CommitSeq(*commit_seq),
            writes: writes
                .iter()
                .map(|(block, payload)| CowWrite {
                    block: BlockNumber(*block),
                    bytes: payload.clone(),
                })
                .collect(),
        })
        .collect();

    let replay_commits = mutate_commits(&mut cursor, &commits, block_size_usize);
    let replay_block_count = replay_device_size(region, &replay_commits);
    let replay_dev_first = MemBlockDevice::new(block_size, replay_block_count);
    let replay_dev_second = MemBlockDevice::new(block_size, replay_block_count);

    let replay_first =
        replay_native_cow(&cx, &replay_dev_first, &replay_commits).map_err(|err| err.to_string());
    let replay_second =
        replay_native_cow(&cx, &replay_dev_second, &replay_commits).map_err(|err| err.to_string());
    assert_eq!(
        replay_first, replay_second,
        "native COW replay must be deterministic"
    );

    if replay_first.is_ok() {
        let left = replay_dev_first.snapshot();
        let right = replay_dev_second.snapshot();
        assert_eq!(left, right, "replay snapshots must be deterministic");

        let expected = expected_snapshot(&replay_commits, block_size_usize);
        if !expected.is_empty() || replay_commits.is_empty() {
            assert_eq!(
                left, expected,
                "replay snapshot must match the write oracle"
            );
        }
    }
});
