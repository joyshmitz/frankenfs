#![no_main]

use asupersync::Cx;
use ffs_block::{BlockBuf, BlockDevice};
use ffs_repair::codec::{
    decode_group, decode_group_with_owned_repair_symbols, encode_group, DecodeOutcome, EncodedGroup,
};
use ffs_types::{BlockNumber, GroupNumber};
use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;

const BLOCK_SIZE_CHOICES: [u32; 3] = [64, 128, 256];
const MAX_SOURCE_BLOCKS: usize = 8;

type NormalizedRepairSymbols = Vec<(u32, Vec<u8>)>;
type NormalizedEncode = (u64, u32, u32, NormalizedRepairSymbols);
type NormalizedRecoveredBlocks = Vec<(u64, Vec<u8>)>;
type NormalizedDecode = (NormalizedRecoveredBlocks, bool);

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
    blocks: Mutex<HashMap<u64, Vec<u8>>>,
    block_size: u32,
    block_count: u64,
}

impl MemBlockDevice {
    fn new(block_size: u32, block_count: u64) -> Self {
        Self {
            blocks: Mutex::new(HashMap::new()),
            block_size,
            block_count,
        }
    }

    fn write_seed(&self, block: BlockNumber, data: Vec<u8>) {
        let mut blocks = match self.blocks.lock() {
            Ok(blocks) => blocks,
            Err(poisoned) => poisoned.into_inner(),
        };
        blocks.insert(block.0, data);
    }
}

impl BlockDevice for MemBlockDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> ffs_error::Result<BlockBuf> {
        let blocks = match self.blocks.lock() {
            Ok(blocks) => blocks,
            Err(poisoned) => poisoned.into_inner(),
        };
        let data = blocks
            .get(&block.0)
            .cloned()
            .unwrap_or_else(|| vec![0_u8; self.block_size as usize]);
        Ok(BlockBuf::new(data))
    }

    fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> ffs_error::Result<()> {
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

    fn sync(&self, _cx: &Cx) -> ffs_error::Result<()> {
        Ok(())
    }
}

fn next_uuid(cursor: &mut ByteCursor<'_>) -> [u8; 16] {
    let mut uuid = [0_u8; 16];
    for byte in &mut uuid {
        *byte = cursor.next_u8();
    }
    uuid
}

fn next_block_data(cursor: &mut ByteCursor<'_>, block_size: usize, salt: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(block_size);
    for i in 0..block_size {
        let byte = cursor
            .next_u8()
            .wrapping_add(salt)
            .wrapping_add((i & 0xff) as u8);
        out.push(byte);
    }
    out
}

fn normalize_encode(result: ffs_error::Result<EncodedGroup>) -> Result<NormalizedEncode, String> {
    result
        .map(|encoded| {
            let repair_symbols = encoded
                .repair_symbols
                .into_iter()
                .map(|symbol| (symbol.esi, symbol.data))
                .collect();
            (
                encoded.seed,
                encoded.source_block_count,
                encoded.symbol_size,
                repair_symbols,
            )
        })
        .map_err(|err| err.to_string())
}

fn normalize_decode(result: ffs_error::Result<DecodeOutcome>) -> Result<NormalizedDecode, String> {
    result
        .map(|outcome| {
            let recovered = outcome
                .recovered
                .into_iter()
                .map(|block| (block.block.0, block.data))
                .collect();
            (recovered, outcome.complete)
        })
        .map_err(|err| err.to_string())
}

fn assert_empty_corruption_fast_path(
    cx: &Cx,
    device: &dyn BlockDevice,
    uuid: &[u8; 16],
    group: GroupNumber,
    first_block: BlockNumber,
    source_block_count: u32,
) {
    let malformed_symbols = vec![(
        source_block_count,
        vec![0_u8; (device.block_size() as usize).saturating_sub(1)],
    )];
    let expected = Ok((Vec::<(u64, Vec<u8>)>::new(), true));

    let borrowed = normalize_decode(decode_group(
        cx,
        device,
        uuid,
        group,
        first_block,
        source_block_count,
        &[],
        &malformed_symbols,
    ));
    assert_eq!(
        borrowed, expected,
        "empty corrupt-index decode should complete without consulting malformed repair symbols"
    );

    let owned = normalize_decode(decode_group_with_owned_repair_symbols(
        cx,
        device,
        uuid,
        group,
        first_block,
        source_block_count,
        &[],
        malformed_symbols,
    ));
    assert_eq!(
        owned, expected,
        "owned empty corrupt-index decode should match borrowed fast-path semantics"
    );
}

fuzz_target!(|data: &[u8]| {
    let cx = Cx::for_testing();
    let mut cursor = ByteCursor::new(data);

    let block_size = BLOCK_SIZE_CHOICES[cursor.next_index(BLOCK_SIZE_CHOICES.len())];
    let source_block_count = 1 + cursor.next_index(MAX_SOURCE_BLOCKS);
    let repair_count = cursor.next_index(source_block_count + 1);
    let first_block = BlockNumber(u64::from(cursor.next_u8()));
    let group = GroupNumber(u32::from(cursor.next_u8()));
    let uuid = next_uuid(&mut cursor);

    let device = MemBlockDevice::new(
        block_size,
        first_block.0 + u64::try_from(source_block_count).unwrap_or(u64::MAX) + 16,
    );
    let mut originals = Vec::with_capacity(source_block_count);
    for i in 0..source_block_count {
        let block = next_block_data(&mut cursor, block_size as usize, i as u8);
        let block_number = BlockNumber(first_block.0 + u64::try_from(i).unwrap_or_default());
        device.write_seed(block_number, block.clone());
        originals.push(block);
    }

    let encoded_first = normalize_encode(encode_group(
        &cx,
        &device,
        &uuid,
        group,
        first_block,
        source_block_count as u32,
        repair_count as u32,
    ));
    let encoded_second = normalize_encode(encode_group(
        &cx,
        &device,
        &uuid,
        group,
        first_block,
        source_block_count as u32,
        repair_count as u32,
    ));
    assert_eq!(
        encoded_first, encoded_second,
        "repair codec encode path must be deterministic for identical inputs"
    );

    let Ok((_seed, encoded_k, encoded_block_size, repair_symbols)) = encoded_first else {
        return;
    };
    assert_eq!(encoded_k, source_block_count as u32);
    assert_eq!(encoded_block_size, block_size);
    assert_eq!(repair_symbols.len(), repair_count);
    for (esi, symbol) in &repair_symbols {
        assert!(
            *esi >= source_block_count as u32,
            "repair symbols must use repair ESI space"
        );
        assert_eq!(
            symbol.len(),
            block_size as usize,
            "repair symbol size must match the device block size"
        );
    }
    assert_empty_corruption_fast_path(
        &cx,
        &device,
        &uuid,
        group,
        first_block,
        source_block_count as u32,
    );

    let mut corrupt_set = BTreeSet::new();
    let corrupt_count = cursor.next_index(source_block_count + 1);
    // Bound the loop iterations: when corrupt_count == source_block_count
    // the harness needs every distinct index in [0, k). With cursor
    // exhausted the next_index helper returns 0 forever, so an unbounded
    // loop spins indefinitely (libFuzzer reports a 60+s timeout). Cap
    // the attempts at 8 × source_block_count — more than enough to
    // collect every distinct index when the cursor still has entropy,
    // but a hard exit when the cursor is exhausted. Decode_group below
    // tolerates an under-filled corrupt set: it just decodes fewer
    // blocks than corrupt_count requested.
    let max_attempts = source_block_count.saturating_mul(8).max(16);
    let mut attempts = 0_usize;
    while corrupt_set.len() < corrupt_count && attempts < max_attempts {
        corrupt_set.insert(cursor.next_index(source_block_count) as u32);
        attempts += 1;
    }
    let corrupt_indices: Vec<u32> = corrupt_set.into_iter().collect();

    let mut repair_pairs = repair_symbols;
    let mut repair_mutated = false;
    if !repair_pairs.is_empty() {
        match cursor.next_u8() % 4 {
            0 => {}
            1 => {
                let idx = cursor.next_index(repair_pairs.len());
                let new_len = cursor.next_index(block_size as usize);
                repair_pairs[idx].1.truncate(new_len);
                repair_mutated = true;
            }
            2 => {
                let keep = cursor.next_index(repair_pairs.len() + 1);
                repair_pairs.truncate(keep);
                repair_mutated = true;
            }
            _ => {
                let idx = cursor.next_index(repair_pairs.len());
                if !repair_pairs[idx].1.is_empty() {
                    let byte = cursor.next_index(repair_pairs[idx].1.len());
                    repair_pairs[idx].1[byte] ^= cursor.next_u8();
                    repair_mutated = true;
                }
            }
        }
    }

    let decode_first = normalize_decode(decode_group(
        &cx,
        &device,
        &uuid,
        group,
        first_block,
        source_block_count as u32,
        &corrupt_indices,
        &repair_pairs,
    ));
    let decode_second = normalize_decode(decode_group(
        &cx,
        &device,
        &uuid,
        group,
        first_block,
        source_block_count as u32,
        &corrupt_indices,
        &repair_pairs,
    ));
    assert_eq!(
        decode_first, decode_second,
        "repair codec decode path must be deterministic for identical inputs"
    );
    let decode_owned = normalize_decode(decode_group_with_owned_repair_symbols(
        &cx,
        &device,
        &uuid,
        group,
        first_block,
        source_block_count as u32,
        &corrupt_indices,
        repair_pairs.clone(),
    ));
    assert_eq!(
        decode_first, decode_owned,
        "owned repair-symbol decode path must match borrowed decode semantics"
    );

    if !repair_mutated
        && corrupt_indices.len() <= repair_count
        && corrupt_indices.len() < source_block_count
    {
        let Ok((recovered, complete)) = decode_first else {
            return;
        };
        assert!(
            complete,
            "unmodified repair symbols should recover any corruption set within repair capacity"
        );
        assert_eq!(recovered.len(), corrupt_indices.len());
        for ((block, bytes), corrupt_idx) in recovered.iter().zip(corrupt_indices.iter()) {
            assert_eq!(
                *block,
                first_block.0 + u64::from(*corrupt_idx),
                "decode must return the requested corrupt block number"
            );
            assert_eq!(
                bytes.as_slice(),
                originals[*corrupt_idx as usize].as_slice(),
                "decode must reconstruct the original source block bytes"
            );
        }
    }
});
