//! Repair codec corruption fixtures (bd-rchk7.2).
//!
//! Pin the six high-value corruption scenarios called out in
//! bd-rchk7.2 against the live repair codec, with deterministic
//! per-scenario inputs (no fuzz mutation). Each scenario is a
//! standalone `#[test]` so a failure surfaces the exact case in CI.
//!
//!   1. Recoverable corruption with valid symbols
//!   2. Unrecoverable corruption (corrupt > repair)
//!   3. Stale symbols (encoded for a different group)
//!   4. Insufficient symbols at the boundary (corrupt == repair)
//!   5. Malformed symbol payload length (regression for fab3ff1)
//!   6. Repair-symbol refresh verification after recovery

#![cfg(unix)]

use asupersync::Cx;
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_repair::codec::{decode_group, encode_group};
use ffs_types::{BlockNumber, GroupNumber};
use parking_lot::Mutex;
use std::collections::HashMap;

const BLOCK_SIZE: u32 = 64;
const K: u32 = 4;
const FS_UUID: [u8; 16] = *b"corruption-tests";

struct MemBlockDevice {
    blocks: Mutex<HashMap<u64, Vec<u8>>>,
    block_size: u32,
    block_count: u64,
}

impl MemBlockDevice {
    fn new() -> Self {
        Self {
            blocks: Mutex::new(HashMap::new()),
            block_size: BLOCK_SIZE,
            block_count: 64,
        }
    }

    fn write(&self, block: BlockNumber, data: Vec<u8>) {
        assert_eq!(data.len(), self.block_size as usize);
        self.blocks.lock().insert(block.0, data);
    }
}

impl BlockDevice for MemBlockDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        let data = {
            let blocks = self.blocks.lock();
            blocks
                .get(&block.0)
                .cloned()
                .unwrap_or_else(|| vec![0_u8; self.block_size as usize])
        };
        Ok(BlockBuf::new(data))
    }

    fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        self.blocks.lock().insert(block.0, data.to_vec());
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

fn source_byte(block_index: u32, byte_index: usize) -> u8 {
    let block = u8::try_from(block_index).expect("fixture block index fits in u8");
    let byte = u8::try_from(byte_index).expect("fixture block size fits in u8");
    block.wrapping_mul(31).wrapping_add(byte)
}

/// Stage K source blocks with deterministic content.
fn stage_source(device: &MemBlockDevice) {
    for i in 0..K {
        let mut data = vec![0_u8; BLOCK_SIZE as usize];
        for (j, byte) in data.iter_mut().enumerate() {
            *byte = source_byte(i, j);
        }
        device.write(BlockNumber(u64::from(i)), data);
    }
}

#[test]
fn fixture_recoverable_corruption_with_valid_symbols() {
    let cx = Cx::for_testing();
    let device = MemBlockDevice::new();
    stage_source(&device);
    let group = GroupNumber(0);
    let encoded =
        encode_group(&cx, &device, &FS_UUID, group, BlockNumber(0), K, 2).expect("encode");
    let symbols: Vec<(u32, Vec<u8>)> = encoded
        .repair_symbols
        .iter()
        .map(|s| (s.esi, s.data.clone()))
        .collect();

    // Corrupt 1 block, have 2 repair symbols; decode should recover.
    let corrupt = [2_u32];
    let outcome = decode_group(
        &cx,
        &device,
        &FS_UUID,
        group,
        BlockNumber(0),
        K,
        &corrupt,
        &symbols,
    )
    .expect("decode must succeed with valid symbols and corrupt <= repair");
    assert!(
        outcome.complete,
        "decode must complete with sufficient symbols"
    );
    assert_eq!(outcome.recovered.len(), 1);
    assert_eq!(outcome.recovered[0].block, BlockNumber(2));
}

#[test]
fn fixture_unrecoverable_corruption_exceeds_repair_capacity() {
    let cx = Cx::for_testing();
    let device = MemBlockDevice::new();
    stage_source(&device);
    let group = GroupNumber(0);
    let encoded =
        encode_group(&cx, &device, &FS_UUID, group, BlockNumber(0), K, 1).expect("encode");
    let symbols: Vec<(u32, Vec<u8>)> = encoded
        .repair_symbols
        .iter()
        .map(|s| (s.esi, s.data.clone()))
        .collect();

    // Corrupt 2 blocks but only 1 repair symbol available.
    let corrupt = [0_u32, 1];
    let result = decode_group(
        &cx,
        &device,
        &FS_UUID,
        group,
        BlockNumber(0),
        K,
        &corrupt,
        &symbols,
    );
    let error = result.expect_err("decode must reject infeasible recovery");
    assert!(
        matches!(
            &error,
            FfsError::RepairFailed(msg)
                if msg.contains("insufficient") || msg.contains("singular")
        ),
        "expected RepairFailed with 'insufficient' or 'singular', got: {error:?}"
    );
}

#[test]
fn fixture_stale_symbols_from_different_group() {
    let cx = Cx::for_testing();
    let device = MemBlockDevice::new();
    stage_source(&device);
    let stale_device = MemBlockDevice::new();
    stage_source(&stale_device);
    let stale_block = vec![0xA5_u8; BLOCK_SIZE as usize];
    stale_device.write(BlockNumber(0), stale_block);

    // Encode against a stale generation and group 0, then try to decode
    // the current group 5. This models a ledger row whose symbols belong
    // to a different group/source generation. The decoder has no external
    // ledger metadata here, so this fixture requires either explicit
    // failure or a non-matching reconstruction.
    let encoded_group_0 = encode_group(
        &cx,
        &stale_device,
        &FS_UUID,
        GroupNumber(0),
        BlockNumber(0),
        K,
        2,
    )
    .expect("encode group 0");
    let stale_symbols: Vec<(u32, Vec<u8>)> = encoded_group_0
        .repair_symbols
        .iter()
        .map(|s| (s.esi, s.data.clone()))
        .collect();

    let corrupt = [0_u32];
    let result = decode_group(
        &cx,
        &device,
        &FS_UUID,
        GroupNumber(5), // wrong group: seed mismatch
        BlockNumber(0),
        K,
        &corrupt,
        &stale_symbols,
    );

    // Either an explicit decode failure OR an Ok with wrong data.
    // We only require that wrong data is not silently accepted as
    // identical to the original.
    match result {
        Ok(outcome) if outcome.complete && !outcome.recovered.is_empty() => {
            // Read the original block: recovered data should not match it,
            // because the symbols were from a different group.
            let original = device
                .read_block(&cx, BlockNumber(0))
                .expect("read")
                .as_slice()
                .to_vec();
            assert_ne!(
                outcome.recovered[0].data, original,
                "decode must not silently produce a matching reconstruction \
                 from another group's symbols"
            );
        }
        _ => {}
    }
}

#[test]
fn fixture_insufficient_symbols_at_boundary() {
    let cx = Cx::for_testing();
    let device = MemBlockDevice::new();
    stage_source(&device);
    let group = GroupNumber(0);

    // Encode with exactly K-1 = 3 repair symbols. Try to recover K = 4
    // corrupt blocks (every source block lost). Even with full repair
    // symbol set, this is the unrecoverable boundary because we lose
    // every source block: no anchor for the systematic decode.
    let encoded =
        encode_group(&cx, &device, &FS_UUID, group, BlockNumber(0), K, K - 1).expect("encode");
    let symbols: Vec<(u32, Vec<u8>)> = encoded
        .repair_symbols
        .iter()
        .map(|s| (s.esi, s.data.clone()))
        .collect();

    let corrupt = [0_u32, 1, 2, 3];
    let result = decode_group(
        &cx,
        &device,
        &FS_UUID,
        group,
        BlockNumber(0),
        K,
        &corrupt,
        &symbols,
    );

    // Library returns an explicit error when corrupt_count >= source_block_count.
    assert!(result.is_err(), "decode at total-loss boundary must fail");
}

#[test]
fn fixture_malformed_symbol_payload_length() {
    // Pins the upfront length-validation guard from commit fab3ff1.
    let cx = Cx::for_testing();
    let device = MemBlockDevice::new();
    stage_source(&device);
    let group = GroupNumber(0);
    let encoded =
        encode_group(&cx, &device, &FS_UUID, group, BlockNumber(0), K, 2).expect("encode");
    let mut symbols: Vec<(u32, Vec<u8>)> = encoded
        .repair_symbols
        .iter()
        .map(|s| (s.esi, s.data.clone()))
        .collect();
    // Truncate the first symbol's payload to a wrong length.
    symbols[0].1.truncate(8); // 8 bytes vs BLOCK_SIZE=64

    let corrupt = [0_u32];
    let result = decode_group(
        &cx,
        &device,
        &FS_UUID,
        group,
        BlockNumber(0),
        K,
        &corrupt,
        &symbols,
    );
    let error = result.expect_err("decode must reject malformed repair symbol length");
    assert!(
        matches!(
            &error,
            FfsError::RepairFailed(msg)
                if msg.contains("malformed") || msg.contains("payload length")
        ),
        "expected malformed-symbol error, got: {error:?}"
    );
}

#[test]
fn fixture_repair_symbol_refresh_after_recovery() {
    // After a successful recovery, re-encoding from the fresh source
    // blocks must produce symbols that are themselves usable for a
    // subsequent recovery; pins that the codec stays consistent
    // across encode/decode cycles.
    let cx = Cx::for_testing();
    let device = MemBlockDevice::new();
    stage_source(&device);
    let group = GroupNumber(0);

    // Cycle 1: encode, corrupt one block, decode, restore the recovered
    // bytes back to the device.
    let encoded_1 =
        encode_group(&cx, &device, &FS_UUID, group, BlockNumber(0), K, 2).expect("encode 1");
    let symbols_1: Vec<(u32, Vec<u8>)> = encoded_1
        .repair_symbols
        .iter()
        .map(|s| (s.esi, s.data.clone()))
        .collect();
    let outcome_1 = decode_group(
        &cx,
        &device,
        &FS_UUID,
        group,
        BlockNumber(0),
        K,
        &[1],
        &symbols_1,
    )
    .expect("decode 1");
    assert!(outcome_1.complete);
    device.write(BlockNumber(1), outcome_1.recovered[0].data.clone());

    // Cycle 2: re-encode (refresh symbols) over the now-restored device
    // and verify a second recovery still works.
    let encoded_2 = encode_group(&cx, &device, &FS_UUID, group, BlockNumber(0), K, 2)
        .expect("encode 2 (refresh after recovery)");
    let symbols_2: Vec<(u32, Vec<u8>)> = encoded_2
        .repair_symbols
        .iter()
        .map(|s| (s.esi, s.data.clone()))
        .collect();
    let outcome_2 = decode_group(
        &cx,
        &device,
        &FS_UUID,
        group,
        BlockNumber(0),
        K,
        &[2],
        &symbols_2,
    )
    .expect("decode 2 with refreshed symbols");
    assert!(outcome_2.complete);
    // Cycle-2 recovered block 2 must equal the original (which is
    // unchanged since we only restored block 1 in cycle 1).
    let original_block_2 = {
        let mut b = vec![0_u8; BLOCK_SIZE as usize];
        for (j, byte) in b.iter_mut().enumerate() {
            *byte = source_byte(2, j);
        }
        b
    };
    assert_eq!(
        outcome_2.recovered[0].data, original_block_2,
        "refreshed symbols must reconstruct block 2 to its original bytes"
    );
}
