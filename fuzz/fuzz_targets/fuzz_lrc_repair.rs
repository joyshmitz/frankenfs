#![no_main]

use ffs_repair::lrc::{encode, repair_global, repair_local_single, BlockAvailability, LrcConfig};
use libfuzzer_sys::fuzz_target;

const GROUP_SIZES: [u32; 3] = [2, 3, 4];
const MAX_GROUP_COUNT: u32 = 4;
const MAX_GLOBAL_PARITY_COUNT: u32 = 4;
const MAX_BLOCK_SIZE: usize = 128;

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

fn build_data_blocks(
    cursor: &mut ByteCursor<'_>,
    block_count: usize,
    block_size: usize,
) -> Vec<Vec<u8>> {
    (0..block_count)
        .map(|block_idx| {
            (0..block_size)
                .map(|byte_idx| {
                    cursor
                        .next_u8()
                        .wrapping_add((block_idx as u8).wrapping_mul(17))
                        .wrapping_add((byte_idx as u8).wrapping_mul(31))
                })
                .collect()
        })
        .collect()
}

fn choose_unique_indices(
    cursor: &mut ByteCursor<'_>,
    universe_len: usize,
    selection_len: usize,
) -> Vec<usize> {
    let target_len = selection_len.min(universe_len);
    let mut seen = vec![false; universe_len];
    let mut out = Vec::with_capacity(target_len);

    while out.len() < target_len {
        let mut candidate = cursor.next_index(universe_len);
        if seen[candidate] {
            candidate = seen
                .iter()
                .position(|is_seen| !is_seen)
                .unwrap_or(candidate);
        }
        if !seen[candidate] {
            seen[candidate] = true;
            out.push(candidate);
        }
    }

    out
}

fn assert_repair_result_matches(
    actual: &ffs_repair::lrc::RepairResult,
    expected_missing: &[usize],
    source_data: &[Vec<u8>],
) {
    assert!(
        actual.success,
        "repair should succeed for recoverable erasures"
    );
    assert!(
        actual.used_global,
        "global repair path should report global usage"
    );
    assert!(
        !actual.used_local_only,
        "global repair path should not claim local-only recovery"
    );
    assert_eq!(
        actual.blocks_repaired as usize,
        expected_missing.len(),
        "repair should reconstruct exactly the missing block count"
    );
    assert_eq!(
        actual.repaired_indices.len(),
        expected_missing.len(),
        "repair index accounting should match the missing block count"
    );

    for &missing_idx in expected_missing {
        let key = u32::try_from(missing_idx).unwrap_or(u32::MAX);
        assert_eq!(
            actual.recovered_data.get(&key),
            Some(&source_data[missing_idx]),
            "repair should reconstruct the original block bytes"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = ByteCursor::new(data);

    let local_group_size = GROUP_SIZES[cursor.next_index(GROUP_SIZES.len())];
    let group_count = 1 + (u32::from(cursor.next_u8()) % MAX_GROUP_COUNT);
    let data_blocks = local_group_size * group_count;
    let max_global_parity = MAX_GLOBAL_PARITY_COUNT
        .min(data_blocks.saturating_sub(1))
        .max(1);
    let global_parity_count = 1 + (u32::from(cursor.next_u8()) % max_global_parity);
    let block_size = 1 + cursor.next_index(MAX_BLOCK_SIZE);

    let config = LrcConfig::new(data_blocks, local_group_size, global_parity_count);
    let source_data = build_data_blocks(&mut cursor, data_blocks as usize, block_size);

    let (local_first, global_first) = encode(&config, &source_data);
    let (local_second, global_second) = encode(&config, &source_data);
    assert_eq!(
        local_first, local_second,
        "local parity encoding must be deterministic"
    );
    assert_eq!(
        global_first, global_second,
        "global parity encoding must be deterministic"
    );

    let chosen_group = cursor.next_index(config.num_groups() as usize);
    let missing_idx_in_group = cursor.next_index(config.local_group_size as usize);
    let group_start = chosen_group * config.local_group_size as usize;
    let missing_abs_idx = group_start + missing_idx_in_group;
    let available_local_group: Vec<Option<&[u8]>> = (0..config.local_group_size as usize)
        .map(|offset| {
            if offset == missing_idx_in_group {
                None
            } else {
                Some(source_data[group_start + offset].as_slice())
            }
        })
        .collect();

    let local_repair_first = repair_local_single(
        &config,
        chosen_group as u32,
        missing_idx_in_group as u32,
        &available_local_group,
        &local_first[chosen_group],
    );
    let local_repair_second = repair_local_single(
        &config,
        chosen_group as u32,
        missing_idx_in_group as u32,
        &available_local_group,
        &local_first[chosen_group],
    );
    assert_eq!(
        local_repair_first, local_repair_second,
        "local repair must be deterministic for the same erased-group input"
    );
    assert_eq!(
        local_repair_first,
        Some(source_data[missing_abs_idx].clone()),
        "local repair should recover the erased block exactly"
    );

    let recoverable_missing_count = 1 + cursor.next_index(global_parity_count as usize);
    let recoverable_missing =
        choose_unique_indices(&mut cursor, data_blocks as usize, recoverable_missing_count);
    let recoverable_availability = BlockAvailability {
        data: source_data
            .iter()
            .enumerate()
            .map(|(idx, block)| {
                if recoverable_missing.contains(&idx) {
                    None
                } else {
                    Some(block.clone())
                }
            })
            .collect(),
        local_parity: local_first.iter().cloned().map(Some).collect(),
        global_parity: global_first.iter().cloned().map(Some).collect(),
    };

    let global_repair_first = repair_global(&config, &recoverable_availability, block_size);
    let global_repair_second = repair_global(&config, &recoverable_availability, block_size);
    assert_eq!(
        global_repair_first.success, global_repair_second.success,
        "global repair success must be deterministic"
    );
    assert_eq!(
        global_repair_first.blocks_repaired, global_repair_second.blocks_repaired,
        "global repair block accounting must be deterministic"
    );
    assert_eq!(
        global_repair_first.repaired_indices, global_repair_second.repaired_indices,
        "global repair index ordering must be deterministic"
    );
    assert_eq!(
        global_repair_first.recovered_data, global_repair_second.recovered_data,
        "global repair payloads must be deterministic"
    );
    assert_eq!(
        global_repair_first.used_local_only, global_repair_second.used_local_only,
        "global repair local-only flag must be deterministic"
    );
    assert_eq!(
        global_repair_first.used_global, global_repair_second.used_global,
        "global repair global-usage flag must be deterministic"
    );
    assert_repair_result_matches(&global_repair_first, &recoverable_missing, &source_data);

    let unrecoverable_missing_count = (global_parity_count as usize + 1).min(data_blocks as usize);
    if unrecoverable_missing_count > global_parity_count as usize {
        let unrecoverable_missing = choose_unique_indices(
            &mut cursor,
            data_blocks as usize,
            unrecoverable_missing_count,
        );
        let unrecoverable_availability = BlockAvailability {
            data: source_data
                .iter()
                .enumerate()
                .map(|(idx, block)| {
                    if unrecoverable_missing.contains(&idx) {
                        None
                    } else {
                        Some(block.clone())
                    }
                })
                .collect(),
            local_parity: local_first.iter().cloned().map(Some).collect(),
            global_parity: global_first.iter().cloned().map(Some).collect(),
        };
        let failed_repair = repair_global(&config, &unrecoverable_availability, block_size);
        assert!(
            !failed_repair.success,
            "repair should fail once missing blocks exceed global parity capacity"
        );
        assert_eq!(
            failed_repair.blocks_repaired, 0,
            "failed global repair should not claim reconstructed blocks"
        );
        assert!(
            failed_repair.recovered_data.is_empty(),
            "failed global repair should not fabricate recovered payloads"
        );
    }
});
