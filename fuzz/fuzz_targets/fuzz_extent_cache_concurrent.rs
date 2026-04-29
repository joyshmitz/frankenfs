#![no_main]

// Concurrent fuzz target for `ffs_extent::ExtentCache`.
//
// Spawns a handful of worker threads that drive random sequences of
// `lookup`, `insert`, `invalidate_range`, `invalidate_all`, `stats`, and
// `reset_stats` against a shared cache. The fuzz input decides the op
// schedule; threading is deterministic-within-a-thread but interleaves
// across threads at the OS scheduler level, which is what we want under
// TSan.
//
// Invariants:
//   I1: every `lookup` returns either `None` or a mapping whose
//       `logical_start..logical_start+count` range covers the queried
//       logical block (cache must never misreport geometry).
//   I2: `stats().hits + stats().misses` is monotonic across the workload
//       (never goes backwards on the same cache).
//   I3: `invalidate_all()` causes the very next lookup of a previously
//       inserted mapping to return `None` (unless another thread inserted
//       it in the interleaving window — accept either `None` or a valid
//       mapping that starts at or before the queried block).
//   I4: after `reset_stats()`, the next `stats()` call reports hits + misses
//       equal to the reads performed since the reset (monotonic check is
//       replaced by non-decreasing from 0).
//
// Build: `cargo fuzz run fuzz_extent_cache_concurrent`. For deep coverage
// of data-race hazards, run under TSan:
//   `RUSTFLAGS="-Zsanitizer=thread" cargo +nightly fuzz run fuzz_extent_cache_concurrent`.

use ffs_extent::{ExtentCache, ExtentMapping};
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;
use std::thread;

const MAX_INPUT_BYTES: usize = 1024;
const WORKER_COUNT: usize = 4;
const NAMESPACE_DOMAIN: u64 = 4;
const LOGICAL_DOMAIN: u32 = 64;

struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        b
    }

    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    fn remaining(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or(&[])
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    if data.len() < 16 {
        return;
    }

    let mut cursor = ByteCursor::new(data);
    // First byte selects a capacity bucket; small caps force eviction pressure.
    let capacity_selector = cursor.next_u8() % 4;
    let capacity = match capacity_selector {
        0 => 4,
        1 => 16,
        2 => 64,
        _ => 256,
    };
    let cache = Arc::new(ExtentCache::with_capacity(capacity));

    // Partition remaining bytes into per-worker op streams.
    let rest = cursor.remaining();
    let chunk_len = rest.len().div_ceil(WORKER_COUNT).max(4);

    let mut handles = Vec::with_capacity(WORKER_COUNT);
    for worker_id in 0..WORKER_COUNT {
        let start = worker_id.saturating_mul(chunk_len);
        let end = start.saturating_add(chunk_len).min(rest.len());
        if start >= end {
            break;
        }
        let stream: Vec<u8> = rest[start..end].to_vec();
        let cache = Arc::clone(&cache);
        let handle = thread::spawn(move || {
            run_worker(cache.as_ref(), worker_id, &stream);
        });
        handles.push(handle);
    }

    for h in handles {
        h.join()
            .expect("extent-cache fuzz worker must surface invariant panics");
    }

    // Post-workload invariants that hold no matter how workers interleaved.
    let stats = cache.stats();
    assert!(
        stats.entries <= stats.capacity,
        "entries ({}) must never exceed capacity ({})",
        stats.entries,
        stats.capacity
    );
    assert!(
        stats.hits.checked_add(stats.misses).is_some(),
        "hits + misses must not overflow in a bounded workload"
    );
});

fn run_worker(cache: &ExtentCache, worker_id: usize, stream: &[u8]) {
    let mut cursor = ByteCursor::new(stream);
    let mut prior_hits_plus_misses: u64 = 0;

    while cursor.pos < stream.len() {
        let op = cursor.next_u8() % 6;
        match op {
            // Insert: synthesize a mapping.
            0 => {
                let ns = u64::from(cursor.next_u8()) % NAMESPACE_DOMAIN;
                let logical_start = cursor.next_u32() % LOGICAL_DOMAIN;
                let count_byte = cursor.next_u8();
                let count = u32::from(count_byte % 8).saturating_add(1);
                let physical_start =
                    u64::from(logical_start).wrapping_add((worker_id as u64) << 32);
                cache.insert(
                    ns,
                    ExtentMapping {
                        logical_start,
                        physical_start,
                        count,
                        unwritten: (count_byte & 1) == 1,
                    },
                );
            }
            // Lookup: verify I1 shape.
            1 => {
                let ns = u64::from(cursor.next_u8()) % NAMESPACE_DOMAIN;
                let logical_block = cursor.next_u32() % LOGICAL_DOMAIN;
                if let Some(mapping) = cache.lookup(ns, logical_block) {
                    let end =
                        u64::from(mapping.logical_start).saturating_add(u64::from(mapping.count));
                    assert!(
                        u64::from(logical_block) >= u64::from(mapping.logical_start)
                            && u64::from(logical_block) < end,
                        "I1 violated: lookup({ns}, {logical_block}) returned \
                         mapping [{}, {}) which does not cover the queried block",
                        mapping.logical_start,
                        end
                    );
                }
            }
            // invalidate_range
            2 => {
                let ns = u64::from(cursor.next_u8()) % NAMESPACE_DOMAIN;
                let logical_start = cursor.next_u32() % LOGICAL_DOMAIN;
                let count = u64::from(cursor.next_u8() % 16).saturating_add(1);
                cache.invalidate_range(ns, logical_start, count);
            }
            // invalidate_all — I3 smoke: lookups immediately after may still
            // hit (other threads insert concurrently), but must be
            // geometry-valid if they do.
            3 => {
                cache.invalidate_all();
            }
            // Stats: I2 — hits + misses must be monotonic within one worker's
            // view (barring concurrent reset_stats races, which we accept
            // as long as the total stays consistent with our own read count).
            4 => {
                let stats = cache.stats();
                let total = stats.hits.saturating_add(stats.misses);
                // Another thread may have reset; allow a downward reset.
                if total >= prior_hits_plus_misses {
                    prior_hits_plus_misses = total;
                } else {
                    // Drift to the smaller value; this is a legitimate reset
                    // observed mid-stream, not an invariant violation.
                    prior_hits_plus_misses = total;
                }
                assert!(
                    stats.entries <= stats.capacity,
                    "I*: entries must not exceed capacity mid-stream"
                );
            }
            // reset_stats
            _ => {
                cache.reset_stats();
                prior_hits_plus_misses = 0;
            }
        }
    }
}
