#![no_main]

use ffs_alloc::succinct::SuccinctBitmap;
use libfuzzer_sys::fuzz_target;
use std::fmt::Debug;

const MAX_INPUT_BYTES: usize = 2048;
const MAX_BITMAP_BYTES: usize = 512;
const RANK_PROBES: usize = 16;
const SELECT_PROBES: usize = 16;

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

    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    fn next_u32_inclusive(&mut self, upper: u32) -> u32 {
        if upper == u32::MAX {
            self.next_u32()
        } else {
            self.next_u32() % upper.saturating_add(1)
        }
    }

    fn take_vec(&mut self, max_len: usize) -> Vec<u8> {
        let upper = u32::try_from(max_len).unwrap_or(u32::MAX);
        let len = usize::try_from(self.next_u32_inclusive(upper)).unwrap_or(max_len);
        (0..len).map(|_| self.next_u8()).collect()
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut cursor = ByteCursor::new(data);
    let bitmap = cursor.take_vec(MAX_BITMAP_BYTES);
    let capacity_bits = bitmap_bits(&bitmap);
    let len = if capacity_bits == 0 {
        0
    } else {
        cursor.next_u32_inclusive(capacity_bits)
    };
    let bitmap = mask_trailing_bits(bitmap, len);
    let succinct = SuccinctBitmap::build(&bitmap, len);

    require_eq(succinct.len(), len, "len");
    require_eq(succinct.is_empty(), len == 0, "is_empty");

    let model_ones = model_rank1(&bitmap, len, len);
    require_eq(succinct.count_ones(), model_ones, "count_ones");
    require_eq(
        succinct.count_zeros(),
        len.saturating_sub(model_ones),
        "count_zeros",
    );

    verify_rank_probes(&mut cursor, &succinct, &bitmap, len);
    verify_select_probes(&mut cursor, &succinct, &bitmap, len, model_ones);
    verify_find_probes(&mut cursor, &succinct, &bitmap, len);
});

fn verify_rank_probes(
    cursor: &mut ByteCursor<'_>,
    succinct: &SuccinctBitmap,
    bitmap: &[u8],
    len: u32,
) {
    let rank_bound = len.saturating_add(64);
    for _ in 0..RANK_PROBES {
        let pos = cursor.next_u32_inclusive(rank_bound);
        let expected_rank1 = model_rank1(bitmap, len, pos);
        require_eq(succinct.rank1(pos), expected_rank1, "rank1");
        require_eq(
            succinct.rank0(pos),
            pos.min(len).saturating_sub(expected_rank1),
            "rank0",
        );

        let next_pos = pos.saturating_add(1);
        let delta = succinct.rank1(next_pos).saturating_sub(succinct.rank1(pos));
        if delta > 1 {
            invariant_failure(format!(
                "rank1 must increase by at most one: pos={pos} next={next_pos} delta={delta}"
            ));
        }
    }
}

fn verify_select_probes(
    cursor: &mut ByteCursor<'_>,
    succinct: &SuccinctBitmap,
    bitmap: &[u8],
    len: u32,
    model_ones: u32,
) {
    let model_zeros = len.saturating_sub(model_ones);
    for _ in 0..SELECT_PROBES {
        let one_k = cursor.next_u32_inclusive(model_ones.saturating_add(2));
        let actual_one = succinct.select1(one_k);
        let expected_one = model_select(bitmap, len, one_k, true);
        require_eq(actual_one, expected_one, "select1");
        if let Some(pos) = actual_one {
            if !model_get(bitmap, pos) {
                invariant_failure(format!("select1 returned zero bit at {pos}"));
            }
            require_eq(
                succinct.rank1(pos.saturating_add(1)),
                one_k.saturating_add(1),
                "select1 rank witness",
            );
        }

        let zero_k = cursor.next_u32_inclusive(model_zeros.saturating_add(2));
        let actual_zero = succinct.select0(zero_k);
        let expected_zero = model_select(bitmap, len, zero_k, false);
        require_eq(actual_zero, expected_zero, "select0");
        if let Some(pos) = actual_zero {
            if model_get(bitmap, pos) {
                invariant_failure(format!("select0 returned one bit at {pos}"));
            }
            require_eq(
                succinct.rank0(pos.saturating_add(1)),
                zero_k.saturating_add(1),
                "select0 rank witness",
            );
        }
    }
}

fn verify_find_probes(
    cursor: &mut ByteCursor<'_>,
    succinct: &SuccinctBitmap,
    bitmap: &[u8],
    len: u32,
) {
    for _ in 0..SELECT_PROBES {
        let start = cursor.next_u32_inclusive(len.saturating_add(64));
        let actual_free = succinct.find_free(start);
        let expected_free = model_find_free(bitmap, len, start);
        require_eq(actual_free, expected_free, "find_free");

        let run_len = cursor.next_u32_inclusive(len.saturating_add(2));
        let actual_run = succinct.find_contiguous(run_len);
        let expected_run = model_find_contiguous(bitmap, len, run_len);
        require_eq(actual_run, expected_run, "find_contiguous");
        if let Some(pos) = actual_run {
            if !model_run_is_free(bitmap, len, pos, run_len) {
                invariant_failure(format!(
                    "find_contiguous returned non-free run: start={pos} len={run_len}"
                ));
            }
        }
    }
}

fn bitmap_bits(bitmap: &[u8]) -> u32 {
    u32::try_from(bitmap.len())
        .unwrap_or(u32::MAX / 8)
        .saturating_mul(8)
}

fn mask_trailing_bits(mut bitmap: Vec<u8>, len: u32) -> Vec<u8> {
    if len == 0 || bitmap.is_empty() {
        return bitmap;
    }

    let valid_bytes = usize::try_from(len.div_ceil(8)).unwrap_or(bitmap.len());
    bitmap.truncate(valid_bytes);
    let trailing = len % 8;
    if trailing != 0 {
        let mask = u8::try_from((1_u16 << trailing) - 1).unwrap_or(u8::MAX);
        if let Some(last) = bitmap.last_mut() {
            *last &= mask;
        }
    }
    bitmap
}

fn model_get(bitmap: &[u8], pos: u32) -> bool {
    let byte_idx = usize::try_from(pos / 8).unwrap_or(usize::MAX);
    let bit_idx = pos % 8;
    bitmap
        .get(byte_idx)
        .is_some_and(|byte| (byte >> bit_idx) & 1 == 1)
}

fn model_rank1(bitmap: &[u8], len: u32, pos: u32) -> u32 {
    let end = pos.min(len);
    let mut ones = 0_u32;
    for bit in 0..end {
        if model_get(bitmap, bit) {
            ones = ones.saturating_add(1);
        }
    }
    ones
}

fn model_select(bitmap: &[u8], len: u32, k: u32, want_one: bool) -> Option<u32> {
    let mut seen = 0_u32;
    for pos in 0..len {
        if model_get(bitmap, pos) == want_one {
            if seen == k {
                return Some(pos);
            }
            seen = seen.saturating_add(1);
        }
    }
    None
}

fn model_find_free(bitmap: &[u8], len: u32, start: u32) -> Option<u32> {
    if start < len {
        for pos in start..len {
            if !model_get(bitmap, pos) {
                return Some(pos);
            }
        }
    }
    (0..len.min(start)).find(|&pos| !model_get(bitmap, pos))
}

fn model_find_contiguous(bitmap: &[u8], len: u32, run_len: u32) -> Option<u32> {
    if run_len == 0 {
        return Some(0);
    }
    if run_len > len {
        return None;
    }

    let last_start = len.saturating_sub(run_len);
    (0..=last_start).find(|&pos| model_run_is_free(bitmap, len, pos, run_len))
}

fn model_run_is_free(bitmap: &[u8], len: u32, start: u32, run_len: u32) -> bool {
    if run_len == 0 {
        return start == 0;
    }
    let Some(end) = start.checked_add(run_len) else {
        return false;
    };
    if end > len {
        return false;
    }
    (start..end).all(|pos| !model_get(bitmap, pos))
}

fn require_eq<T>(actual: T, expected: T, label: &str)
where
    T: Debug + PartialEq,
{
    if actual != expected {
        invariant_failure(format!(
            "{label} mismatch: actual={actual:?} expected={expected:?}"
        ));
    }
}

fn invariant_failure(message: String) -> ! {
    std::panic::panic_any(message);
}
