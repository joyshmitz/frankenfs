#![no_main]

use ffs_alloc::{
    bitmap_clear, bitmap_count_free, bitmap_find_contiguous, bitmap_find_free, bitmap_get,
    bitmap_largest_free_run, bitmap_set,
};
use libfuzzer_sys::fuzz_target;

const MAX_BITMAP_BYTES: usize = 128;
const EXTRA_BITS: u32 = 64;

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
            return self.next_u32();
        }
        self.next_u32() % upper.saturating_add(1)
    }

    fn take_vec(&mut self, max_len: usize) -> Vec<u8> {
        let upper = u32::try_from(max_len).unwrap_or(u32::MAX);
        let len = usize::try_from(self.next_u32_inclusive(upper)).unwrap_or(max_len);
        (0..len).map(|_| self.next_u8()).collect()
    }
}

fn bitmap_bits(bitmap: &[u8]) -> u32 {
    u32::try_from(bitmap.len())
        .unwrap_or(u32::MAX)
        .saturating_mul(8)
}

fn model_get(bitmap: &[u8], idx: u32) -> bool {
    let byte_idx = usize::try_from(idx / 8).unwrap_or(usize::MAX);
    let bit_idx = idx % 8;
    if let Some(byte) = bitmap.get(byte_idx) {
        (byte >> bit_idx) & 1 == 1
    } else {
        true
    }
}

fn model_set(bitmap: &mut [u8], idx: u32) {
    let byte_idx = usize::try_from(idx / 8).unwrap_or(usize::MAX);
    let bit_idx = idx % 8;
    if let Some(byte) = bitmap.get_mut(byte_idx) {
        *byte |= 1 << bit_idx;
    }
}

fn model_clear(bitmap: &mut [u8], idx: u32) {
    let byte_idx = usize::try_from(idx / 8).unwrap_or(usize::MAX);
    let bit_idx = idx % 8;
    if let Some(byte) = bitmap.get_mut(byte_idx) {
        *byte &= !(1 << bit_idx);
    }
}

fn model_count_free(bitmap: &[u8], count: u32) -> u32 {
    let mut free = 0_u32;
    for idx in 0..count {
        if !model_get(bitmap, idx) {
            free = free.saturating_add(1);
        }
    }
    free
}

fn run_is_free(bitmap: &[u8], start: u32, limit: u32, len: u32) -> bool {
    if len > limit.saturating_sub(start) {
        return false;
    }
    for idx in start..start.saturating_add(len) {
        if model_get(bitmap, idx) {
            return false;
        }
    }
    true
}

fn model_find_free(bitmap: &[u8], count: u32, start: u32) -> Option<u32> {
    let start = start.min(count);
    for idx in start..count {
        if !model_get(bitmap, idx) {
            return Some(idx);
        }
    }
    (0..start).find(|&idx| !model_get(bitmap, idx))
}

fn model_find_contiguous(bitmap: &[u8], count: u32, len: u32, start: u32) -> Option<u32> {
    if len == 0 {
        return Some(0);
    }
    if len > count {
        return None;
    }

    for pos in start..count {
        if run_is_free(bitmap, pos, count, len) {
            return Some(pos);
        }
    }

    let pass2_end = start.saturating_add(len).saturating_sub(1).min(count);
    (0..pass2_end).find(|&pos| run_is_free(bitmap, pos, pass2_end, len))
}

fn model_largest_free_run(bitmap: &[u8], count: u32) -> u32 {
    let mut best = 0_u32;
    let mut run = 0_u32;
    for idx in 0..count {
        if model_get(bitmap, idx) {
            run = 0;
        } else {
            run = run.saturating_add(1);
            best = best.max(run);
        }
    }
    best
}

fn assert_query_determinism(bitmap: &[u8], idx: u32, count: u32, start: u32, len: u32) {
    let get_first = bitmap_get(bitmap, idx);
    let get_second = bitmap_get(bitmap, idx);
    if get_first != get_second {
        std::process::abort();
    }
    let count_first = bitmap_count_free(bitmap, count);
    let count_second = bitmap_count_free(bitmap, count);
    if count_first != count_second {
        std::process::abort();
    }
    let largest_first = bitmap_largest_free_run(bitmap, count);
    let largest_second = bitmap_largest_free_run(bitmap, count);
    if largest_first != largest_second {
        std::process::abort();
    }
    let free_first = bitmap_find_free(bitmap, count, start);
    let free_second = bitmap_find_free(bitmap, count, start);
    if free_first != free_second {
        std::process::abort();
    }
    let contiguous_first = bitmap_find_contiguous(bitmap, count, len, start);
    let contiguous_second = bitmap_find_contiguous(bitmap, count, len, start);
    if contiguous_first != contiguous_second {
        std::process::abort();
    }
}

fn assert_set_clear_matches_model(bitmap: &[u8], idx: u32) {
    let mut actual = bitmap.to_vec();
    let mut expected = bitmap.to_vec();
    bitmap_set(&mut actual, idx);
    model_set(&mut expected, idx);
    if actual != expected {
        std::process::abort();
    }
    let after_set = actual.clone();
    bitmap_set(&mut actual, idx);
    if actual != after_set {
        std::process::abort();
    }

    bitmap_clear(&mut actual, idx);
    model_clear(&mut expected, idx);
    if actual != expected {
        std::process::abort();
    }
    let after_clear = actual.clone();
    bitmap_clear(&mut actual, idx);
    if actual != after_clear {
        std::process::abort();
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = ByteCursor::new(data);
    let bitmap = cursor.take_vec(MAX_BITMAP_BYTES);
    let bit_count = bitmap_bits(&bitmap);
    let index_limit = bit_count.saturating_add(EXTRA_BITS);
    let idx = cursor.next_u32_inclusive(index_limit);
    let count = cursor.next_u32_inclusive(index_limit);
    let start = cursor.next_u32_inclusive(count.saturating_add(EXTRA_BITS));
    let len = cursor.next_u32_inclusive(count.saturating_add(8));

    assert_query_determinism(&bitmap, idx, count, start, len);

    let actual_get = bitmap_get(&bitmap, idx);
    let expected_get = model_get(&bitmap, idx);
    if actual_get != expected_get {
        std::process::abort();
    }

    let actual_count_free = bitmap_count_free(&bitmap, count);
    let expected_count_free = model_count_free(&bitmap, count);
    if actual_count_free != expected_count_free {
        std::process::abort();
    }

    let actual_largest_free_run = bitmap_largest_free_run(&bitmap, count);
    let expected_largest_free_run = model_largest_free_run(&bitmap, count);
    if actual_largest_free_run != expected_largest_free_run {
        std::process::abort();
    }

    let actual_find_free = bitmap_find_free(&bitmap, count, start);
    let expected_find_free = model_find_free(&bitmap, count, start);
    if actual_find_free != expected_find_free {
        std::process::abort();
    }

    let actual_find_contiguous = bitmap_find_contiguous(&bitmap, count, len, start);
    let expected_find_contiguous = model_find_contiguous(&bitmap, count, len, start);
    if actual_find_contiguous != expected_find_contiguous {
        std::process::abort();
    }

    if let Some(pos) = actual_find_free {
        if pos >= count || bitmap_get(&bitmap, pos) {
            std::process::abort();
        }
    }

    if let Some(pos) = actual_find_contiguous {
        if len == 0 {
            if pos != 0 {
                std::process::abort();
            }
        } else if !run_is_free(&bitmap, pos, count, len) {
            std::process::abort();
        }
    }

    assert_set_clear_matches_model(&bitmap, idx);
});
