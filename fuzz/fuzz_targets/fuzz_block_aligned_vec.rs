#![no_main]

use ffs_block::AlignedVec;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 2048;
const MAX_VEC_LEN: usize = 512;
const MAX_ALIGNMENT_REQUEST: usize = 8192;
const MAX_ALIGNMENT_POWER: usize = 8192;

struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> bool {
        self.pos < self.data.len()
    }

    fn next_u8(&mut self) -> u8 {
        let byte = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        byte
    }

    fn next_u16(&mut self) -> u16 {
        u16::from_le_bytes([self.next_u8(), self.next_u8()])
    }

    fn next_len(&mut self) -> usize {
        usize::from(self.next_u16()) % MAX_VEC_LEN.saturating_add(1)
    }

    fn next_alignment_request(&mut self) -> usize {
        usize::from(self.next_u16()) % MAX_ALIGNMENT_REQUEST.saturating_add(1)
    }

    fn next_payload(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u8()).collect()
    }
}

fn fail() -> ! {
    std::process::abort();
}

fn require(condition: bool) {
    if !condition {
        fail();
    }
}

fn normalized_alignment(requested: usize) -> usize {
    if requested <= 1 {
        1
    } else if requested.is_power_of_two() {
        requested
    } else {
        requested
            .checked_next_power_of_two()
            .unwrap_or(MAX_ALIGNMENT_POWER)
            .min(MAX_ALIGNMENT_POWER)
    }
}

fn check_vec(actual: &AlignedVec, expected: &[u8], expected_alignment: usize) {
    require(actual.as_slice() == expected);
    require(actual.len() == expected.len());
    require(actual.is_empty() == expected.is_empty());
    require(actual.alignment() == expected_alignment);
    let address = actual.as_slice().as_ptr().addr();
    if !actual.is_empty() {
        require(address.is_multiple_of(expected_alignment));
    }
}

fn replace_with_new(
    cursor: &mut ByteCursor<'_>,
    current: &mut AlignedVec,
    model: &mut Vec<u8>,
    alignment: &mut usize,
) {
    let len = cursor.next_len();
    let requested = cursor.next_alignment_request();
    *alignment = normalized_alignment(requested);
    *current = AlignedVec::new(len, requested);
    *model = vec![0_u8; len];
    check_vec(current, model, *alignment);
}

fn replace_from_vec(
    cursor: &mut ByteCursor<'_>,
    current: &mut AlignedVec,
    model: &mut Vec<u8>,
    alignment: &mut usize,
) {
    let len = cursor.next_len();
    let requested = cursor.next_alignment_request();
    let payload = cursor.next_payload(len);
    *alignment = normalized_alignment(requested);
    *current = AlignedVec::from_vec(payload.clone(), requested);
    *model = payload;
    check_vec(current, model, *alignment);
}

fn mutate_slice(cursor: &mut ByteCursor<'_>, current: &mut AlignedVec, model: &mut [u8]) {
    if model.is_empty() {
        return;
    }
    let start = usize::from(cursor.next_u16()) % model.len();
    let remaining = model.len().saturating_sub(start);
    let len = usize::from(cursor.next_u8()) % remaining.saturating_add(1);
    let fill = cursor.next_u8();
    current.as_mut_slice()[start..start + len].fill(fill);
    model[start..start + len].fill(fill);
}

fn clone_roundtrip(current: &AlignedVec, model: &[u8], alignment: usize) -> AlignedVec {
    let cloned = current.clone();
    check_vec(&cloned, model, alignment);
    require(&cloned == current);
    cloned
}

fn into_vec_roundtrip(current: AlignedVec, model: &[u8], alignment: usize) -> AlignedVec {
    let bytes = current.into_vec();
    require(bytes == model);
    let rebuilt = AlignedVec::from_vec(bytes, alignment);
    check_vec(&rebuilt, model, alignment);
    rebuilt
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut cursor = ByteCursor::new(data);
    let mut current = AlignedVec::new(0, 1);
    let mut model = Vec::new();
    let mut alignment = 1_usize;
    check_vec(&current, &model, alignment);

    while cursor.remaining() {
        match cursor.next_u8() % 6 {
            0 => replace_with_new(&mut cursor, &mut current, &mut model, &mut alignment),
            1 => replace_from_vec(&mut cursor, &mut current, &mut model, &mut alignment),
            2 => mutate_slice(&mut cursor, &mut current, &mut model),
            3 => {
                current = clone_roundtrip(&current, &model, alignment);
            }
            4 => {
                current = into_vec_roundtrip(current, &model, alignment);
            }
            _ => {}
        }
        check_vec(&current, &model, alignment);
    }
});
