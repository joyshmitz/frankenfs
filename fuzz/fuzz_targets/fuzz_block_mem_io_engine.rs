#![no_main]

use ffs_block::io_engine::{IoCompletion, IoEngine, IoEngineStats, IoOp, MemIoEngine};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 2048;
const MAX_MEMORY_SIZE: usize = 4096;
const MAX_BATCH_OPS: usize = 24;
const MAX_IO_LEN: usize = 128;
const OFFSET_SLACK: u64 = 256;

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

    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    fn next_len(&mut self) -> usize {
        usize::from(self.next_u8()) % (MAX_IO_LEN.saturating_add(1))
    }

    fn next_offset(&mut self, model_len: usize) -> u64 {
        let model_len = u64::try_from(model_len).unwrap_or(u64::MAX.saturating_sub(OFFSET_SLACK));
        let limit = model_len.saturating_add(OFFSET_SLACK);
        u64::from(self.next_u32()) % limit.saturating_add(1)
    }

    fn next_payload(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u8()).collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ExpectedCompletion {
    Read(Vec<u8>),
    Write,
    Sync,
    Error,
}

#[derive(Clone, Debug, Default)]
struct ExpectedStats {
    reads: u64,
    writes: u64,
    syncs: u64,
    bytes_read: u64,
    bytes_written: u64,
    batches: u64,
}

impl ExpectedStats {
    fn record_batch(&mut self) {
        self.batches = self.batches.saturating_add(1);
    }

    fn record_read(&mut self, len: usize, success: bool) {
        self.reads = self.reads.saturating_add(1);
        if success {
            self.bytes_read = self.bytes_read.saturating_add(usize_to_u64(len));
        }
    }

    fn record_write(&mut self, len: usize, success: bool) {
        self.writes = self.writes.saturating_add(1);
        if success {
            self.bytes_written = self.bytes_written.saturating_add(usize_to_u64(len));
        }
    }

    fn record_sync(&mut self) {
        self.syncs = self.syncs.saturating_add(1);
    }
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn fail() -> ! {
    std::process::abort();
}

fn require(condition: bool) {
    if !condition {
        fail();
    }
}

fn checked_range(offset: u64, len: usize, capacity: usize) -> Option<std::ops::Range<usize>> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(len)?;
    if end > capacity {
        return None;
    }
    Some(start..end)
}

fn expected_read(
    model: &[u8],
    offset: u64,
    len: usize,
    stats: &mut ExpectedStats,
) -> ExpectedCompletion {
    if let Some(range) = checked_range(offset, len, model.len()) {
        stats.record_read(len, true);
        ExpectedCompletion::Read(model[range].to_vec())
    } else {
        stats.record_read(len, false);
        ExpectedCompletion::Error
    }
}

fn expected_write(
    model: &mut [u8],
    offset: u64,
    payload: &[u8],
    stats: &mut ExpectedStats,
) -> ExpectedCompletion {
    if let Some(range) = checked_range(offset, payload.len(), model.len()) {
        model[range].copy_from_slice(payload);
        stats.record_write(payload.len(), true);
        ExpectedCompletion::Write
    } else {
        stats.record_write(payload.len(), false);
        ExpectedCompletion::Error
    }
}

fn build_batch(
    cursor: &mut ByteCursor<'_>,
    model: &mut [u8],
    stats: &mut ExpectedStats,
) -> (Vec<IoOp>, Vec<ExpectedCompletion>) {
    let op_count = usize::from(cursor.next_u8()) % (MAX_BATCH_OPS.saturating_add(1));
    let mut ops = Vec::with_capacity(op_count);
    let mut expected = Vec::with_capacity(op_count);
    stats.record_batch();

    for _ in 0..op_count {
        match cursor.next_u8() % 3 {
            0 => {
                let offset = cursor.next_offset(model.len());
                let len = cursor.next_len();
                ops.push(IoOp::Read {
                    offset,
                    buf: vec![0_u8; len],
                });
                expected.push(expected_read(model, offset, len, stats));
            }
            1 => {
                let offset = cursor.next_offset(model.len());
                let len = cursor.next_len();
                let payload = cursor.next_payload(len);
                expected.push(expected_write(model, offset, &payload, stats));
                ops.push(IoOp::Write {
                    offset,
                    data: payload,
                });
            }
            _ => {
                ops.push(IoOp::Sync);
                stats.record_sync();
                expected.push(ExpectedCompletion::Sync);
            }
        }
    }

    (ops, expected)
}

fn check_completion(actual: &IoCompletion, expected: &ExpectedCompletion) {
    match (actual, expected) {
        (IoCompletion::Read(actual), ExpectedCompletion::Read(expected)) => {
            require(actual == expected);
        }
        (IoCompletion::Write, ExpectedCompletion::Write)
        | (IoCompletion::Sync, ExpectedCompletion::Sync)
        | (IoCompletion::Error(_), ExpectedCompletion::Error) => {}
        _ => fail(),
    }
}

fn check_stats(actual: &IoEngineStats, expected: &ExpectedStats) {
    require(actual.reads == expected.reads);
    require(actual.writes == expected.writes);
    require(actual.syncs == expected.syncs);
    require(actual.bytes_read == expected.bytes_read);
    require(actual.bytes_written == expected.bytes_written);
    require(actual.batches == expected.batches);
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut cursor = ByteCursor::new(data);
    let size = usize::from(cursor.next_u16()) % (MAX_MEMORY_SIZE.saturating_add(1));
    let engine = MemIoEngine::new(size);
    let mut model = vec![0_u8; size];
    let mut stats = ExpectedStats::default();

    require(engine.name() == "memory");
    check_stats(&engine.stats(), &stats);

    while cursor.remaining() {
        let (ops, expected) = build_batch(&mut cursor, &mut model, &mut stats);
        let completions = engine.submit_batch(ops);
        require(completions.len() == expected.len());
        for (actual, expected) in completions.iter().zip(expected.iter()) {
            check_completion(actual, expected);
        }
        check_stats(&engine.stats(), &stats);
    }
});
