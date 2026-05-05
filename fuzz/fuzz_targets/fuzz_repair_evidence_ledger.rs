#![no_main]

use ffs_repair::evidence::{
    parse_evidence_ledger, CorruptionDetail, EvidenceRecord, PolicyDecisionDetail, RepairDetail,
    ScrubCycleDetail, SymbolRefreshDetail,
};
use ffs_repair::recovery::RecoveryDecoderStats;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 8 * 1024;

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

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 == 1
    }

    fn next_label(&mut self, prefix: &str) -> String {
        let suffix_len = usize::from(self.next_u8() % 8);
        let mut label = String::with_capacity(prefix.len() + suffix_len);
        label.push_str(prefix);
        for _ in 0..suffix_len {
            let ch = match self.next_u8() % 16 {
                0 => 'a',
                1 => 'b',
                2 => 'c',
                3 => 'd',
                4 => 'e',
                5 => 'f',
                6 => 'g',
                7 => 'h',
                8 => '0',
                9 => '1',
                10 => '2',
                11 => '3',
                12 => '_',
                13 => '-',
                14 => ':',
                _ => '.',
            };
            label.push(ch);
        }
        label
    }

    fn next_quarter_ratio(&mut self) -> f64 {
        match self.next_u8() % 5 {
            0 => 0.0,
            1 => 0.25,
            2 => 0.5,
            3 => 0.75,
            _ => 1.0,
        }
    }
}

fn non_empty_line_count(data: &[u8]) -> usize {
    String::from_utf8_lossy(data)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
}

fn normalize_records(data: &[u8]) -> Vec<String> {
    parse_evidence_ledger(data)
        .into_iter()
        .map(|record| {
            let json = record.to_json().expect("serialize parsed evidence record");
            assert!(
                !json.contains('\n'),
                "serialized evidence records must stay single-line JSONL entries"
            );
            let reparsed = EvidenceRecord::from_json(&json).expect("reparse serialized record");
            assert_eq!(
                reparsed, record,
                "serialized evidence records must round-trip exactly"
            );
            json
        })
        .collect()
}

fn bounded_usize(cursor: &mut ByteCursor<'_>, max_exclusive: usize) -> usize {
    if max_exclusive == 0 {
        0
    } else {
        usize::from(cursor.next_u8()) % max_exclusive
    }
}

fn corruption_detail(cursor: &mut ByteCursor<'_>) -> CorruptionDetail {
    CorruptionDetail {
        blocks_affected: 1 + (cursor.next_u32() % 128),
        corruption_kind: cursor.next_label("kind_"),
        severity: cursor.next_label("severity_"),
        detail: cursor.next_label("detail_"),
    }
}

fn decoder_stats(cursor: &mut ByteCursor<'_>) -> RecoveryDecoderStats {
    RecoveryDecoderStats {
        peeled: bounded_usize(cursor, 512),
        inactivated: bounded_usize(cursor, 512),
        gauss_ops: bounded_usize(cursor, 1024),
        pivots_selected: bounded_usize(cursor, 512),
    }
}

fn repair_detail(cursor: &mut ByteCursor<'_>) -> RepairDetail {
    let symbols_available = 1 + bounded_usize(cursor, 32);
    let symbols_used = bounded_usize(cursor, symbols_available + 1);
    RepairDetail {
        generation: cursor.next_u64(),
        corrupt_count: bounded_usize(cursor, 32),
        symbols_used,
        symbols_available,
        decoder_stats: decoder_stats(cursor),
        verify_pass: cursor.next_bool(),
        reason: cursor
            .next_bool()
            .then(|| cursor.next_label("repair_reason_")),
    }
}

fn scrub_cycle_detail(cursor: &mut ByteCursor<'_>) -> ScrubCycleDetail {
    let blocks_scanned = 1 + (cursor.next_u64() % 65_536);
    let blocks_corrupt = u64::from(cursor.next_u16()) % (blocks_scanned + 1);
    let blocks_io_error = u64::from(cursor.next_u16()) % (blocks_scanned + 1);
    ScrubCycleDetail {
        blocks_scanned,
        blocks_corrupt,
        blocks_io_error,
        findings_count: bounded_usize(cursor, 512),
    }
}

fn policy_detail(cursor: &mut ByteCursor<'_>) -> PolicyDecisionDetail {
    let posterior_alpha = 1.0 + f64::from(cursor.next_u8());
    let posterior_beta = 1.0 + f64::from(cursor.next_u8());
    let corruption_posterior = cursor.next_quarter_ratio();
    let overhead_ratio = cursor.next_quarter_ratio();
    let risk_bound = cursor.next_quarter_ratio();
    PolicyDecisionDetail {
        corruption_posterior,
        posterior_alpha,
        posterior_beta,
        overhead_ratio,
        risk_bound,
        expected_loss: overhead_ratio * corruption_posterior,
        symbols_selected: cursor.next_u32() % 256,
        metadata_group: cursor.next_bool(),
        decision: cursor.next_label("policy_"),
    }
}

fn symbol_refresh_detail(cursor: &mut ByteCursor<'_>) -> SymbolRefreshDetail {
    let previous_generation = cursor.next_u64();
    SymbolRefreshDetail {
        previous_generation,
        new_generation: previous_generation.saturating_add(u64::from(cursor.next_u32())),
        symbols_generated: cursor.next_u32() % 512,
    }
}

fn with_cursor_range(record: EvidenceRecord, cursor: &mut ByteCursor<'_>) -> EvidenceRecord {
    if !cursor.next_bool() {
        return record;
    }
    let start = cursor.next_u64() % 1_000_000;
    let len = 1 + u64::from(cursor.next_u16());
    record.with_block_range(start, start.saturating_add(len))
}

fn cursor_records(data: &[u8]) -> Vec<EvidenceRecord> {
    let mut cursor = ByteCursor::new(data);
    let base_group = cursor.next_u32();

    vec![
        with_cursor_range(
            EvidenceRecord::corruption_detected(base_group, corruption_detail(&mut cursor))
                .with_timestamp(cursor.next_u64()),
            &mut cursor,
        ),
        with_cursor_range(
            EvidenceRecord::repair_succeeded(
                base_group.wrapping_add(1),
                repair_detail(&mut cursor),
            )
            .with_timestamp(cursor.next_u64()),
            &mut cursor,
        ),
        EvidenceRecord::scrub_cycle_complete(
            base_group.wrapping_add(2),
            scrub_cycle_detail(&mut cursor),
        )
        .with_timestamp(cursor.next_u64()),
        EvidenceRecord::policy_decision(base_group.wrapping_add(3), policy_detail(&mut cursor))
            .with_timestamp(cursor.next_u64()),
        EvidenceRecord::symbol_refresh(
            base_group.wrapping_add(4),
            symbol_refresh_detail(&mut cursor),
        )
        .with_timestamp(cursor.next_u64()),
    ]
}

fn record_json(record: &EvidenceRecord) -> String {
    let json = record
        .to_json()
        .expect("serialize synthetic evidence record");
    assert!(
        !json.contains('\n'),
        "synthetic evidence JSON must stay one physical JSONL line"
    );
    json
}

fn assert_valid_jsonl_contracts(records: &[EvidenceRecord]) {
    let mut ledger = Vec::new();
    for record in records {
        ledger.extend_from_slice(record_json(record).as_bytes());
        ledger.extend_from_slice(b"\r\n\n\t \n");
    }

    let parsed = parse_evidence_ledger(&ledger);
    assert_eq!(
        parsed, records,
        "valid records must parse in order while CRLF and blank lines are ignored"
    );
}

fn assert_malformed_line_isolation(records: &[EvidenceRecord]) {
    let Some(first) = records.first() else {
        return;
    };
    let Some(last) = records.last() else {
        return;
    };

    let mut ledger = Vec::new();
    ledger.extend_from_slice(record_json(first).as_bytes());
    ledger.extend_from_slice(b"\n\xff\xfe\xfd\n{\"event_type\":\n");
    ledger.extend_from_slice(record_json(last).as_bytes());
    ledger.extend_from_slice(b"\n{\"timestamp_ns\":1,\"event_type\":\"corruption_detected\"");

    let parsed = parse_evidence_ledger(&ledger);
    assert_eq!(
        parsed,
        vec![first.clone(), last.clone()],
        "invalid UTF-8 and torn JSONL lines must be skipped without poisoning adjacent records"
    );
}

fn assert_arbitrary_parse_contracts(data: &[u8]) {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let first = normalize_records(data);
    let second = normalize_records(data);
    assert_eq!(
        first, second,
        "parse_evidence_ledger must be deterministic for identical inputs"
    );
    assert!(
        first.len() <= non_empty_line_count(data),
        "parser cannot emit more records than non-empty input lines"
    );

    if first.is_empty() {
        return;
    }

    let roundtrip = first.join("\n");
    let reparsed = normalize_records(roundtrip.as_bytes());
    assert_eq!(
        reparsed, first,
        "serialized JSONL output must remain stable under reparse"
    );
}

fuzz_target!(|data: &[u8]| {
    assert_arbitrary_parse_contracts(data);

    let records = cursor_records(data);
    assert_valid_jsonl_contracts(&records);
    assert_malformed_line_isolation(&records);
});
