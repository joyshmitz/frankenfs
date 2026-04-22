#![no_main]

use ffs_repair::evidence::{parse_evidence_ledger, EvidenceRecord};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 8 * 1024;

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

fuzz_target!(|data: &[u8]| {
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
});
