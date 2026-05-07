#![no_main]

use ffs_harness::fuzz_smoke::{
    fail_on_fuzz_smoke_errors, parse_fuzz_smoke_manifest, validate_fuzz_smoke_manifest,
    FuzzSmokeManifest, FuzzSmokeMinimization, FuzzSmokeQuarantine, FuzzSmokeReport,
    FuzzSmokeResourceBudget, FuzzSmokeSeed,
};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

const MAX_INPUT_BYTES: usize = 16 * 1024;
const REQUIRED_ARTIFACT_FIELDS: [&str; 8] = [
    "command_line",
    "seed_ids",
    "corpus_checksum",
    "duration_ms",
    "stdout_path",
    "stderr_path",
    "cleanup_status",
    "report_json",
];
const TARGETS: [&str; 11] = [
    "ext4_superblock",
    "ext4_group_desc_32",
    "ext4_inode",
    "ext4_extent_tree",
    "ext4_dir_block",
    "btrfs_superblock",
    "btrfs_sys_chunk_array",
    "btrfs_leaf_items",
    "repair_corpus_manifest",
    "mounted_write_error_classes_catalog",
    "unknown_target",
];
const EXPECTED_CLASSES: [&str; 12] = [
    "accepted",
    "InsufficientData",
    "InvalidMagic",
    "InvalidField",
    "IntegerConversion",
    "RepairCorpusInvalid",
    "MountedWriteErrorClassesInvalid",
    "Utf8Error",
    "panic",
    "timeout",
    "resource_cap",
    "unexpected_class",
];
const MINIMIZATION_STATUSES: [&str; 4] = [
    "minimized",
    "not_minimized",
    "not_applicable",
    "unknown_status",
];
const QUARANTINE_STATUSES: [&str; 4] = ["none", "active", "expired", "unknown_status"];

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

    fn choose<'b>(&mut self, values: &'b [&'b str]) -> &'b str {
        values
            .get(usize::from(self.next_u8()) % values.len())
            .copied()
            .unwrap_or("")
    }

    fn label(&mut self, prefix: &str) -> String {
        if self.next_u8().is_multiple_of(19) {
            return String::new();
        }

        let len = 1 + usize::from(self.next_u8() % 20);
        let mut label = String::from(prefix);
        for _ in 0..len {
            let ch = match self.next_u8() % 18 {
                0 => 'a',
                1 => 'b',
                2 => 'c',
                3 => 'd',
                4 => 'e',
                5 => 'f',
                6 => '0',
                7 => '1',
                8 => '2',
                9 => '3',
                10 => '-',
                11 => '_',
                12 => '.',
                13 => '/',
                14 => '\\',
                15 => ' ',
                16 => ':',
                _ => 'z',
            };
            label.push(ch);
        }
        label
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(text) = std::str::from_utf8(data) {
        assert_eq!(
            parse_signature(text),
            parse_signature(text),
            "fuzz-smoke manifest parsing must be deterministic"
        );
        if let Ok(manifest) = parse_fuzz_smoke_manifest(text) {
            exercise_manifest(&manifest);
        }
    }

    let mut cursor = ByteCursor::new(data);
    let manifest = manifest_from_bytes(&mut cursor);
    exercise_manifest(&manifest);
});

fn parse_signature(text: &str) -> Result<Vec<String>, String> {
    parse_fuzz_smoke_manifest(text)
        .map(|manifest| validate_fuzz_smoke_manifest(&manifest))
        .map_err(|error| error.to_string())
}

fn exercise_manifest(manifest: &FuzzSmokeManifest) {
    let errors = validate_fuzz_smoke_manifest(manifest);
    assert_eq!(
        errors,
        validate_fuzz_smoke_manifest(manifest),
        "fuzz-smoke manifest validation must be deterministic"
    );

    let report = report_from_manifest(manifest, errors);
    assert_eq!(
        report.valid,
        report.errors.is_empty(),
        "fuzz-smoke report validity must track the error list"
    );
    assert_eq!(
        fail_on_fuzz_smoke_errors(&report).is_err(),
        !report.valid,
        "fuzz-smoke gate must fail closed exactly when the report is invalid"
    );

    if report.valid {
        assert!(
            !manifest.seeds.is_empty(),
            "valid fuzz-smoke manifests must include at least one seed"
        );
        assert!(
            manifest
                .seeds
                .iter()
                .all(|seed| !std::path::Path::new(&seed.path).is_absolute()
                    && !seed.path.split('/').any(|component| component == "..")),
            "valid fuzz-smoke seed paths must stay under the workspace root"
        );
    }
}

fn report_from_manifest(manifest: &FuzzSmokeManifest, errors: Vec<String>) -> FuzzSmokeReport {
    FuzzSmokeReport {
        schema_version: manifest.schema_version,
        corpus_id: manifest.corpus_id.clone(),
        bead_id: manifest.bead_id.clone(),
        corpus_version: manifest.corpus_version.clone(),
        command_line: "cargo fuzz run fuzz_fuzz_smoke_manifest".to_owned(),
        seed_count: manifest.seeds.len(),
        seed_ids: manifest
            .seeds
            .iter()
            .map(|seed| seed.seed_id.clone())
            .collect(),
        corpus_checksum: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_owned(),
        duration_ms: 0,
        target_summary: BTreeMap::new(),
        outcome_summary: BTreeMap::new(),
        minimization_summary: BTreeMap::new(),
        quarantine_summary: BTreeMap::new(),
        artifact_contract: manifest.artifact_contract.clone(),
        seed_results: Vec::new(),
        valid: errors.is_empty(),
        errors,
    }
}

fn manifest_from_bytes(cursor: &mut ByteCursor<'_>) -> FuzzSmokeManifest {
    let seed_count = usize::from(cursor.next_u8() % 4);
    let artifact_contract = artifact_contract_from_bytes(cursor);
    let duplicate_seed_ids = cursor.next_u8().is_multiple_of(5);
    FuzzSmokeManifest {
        schema_version: match cursor.next_u8() % 4 {
            0 => 1,
            1 => 0,
            2 => cursor.next_u32(),
            _ => u32::MAX,
        },
        corpus_id: cursor.label("corpus-"),
        bead_id: if cursor.next_u8().is_multiple_of(4) {
            cursor.label("not-bd-")
        } else {
            "bd-51wzf".to_owned()
        },
        corpus_version: cursor.label("v"),
        default_timeout_ms: match cursor.next_u8() % 4 {
            0 => 0,
            1 => 1,
            2 => u64::from(cursor.next_u16()).saturating_add(1),
            _ => cursor.next_u64(),
        },
        artifact_contract,
        seeds: (0..seed_count)
            .map(|index| seed_from_bytes(cursor, index, duplicate_seed_ids))
            .collect(),
    }
}

fn artifact_contract_from_bytes(cursor: &mut ByteCursor<'_>) -> Vec<String> {
    if cursor.next_u8().is_multiple_of(2) {
        return REQUIRED_ARTIFACT_FIELDS
            .iter()
            .map(|field| (*field).to_owned())
            .collect();
    }

    let count = usize::from(cursor.next_u8() % 12);
    (0..count).map(|_| cursor.label("field-")).collect()
}

fn seed_from_bytes(
    cursor: &mut ByteCursor<'_>,
    index: usize,
    duplicate_seed_ids: bool,
) -> FuzzSmokeSeed {
    let timeout_ms = match cursor.next_u8() % 4 {
        0 => 0,
        1 => 1,
        2 => u64::from(cursor.next_u16()).saturating_add(1),
        _ => cursor.next_u64(),
    };
    let max_duration_ms = match cursor.next_u8() % 4 {
        0 => 0,
        1 => timeout_ms,
        2 => timeout_ms.saturating_sub(1),
        _ => timeout_ms.saturating_add(u64::from(cursor.next_u16())),
    };

    FuzzSmokeSeed {
        seed_id: if duplicate_seed_ids {
            "seed-duplicate".to_owned()
        } else {
            format!("seed-{index}-{}", cursor.label(""))
        },
        path: path_from_bytes(cursor),
        source: cursor.label("source-"),
        provenance: cursor.label("provenance-"),
        target: cursor.choose(&TARGETS).to_owned(),
        expected_class: cursor.choose(&EXPECTED_CLASSES).to_owned(),
        expected_error_contains: if cursor.next_u8().is_multiple_of(3) {
            Some(cursor.label("error-"))
        } else {
            None
        },
        corpus_checksum: checksum_from_bytes(cursor),
        timeout_ms,
        resource_budget: FuzzSmokeResourceBudget {
            max_input_bytes: usize::from(cursor.next_u16()),
            max_duration_ms,
            max_artifact_bytes: usize::from(cursor.next_u16()),
        },
        minimization: minimization_from_bytes(cursor),
        quarantine: quarantine_from_bytes(cursor),
    }
}

fn path_from_bytes(cursor: &mut ByteCursor<'_>) -> String {
    match cursor.next_u8() % 6 {
        0 => String::new(),
        1 => "tests/fuzz-smoke/seed.bin".to_owned(),
        2 => "/tmp/seed.bin".to_owned(),
        3 => "../outside.seed".to_owned(),
        4 => "tests/../outside.seed".to_owned(),
        _ => cursor.label("tests/fuzz-smoke/"),
    }
}

fn checksum_from_bytes(cursor: &mut ByteCursor<'_>) -> String {
    if cursor.next_u8().is_multiple_of(2) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut digest = String::from("sha256:");
        for _ in 0..64 {
            let nibble = cursor.next_u8() % 16;
            digest.push(char::from(*HEX.get(usize::from(nibble)).unwrap_or(&b'0')));
        }
        digest
    } else {
        cursor.label("sha256:")
    }
}

fn minimization_from_bytes(cursor: &mut ByteCursor<'_>) -> FuzzSmokeMinimization {
    let status = cursor.choose(&MINIMIZATION_STATUSES).to_owned();
    FuzzSmokeMinimization {
        status,
        replay_command: cursor.label("cargo fuzz run "),
        follow_up_bead: if cursor.next_u8().is_multiple_of(2) {
            Some("bd-51wzf".to_owned())
        } else {
            Some(cursor.label("follow-up-"))
        },
    }
}

fn quarantine_from_bytes(cursor: &mut ByteCursor<'_>) -> FuzzSmokeQuarantine {
    FuzzSmokeQuarantine {
        status: cursor.choose(&QUARANTINE_STATUSES).to_owned(),
        quarantine_id: optional_label(cursor, "q-"),
        owner: optional_label(cursor, "owner-"),
        expires_at: optional_label(cursor, "2026-06-"),
        owning_bead: optional_label(cursor, "bd-"),
        rationale: optional_label(cursor, "reason-"),
    }
}

fn optional_label(cursor: &mut ByteCursor<'_>, prefix: &str) -> Option<String> {
    if cursor.next_u8().is_multiple_of(2) {
        Some(cursor.label(prefix))
    } else {
        None
    }
}
