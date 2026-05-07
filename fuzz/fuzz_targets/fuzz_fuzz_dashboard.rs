#![no_main]

use ffs_harness::fuzz_dashboard::{
    assess_campaign_health, detect_regressions, parse_campaign_summary, validate_campaign_schema,
    validate_campaign_summary, CampaignConfig, CampaignSummary, CampaignTotals, TargetResult,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 16 * 1024;
const TARGET_NAMES: [&str; 9] = [
    "fuzz_ext4_metadata",
    "fuzz_btrfs_metadata",
    "fuzz_wal_replay",
    "fuzz_mvcc_operations",
    "fuzz_extent_tree",
    "fuzz_ioctl_dispatch",
    "fuzz_fuse_splice_mount",
    "fuzz_dashboard_generated",
    "",
];
const STATUS_VALUES: [&str; 7] = [
    "ok",
    "crashes_found",
    "timeout",
    "oom",
    "build_failed",
    "skipped",
    "",
];

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

    fn next_i32(&mut self) -> i32 {
        i32::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 == 1
    }

    fn choose<'b>(&mut self, values: &'b [&'b str]) -> &'b str {
        values
            .get(usize::from(self.next_u8()) % values.len())
            .copied()
            .unwrap_or("")
    }

    fn label(&mut self, prefix: &str) -> String {
        if self.next_u8().is_multiple_of(17) {
            return String::new();
        }

        let len = usize::from(self.next_u8() % 16);
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
                10 => '_',
                11 => '-',
                12 => '.',
                13 => '/',
                14 => ':',
                15 => '"',
                16 => '\\',
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
            validate_campaign_schema(text),
            validate_campaign_schema(text),
            "fuzz dashboard schema checks must be deterministic"
        );
        assert_eq!(
            parse_signature(text),
            parse_signature(text),
            "fuzz dashboard parser must be deterministic"
        );
        if let Ok(summary) = parse_campaign_summary(text) {
            exercise_summary(&summary);
        }
    }

    let mut cursor = ByteCursor::new(data);
    let baseline = campaign_summary_from_bytes(&mut cursor);
    let current = campaign_summary_from_bytes(&mut cursor);
    exercise_summary(&baseline);
    exercise_summary(&current);
    exercise_regressions(&baseline, &current);
});

fn parse_signature(text: &str) -> Result<Vec<String>, String> {
    parse_campaign_summary(text)
        .map(|summary| validate_campaign_summary(&summary))
        .map_err(|error| error.to_string())
}

fn exercise_summary(summary: &CampaignSummary) {
    let errors = validate_campaign_summary(summary);
    assert_eq!(
        errors,
        validate_campaign_summary(summary),
        "fuzz dashboard validation must be deterministic"
    );

    let Ok(json) = serde_json::to_string(summary) else {
        return;
    };
    let schema_checks = validate_campaign_schema(&json);
    assert_eq!(
        schema_checks.len(),
        5,
        "campaign schema checker should report the required five top-level fields"
    );
    assert!(
        schema_checks.iter().all(|check| check.present),
        "serialized campaign summaries must contain all schema fields"
    );

    let parsed = parse_campaign_summary(&json);
    assert_eq!(
        parsed.is_ok(),
        errors.is_empty(),
        "parser and validator must agree on generated campaign summary validity"
    );
    match parsed {
        Ok(parsed) => assert_eq!(
            parsed, *summary,
            "valid generated campaign summaries must round-trip through JSON"
        ),
        Err(error) => {
            for expected in errors {
                assert!(
                    error.contains(&expected),
                    "parser error should preserve validator finding {expected:?}: {error}"
                );
            }
        }
    }

    let health = assess_campaign_health(summary);
    assert_eq!(
        health.len(),
        summary.targets.len(),
        "health report cardinality must match target rows"
    );
    for (report, target) in health.iter().zip(&summary.targets) {
        assert_eq!(report.target, target.target);
        assert_eq!(report.coverage, target.coverage);
        assert_eq!(report.crash_count, target.crash_count);
        assert_eq!(report.corpus_size, target.corpus_size);
        assert_eq!(report.new_inputs, target.new_inputs);
        assert!(
            report.execs_per_sec.is_finite(),
            "target health throughput must remain finite"
        );
    }

    assert!(
        detect_regressions(summary, summary).is_empty(),
        "a campaign must not regress against itself"
    );
}

fn exercise_regressions(baseline: &CampaignSummary, current: &CampaignSummary) {
    let alerts = detect_regressions(baseline, current);
    assert_eq!(
        alerts,
        detect_regressions(baseline, current),
        "fuzz dashboard regression detection must be deterministic"
    );
    for alert in alerts {
        assert!(
            alert.baseline_value.is_finite()
                && alert.current_value.is_finite()
                && alert.change_pct.is_finite()
                && alert.threshold_pct.is_finite(),
            "regression alert metrics must stay finite"
        );
    }
}

fn campaign_summary_from_bytes(cursor: &mut ByteCursor<'_>) -> CampaignSummary {
    let target_len = usize::from(cursor.next_u8() % 8);
    let targets = (0..target_len)
        .map(|index| target_result_from_bytes(cursor, index))
        .collect::<Vec<_>>();

    let total_crashes = targets
        .iter()
        .fold(0_u64, |sum, target| sum.saturating_add(target.crash_count));
    let total_coverage = targets
        .iter()
        .fold(0_u64, |sum, target| sum.saturating_add(target.coverage));
    let total_runs = targets
        .iter()
        .fold(0_u64, |sum, target| sum.saturating_add(target.total_runs));

    let target_count = u32::try_from(targets.len()).unwrap_or(u32::MAX);
    let duration_per_target = 1 + cursor.next_u64() % 3_600;
    let jobs = 1 + cursor.next_u32() % 64;
    CampaignSummary {
        campaign_id: cursor.label("campaign_"),
        commit_sha: cursor.label("commit_"),
        timestamp: cursor.label("2026-05-07T"),
        config: CampaignConfig {
            duration_per_target: maybe_zero(cursor, duration_per_target),
            jobs: maybe_zero(cursor, jobs),
            target_count: maybe_drift_u32(cursor, target_count),
        },
        totals: CampaignTotals {
            elapsed_seconds: cursor.next_u64() % 86_400,
            total_crashes: maybe_drift_u64(cursor, total_crashes),
            total_coverage: maybe_drift_u64(cursor, total_coverage),
            total_runs: maybe_drift_u64(cursor, total_runs),
        },
        targets,
    }
}

fn target_result_from_bytes(cursor: &mut ByteCursor<'_>, index: usize) -> TargetResult {
    TargetResult {
        target: if cursor.next_bool() {
            cursor.choose(&TARGET_NAMES).to_owned()
        } else {
            cursor.label(&format!("target_{index}_"))
        },
        status: if cursor.next_bool() {
            cursor.choose(&STATUS_VALUES).to_owned()
        } else {
            cursor.label("status_")
        },
        exit_code: cursor.next_i32() % 128,
        coverage: cursor.next_u64() % 1_000_000,
        total_runs: cursor.next_u64() % 10_000_000,
        corpus_size: cursor.next_u64() % 100_000,
        crash_count: cursor.next_u64() % 1_024,
        new_inputs: cursor.next_u64() % 100_000,
        elapsed_seconds: cursor.next_u64() % 86_400,
    }
}

fn maybe_zero<T>(cursor: &mut ByteCursor<'_>, value: T) -> T
where
    T: From<u8>,
{
    if cursor.next_u8().is_multiple_of(13) {
        T::from(0)
    } else {
        value
    }
}

fn maybe_drift_u32(cursor: &mut ByteCursor<'_>, value: u32) -> u32 {
    if cursor.next_u8().is_multiple_of(5) {
        value.saturating_add(1 + cursor.next_u32() % 8)
    } else {
        value
    }
}

fn maybe_drift_u64(cursor: &mut ByteCursor<'_>, value: u64) -> u64 {
    if cursor.next_u8().is_multiple_of(5) {
        value.saturating_add(1 + cursor.next_u64() % 1_024)
    } else {
        value
    }
}
