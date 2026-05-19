#![no_main]

use ffs_harness::rch_capacity_preflight::{
    fail_on_rch_capacity_preflight_errors, render_rch_capacity_preflight_markdown,
    validate_rch_capacity_preflight_report, RchCapacityDaemonSummary, RchCapacityPreflightReport,
    RchCapacityProbeReport, RchCapacityStatusCapture, RchCapacityWorkerCounts,
    RCH_CAPACITY_PREFLIGHT_SCHEMA_VERSION,
};
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value};
use std::collections::BTreeSet;

const MAX_INPUT_BYTES: usize = 16 * 1024;
const EXPECTED_PROBE_COMMAND: [&str; 5] = ["cargo", "check", "-p", "ffs-error", "--lib"];
const CAPACITY_VERDICTS: [&str; 6] = [
    "admissible_capacity_available",
    "no_admissible_workers",
    "no_workers_reported",
    "status_capture_failed",
    "unknown_capacity",
    "",
];
const PROBE_VERDICTS: [&str; 8] = [
    "not_run",
    "remote_success",
    "local_fallback_rejected",
    "remote_required_refused",
    "remote_failure",
    "no_remote_summary",
    "unknown_probe",
    "",
];

type ValidationSignature = (
    u32,
    String,
    u32,
    bool,
    String,
    String,
    Vec<(String, String)>,
);
const BLOCKER_REASONS: [&str; 6] = [
    "critical_pressure",
    "telemetry_gap",
    "unreachable_workers",
    "unhealthy_workers",
    "other_reason",
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

    fn choose<'b>(&mut self, values: &'b [&str]) -> &'b str {
        values[usize::from(self.next_u8()) % values.len()]
    }

    fn bounded_count(&mut self) -> u64 {
        match self.next_u8() % 8 {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 7,
            4 => 10,
            5 => u64::from(self.next_u32() % 64),
            6 => u64::MAX,
            _ => self.next_u64() % 1_024,
        }
    }

    fn short_string(&mut self, prefix: &str) -> String {
        if self.next_u8().is_multiple_of(19) {
            return String::new();
        }

        let len = usize::from(self.next_u8() % 24);
        let mut value = String::from(prefix);
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
                12 => '/',
                13 => ':',
                14 => '.',
                15 => ' ',
                16 => '"',
                _ => 'z',
            };
            value.push(ch);
        }
        value
    }

    fn string_vec(&mut self, candidates: &[&str]) -> Vec<String> {
        let count = usize::from(self.next_u8() % 5);
        (0..count)
            .map(|_| {
                if self.next_bool() {
                    self.choose(candidates).to_owned()
                } else {
                    self.short_string("reason_")
                }
            })
            .collect()
    }

    fn json_value(&mut self, depth: u8) -> Value {
        if depth == 0 {
            return self.scalar_json_value();
        }

        match self.next_u8() % 6 {
            0 => Value::Null,
            1 => Value::Bool(self.next_bool()),
            2 => Value::Number(serde_json::Number::from(self.bounded_count())),
            3 => Value::String(self.short_string("value_")),
            4 => {
                let count = usize::from(self.next_u8() % 4);
                Value::Array((0..count).map(|_| self.json_value(depth - 1)).collect())
            }
            _ => {
                let count = usize::from(self.next_u8() % 4);
                let mut map = Map::new();
                for _ in 0..count {
                    map.insert(self.short_string("key_"), self.json_value(depth - 1));
                }
                Value::Object(map)
            }
        }
    }

    fn scalar_json_value(&mut self) -> Value {
        match self.next_u8() % 4 {
            0 => Value::Null,
            1 => Value::Bool(self.next_bool()),
            2 => Value::Number(serde_json::Number::from(self.bounded_count())),
            _ => Value::String(self.short_string("value_")),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let lossy = String::from_utf8_lossy(data);
    if let Ok(report) = serde_json::from_str::<RchCapacityPreflightReport>(&lossy) {
        exercise_report(&report);
    }

    let mut cursor = ByteCursor::new(data);
    for report in generated_reports(&mut cursor) {
        exercise_generated_report(&report);
    }
});

fn exercise_generated_report(report: &RchCapacityPreflightReport) {
    let encoded = serde_json::to_string(report).expect("generated reports must serialize");
    let decoded: RchCapacityPreflightReport =
        serde_json::from_str(&encoded).expect("generated reports must round-trip through JSON");
    assert_eq!(
        decoded, *report,
        "generated reports must preserve every field through JSON"
    );

    let validation = exercise_report(&decoded);
    if validation.valid {
        assert!(
            validation.diagnostics.is_empty(),
            "valid generated reports must not carry diagnostics"
        );
    } else {
        let repeated = validate_rch_capacity_preflight_report(&decoded, "generated.json");
        assert_eq!(
            diagnostic_codes(&validation),
            diagnostic_codes(&repeated),
            "invalid generated reports must produce deterministic diagnostic code sets"
        );
    }
}

fn exercise_report(
    report: &RchCapacityPreflightReport,
) -> ffs_harness::rch_capacity_preflight::RchCapacityPreflightValidationReport {
    let first = validate_rch_capacity_preflight_report(report, "fuzz_input.json");
    let second = validate_rch_capacity_preflight_report(report, "fuzz_input.json");
    assert_eq!(
        validation_signature(&first),
        validation_signature(&second),
        "RCH capacity preflight validation must be deterministic"
    );

    let markdown = render_rch_capacity_preflight_markdown(&first);
    assert!(
        markdown.contains("# RCH Capacity Preflight Validation"),
        "markdown renderer must preserve the report heading"
    );

    assert_eq!(
        fail_on_rch_capacity_preflight_errors(&first).is_ok(),
        first.valid,
        "fail_on_rch_capacity_preflight_errors must agree with validation.valid"
    );

    first
}

fn validation_signature(
    report: &ffs_harness::rch_capacity_preflight::RchCapacityPreflightValidationReport,
) -> ValidationSignature {
    (
        report.schema_version,
        report.report_path.clone(),
        report.report_schema_version,
        report.valid,
        report.capacity_verdict.clone(),
        report.probe_verdict.clone(),
        report
            .diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.severity.clone(), diagnostic.code.clone()))
            .collect(),
    )
}

fn diagnostic_codes(
    report: &ffs_harness::rch_capacity_preflight::RchCapacityPreflightValidationReport,
) -> BTreeSet<String> {
    report
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.clone())
        .collect()
}

fn generated_reports(cursor: &mut ByteCursor<'_>) -> Vec<RchCapacityPreflightReport> {
    vec![
        valid_no_admissible_workers_report(),
        valid_remote_success_report(),
        valid_status_capture_failed_report(),
        arbitrary_report(cursor),
    ]
}

fn arbitrary_report(cursor: &mut ByteCursor<'_>) -> RchCapacityPreflightReport {
    let workers_total = cursor.bounded_count();
    let workers_healthy = match cursor.next_u8() % 4 {
        0 => workers_total,
        1 => workers_total.saturating_add(1),
        2 => cursor.bounded_count(),
        _ => workers_total.saturating_sub(u64::from(cursor.next_u8())),
    };
    let requested = cursor.next_bool();

    RchCapacityPreflightReport {
        schema_version: if cursor.next_bool() {
            RCH_CAPACITY_PREFLIGHT_SCHEMA_VERSION
        } else {
            cursor.next_u32() % 5
        },
        capacity_verdict: cursor.choose(&CAPACITY_VERDICTS).to_owned(),
        status_capture: RchCapacityStatusCapture {
            exit_code: match cursor.next_u8() % 5 {
                0 => 0,
                1 => 1,
                2 => -1,
                3 => 127,
                _ => cursor.next_i32(),
            },
            success: match cursor.next_u8() % 3 {
                0 => None,
                1 => Some(true),
                _ => Some(false),
            },
        },
        daemon: RchCapacityDaemonSummary {
            workers_total,
            workers_healthy,
            slots_total: optional_count(cursor),
            slots_available: optional_count(cursor),
        },
        worker_counts: RchCapacityWorkerCounts {
            admissible: cursor.bounded_count(),
            critical_pressure: cursor.bounded_count(),
            telemetry_gap: cursor.bounded_count(),
            telemetry_stale: cursor.bounded_count(),
            unhealthy: cursor.bounded_count(),
            unreachable: cursor.bounded_count(),
        },
        blocker_reasons: cursor.string_vec(&BLOCKER_REASONS),
        operator_actions: generated_operator_actions(cursor),
        probe: RchCapacityProbeReport {
            requested,
            command: generated_probe_command(cursor),
            exit_code: if cursor.next_bool() {
                Some(cursor.next_i32())
            } else {
                None
            },
            verdict: cursor.choose(&PROBE_VERDICTS).to_owned(),
            fail_closed: cursor.next_bool(),
            raw_log: cursor.short_string("artifacts/e2e/rch_capacity_probe_"),
        },
    }
}

fn optional_count(cursor: &mut ByteCursor<'_>) -> Option<u64> {
    if cursor.next_bool() {
        Some(cursor.bounded_count())
    } else {
        None
    }
}

fn generated_operator_actions(cursor: &mut ByteCursor<'_>) -> Vec<Value> {
    let count = usize::from(cursor.next_u8() % 4);
    (0..count).map(|_| cursor.json_value(3)).collect()
}

fn generated_probe_command(cursor: &mut ByteCursor<'_>) -> Vec<String> {
    match cursor.next_u8() % 5 {
        0 => EXPECTED_PROBE_COMMAND
            .iter()
            .map(ToString::to_string)
            .collect(),
        1 => Vec::new(),
        2 => vec!["cargo".to_owned(), "test".to_owned()],
        3 => EXPECTED_PROBE_COMMAND
            .iter()
            .rev()
            .map(ToString::to_string)
            .collect(),
        _ => (0..usize::from(cursor.next_u8() % 6))
            .map(|_| cursor.short_string("cmd_"))
            .collect(),
    }
}

fn valid_no_admissible_workers_report() -> RchCapacityPreflightReport {
    RchCapacityPreflightReport {
        schema_version: RCH_CAPACITY_PREFLIGHT_SCHEMA_VERSION,
        capacity_verdict: "no_admissible_workers".to_owned(),
        status_capture: RchCapacityStatusCapture {
            exit_code: 0,
            success: Some(true),
        },
        daemon: RchCapacityDaemonSummary {
            workers_total: 10,
            workers_healthy: 7,
            slots_total: Some(134),
            slots_available: Some(134),
        },
        worker_counts: RchCapacityWorkerCounts {
            admissible: 0,
            critical_pressure: 7,
            telemetry_gap: 3,
            telemetry_stale: 3,
            unhealthy: 3,
            unreachable: 2,
        },
        blocker_reasons: vec![
            "critical_pressure".to_owned(),
            "telemetry_gap".to_owned(),
            "unreachable_workers".to_owned(),
            "unhealthy_workers".to_owned(),
        ],
        operator_actions: vec![serde_json::json!({
            "source": "remediation_hints",
            "message": "worker under critical pressure",
        })],
        probe: RchCapacityProbeReport {
            requested: true,
            command: EXPECTED_PROBE_COMMAND
                .iter()
                .map(ToString::to_string)
                .collect(),
            exit_code: Some(1),
            verdict: "local_fallback_rejected".to_owned(),
            fail_closed: true,
            raw_log: "artifacts/e2e/rch_capacity_probe.raw".to_owned(),
        },
    }
}

fn valid_remote_success_report() -> RchCapacityPreflightReport {
    let mut report = valid_no_admissible_workers_report();
    report.capacity_verdict = "admissible_capacity_available".to_owned();
    report.worker_counts.admissible = 2;
    report.worker_counts.critical_pressure = 0;
    report.worker_counts.telemetry_gap = 0;
    report.worker_counts.telemetry_stale = 0;
    report.worker_counts.unhealthy = 0;
    report.worker_counts.unreachable = 0;
    report.blocker_reasons.clear();
    report.operator_actions.clear();
    report.probe.exit_code = Some(0);
    report.probe.verdict = "remote_success".to_owned();
    report.probe.fail_closed = false;
    report
}

fn valid_status_capture_failed_report() -> RchCapacityPreflightReport {
    let mut report = valid_no_admissible_workers_report();
    report.capacity_verdict = "status_capture_failed".to_owned();
    report.status_capture.exit_code = 127;
    report.status_capture.success = Some(false);
    report.probe.requested = false;
    report.probe.command.clear();
    report.probe.exit_code = None;
    report.probe.verdict = "not_run".to_owned();
    report.probe.fail_closed = false;
    report.probe.raw_log.clear();
    report
}
