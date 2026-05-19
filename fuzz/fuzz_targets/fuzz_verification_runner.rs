#![no_main]

use ffs_harness::artifact_manifest::{is_valid_scenario_id, ScenarioResult};
use ffs_harness::verification_runner::{
    check_script_conformance, parse_e2e_output, ConformanceViolation, ParsedScenario,
};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

const MAX_INPUT_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy)]
struct ScriptFlags {
    lib_source: bool,
    e2e_init: bool,
    scenario_marker: bool,
    legacy_status: bool,
    strict_mode: bool,
    summary_exit: bool,
}

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

    fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 == 1
    }

    fn valid_id(&mut self) -> String {
        format!(
            "{}_{}_{}",
            self.segment("scenario"),
            self.segment("case"),
            self.segment("run")
        )
    }

    fn segment(&mut self, fallback: &str) -> String {
        let len = 1 + usize::from(self.next_u8() % 10);
        let mut value = String::with_capacity(len);
        for _ in 0..len {
            let ch = match self.next_u8() % 36 {
                0..=25 => char::from(b'a' + (self.data_byte() % 26)),
                _ => char::from(b'0' + (self.data_byte() % 10)),
            };
            value.push(ch);
        }
        if value.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
            fallback.to_owned()
        } else {
            value
        }
    }

    fn data_byte(&mut self) -> u8 {
        self.next_u8()
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let lossy = String::from_utf8_lossy(data);
    exercise_e2e_output(&lossy);
    exercise_script_source(&lossy);

    let mut cursor = ByteCursor::new(data);
    let generated_output = generated_e2e_output(&mut cursor);
    exercise_e2e_output(&generated_output);

    for flags in generated_script_matrix(&mut cursor) {
        let script = script_from_flags(flags);
        exercise_script_source(&script);
        assert_expected_script_violations(flags, &script);
    }
});

fn exercise_e2e_output(output: &str) {
    let first = parse_e2e_output(output);
    let second = parse_e2e_output(output);
    assert_eq!(
        scenario_signature(&first),
        scenario_signature(&second),
        "verification runner output parsing must be deterministic"
    );

    let mut last_line = 0usize;
    for scenario in &first {
        assert!(
            is_valid_scenario_id(&scenario.scenario_id),
            "parsed scenario ids must follow the shared E2E log contract"
        );
        assert!(
            matches!(
                scenario.outcome,
                ScenarioResult::Pass | ScenarioResult::Fail
            ),
            "parsed scenario outcomes must stay in the PASS/FAIL vocabulary"
        );
        assert_ne!(
            scenario.line_number, 0,
            "parsed scenario line numbers are 1-based"
        );
        assert!(
            scenario.line_number > last_line,
            "parsed scenario line numbers must be monotonic by appearance"
        );
        last_line = scenario.line_number;
    }

    assert_malformed_core_fields_are_rejected(output, &first);
}

fn scenario_signature(
    scenarios: &[ParsedScenario],
) -> Vec<(String, &'static str, Option<String>, usize)> {
    scenarios
        .iter()
        .map(|scenario| {
            (
                scenario.scenario_id.clone(),
                match scenario.outcome {
                    ScenarioResult::Pass => "PASS",
                    ScenarioResult::Fail => "FAIL",
                    ScenarioResult::Skip => "SKIP",
                },
                scenario.detail.clone(),
                scenario.line_number,
            )
        })
        .collect()
}

fn assert_malformed_core_fields_are_rejected(output: &str, scenarios: &[ParsedScenario]) {
    let parsed_lines: BTreeSet<usize> = scenarios
        .iter()
        .map(|scenario| scenario.line_number)
        .collect();

    for (idx, line) in output.lines().enumerate() {
        let line_number = idx + 1;
        if duplicate_core_marker(line) || legacy_status_without_outcome(line) {
            assert!(
                !parsed_lines.contains(&line_number),
                "malformed or legacy-core markers must not parse as valid scenarios: {line}"
            );
        }
    }
}

fn duplicate_core_marker(line: &str) -> bool {
    if !line.starts_with("SCENARIO_RESULT|") {
        return false;
    }

    let mut scenario_id_count = 0usize;
    let mut outcome_count = 0usize;
    for part in line.split('|').skip(1) {
        if part.starts_with("scenario_id=") {
            scenario_id_count += 1;
        } else if part.starts_with("outcome=") {
            outcome_count += 1;
        }
    }
    scenario_id_count > 1 || outcome_count > 1
}

fn legacy_status_without_outcome(line: &str) -> bool {
    line.starts_with("SCENARIO_RESULT|") && line.contains("|status=") && !line.contains("|outcome=")
}

fn exercise_script_source(script_source: &str) {
    let first = conformance_signature(script_source);
    let second = conformance_signature(script_source);
    assert_eq!(
        first, second,
        "verification runner script conformance must be deterministic"
    );
}

fn conformance_signature(script_source: &str) -> Vec<&'static str> {
    check_script_conformance(script_source)
        .iter()
        .map(violation_token)
        .collect()
}

fn assert_expected_script_violations(flags: ScriptFlags, script_source: &str) {
    let observed: BTreeSet<&'static str> =
        conformance_signature(script_source).into_iter().collect();
    let mut expected = BTreeSet::new();

    if !flags.lib_source {
        expected.insert("missing_lib_source");
    }
    if !flags.e2e_init {
        expected.insert("missing_e2e_init");
    }
    if !flags.scenario_marker && !flags.legacy_status {
        expected.insert("no_scenario_markers");
    }
    if flags.legacy_status {
        expected.insert("legacy_status_field");
    }
    if !flags.strict_mode {
        expected.insert("missing_strict_mode");
    }
    if !flags.summary_exit {
        expected.insert("missing_summary_exit");
    }

    assert_eq!(
        observed, expected,
        "generated script conformance classification drifted"
    );
}

fn violation_token(violation: &ConformanceViolation) -> &'static str {
    match violation {
        ConformanceViolation::MissingLibSource => "missing_lib_source",
        ConformanceViolation::MissingE2eInit => "missing_e2e_init",
        ConformanceViolation::NoScenarioMarkers => "no_scenario_markers",
        ConformanceViolation::LegacyStatusField => "legacy_status_field",
        ConformanceViolation::MissingStrictMode => "missing_strict_mode",
        ConformanceViolation::MissingSummaryExit => "missing_summary_exit",
    }
}

fn generated_e2e_output(cursor: &mut ByteCursor<'_>) -> String {
    let line_count = 1 + usize::from(cursor.next_u8() % 16);
    let mut output = String::new();
    for _ in 0..line_count {
        let id = cursor.valid_id();
        let line = match cursor.next_u8() % 10 {
            0 => format!("SCENARIO_RESULT|scenario_id={id}|outcome=PASS"),
            1 => format!("SCENARIO_RESULT|scenario_id={id}|outcome=FAIL|detail=generated"),
            2 => format!("SCENARIO_RESULT|scenario_id={id}|scenario_id={id}|outcome=PASS"),
            3 => format!("SCENARIO_RESULT|scenario_id={id}|outcome=PASS|outcome=FAIL"),
            4 => format!("SCENARIO_RESULT|scenario_id={id}|status=PASS"),
            5 => "SCENARIO_RESULT|scenario_id=bad-id|outcome=PASS".to_owned(),
            6 => format!("SCENARIO_RESULT|scenario_id={id}|outcome=MAYBE"),
            7 => format!("SCENARIO_RESULT|scenario_id={id}|detail=not_last|outcome=PASS"),
            8 => format!("SCENARIO_RESULT|scenario_id={id}|worker=ts2|outcome=PASS"),
            _ => format!("noise={id}|outcome=PASS"),
        };
        output.push_str(&line);
        output.push('\n');
    }
    output
}

fn generated_script_matrix(cursor: &mut ByteCursor<'_>) -> Vec<ScriptFlags> {
    let generated = ScriptFlags {
        lib_source: cursor.next_bool(),
        e2e_init: cursor.next_bool(),
        scenario_marker: cursor.next_bool(),
        legacy_status: cursor.next_bool(),
        strict_mode: cursor.next_bool(),
        summary_exit: cursor.next_bool(),
    };

    vec![
        generated,
        ScriptFlags {
            lib_source: true,
            e2e_init: true,
            scenario_marker: true,
            legacy_status: false,
            strict_mode: true,
            summary_exit: true,
        },
        ScriptFlags {
            lib_source: false,
            e2e_init: false,
            scenario_marker: false,
            legacy_status: true,
            strict_mode: false,
            summary_exit: false,
        },
    ]
}

fn script_from_flags(flags: ScriptFlags) -> String {
    let mut script = String::from("#!/usr/bin/env bash\n");
    if flags.strict_mode {
        script.push_str("set -euo pipefail\n");
    } else {
        script.push_str("set -eu\n");
    }
    if flags.lib_source {
        script.push_str("source \"$REPO_ROOT/scripts/e2e/lib.sh\"\n");
    }
    if flags.e2e_init {
        script.push_str("e2e_init \"fuzz_verification_runner\"\n");
    }
    if flags.scenario_marker {
        script.push_str(
            "scenario_result \"verification_runner_valid_case\" \"PASS\" \"generated\"\n",
        );
    }
    if flags.legacy_status {
        script.push_str(
            "echo 'SCENARIO_RESULT|scenario_id=verification_runner_legacy_case|status=PASS'\n",
        );
    }
    if flags.summary_exit {
        script.push_str("if [[ ${FAIL_COUNT:-0} -ne 0 ]]; then exit 1; fi\n");
    }
    script
}
