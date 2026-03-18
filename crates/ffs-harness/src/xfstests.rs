use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum XfstestsStatus {
    Passed,
    Failed,
    Skipped,
    NotRun,
    Planned,
}

impl XfstestsStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
            Self::NotRun => "not_run",
            Self::Planned => "planned",
        }
    }

    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::NotRun | Self::Planned => 1,
            Self::Skipped => 2,
            Self::Passed => 3,
            Self::Failed => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XfstestsCase {
    pub id: String,
    pub status: XfstestsStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_snippet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowlist_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub comparison: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XfstestsRun {
    pub source: String,
    pub check_rc: i32,
    pub dry_run: bool,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub not_run: usize,
    pub planned: usize,
    pub pass_rate: f64,
    pub tests: Vec<XfstestsCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XfstestsAllowlistEntry {
    pub test_id: String,
    pub failure_reason: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XfstestsBaselineEntry {
    pub test_id: String,
    pub expected_status: XfstestsStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct XfstestsComparison {
    pub regressions: Vec<String>,
    pub improvements: Vec<String>,
    pub unchanged: Vec<String>,
}

pub fn load_selected_tests(path: &Path) -> Result<Vec<String>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read selected tests {}", path.display()))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

pub fn load_allowlist(path: &Path) -> Result<Vec<XfstestsAllowlistEntry>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read allowlist {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid allowlist json {}", path.display()))
}

pub fn load_baseline(path: &Path) -> Result<Vec<XfstestsBaselineEntry>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read baseline {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("invalid baseline json {}", path.display()))
}

pub fn parse_check_output(
    selected: &[String],
    check_log: &str,
    check_rc: i32,
    dry_run: bool,
) -> XfstestsRun {
    let mut cases: Vec<XfstestsCase> = selected
        .iter()
        .map(|id| XfstestsCase {
            id: id.clone(),
            status: XfstestsStatus::NotRun,
            duration_secs: None,
            output_snippet: None,
            allowlist_status: None,
            failure_reason: None,
            comparison: Vec::new(),
        })
        .collect();

    let selected_ids: BTreeSet<&str> = selected.iter().map(String::as_str).collect();

    for line in check_log.lines() {
        let lower = line.to_ascii_lowercase();
        for case in &mut cases {
            if !selected_ids.contains(case.id.as_str()) || !line.contains(case.id.as_str()) {
                continue;
            }

            let candidate = if lower.contains("not run")
                || lower.contains("notrun")
                || lower.contains("skipped")
            {
                Some(XfstestsStatus::Skipped)
            } else if contains_word(&lower, "fail")
                || contains_word(&lower, "failed")
                || contains_word(&lower, "error")
            {
                Some(XfstestsStatus::Failed)
            } else if contains_word(&lower, "pass")
                || contains_word(&lower, "passed")
                || contains_word(&lower, "ok")
                || contains_word(&lower, "success")
            {
                Some(XfstestsStatus::Passed)
            } else {
                None
            };

            if let Some(next) = candidate {
                if next.rank() >= case.status.rank() {
                    case.status = next;
                    case.output_snippet = Some(line.trim().to_owned());
                }
                if case.duration_secs.is_none() {
                    case.duration_secs = parse_duration_secs(line);
                }
            }
        }
    }

    if check_rc == 0 && !dry_run {
        for case in &mut cases {
            if case.status == XfstestsStatus::NotRun {
                case.status = XfstestsStatus::Passed;
            }
        }
    }

    summarize_run("check-log", check_rc, dry_run, cases)
}

#[must_use]
pub fn summarize_uniform(
    selected: &[String],
    status: XfstestsStatus,
    note: Option<&str>,
) -> XfstestsRun {
    let cases = selected
        .iter()
        .map(|id| XfstestsCase {
            id: id.clone(),
            status,
            duration_secs: None,
            output_snippet: note.map(ToOwned::to_owned),
            allowlist_status: None,
            failure_reason: None,
            comparison: Vec::new(),
        })
        .collect();
    summarize_run("uniform", 0, false, cases)
}

pub fn apply_allowlist(run: &mut XfstestsRun, allowlist: &[XfstestsAllowlistEntry]) {
    let by_test: BTreeMap<&str, &XfstestsAllowlistEntry> = allowlist
        .iter()
        .map(|entry| (entry.test_id.as_str(), entry))
        .collect();
    for case in &mut run.tests {
        if let Some(entry) = by_test.get(case.id.as_str()) {
            case.allowlist_status = Some(entry.status.clone());
            case.failure_reason = Some(entry.failure_reason.clone());
        }
    }
}

pub fn compare_against_baseline(
    run: &mut XfstestsRun,
    baseline: &[XfstestsBaselineEntry],
) -> XfstestsComparison {
    let baseline_map: BTreeMap<&str, XfstestsStatus> = baseline
        .iter()
        .map(|entry| (entry.test_id.as_str(), entry.expected_status))
        .collect();
    let mut comparison = XfstestsComparison::default();

    for case in &mut run.tests {
        let Some(expected) = baseline_map.get(case.id.as_str()).copied() else {
            continue;
        };

        if expected == case.status {
            comparison.unchanged.push(case.id.clone());
            case.comparison
                .push(format!("baseline match: {}", expected.as_str()));
            continue;
        }

        let message = format!("{} -> {}", expected.as_str(), case.status.as_str());
        match (expected, case.status) {
            (
                XfstestsStatus::Passed,
                XfstestsStatus::Failed | XfstestsStatus::Skipped | XfstestsStatus::NotRun,
            ) => {
                comparison
                    .regressions
                    .push(format!("{} ({message})", case.id));
                case.comparison.push(format!("regression: {message}"));
            }
            (
                XfstestsStatus::Failed | XfstestsStatus::Skipped | XfstestsStatus::NotRun,
                XfstestsStatus::Passed,
            ) => {
                comparison
                    .improvements
                    .push(format!("{} ({message})", case.id));
                case.comparison.push(format!("improvement: {message}"));
            }
            _ => {
                comparison.unchanged.push(case.id.clone());
                case.comparison.push(format!("status drift: {message}"));
            }
        }
    }

    comparison
}

pub fn write_junit_xml(path: &Path, run: &XfstestsRun) -> Result<()> {
    let failures = run.failed;
    let skipped = run.skipped + run.not_run + run.planned;
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(
        xml,
        "<testsuite name=\"ffs_xfstests_e2e\" tests=\"{}\" failures=\"{}\" skipped=\"{}\">",
        run.total, failures, skipped
    );

    for case in &run.tests {
        let _ = write!(
            xml,
            "  <testcase name=\"{}\" time=\"{:.3}\">",
            escape_xml(&case.id),
            case.duration_secs.unwrap_or(0.0)
        );
        match case.status {
            XfstestsStatus::Failed => {
                let detail = case
                    .output_snippet
                    .as_deref()
                    .or(case.failure_reason.as_deref())
                    .unwrap_or("xfstests failure");
                let detail = escape_xml(detail);
                let _ = write!(
                    xml,
                    "<failure message=\"xfstests failure\">{detail}</failure>"
                );
            }
            XfstestsStatus::Skipped | XfstestsStatus::NotRun | XfstestsStatus::Planned => {
                let detail = escape_xml(case.status.as_str());
                let _ = write!(xml, "<skipped message=\"{detail}\"/>");
            }
            XfstestsStatus::Passed => {}
        }
        xml.push_str("</testcase>\n");
    }
    xml.push_str("</testsuite>\n");
    fs::write(path, xml).with_context(|| format!("failed to write junit xml {}", path.display()))
}

fn summarize_run(
    source: &str,
    check_rc: i32,
    dry_run: bool,
    tests: Vec<XfstestsCase>,
) -> XfstestsRun {
    let mut passed = 0_usize;
    let mut failed = 0_usize;
    let mut skipped = 0_usize;
    let mut not_run = 0_usize;
    let mut planned = 0_usize;

    for case in &tests {
        match case.status {
            XfstestsStatus::Passed => passed += 1,
            XfstestsStatus::Failed => failed += 1,
            XfstestsStatus::Skipped => skipped += 1,
            XfstestsStatus::NotRun => not_run += 1,
            XfstestsStatus::Planned => planned += 1,
        }
    }

    let total = tests.len();
    let pass_rate = if total == 0 {
        0.0
    } else {
        passed as f64 / total as f64
    };

    XfstestsRun {
        source: source.to_owned(),
        check_rc,
        dry_run,
        total,
        passed,
        failed,
        skipped,
        not_run,
        planned,
        pass_rate,
        tests,
    }
}

fn contains_word(haystack: &str, needle: &str) -> bool {
    haystack
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '/')
        .any(|part| part == needle)
}

fn parse_duration_secs(line: &str) -> Option<f64> {
    for token in line.split_whitespace() {
        if let Some(raw) = token.strip_suffix('s') {
            if let Ok(value) = raw.parse::<f64>() {
                return Some(value);
            }
        }
    }
    None
}

fn escape_xml(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_check_output_classifies_statuses_and_duration() {
        let selected = vec![
            "generic/001".to_owned(),
            "ext4/003".to_owned(),
            "generic/030".to_owned(),
        ];
        let log = "\
generic/001  1s ... pass\n\
ext4/003  2.5s ... failed due to mismatch\n\
generic/030  skipped: needs root\n";

        let run = parse_check_output(&selected, log, 1, false);

        assert_eq!(run.passed, 1);
        assert_eq!(run.failed, 1);
        assert_eq!(run.skipped, 1);
        assert_eq!(run.not_run, 0);
        assert_eq!(run.tests[0].duration_secs, Some(1.0));
        assert_eq!(run.tests[1].duration_secs, Some(2.5));
        assert_eq!(run.tests[0].status, XfstestsStatus::Passed);
        assert_eq!(run.tests[1].status, XfstestsStatus::Failed);
        assert_eq!(run.tests[2].status, XfstestsStatus::Skipped);
    }

    #[test]
    fn parse_check_output_promotes_not_run_to_passed_on_clean_non_dry_run() {
        let selected = vec!["generic/001".to_owned()];
        let run = parse_check_output(&selected, "", 0, false);
        assert_eq!(run.tests[0].status, XfstestsStatus::Passed);
        assert_eq!(run.passed, 1);
    }

    #[test]
    fn allowlist_annotations_are_applied() {
        let selected = vec!["generic/001".to_owned()];
        let mut run = summarize_uniform(&selected, XfstestsStatus::Failed, Some("boom"));
        let allowlist = vec![XfstestsAllowlistEntry {
            test_id: "generic/001".to_owned(),
            failure_reason: "requires unsupported ioctl".to_owned(),
            status: "known_fail".to_owned(),
        }];

        apply_allowlist(&mut run, &allowlist);

        assert_eq!(run.tests[0].allowlist_status.as_deref(), Some("known_fail"));
        assert_eq!(
            run.tests[0].failure_reason.as_deref(),
            Some("requires unsupported ioctl")
        );
    }

    #[test]
    fn baseline_comparison_detects_regressions_and_improvements() {
        let selected = vec!["generic/001".to_owned(), "generic/013".to_owned()];
        let mut run = XfstestsRun {
            source: "check-log".to_owned(),
            check_rc: 1,
            dry_run: false,
            total: 2,
            passed: 1,
            failed: 1,
            skipped: 0,
            not_run: 0,
            planned: 0,
            pass_rate: 0.5,
            tests: vec![
                XfstestsCase {
                    id: "generic/001".to_owned(),
                    status: XfstestsStatus::Failed,
                    duration_secs: None,
                    output_snippet: None,
                    allowlist_status: None,
                    failure_reason: None,
                    comparison: Vec::new(),
                },
                XfstestsCase {
                    id: "generic/013".to_owned(),
                    status: XfstestsStatus::Passed,
                    duration_secs: None,
                    output_snippet: None,
                    allowlist_status: None,
                    failure_reason: None,
                    comparison: Vec::new(),
                },
            ],
        };
        let baseline = vec![
            XfstestsBaselineEntry {
                test_id: "generic/001".to_owned(),
                expected_status: XfstestsStatus::Passed,
            },
            XfstestsBaselineEntry {
                test_id: "generic/013".to_owned(),
                expected_status: XfstestsStatus::Failed,
            },
        ];

        let comparison = compare_against_baseline(&mut run, &baseline);

        assert_eq!(
            comparison.regressions,
            vec!["generic/001 (passed -> failed)"]
        );
        assert_eq!(
            comparison.improvements,
            vec!["generic/013 (failed -> passed)"]
        );
        assert!(run.tests[0].comparison[0].contains("regression"));
        assert!(run.tests[1].comparison[0].contains("improvement"));
        let _ = selected;
    }
}
