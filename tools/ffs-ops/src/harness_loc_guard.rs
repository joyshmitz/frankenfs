#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use serde_json::json;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const HARNESS_SRC_PREFIX: &str = "crates/ffs-harness/";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModuleClassification {
    Conformance,
    Meta,
}

#[derive(Debug)]
pub struct HarnessLocGuardConfig {
    pub workspace_root: PathBuf,
    pub census_path: PathBuf,
    pub base_ref: String,
    pub head_ref: String,
}

#[derive(Debug)]
pub struct ModuleChange {
    pub path: String,
    pub classification: ModuleClassification,
    pub added_loc: isize,
    pub removed_loc: isize,
    pub base_conformance_tests: usize,
    pub head_conformance_tests: usize,
    pub classified_by_census: bool,
}

#[derive(Debug)]
pub struct HarnessLocGuardReport {
    pub base_ref: String,
    pub head_ref: String,
    pub changed_module_count: usize,
    pub meta_loc_growth: isize,
    pub conformance_loc_growth: isize,
    pub conformance_test_growth: isize,
    pub allowance: isize,
    pub warning: bool,
    pub warning_message: Option<String>,
    pub unclassified_modules: Vec<String>,
}

impl ModuleChange {
    fn net_loc(&self) -> isize {
        self.added_loc - self.removed_loc
    }

    fn conformance_test_delta(&self) -> isize {
        usize_delta(self.head_conformance_tests, self.base_conformance_tests)
    }
}

pub fn run_harness_loc_guard(config: &HarnessLocGuardConfig) -> Result<HarnessLocGuardReport> {
    let classifications = load_census_classifications(&config.census_path)?;
    let diff = run_git(
        &config.workspace_root,
        &[
            "diff",
            "--numstat",
            &format!("{}...{}", config.base_ref, config.head_ref),
            "--",
            "crates/ffs-harness/src/*.rs",
        ],
    )?;
    let changes = parse_numstat(&diff)
        .into_iter()
        .map(|delta| {
            let module_path = delta
                .path
                .strip_prefix(HARNESS_SRC_PREFIX)
                .with_context(|| format!("unexpected harness path {}", delta.path))?
                .to_owned();
            let (classification, classified_by_census) = classifications
                .get(&module_path)
                .copied()
                .map_or((ModuleClassification::Meta, false), |classification| {
                    (classification, true)
                });
            let (base_tests, head_tests) = if classification == ModuleClassification::Conformance {
                (
                    conformance_test_count_at_ref(
                        &config.workspace_root,
                        &config.base_ref,
                        &delta.path,
                    ),
                    conformance_test_count_at_ref(
                        &config.workspace_root,
                        &config.head_ref,
                        &delta.path,
                    ),
                )
            } else {
                (0, 0)
            };
            Ok(ModuleChange {
                path: module_path,
                classification,
                added_loc: delta.added_loc,
                removed_loc: delta.removed_loc,
                base_conformance_tests: base_tests,
                head_conformance_tests: head_tests,
                classified_by_census,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(evaluate_harness_loc_growth(
        &config.base_ref,
        &config.head_ref,
        &changes,
    ))
}

pub fn evaluate_harness_loc_growth(
    base_ref: &str,
    head_ref: &str,
    changes: &[ModuleChange],
) -> HarnessLocGuardReport {
    let mut meta_net = 0isize;
    let mut conformance_net = 0isize;
    let mut conformance_test_net = 0isize;
    let mut unclassified_modules = Vec::new();

    for change in changes {
        match change.classification {
            ModuleClassification::Conformance => {
                conformance_net += change.net_loc();
                conformance_test_net += change.conformance_test_delta();
            }
            ModuleClassification::Meta => meta_net += change.net_loc(),
        }
        if !change.classified_by_census {
            unclassified_modules.push(change.path.clone());
        }
    }

    let meta_loc_growth = meta_net.max(0);
    let conformance_loc_growth = conformance_net.max(0);
    let conformance_test_growth = conformance_test_net.max(0);
    let allowance = conformance_loc_growth + conformance_test_growth;
    let warning = meta_loc_growth > allowance;
    let warning_message = warning.then(|| {
        format!(
            "ffs-harness meta LOC growth ({meta_loc_growth}) exceeds conformance LOC/test growth allowance ({allowance})"
        )
    });

    HarnessLocGuardReport {
        base_ref: base_ref.to_owned(),
        head_ref: head_ref.to_owned(),
        changed_module_count: changes.len(),
        meta_loc_growth,
        conformance_loc_growth,
        conformance_test_growth,
        allowance,
        warning,
        warning_message,
        unclassified_modules,
    }
}

pub fn render_harness_loc_guard_json(report: &HarnessLocGuardReport) -> Result<String> {
    Ok(serde_json::to_string_pretty(&json!({
        "base_ref": &report.base_ref,
        "head_ref": &report.head_ref,
        "changed_module_count": report.changed_module_count,
        "meta_loc_growth": report.meta_loc_growth,
        "conformance_loc_growth": report.conformance_loc_growth,
        "conformance_test_growth": report.conformance_test_growth,
        "allowance": report.allowance,
        "warning": report.warning,
        "warning_message": &report.warning_message,
        "unclassified_modules": &report.unclassified_modules,
    }))?)
}

pub fn render_harness_loc_guard_text(report: &HarnessLocGuardReport) -> String {
    let status = if report.warning { "warning" } else { "ok" };
    let mut out = format!(
        "harness LOC growth guard: status={status} base={} head={} changed_modules={} meta_loc_growth={} conformance_loc_growth={} conformance_test_growth={} allowance={}",
        report.base_ref,
        report.head_ref,
        report.changed_module_count,
        report.meta_loc_growth,
        report.conformance_loc_growth,
        report.conformance_test_growth,
        report.allowance
    );
    if let Some(message) = &report.warning_message {
        write!(&mut out, "\n{message}").expect("writing to a String cannot fail");
    }
    if !report.unclassified_modules.is_empty() {
        write!(
            &mut out,
            "\nunclassified_modules={}",
            report.unclassified_modules.join(",")
        )
        .expect("writing to a String cannot fail");
    }
    out
}

pub fn render_harness_loc_guard_github(report: &HarnessLocGuardReport) -> String {
    if report.warning {
        format!(
            "::warning title=ffs-harness meta LOC growth::{}\n{}",
            report.warning_message.as_deref().unwrap_or("guard warning"),
            render_harness_loc_guard_text(report)
        )
    } else {
        render_harness_loc_guard_text(report)
    }
}

fn load_census_classifications(path: &Path) -> Result<BTreeMap<String, ModuleClassification>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let modules = value
        .get("modules")
        .and_then(serde_json::Value::as_array)
        .context("module census is missing `modules` array")?;
    let mut classifications = BTreeMap::new();
    for module in modules {
        let path = module
            .get("path")
            .and_then(serde_json::Value::as_str)
            .context("module census row is missing path")?;
        let classification = match module
            .get("classification")
            .and_then(serde_json::Value::as_str)
            .context("module census row is missing classification")?
        {
            "conformance" => ModuleClassification::Conformance,
            "meta" => ModuleClassification::Meta,
            other => bail!("unknown module classification `{other}` for {path}"),
        };
        classifications.insert(path.to_owned(), classification);
    }
    Ok(classifications)
}

#[derive(Debug)]
struct NumstatDelta {
    path: String,
    added_loc: isize,
    removed_loc: isize,
}

fn parse_numstat(raw: &str) -> Vec<NumstatDelta> {
    raw.lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let added = fields.next()?;
            let removed = fields.next()?;
            let path = fields.next()?.to_owned();
            let added_loc = added.parse::<isize>().ok()?;
            let removed_loc = removed.parse::<isize>().ok()?;
            if Path::new(&path)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
                && path.starts_with(HARNESS_SRC_PREFIX)
            {
                Some(NumstatDelta {
                    path,
                    added_loc,
                    removed_loc,
                })
            } else {
                None
            }
        })
        .collect()
}

fn conformance_test_count_at_ref(
    workspace_root: &Path,
    git_ref: &str,
    path: &str,
) -> usize {
    let blob = run_git(workspace_root, &["show", &format!("{git_ref}:{path}")])
        .unwrap_or_default();
    count_non_ignored_tests(&blob)
}

fn usize_delta(head: usize, base: usize) -> isize {
    let head = isize::try_from(head).unwrap_or(isize::MAX);
    let base = isize::try_from(base).unwrap_or(isize::MAX);
    head.saturating_sub(base)
}

fn count_non_ignored_tests(source: &str) -> usize {
    let mut count = 0usize;
    let mut pending_ignore = false;
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("#[ignore") || trimmed.contains("ignore]") {
            pending_ignore = true;
            continue;
        }
        if trimmed.starts_with("#[test") {
            if !pending_ignore {
                count += 1;
            }
            pending_ignore = false;
            continue;
        }
        if !trimmed.starts_with("#[") && !trimmed.is_empty() {
            pending_ignore = false;
        }
    }
    count
}

fn run_git(workspace_root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .current_dir(workspace_root)
        .args(args)
        .output()
        .with_context(|| format!("failed to run git {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8(output.stdout).context("git output was not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_meta_growth_without_conformance_growth() {
        let report = evaluate_harness_loc_growth(
            "base",
            "head",
            &[ModuleChange {
                path: "src/meta.rs".to_owned(),
                classification: ModuleClassification::Meta,
                added_loc: 20,
                removed_loc: 2,
                base_conformance_tests: 0,
                head_conformance_tests: 0,
                classified_by_census: true,
            }],
        );

        assert!(report.warning);
        assert_eq!(report.meta_loc_growth, 18);
        assert_eq!(report.allowance, 0);
    }

    #[test]
    fn accepts_meta_growth_matched_by_conformance_tests() {
        let report = evaluate_harness_loc_growth(
            "base",
            "head",
            &[
                ModuleChange {
                    path: "src/meta.rs".to_owned(),
                    classification: ModuleClassification::Meta,
                    added_loc: 4,
                    removed_loc: 0,
                    base_conformance_tests: 0,
                    head_conformance_tests: 0,
                    classified_by_census: true,
                },
                ModuleChange {
                    path: "src/conformance.rs".to_owned(),
                    classification: ModuleClassification::Conformance,
                    added_loc: 2,
                    removed_loc: 0,
                    base_conformance_tests: 1,
                    head_conformance_tests: 3,
                    classified_by_census: true,
                },
            ],
        );

        assert!(!report.warning);
        assert_eq!(report.meta_loc_growth, 4);
        assert_eq!(report.allowance, 4);
    }

    #[test]
    fn ignored_tests_do_not_increase_allowance() {
        let source = r"
            #[test]
            fn counted() {}

            #[ignore]
            #[test]
            fn ignored() {}
        ";

        assert_eq!(count_non_ignored_tests(source), 1);
    }
}
