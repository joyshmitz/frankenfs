#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ModuleCensus {
    schema_version: u32,
    scope: String,
    summary: CensusSummary,
    modules: Vec<ModuleEntry>,
}

#[derive(Debug, Deserialize)]
struct CensusSummary {
    modules: usize,
    total_loc: usize,
    conformance_modules: usize,
    conformance_loc: usize,
    conformance_loc_basis_points: usize,
    meta_modules: usize,
    meta_loc: usize,
    meta_loc_basis_points: usize,
}

#[derive(Debug, Deserialize)]
struct ModuleEntry {
    path: String,
    classification: ModuleClassification,
    loc: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ModuleClassification {
    Conformance,
    Meta,
}

#[test]
fn module_census_matches_tracked_harness_src_tree() -> Result<(), Box<dyn Error>> {
    let census: ModuleCensus = serde_json::from_str(include_str!("../module_census.json"))?;

    assert_eq!(census.schema_version, 1);
    assert_eq!(
        census.scope,
        "git-tracked index:crates/ffs-harness/src/*.rs"
    );

    let mut entries_by_path = BTreeMap::new();
    for entry in &census.modules {
        assert!(
            entry.path.starts_with("src/") && has_rust_extension(&entry.path),
            "invalid module census path: {}",
            entry.path
        );
        assert!(
            entries_by_path.insert(entry.path.clone(), entry).is_none(),
            "duplicate module census path: {}",
            entry.path
        );
    }

    let Some(source_names) = try_run_git(&["ls-files", "crates/ffs-harness/src/*.rs"])? else {
        assert_internal_summary(&census, &entries_by_path);
        assert_artifact_paths_exist(&entries_by_path);
        return Ok(());
    };
    let source_names = String::from_utf8(source_names)?;
    let tracked_paths = source_names
        .lines()
        .filter_map(|name| name.strip_prefix("crates/ffs-harness/"))
        .filter(|path| path.starts_with("src/") && has_rust_extension(path))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let artifact_paths = entries_by_path.keys().cloned().collect::<BTreeSet<_>>();

    if tracked_paths.len() < artifact_paths.len() {
        assert_internal_summary(&census, &entries_by_path);
        assert_artifact_paths_exist(&entries_by_path);
        return Ok(());
    }

    assert_eq!(artifact_paths, tracked_paths);

    let mut total_loc = 0usize;
    let mut conformance_loc = 0usize;
    let mut conformance_modules = 0usize;
    let mut meta_loc = 0usize;
    let mut meta_modules = 0usize;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for path in &tracked_paths {
        let entry = entries_by_path
            .get(path)
            .ok_or_else(|| io::Error::other(format!("missing census entry for {path}")))?;
        let source_blob = read_tracked_source_blob(manifest_dir, path)?;
        let loc = wc_compatible_line_count(&source_blob);

        assert_eq!(entry.loc, loc, "LOC drift for {path}");

        total_loc += loc;
        match entry.classification {
            ModuleClassification::Conformance => {
                conformance_modules += 1;
                conformance_loc += loc;
            }
            ModuleClassification::Meta => {
                meta_modules += 1;
                meta_loc += loc;
            }
        }
    }

    assert_summary(
        &census.summary,
        SummaryValues {
            modules: tracked_paths.len(),
            total_loc,
            conformance_modules,
            conformance_loc,
            meta_modules,
            meta_loc,
        },
    );

    Ok(())
}

#[derive(Clone, Copy)]
struct SummaryValues {
    modules: usize,
    total_loc: usize,
    conformance_modules: usize,
    conformance_loc: usize,
    meta_modules: usize,
    meta_loc: usize,
}

fn assert_internal_summary(
    census: &ModuleCensus,
    entries_by_path: &BTreeMap<String, &ModuleEntry>,
) {
    let mut total_loc = 0usize;
    let mut conformance_loc = 0usize;
    let mut conformance_modules = 0usize;
    let mut meta_loc = 0usize;
    let mut meta_modules = 0usize;

    for entry in entries_by_path.values() {
        assert!(entry.loc > 0, "zero LOC census entry: {}", entry.path);
        total_loc += entry.loc;
        match entry.classification {
            ModuleClassification::Conformance => {
                conformance_modules += 1;
                conformance_loc += entry.loc;
            }
            ModuleClassification::Meta => {
                meta_modules += 1;
                meta_loc += entry.loc;
            }
        }
    }

    assert_summary(
        &census.summary,
        SummaryValues {
            modules: entries_by_path.len(),
            total_loc,
            conformance_modules,
            conformance_loc,
            meta_modules,
            meta_loc,
        },
    );
}

fn assert_artifact_paths_exist(entries_by_path: &BTreeMap<String, &ModuleEntry>) {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for path in entries_by_path.keys() {
        let source_path = manifest_dir.join(path);
        assert!(
            source_path.is_file(),
            "module census path is absent from checkout: {}",
            source_path.display()
        );
    }
}

fn read_tracked_source_blob(manifest_dir: &Path, path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let git_path = format!("crates/ffs-harness/{path}");
    if let Some(blob) = try_run_git(&["show", &format!(":{git_path}")])? {
        return Ok(blob);
    }

    Ok(std::fs::read(manifest_dir.join(path))?)
}

fn assert_summary(summary: &CensusSummary, values: SummaryValues) {
    assert!(values.total_loc > 0);
    assert_eq!(summary.modules, values.modules);
    assert_eq!(summary.total_loc, values.total_loc);
    assert_eq!(summary.conformance_modules, values.conformance_modules);
    assert_eq!(summary.conformance_loc, values.conformance_loc);
    assert_eq!(
        summary.conformance_loc_basis_points,
        rounded_basis_points(values.conformance_loc, values.total_loc)
    );
    assert_eq!(summary.meta_modules, values.meta_modules);
    assert_eq!(summary.meta_loc, values.meta_loc);
    assert_eq!(
        summary.meta_loc_basis_points,
        rounded_basis_points(values.meta_loc, values.total_loc)
    );
}

fn try_run_git(args: &[&str]) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    let output = Command::new("git")
        .current_dir(repository_root()?)
        .args(args)
        .output()?;

    if output.status.success() {
        Ok(Some(output.stdout))
    } else {
        Ok(None)
    }
}

fn repository_root() -> Result<PathBuf, Box<dyn Error>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| {
            io::Error::other(format!(
                "could not resolve repository root from {}",
                manifest_dir.display()
            ))
        })?;
    Ok(root.to_path_buf())
}

fn wc_compatible_line_count(bytes: &[u8]) -> usize {
    let newline_count = bytes.split(|byte| *byte == b'\n').count().saturating_sub(1);
    if bytes.is_empty() || bytes.ends_with(b"\n") {
        newline_count
    } else {
        newline_count + 1
    }
}

fn has_rust_extension(path: &str) -> bool {
    Path::new(path).extension() == Some(OsStr::new("rs"))
}

fn rounded_basis_points(part: usize, total: usize) -> usize {
    ((part * 10_000) + (total / 2)) / total
}
