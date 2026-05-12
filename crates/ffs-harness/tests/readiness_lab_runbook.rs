#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut ancestors = manifest_dir.ancestors();
    let _crate_dir = ancestors.next();
    let _crates_dir = ancestors.next();
    ancestors.next().map(Path::to_path_buf).ok_or_else(|| {
        "ffs-harness crate should be two levels below the repository root".to_owned()
    })
}

fn read_repo_file(path: &str) -> Result<String, String> {
    fs::read_to_string(repo_root()?.join(path))
        .map_err(|err| format!("expected {path} to be readable from repository root: {err}"))
}

#[test]
fn readiness_lab_runbook_preserves_advisory_claim_boundaries() -> Result<(), String> {
    let readme = read_repo_file("README.md")?;
    let runbook = read_repo_file("docs/runbooks/readiness-action-autopilot.md")?;
    let combined = format!("{readme}\n{runbook}");

    for required in [
        "Advisory Readiness Lab",
        "product_evidence_claim=none",
        "advisory_only_no_public_readiness_change",
        "readiness_lab_combined_manifest.json",
        "XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices",
        "FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host",
        "Allowed use",
        "Forbidden claim effect",
        "upgrade `swarm.responsiveness`",
        "satisfy `xfstests.baseline`",
        "set `release_ready=true`",
    ] {
        if !combined.contains(required) {
            return Err(format!(
                "readiness lab runbook should preserve advisory boundary marker {required:?}"
            ));
        }
    }

    for forbidden in [
        "simulated evidence marks xfstests validated",
        "simulated evidence marks swarm responsiveness validated",
        "advisory artifacts are authoritative",
        "readiness lab sets release_ready=true",
        "readiness lab satisfies xfstests.baseline",
        "readiness lab upgrades swarm.responsiveness",
    ] {
        if combined.to_lowercase().contains(forbidden) {
            return Err(format!(
                "runbook must not promote advisory readiness lab evidence with phrase {forbidden:?}"
            ));
        }
    }

    Ok(())
}

#[test]
fn agents_workspace_layout_names_crate_local_benchmarks() -> Result<(), String> {
    let agents = read_repo_file("AGENTS.md")?;

    if !agents.contains(
        "| `crates/*/benches/` | Crate-local performance benchmarks with regression detection |",
    ) {
        return Err("AGENTS.md should preserve crate-local benchmark table marker".to_owned());
    }

    if !agents.contains("├── crates/*/benches/              # Crate-local performance benchmarks")
    {
        return Err("AGENTS.md should preserve crate-local benchmark tree marker".to_owned());
    }

    if agents
        .contains("| `benches/` (workspace) | Performance benchmarks with regression detection |")
    {
        return Err("AGENTS.md must not keep the stale root benchmark table marker".to_owned());
    }

    if agents.contains("├── benches/                       # Performance benchmarks") {
        return Err("AGENTS.md must not keep the stale root benchmark tree marker".to_owned());
    }

    Ok(())
}
