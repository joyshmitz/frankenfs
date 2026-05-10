#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("ffs-harness crate should be two levels below the repository root")
        .to_path_buf()
}

fn orchestrator_script() -> PathBuf {
    repo_root().join("scripts/e2e/ffs_readiness_lab_e2e.sh")
}

#[test]
fn readiness_lab_orchestrator_script_has_valid_bash_syntax() {
    let status = Command::new("bash")
        .arg("-n")
        .arg(orchestrator_script())
        .status()
        .expect("bash -n should run for readiness lab orchestrator");
    assert!(status.success(), "readiness lab orchestrator must parse");
}

#[test]
fn readiness_lab_orchestrator_covers_required_evidence_lanes() {
    let script = fs::read_to_string(orchestrator_script())
        .expect("readiness lab orchestrator script should be readable");
    for marker in [
        "readiness_lab_contract_bundle",
        "readiness_lab_host_simulator",
        "readiness_lab_rch_scheduler",
        "readiness_lab_truth_graph",
        "readiness_lab_xfstests_rehearsal",
        "readiness_lab_numa_p99_replay",
        "readiness_lab_dashboard_integration",
        "readiness_lab_advisory_release_gate",
    ] {
        assert!(
            script.contains(marker),
            "orchestrator should cover scenario marker {marker}"
        );
    }
    for child in [
        "scripts/e2e/ffs_readiness_lab_contracts_e2e.sh",
        "scripts/e2e/ffs_permissioned_campaign_broker_e2e.sh",
        "scripts/e2e/ffs_readiness_dashboard_e2e.sh",
    ] {
        assert!(
            script.contains(child),
            "orchestrator should run child gate {child}"
        );
    }
}

#[test]
fn readiness_lab_orchestrator_forbids_permissioned_ack_consumption() {
    let script = fs::read_to_string(orchestrator_script())
        .expect("readiness lab orchestrator script should be readable");
    assert!(script.contains("assert_no_permissioned_ack"));
    for env_name in [
        "XFSTESTS_REAL_RUN_ACK",
        "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD",
        "FFS_SWARM_WORKLOAD_REAL_RUN_ACK",
        "FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER",
    ] {
        assert!(
            script.contains(env_name),
            "orchestrator should guard {env_name}"
        );
    }
    assert!(
        !script.contains("XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices"),
        "orchestrator must not export the xfstests mutation ACK"
    );
    assert!(
        !script.contains(
            "FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host"
        ),
        "orchestrator must not export the large-host swarm ACK"
    );
}
