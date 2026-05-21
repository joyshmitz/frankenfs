// This test should fail to compile, proving ExecutedEvidence cannot be forged
// through a direct struct literal with hand-authored fields.

use ffs_harness::executed_evidence::{ExecutedEvidence, ExecutionOutcome, HostClass};

fn main() {
    let _evidence = ExecutedEvidence {
        command: "true".to_string(),
        args: Vec::new(),
        exit_code: Some(0),
        stdout_sha256: "0".repeat(64),
        stderr_sha256: "0".repeat(64),
        duration_ms: 0,
        ran_at: 0,
        git_sha: "forged".to_string(),
        host_class: HostClass::Full,
        outcome: ExecutionOutcome::Success,
    };
}
