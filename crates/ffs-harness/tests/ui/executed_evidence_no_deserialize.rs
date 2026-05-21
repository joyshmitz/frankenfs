// This test should fail to compile, proving ExecutedEvidence cannot be deserialized.
// If this compiles, the security invariant is broken.

use ffs_harness::executed_evidence::ExecutedEvidence;

fn main() {
    // Attempting to deserialize ExecutedEvidence should fail at compile time
    // because it intentionally does not implement Deserialize.
    let json = r#"{"command":"echo","args":[],"exit_code":0}"#;
    let _evidence: ExecutedEvidence = serde_json::from_str(json).unwrap();
}
