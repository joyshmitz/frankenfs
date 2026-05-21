//! Compile-fail tests for ExecutedEvidence security invariants.
//!
//! These tests verify that ExecutedEvidence cannot be deserialized from JSON,
//! ensuring the only way to construct one is by actually running a process.

#[test]
fn executed_evidence_cannot_be_deserialized() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/executed_evidence_no_deserialize.rs");
}
