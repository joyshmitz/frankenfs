#![forbid(unsafe_code)]

use std::fs;
use std::process::Command;

#[test]
fn help_lists_relocated_ops_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_ffs-ops"))
        .arg("--help")
        .output()
        .expect("run ffs-ops --help");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("help is valid UTF-8");
    for command in [
        "validate-ambition-evidence-matrix",
        "recommend-readiness-actions",
        "validate-open-ended-inventory",
        "validate-docs-status-drift",
        "validate-report-schema-inventory",
        "validate-permissioned-campaign-broker",
    ] {
        assert!(stdout.contains(command), "missing command: {command}");
    }
}

#[test]
fn relocated_open_ended_inventory_command_writes_json() {
    let out_dir = std::env::temp_dir().join(format!(
        "ffs-ops-open-ended-inventory-{}",
        std::process::id()
    ));
    fs::create_dir_all(&out_dir).expect("create temp output directory");
    let report_path = out_dir.join("inventory.json");

    let output = Command::new(env!("CARGO_BIN_EXE_ffs-ops"))
        .args([
            "validate-open-ended-inventory",
            "--out",
            report_path.to_str().expect("temp path is UTF-8"),
        ])
        .output()
        .expect("run relocated inventory command");

    assert!(output.status.success());
    let report = fs::read_to_string(&report_path).expect("inventory report was written");
    assert!(report.contains("\"row_count\""));
}
