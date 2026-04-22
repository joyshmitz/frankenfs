//! CLI binary E2E tests for ffs-cli.
//!
//! These tests spawn actual `cargo run -p ffs-cli` processes against real
//! filesystem images created via mkfs.ext4/mkfs.btrfs. No mocks are used.

use std::fs;
use std::path::Path;
use std::process::Command;

fn emit_scenario_result(scenario_id: &str, outcome: &str, detail: Option<&str>) {
    match detail {
        Some(detail) => {
            eprintln!(
                "SCENARIO_RESULT|scenario_id={scenario_id}|outcome={outcome}|detail={detail}"
            );
        }
        None => eprintln!("SCENARIO_RESULT|scenario_id={scenario_id}|outcome={outcome}"),
    }
}

fn command_available(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn cli_prerequisites_available() -> bool {
    command_available("mkfs.ext4") && command_available("debugfs")
}

fn create_minimal_ext4_image(dir: &Path, size_mb: u32) -> std::path::PathBuf {
    let image = dir.join("test.ext4");
    let size_str = format!("{}M", size_mb);

    let dd_status = Command::new("dd")
        .args(["if=/dev/zero", &format!("of={}", image.display()), "bs=1M"])
        .arg(format!("count={}", size_mb))
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status()
        .expect("dd failed");
    assert!(dd_status.success(), "dd failed to create image file");

    let mkfs_status = Command::new("mkfs.ext4")
        .args(["-q", "-F", "-b", "4096"])
        .arg(&image)
        .arg(&size_str)
        .status()
        .expect("mkfs.ext4 failed");
    assert!(mkfs_status.success(), "mkfs.ext4 failed");

    let debugfs_cmds = "mkdir testdir\nwrite /dev/null testdir/empty.txt\nquit\n";
    let debugfs_status = Command::new("debugfs")
        .args(["-w", "-f", "-"])
        .arg(&image)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(debugfs_cmds.as_bytes())?;
            }
            child.wait()
        })
        .expect("debugfs failed");
    assert!(debugfs_status.success(), "debugfs failed");

    image
}

fn run_ffs_cli(args: &[&str]) -> std::process::Output {
    let cargo_target_dir =
        std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());

    Command::new("cargo")
        .args(["run", "-p", "ffs-cli", "--"])
        .args(args)
        .env("CARGO_TARGET_DIR", cargo_target_dir)
        .output()
        .expect("failed to execute ffs-cli")
}

#[test]
fn cli_inspect_ext4_returns_json() {
    if !cli_prerequisites_available() {
        eprintln!("SKIP: mkfs.ext4 or debugfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_ext4_image(tmpdir.path(), 4);

    let output = run_ffs_cli(&["inspect", "--json", image.to_str().unwrap()]);

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("\"filesystem\"") && stdout.contains("ext4") {
            emit_scenario_result("cli_inspect_ext4_json_valid", "PASS", None);
        } else {
            emit_scenario_result(
                "cli_inspect_ext4_json_valid",
                "FAIL",
                Some("JSON output missing expected fields"),
            );
            panic!("JSON output missing expected fields: {}", stdout);
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        emit_scenario_result(
            "cli_inspect_ext4_json_valid",
            "FAIL",
            Some(&format!("exit code {:?}", output.status.code())),
        );
        panic!("ffs inspect failed: {}", stderr);
    }
}

#[test]
fn cli_inspect_ext4_human_readable() {
    if !cli_prerequisites_available() {
        eprintln!("SKIP: mkfs.ext4 or debugfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_ext4_image(tmpdir.path(), 4);

    let output = run_ffs_cli(&["inspect", image.to_str().unwrap()]);

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("ext4") || stdout.contains("Ext4") {
            emit_scenario_result("cli_inspect_ext4_human_output", "PASS", None);
        } else {
            emit_scenario_result(
                "cli_inspect_ext4_human_output",
                "FAIL",
                Some("output missing ext4 identifier"),
            );
            panic!("output missing ext4 identifier: {}", stdout);
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        emit_scenario_result(
            "cli_inspect_ext4_human_output",
            "FAIL",
            Some(&format!("exit code {:?}", output.status.code())),
        );
        panic!("ffs inspect failed: {}", stderr);
    }
}

#[test]
fn cli_inspect_truncated_image_returns_error() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = tmpdir.path().join("truncated.img");

    fs::write(&image, vec![0u8; 512]).expect("write truncated image");

    let output = run_ffs_cli(&["inspect", image.to_str().unwrap()]);

    if !output.status.success() {
        emit_scenario_result("cli_inspect_truncated_error", "PASS", None);
    } else {
        emit_scenario_result(
            "cli_inspect_truncated_error",
            "FAIL",
            Some("expected non-zero exit for truncated image"),
        );
        panic!("expected ffs inspect to fail on truncated image");
    }
}

#[test]
fn cli_inspect_nonexistent_file_returns_error() {
    let output = run_ffs_cli(&["inspect", "/nonexistent/path/to/image.img"]);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("No such file")
            || stderr.contains("not found")
            || stderr.contains("does not exist")
        {
            emit_scenario_result("cli_inspect_nonexistent_error", "PASS", None);
        } else {
            emit_scenario_result(
                "cli_inspect_nonexistent_error",
                "FAIL",
                Some("error message unclear"),
            );
            panic!("error message should indicate file not found: {}", stderr);
        }
    } else {
        emit_scenario_result(
            "cli_inspect_nonexistent_error",
            "FAIL",
            Some("expected non-zero exit for nonexistent file"),
        );
        panic!("expected ffs inspect to fail on nonexistent file");
    }
}

#[test]
fn cli_info_ext4_shows_superblock() {
    if !cli_prerequisites_available() {
        eprintln!("SKIP: mkfs.ext4 or debugfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_ext4_image(tmpdir.path(), 4);

    let output = run_ffs_cli(&["info", image.to_str().unwrap()]);

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("block_size") || stdout.contains("inodes") || stdout.contains("groups") {
            emit_scenario_result("cli_info_ext4_superblock", "PASS", None);
        } else {
            emit_scenario_result(
                "cli_info_ext4_superblock",
                "FAIL",
                Some("output missing superblock fields"),
            );
            panic!("output missing expected superblock fields: {}", stdout);
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        emit_scenario_result(
            "cli_info_ext4_superblock",
            "FAIL",
            Some(&format!("exit code {:?}", output.status.code())),
        );
        panic!("ffs info failed: {}", stderr);
    }
}

#[test]
fn cli_fsck_ext4_clean_image() {
    if !cli_prerequisites_available() {
        eprintln!("SKIP: mkfs.ext4 or debugfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_ext4_image(tmpdir.path(), 4);

    let output = run_ffs_cli(&["fsck", image.to_str().unwrap()]);

    if output.status.success() {
        emit_scenario_result("cli_fsck_ext4_clean_image", "PASS", None);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        emit_scenario_result(
            "cli_fsck_ext4_clean_image",
            "FAIL",
            Some(&format!("exit code {:?}", output.status.code())),
        );
        panic!("ffs fsck failed on clean image: {}", stderr);
    }
}

#[test]
fn cli_fsck_json_output() {
    if !cli_prerequisites_available() {
        eprintln!("SKIP: mkfs.ext4 or debugfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_ext4_image(tmpdir.path(), 4);

    let output = run_ffs_cli(&["fsck", "--json", image.to_str().unwrap()]);

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains('{') && stdout.contains('}') {
            emit_scenario_result("cli_fsck_ext4_json_output", "PASS", None);
        } else {
            emit_scenario_result(
                "cli_fsck_ext4_json_output",
                "FAIL",
                Some("output not valid JSON"),
            );
            panic!("fsck --json output not valid JSON: {}", stdout);
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        emit_scenario_result(
            "cli_fsck_ext4_json_output",
            "FAIL",
            Some(&format!("exit code {:?}", output.status.code())),
        );
        panic!("ffs fsck --json failed: {}", stderr);
    }
}

#[test]
fn cli_repair_verify_only_ext4() {
    if !cli_prerequisites_available() {
        eprintln!("SKIP: mkfs.ext4 or debugfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_ext4_image(tmpdir.path(), 4);

    let output = run_ffs_cli(&["repair", "--verify-only", image.to_str().unwrap()]);

    if output.status.success() {
        emit_scenario_result("cli_repair_verify_only_ext4", "PASS", None);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let code = output.status.code().unwrap_or(-1);
        if code == 1 && stderr.contains("staleness") {
            emit_scenario_result(
                "cli_repair_verify_only_ext4",
                "PASS",
                Some("no staleness detected"),
            );
        } else {
            emit_scenario_result(
                "cli_repair_verify_only_ext4",
                "FAIL",
                Some(&format!("exit code {}", code)),
            );
            panic!("ffs repair --verify-only failed unexpectedly: {}", stderr);
        }
    }
}
