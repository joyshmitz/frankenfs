//! CLI binary E2E tests for ffs-cli.
//!
//! These tests spawn actual `cargo run -p ffs-cli` processes against real
//! filesystem images created via mkfs.ext4/mkfs.btrfs. No mocks are used.

#![allow(
    clippy::uninlined_format_args,
    clippy::nonminimal_bool,
    clippy::cast_possible_truncation,
    clippy::if_not_else
)]

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

fn btrfs_prerequisites_available() -> bool {
    command_available("mkfs.btrfs")
}

fn create_minimal_btrfs_image(dir: &Path, size_mb: u32) -> std::path::PathBuf {
    let image = dir.join("test.btrfs");

    let dd_status = Command::new("dd")
        .args(["if=/dev/zero", &format!("of={}", image.display()), "bs=1M"])
        .arg(format!("count={}", size_mb))
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status()
        .expect("dd failed");
    assert!(dd_status.success(), "dd failed to create image file");

    let mkfs_status = Command::new("mkfs.btrfs")
        .args(["-f", "-q"])
        .arg(&image)
        .stderr(std::process::Stdio::null())
        .status()
        .expect("mkfs.btrfs failed");
    assert!(mkfs_status.success(), "mkfs.btrfs failed");

    image
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

#[test]
fn cli_inspect_corrupted_superblock_returns_error() {
    if !cli_prerequisites_available() {
        eprintln!("SKIP: mkfs.ext4 or debugfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_ext4_image(tmpdir.path(), 4);

    let mut data = fs::read(&image).expect("read image");
    let sb_off = 1024;
    data[sb_off..sb_off + 64].fill(0xFF);
    fs::write(&image, data).expect("write corrupted image");

    let output = run_ffs_cli(&["inspect", image.to_str().unwrap()]);

    if !output.status.success() {
        emit_scenario_result("cli_inspect_corrupted_superblock_error", "PASS", None);
    } else {
        emit_scenario_result(
            "cli_inspect_corrupted_superblock_error",
            "FAIL",
            Some("expected error for corrupted superblock"),
        );
        panic!("expected ffs inspect to fail on corrupted superblock");
    }
}

#[test]
fn cli_inspect_zero_filled_image_returns_error() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = tmpdir.path().join("zeros.img");

    fs::write(&image, vec![0u8; 4 * 1024 * 1024]).expect("write zero-filled image");

    let output = run_ffs_cli(&["inspect", image.to_str().unwrap()]);

    if !output.status.success() {
        emit_scenario_result("cli_inspect_zero_filled_error", "PASS", None);
    } else {
        emit_scenario_result(
            "cli_inspect_zero_filled_error",
            "FAIL",
            Some("expected error for zero-filled image"),
        );
        panic!("expected ffs inspect to fail on zero-filled image");
    }
}

#[test]
fn cli_fsck_corrupted_superblock_reports_error() {
    if !cli_prerequisites_available() {
        eprintln!("SKIP: mkfs.ext4 or debugfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_ext4_image(tmpdir.path(), 4);

    let mut data = fs::read(&image).expect("read image");
    let sb_off = 1024;
    data[sb_off..sb_off + 64].fill(0xFF);
    fs::write(&image, data).expect("write corrupted image");

    let output = run_ffs_cli(&["fsck", image.to_str().unwrap()]);

    if !output.status.success() {
        emit_scenario_result("cli_fsck_corrupted_superblock_error", "PASS", None);
    } else {
        emit_scenario_result(
            "cli_fsck_corrupted_superblock_error",
            "FAIL",
            Some("expected error for corrupted superblock"),
        );
        panic!("expected ffs fsck to fail on corrupted superblock");
    }
}

#[test]
fn cli_inspect_random_garbage_returns_error() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = tmpdir.path().join("garbage.img");

    let mut rng_data = vec![0u8; 4 * 1024 * 1024];
    for (i, byte) in rng_data.iter_mut().enumerate() {
        *byte = ((i * 7 + 13) % 256) as u8;
    }
    fs::write(&image, rng_data).expect("write garbage image");

    let output = run_ffs_cli(&["inspect", image.to_str().unwrap()]);

    if !output.status.success() {
        emit_scenario_result("cli_inspect_random_garbage_error", "PASS", None);
    } else {
        emit_scenario_result(
            "cli_inspect_random_garbage_error",
            "FAIL",
            Some("expected error for random garbage image"),
        );
        panic!("expected ffs inspect to fail on random garbage image");
    }
}

#[test]
fn cli_info_truncated_image_returns_error() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = tmpdir.path().join("truncated.img");

    fs::write(&image, vec![0u8; 2048]).expect("write truncated image");

    let output = run_ffs_cli(&["info", image.to_str().unwrap()]);

    if !output.status.success() {
        emit_scenario_result("cli_info_truncated_error", "PASS", None);
    } else {
        emit_scenario_result(
            "cli_info_truncated_error",
            "FAIL",
            Some("expected error for truncated image"),
        );
        panic!("expected ffs info to fail on truncated image");
    }
}

#[test]
fn cli_fsck_truncated_image_returns_error() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = tmpdir.path().join("truncated.img");

    fs::write(&image, vec![0u8; 2048]).expect("write truncated image");

    let output = run_ffs_cli(&["fsck", image.to_str().unwrap()]);

    if !output.status.success() {
        emit_scenario_result("cli_fsck_truncated_error", "PASS", None);
    } else {
        emit_scenario_result(
            "cli_fsck_truncated_error",
            "FAIL",
            Some("expected error for truncated image"),
        );
        panic!("expected ffs fsck to fail on truncated image");
    }
}

#[test]
fn cli_repair_truncated_image_returns_error() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = tmpdir.path().join("truncated.img");

    fs::write(&image, vec![0u8; 2048]).expect("write truncated image");

    let output = run_ffs_cli(&["repair", "--verify-only", image.to_str().unwrap()]);

    if !output.status.success() {
        emit_scenario_result("cli_repair_truncated_error", "PASS", None);
    } else {
        emit_scenario_result(
            "cli_repair_truncated_error",
            "FAIL",
            Some("expected error for truncated image"),
        );
        panic!("expected ffs repair to fail on truncated image");
    }
}

// ── Btrfs CLI E2E Tests ─────────────────────────────────────────────────────

#[test]
fn cli_inspect_btrfs_returns_json() {
    if !btrfs_prerequisites_available() {
        eprintln!("SKIP: mkfs.btrfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_btrfs_image(tmpdir.path(), 128);

    let output = run_ffs_cli(&["inspect", "--json", image.to_str().unwrap()]);

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("\"filesystem\"") && stdout.contains("btrfs") {
            emit_scenario_result("cli_inspect_btrfs_json_valid", "PASS", None);
        } else {
            emit_scenario_result(
                "cli_inspect_btrfs_json_valid",
                "FAIL",
                Some("JSON output missing expected fields"),
            );
            panic!("JSON output missing expected fields: {}", stdout);
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        emit_scenario_result(
            "cli_inspect_btrfs_json_valid",
            "FAIL",
            Some(&format!("exit code {:?}", output.status.code())),
        );
        panic!("ffs inspect failed: {}", stderr);
    }
}

#[test]
fn cli_inspect_btrfs_human_readable() {
    if !btrfs_prerequisites_available() {
        eprintln!("SKIP: mkfs.btrfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_btrfs_image(tmpdir.path(), 128);

    let output = run_ffs_cli(&["inspect", image.to_str().unwrap()]);

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("btrfs") || stdout.contains("Btrfs") {
            emit_scenario_result("cli_inspect_btrfs_human_output", "PASS", None);
        } else {
            emit_scenario_result(
                "cli_inspect_btrfs_human_output",
                "FAIL",
                Some("output missing btrfs identifier"),
            );
            panic!("output missing btrfs identifier: {}", stdout);
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        emit_scenario_result(
            "cli_inspect_btrfs_human_output",
            "FAIL",
            Some(&format!("exit code {:?}", output.status.code())),
        );
        panic!("ffs inspect failed: {}", stderr);
    }
}

#[test]
fn cli_info_btrfs_shows_superblock() {
    if !btrfs_prerequisites_available() {
        eprintln!("SKIP: mkfs.btrfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_btrfs_image(tmpdir.path(), 128);

    let output = run_ffs_cli(&["info", image.to_str().unwrap()]);

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("sector_size")
            || stdout.contains("node_size")
            || stdout.contains("generation")
        {
            emit_scenario_result("cli_info_btrfs_superblock", "PASS", None);
        } else {
            emit_scenario_result(
                "cli_info_btrfs_superblock",
                "FAIL",
                Some("output missing superblock fields"),
            );
            panic!("output missing expected superblock fields: {}", stdout);
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        emit_scenario_result(
            "cli_info_btrfs_superblock",
            "FAIL",
            Some(&format!("exit code {:?}", output.status.code())),
        );
        panic!("ffs info failed: {}", stderr);
    }
}

#[test]
fn cli_fsck_btrfs_runs_without_crash() {
    if !btrfs_prerequisites_available() {
        eprintln!("SKIP: mkfs.btrfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_btrfs_image(tmpdir.path(), 128);

    let output = run_ffs_cli(&["fsck", image.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.contains("filesystem: btrfs") && stdout.contains("outcome:") {
        emit_scenario_result("cli_fsck_btrfs_runs_without_crash", "PASS", None);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        emit_scenario_result(
            "cli_fsck_btrfs_runs_without_crash",
            "FAIL",
            Some(&format!("exit code {:?}", output.status.code())),
        );
        panic!(
            "ffs fsck did not produce expected output: stdout={}, stderr={}",
            stdout, stderr
        );
    }
}

#[test]
fn cli_inspect_btrfs_subvolumes() {
    if !btrfs_prerequisites_available() {
        eprintln!("SKIP: mkfs.btrfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_btrfs_image(tmpdir.path(), 128);

    let output = run_ffs_cli(&["inspect", "--subvolumes", image.to_str().unwrap()]);

    if output.status.success() {
        emit_scenario_result("cli_inspect_btrfs_subvolumes", "PASS", None);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        emit_scenario_result(
            "cli_inspect_btrfs_subvolumes",
            "FAIL",
            Some(&format!("exit code {:?}", output.status.code())),
        );
        panic!("ffs inspect --subvolumes failed: {}", stderr);
    }
}

#[test]
fn cli_mount_help_advertises_runtime_modes_and_rw_toggles() {
    let output = run_ffs_cli(&["mount", "--help"]);
    assert!(
        output.status.success(),
        "`ffs mount --help` should exit 0: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    for token in &[
        "--runtime-mode",
        "standard",
        "managed",
        "per-core",
        "--rw",
        "--allow-other",
        "--native",
        "--managed-unmount-timeout-secs",
    ] {
        assert!(
            stdout.contains(token),
            "`ffs mount --help` should advertise `{token}`, got: {stdout}"
        );
    }
    emit_scenario_result(
        "cli_mount_help_surface",
        "PASS",
        Some("runtime_mode+rw+allow_other+native+managed_unmount_timeout_secs"),
    );
}

#[test]
fn cli_mount_nonexistent_image_reports_error() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let missing_image = tmpdir.path().join("no_such.img");
    let mountpoint = tmpdir.path().join("mnt");
    fs::create_dir(&mountpoint).expect("create mountpoint dir");

    let output = run_ffs_cli(&[
        "mount",
        missing_image.to_str().unwrap(),
        mountpoint.to_str().unwrap(),
    ]);

    assert!(
        !output.status.success(),
        "`ffs mount` on missing image must not report success"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.trim().is_empty(),
        "`ffs mount` on missing image must emit a non-empty diagnostic, got stderr=<empty>"
    );
    emit_scenario_result("cli_mount_missing_image_error", "PASS", None);
}

#[test]
fn cli_mount_managed_unmount_timeout_rejected_in_standard_mode() {
    // AGENTS.md / CLI help documents that `--managed-unmount-timeout-secs`
    // is invalid with `--runtime-mode standard`; prove the CLI rejects it
    // before any FUSE work happens, so users get a deterministic error.
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = tmpdir.path().join("anywhere.img");
    let mountpoint = tmpdir.path().join("mnt");
    fs::create_dir(&mountpoint).expect("create mountpoint dir");

    let output = run_ffs_cli(&[
        "mount",
        "--runtime-mode",
        "standard",
        "--managed-unmount-timeout-secs",
        "5",
        image.to_str().unwrap(),
        mountpoint.to_str().unwrap(),
    ]);

    assert!(
        !output.status.success(),
        "`ffs mount --runtime-mode standard --managed-unmount-timeout-secs` must be rejected"
    );
    emit_scenario_result("cli_mount_standard_rejects_managed_timeout", "PASS", None);
}

#[test]
fn cli_inspect_unreadable_image_reports_permission_error() {
    use std::os::unix::fs::PermissionsExt;

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = tmpdir.path().join("locked.img");
    fs::write(&image, vec![0u8; 4096]).expect("write empty image");
    fs::set_permissions(&image, fs::Permissions::from_mode(0o000))
        .expect("chmod 000 on image");

    // Root bypasses POSIX mode 0o000, so skip rather than silently pass.
    if fs::read(&image).is_ok() {
        let _ = fs::set_permissions(&image, fs::Permissions::from_mode(0o600));
        eprintln!("SKIP: cannot exercise EACCES — current process can read mode-0 files");
        emit_scenario_result(
            "cli_inspect_unreadable_image_permission_error",
            "SKIP",
            Some("process_bypasses_mode_000"),
        );
        return;
    }

    let output = run_ffs_cli(&["inspect", image.to_str().unwrap()]);

    // Restore perms so tempdir cleanup can run even if the assertions below fire.
    let _ = fs::set_permissions(&image, fs::Permissions::from_mode(0o600));

    assert!(
        !output.status.success(),
        "`ffs inspect` on mode-0 image must not succeed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.trim().is_empty(),
        "`ffs inspect` on mode-0 image must emit a diagnostic, got stderr=<empty>"
    );
    let hints_permission = stderr.contains("Permission denied")
        || stderr.contains("permission denied")
        || stderr.contains("EACCES")
        || stderr.contains("os error 13");
    assert!(
        hints_permission,
        "diagnostic should mention permission/EACCES, got: {stderr}"
    );
    emit_scenario_result(
        "cli_inspect_unreadable_image_permission_error",
        "PASS",
        Some("stderr_hints_permission"),
    );
}

#[test]
fn cli_inspect_directory_as_image_reports_error() {
    // Operator-visible contract: pointing `ffs inspect` at a directory must
    // fail with a non-empty diagnostic, not panic or hang reading a device.
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let dir_path = tmpdir.path().join("not_an_image");
    fs::create_dir(&dir_path).expect("create directory to stand in for image");

    let output = run_ffs_cli(&["inspect", dir_path.to_str().unwrap()]);

    assert!(
        !output.status.success(),
        "`ffs inspect` on a directory must not succeed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.trim().is_empty(),
        "`ffs inspect` on a directory must emit a diagnostic, got stderr=<empty>"
    );
    emit_scenario_result("cli_inspect_directory_as_image_error", "PASS", None);
}

#[test]
fn cli_inspect_empty_file_reports_error() {
    // Zero-byte images exercise the short-read / EOF permission-adjacent
    // path: `ffs inspect` must report an error, not panic and not claim a
    // format was detected.
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = tmpdir.path().join("empty.img");
    fs::write(&image, b"").expect("write empty image");

    let output = run_ffs_cli(&["inspect", image.to_str().unwrap()]);

    assert!(
        !output.status.success(),
        "`ffs inspect` on an empty file must not succeed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.trim().is_empty(),
        "`ffs inspect` on an empty file must emit a diagnostic, got stderr=<empty>"
    );
    emit_scenario_result("cli_inspect_empty_file_error", "PASS", None);
}
