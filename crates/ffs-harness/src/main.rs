#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use ffs_harness::{
    ParityReport,
    ambition_evidence_matrix::{
        AmbitionEvidenceMatrixConfig, fail_on_ambition_evidence_matrix_errors,
        run_ambition_evidence_matrix,
    },
    artifact_manifest::{ArtifactManifest, validate_operational_manifest},
    deferred_parity_audit::{
        DeferredParityAuditConfig, fail_on_audit_errors, run_deferred_parity_audit,
    },
    e2e::{CrashReplaySuiteConfig, FsxStressConfig, run_crash_replay_suite, run_fsx_stress},
    extract_btrfs_superblock, extract_ext4_superblock, extract_region,
    mounted_write_matrix::{
        DEFAULT_MATRIX_PATH, fail_on_mounted_write_matrix_errors, load_mounted_write_matrix,
        validate_mounted_write_matrix,
    },
    open_ended_inventory::validate_current_inventory,
    validate_btrfs_fixture, validate_ext4_fixture,
    verification_runner::{FuseHostProbeOptions, probe_host_fuse_capability},
    xfstests::{
        XfstestsStatus, apply_allowlist, compare_against_baseline, load_allowlist, load_baseline,
        load_selected_tests, parse_check_output, summarize_uniform, write_junit_xml,
    },
};
use std::env;
use std::fs;
use std::path::Path;

#[derive(Debug, Default)]
struct XfstestsReportConfig {
    selected: Option<String>,
    check_log: Option<String>,
    results_json: Option<String>,
    junit_xml: Option<String>,
    allowlist_json: Option<String>,
    baseline_json: Option<String>,
    uniform_status: Option<XfstestsStatus>,
    uniform_note: Option<String>,
    check_rc: i32,
    dry_run: bool,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str);

    match cmd {
        Some("parity") => {
            let report = ParityReport::current();
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Some("check-fixtures") => {
            let ext4 = Path::new("conformance/fixtures/ext4_superblock_sparse.json");
            let btrfs = Path::new("conformance/fixtures/btrfs_superblock_sparse.json");
            let ext4_sb = validate_ext4_fixture(ext4)?;
            let btrfs_sb = validate_btrfs_fixture(btrfs)?;

            println!(
                "ext4: block_size={} volume={}",
                ext4_sb.block_size, ext4_sb.volume_name
            );
            println!(
                "btrfs: nodesize={} label={}",
                btrfs_sb.nodesize, btrfs_sb.label
            );
            Ok(())
        }
        Some("generate-fixture") => generate_fixture(&args[1..]),
        Some("run-crash-replay") => run_crash_replay(&args[1..]),
        Some("run-fsx-stress") => run_fsx_stress_cmd(&args[1..]),
        Some("xfstests-report") => xfstests_report(&args[1..]),
        Some("validate-operational-manifest") => validate_operational_manifest_cmd(&args[1..]),
        Some("fuse-capability-probe") => fuse_capability_probe_cmd(&args[1..]),
        Some("validate-open-ended-inventory") => validate_open_ended_inventory_cmd(&args[1..]),
        Some("validate-deferred-parity-audit") => validate_deferred_parity_audit_cmd(&args[1..]),
        Some("validate-ambition-evidence-matrix") => {
            validate_ambition_evidence_matrix_cmd(&args[1..])
        }
        Some("validate-mounted-write-matrix") => validate_mounted_write_matrix_cmd(&args[1..]),
        Some("--help" | "-h" | "help") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => {
            print_usage();
            bail!("unknown command: {other}")
        }
    }
}

fn xfstests_report(args: &[String]) -> Result<()> {
    let config = parse_xfstests_report_config(args)?;
    let selected_path = Path::new(
        config
            .selected
            .as_deref()
            .context("--selected is required")?,
    );
    let results_path = Path::new(
        config
            .results_json
            .as_deref()
            .context("--results-json is required")?,
    );
    let junit_path = Path::new(
        config
            .junit_xml
            .as_deref()
            .context("--junit-xml is required")?,
    );
    let selected_tests = load_selected_tests(selected_path)?;
    let mut run = build_xfstests_run(&config, &selected_tests)?;
    apply_xfstests_metadata(&config, &mut run)?;

    fs::write(results_path, serde_json::to_string_pretty(&run)? + "\n")
        .with_context(|| format!("failed to write {}", results_path.display()))?;
    write_junit_xml(junit_path, &run)?;
    println!("{}", serde_json::to_string_pretty(&run)?);
    Ok(())
}

fn parse_xfstests_report_config(args: &[String]) -> Result<XfstestsReportConfig> {
    let mut config = XfstestsReportConfig::default();
    let mut index = 0_usize;

    while index < args.len() {
        match args[index].as_str() {
            "--selected" => {
                config.selected = Some(require_value(args, index, "--selected")?.clone());
                index += 2;
            }
            "--check-log" => {
                config.check_log = Some(require_value(args, index, "--check-log")?.clone());
                index += 2;
            }
            "--results-json" => {
                config.results_json = Some(require_value(args, index, "--results-json")?.clone());
                index += 2;
            }
            "--junit-xml" => {
                config.junit_xml = Some(require_value(args, index, "--junit-xml")?.clone());
                index += 2;
            }
            "--allowlist-json" => {
                config.allowlist_json =
                    Some(require_value(args, index, "--allowlist-json")?.clone());
                index += 2;
            }
            "--baseline-json" => {
                config.baseline_json = Some(require_value(args, index, "--baseline-json")?.clone());
                index += 2;
            }
            "--check-rc" => {
                config.check_rc = require_value(args, index, "--check-rc")?
                    .parse()
                    .context("invalid --check-rc value")?;
                index += 2;
            }
            "--dry-run" => {
                config.dry_run = require_value(args, index, "--dry-run")?
                    .parse::<u8>()
                    .context("invalid --dry-run value")?
                    != 0;
                index += 2;
            }
            "--uniform-status" => {
                config.uniform_status = Some(parse_xfstests_status(require_value(
                    args,
                    index,
                    "--uniform-status",
                )?)?);
                index += 2;
            }
            "--uniform-note" => {
                config.uniform_note = Some(require_value(args, index, "--uniform-note")?.clone());
                index += 2;
            }
            other => bail!("unknown xfstests-report option: {other}"),
        }
    }

    Ok(config)
}

fn require_value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a String> {
    args.get(index + 1)
        .with_context(|| format!("{flag} requires a value"))
}

fn parse_xfstests_status(raw: &str) -> Result<XfstestsStatus> {
    match raw {
        "passed" => Ok(XfstestsStatus::Passed),
        "failed" => Ok(XfstestsStatus::Failed),
        "skipped" => Ok(XfstestsStatus::Skipped),
        "not_run" => Ok(XfstestsStatus::NotRun),
        "planned" => Ok(XfstestsStatus::Planned),
        other => bail!("invalid --uniform-status value: {other}"),
    }
}

fn build_xfstests_run(
    config: &XfstestsReportConfig,
    selected_tests: &[String],
) -> Result<ffs_harness::xfstests::XfstestsRun> {
    if let Some(status) = config.uniform_status {
        return Ok(summarize_uniform(
            selected_tests,
            status,
            config.uniform_note.as_deref(),
        ));
    }

    let check_log_path = Path::new(
        config
            .check_log
            .as_deref()
            .context("--check-log is required")?,
    );
    let check_log_text = fs::read_to_string(check_log_path)
        .with_context(|| format!("failed to read {}", check_log_path.display()))?;
    Ok(parse_check_output(
        selected_tests,
        &check_log_text,
        config.check_rc,
        config.dry_run,
    ))
}

fn apply_xfstests_metadata(
    config: &XfstestsReportConfig,
    run: &mut ffs_harness::xfstests::XfstestsRun,
) -> Result<()> {
    apply_allowlist_if_present(run, config.allowlist_json.as_deref())?;
    emit_baseline_comparison_if_present(run, config.baseline_json.as_deref())
}

fn apply_allowlist_if_present(
    run: &mut ffs_harness::xfstests::XfstestsRun,
    allowlist_json: Option<&str>,
) -> Result<()> {
    let Some(path) = allowlist_json else {
        return Ok(());
    };
    let allowlist_path = Path::new(path);
    if allowlist_path.exists() {
        let allowlist = load_allowlist(allowlist_path)?;
        apply_allowlist(run, &allowlist);
    }
    Ok(())
}

fn emit_baseline_comparison_if_present(
    run: &mut ffs_harness::xfstests::XfstestsRun,
    baseline_json: Option<&str>,
) -> Result<()> {
    let Some(path) = baseline_json else {
        return Ok(());
    };
    let baseline_path = Path::new(path);
    if !baseline_path.exists() {
        return Ok(());
    }

    let baseline = load_baseline(baseline_path)?;
    let comparison = compare_against_baseline(run, &baseline);
    if !comparison.regressions.is_empty()
        || !comparison.improvements.is_empty()
        || !comparison.unchanged.is_empty()
    {
        eprintln!("{}", serde_json::to_string_pretty(&comparison)?);
    }
    Ok(())
}

fn validate_operational_manifest_cmd(args: &[String]) -> Result<()> {
    let manifest_path = Path::new(
        args.first()
            .context("usage: ffs-harness validate-operational-manifest <manifest.json>")?,
    );
    if args.len() != 1 {
        bail!("usage: ffs-harness validate-operational-manifest <manifest.json>");
    }

    let manifest_text = fs::read_to_string(manifest_path)
        .with_context(|| format!("failed to read {}", manifest_path.display()))?;
    let manifest: ArtifactManifest = serde_json::from_str(&manifest_text)
        .with_context(|| format!("invalid manifest json {}", manifest_path.display()))?;
    let errors = validate_operational_manifest(&manifest);
    if !errors.is_empty() {
        for error in &errors {
            eprintln!("manifest validation error: {error}");
        }
        bail!(
            "operational manifest validation failed with {} error(s)",
            errors.len()
        );
    }

    println!(
        "operational manifest valid: run_id={} gate_id={} scenarios={} artifacts={}",
        manifest.run_id,
        manifest.gate_id,
        manifest.scenarios.len(),
        manifest.artifacts.len()
    );
    Ok(())
}

fn validate_open_ended_inventory_cmd(args: &[String]) -> Result<()> {
    let mut out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--help" | "-h" => {
                print_open_ended_inventory_usage();
                return Ok(());
            }
            other => bail!("unknown validate-open-ended-inventory argument: {other}"),
        }
        i += 1;
    }

    let report = validate_current_inventory()?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out_path {
        let path = Path::new(&path);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(path, format!("{json}\n"))
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!(
            "open-ended inventory report written: {} rows={}",
            path.display(),
            report.row_count
        );
    } else {
        println!("{json}");
    }
    Ok(())
}

fn validate_deferred_parity_audit_cmd(args: &[String]) -> Result<()> {
    let mut config = DeferredParityAuditConfig::default();
    let mut out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--issues" => {
                i += 1;
                config.issues_jsonl =
                    Path::new(args.get(i).context("--issues requires a path")?).to_path_buf();
            }
            "--report" => {
                i += 1;
                config.report_markdown =
                    Path::new(args.get(i).context("--report requires a path")?).to_path_buf();
            }
            "--doc" => {
                i += 1;
                config
                    .docs
                    .push(Path::new(args.get(i).context("--doc requires a path")?).to_path_buf());
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--help" | "-h" => {
                print_deferred_parity_audit_usage();
                return Ok(());
            }
            other => bail!("unknown validate-deferred-parity-audit argument: {other}"),
        }
        i += 1;
    }

    let report = run_deferred_parity_audit(&config)?;
    fail_on_audit_errors(&report)?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out_path {
        let path = Path::new(&path);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(path, format!("{json}\n"))
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!(
            "deferred parity audit report written: {} rows={} findings={}",
            path.display(),
            report.registry_row_count,
            report.detected_gap_count
        );
    } else {
        println!("{json}");
    }
    Ok(())
}

fn validate_ambition_evidence_matrix_cmd(args: &[String]) -> Result<()> {
    let mut config = AmbitionEvidenceMatrixConfig::default();
    let mut out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--issues" => {
                i += 1;
                config.issues_jsonl =
                    Path::new(args.get(i).context("--issues requires a path")?).to_path_buf();
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--help" | "-h" => {
                print_ambition_evidence_matrix_usage();
                return Ok(());
            }
            other => bail!("unknown validate-ambition-evidence-matrix argument: {other}"),
        }
        i += 1;
    }

    if let Some(path) = &out_path {
        config.generated_artifact_paths = vec![path.clone()];
    }

    let report = run_ambition_evidence_matrix(&config)?;
    fail_on_ambition_evidence_matrix_errors(&report)?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out_path {
        let path = Path::new(&path);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(path, format!("{json}\n"))
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!(
            "ambition evidence matrix report written: {} rows={}",
            path.display(),
            report.row_count
        );
    } else {
        println!("{json}");
    }
    Ok(())
}

fn validate_mounted_write_matrix_cmd(args: &[String]) -> Result<()> {
    let mut matrix_path = DEFAULT_MATRIX_PATH.to_owned();
    let mut out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--matrix" => {
                i += 1;
                args.get(i)
                    .context("--matrix requires a path")?
                    .clone_into(&mut matrix_path);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--help" | "-h" => {
                print_mounted_write_matrix_usage();
                return Ok(());
            }
            other => bail!("unknown validate-mounted-write-matrix argument: {other}"),
        }
        i += 1;
    }

    let matrix = load_mounted_write_matrix(Path::new(&matrix_path))?;
    let report = validate_mounted_write_matrix(&matrix);
    fail_on_mounted_write_matrix_errors(&report)?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out_path {
        let path = Path::new(&path);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(path, format!("{json}\n"))
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!(
            "mounted write matrix report written: {} scenarios={}",
            path.display(),
            report.scenario_count
        );
    } else {
        println!("{json}");
    }
    Ok(())
}

fn fuse_capability_probe_cmd(args: &[String]) -> Result<()> {
    let mut out_path: Option<String> = None;
    let mut options = FuseHostProbeOptions::default();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--user-disabled" => options.user_disabled = true,
            "--default-permissions-eacces" => options.default_permissions_eacces = true,
            "--require-mount-probe" => options.mount_probe_required = true,
            "--mount-probe-exit" => {
                i += 1;
                options.mount_probe_exit = Some(parse_i32_arg(args.get(i), "--mount-probe-exit")?);
            }
            "--unmount-probe-exit" => {
                i += 1;
                options.unmount_probe_exit =
                    Some(parse_i32_arg(args.get(i), "--unmount-probe-exit")?);
            }
            "--help" | "-h" => {
                print_fuse_capability_probe_usage();
                return Ok(());
            }
            other => bail!("unknown fuse-capability-probe argument: {other}"),
        }
        i += 1;
    }

    let report = probe_host_fuse_capability(options);
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out_path {
        let path = Path::new(&path);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(path, format!("{json}\n"))
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!(
            "fuse capability report written: {} result={:?}",
            path.display(),
            report.result
        );
    } else {
        println!("{json}");
    }
    Ok(())
}

fn parse_i32_arg(value: Option<&String>, flag: &str) -> Result<i32> {
    value
        .with_context(|| format!("{flag} requires an integer"))?
        .parse()
        .with_context(|| format!("invalid integer for {flag}"))
}

fn generate_fixture(args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!(
            "usage: ffs-harness generate-fixture <image> [ext4-superblock|btrfs-superblock|region <offset> <len>]"
        );
    }

    let image_path = Path::new(&args[0]);
    let image_data =
        fs::read(image_path).with_context(|| format!("failed to read {}", image_path.display()))?;

    let kind = args.get(1).map_or("auto", String::as_str);

    let fixture = match kind {
        "ext4-superblock" => extract_ext4_superblock(&image_data)?,
        "btrfs-superblock" => extract_btrfs_superblock(&image_data)?,
        "region" => {
            let offset: usize = args
                .get(2)
                .context("region requires <offset>")?
                .parse()
                .context("invalid offset")?;
            let len: usize = args
                .get(3)
                .context("region requires <len>")?
                .parse()
                .context("invalid len")?;
            extract_region(&image_data, offset, len)?
        }
        "auto" => {
            // Try ext4 first, then btrfs.
            if let Ok(f) = extract_ext4_superblock(&image_data) {
                eprintln!("detected: ext4 superblock");
                f
            } else if let Ok(f) = extract_btrfs_superblock(&image_data) {
                eprintln!("detected: btrfs superblock");
                f
            } else {
                bail!("could not detect ext4 or btrfs superblock; use explicit mode");
            }
        }
        _ => bail!("unknown fixture kind: {kind}"),
    };

    println!("{}", serde_json::to_string_pretty(&fixture)?);
    Ok(())
}

fn run_crash_replay(args: &[String]) -> Result<()> {
    let mut config = CrashReplaySuiteConfig::default();
    let mut index = 0_usize;
    while index < args.len() {
        match args[index].as_str() {
            "--count" => {
                let raw = args.get(index + 1).context("--count requires a value")?;
                config.schedule_count = raw.parse().context("invalid --count value")?;
                index += 2;
            }
            "--seed" => {
                let raw = args.get(index + 1).context("--seed requires a value")?;
                config.base_seed = raw.parse().context("invalid --seed value")?;
                index += 2;
            }
            "--min-ops" => {
                let raw = args.get(index + 1).context("--min-ops requires a value")?;
                config.min_operations = raw.parse().context("invalid --min-ops value")?;
                index += 2;
            }
            "--max-ops" => {
                let raw = args.get(index + 1).context("--max-ops requires a value")?;
                config.max_operations = raw.parse().context("invalid --max-ops value")?;
                index += 2;
            }
            "--out" => {
                let raw = args.get(index + 1).context("--out requires a value")?;
                config.output_dir = Some(Path::new(raw).to_path_buf());
                index += 2;
            }
            other => {
                bail!("unknown run-crash-replay option: {other}");
            }
        }
    }

    let report = run_crash_replay_suite(&config)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if report.failed_schedules > 0 {
        bail!(
            "crash replay suite reported {} failing schedule(s)",
            report.failed_schedules
        );
    }
    Ok(())
}

fn run_fsx_stress_cmd(args: &[String]) -> Result<()> {
    let mut config = FsxStressConfig::default();
    let mut index = 0_usize;
    while index < args.len() {
        match args[index].as_str() {
            "--ops" => {
                let raw = args.get(index + 1).context("--ops requires a value")?;
                config.operation_count = raw.parse().context("invalid --ops value")?;
                index += 2;
            }
            "--seed" => {
                let raw = args.get(index + 1).context("--seed requires a value")?;
                config.seed = raw.parse().context("invalid --seed value")?;
                index += 2;
            }
            "--max-file-bytes" => {
                let raw = args
                    .get(index + 1)
                    .context("--max-file-bytes requires a value")?;
                config.max_file_size_bytes =
                    raw.parse().context("invalid --max-file-bytes value")?;
                index += 2;
            }
            "--corrupt-every" => {
                let raw = args
                    .get(index + 1)
                    .context("--corrupt-every requires a value")?;
                config.corruption_every_ops =
                    raw.parse().context("invalid --corrupt-every value")?;
                index += 2;
            }
            "--verify-every" => {
                let raw = args
                    .get(index + 1)
                    .context("--verify-every requires a value")?;
                config.full_verify_every_ops =
                    raw.parse().context("invalid --verify-every value")?;
                index += 2;
            }
            "--out" => {
                let raw = args.get(index + 1).context("--out requires a value")?;
                config.output_dir = Some(Path::new(raw).to_path_buf());
                index += 2;
            }
            other => {
                bail!("unknown run-fsx-stress option: {other}");
            }
        }
    }

    let report = run_fsx_stress(&config)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if !report.passed {
        bail!("fsx stress reported a mismatch");
    }
    Ok(())
}

fn print_usage() {
    println!("ffs-harness — fixture management and parity reporting");
    println!();
    println!("USAGE:");
    println!("  ffs-harness parity");
    println!("  ffs-harness check-fixtures");
    println!(
        "  ffs-harness generate-fixture <image> [ext4-superblock|btrfs-superblock|region <offset> <len>]"
    );
    println!(
        "  ffs-harness run-crash-replay [--count N] [--seed S] [--min-ops N] [--max-ops N] [--out DIR]"
    );
    println!(
        "  ffs-harness run-fsx-stress [--ops N] [--seed S] [--max-file-bytes N] [--corrupt-every N] [--verify-every N] [--out DIR]"
    );
    println!(
        "  ffs-harness xfstests-report --selected FILE --results-json FILE --junit-xml FILE [--check-log FILE --check-rc N --dry-run 0|1] [--allowlist-json FILE] [--baseline-json FILE] [--uniform-status STATUS --uniform-note NOTE]"
    );
    println!("  ffs-harness validate-operational-manifest <manifest.json>");
    println!(
        "  ffs-harness fuse-capability-probe [--out FILE] [--require-mount-probe] [--mount-probe-exit N] [--unmount-probe-exit N] [--user-disabled] [--default-permissions-eacces]"
    );
    println!("  ffs-harness validate-open-ended-inventory [--out FILE]");
    println!(
        "  ffs-harness validate-deferred-parity-audit [--issues FILE] [--report FILE] [--doc FILE] [--out FILE]"
    );
    println!("  ffs-harness validate-ambition-evidence-matrix [--issues FILE] [--out FILE]");
    println!("  ffs-harness validate-mounted-write-matrix [--matrix FILE] [--out FILE]");
    println!();
    println!("FIXTURE GENERATION:");
    println!("  Extracts sparse JSON fixtures from real filesystem images.");
    println!("  In 'auto' mode (default), detects ext4/btrfs and extracts the superblock.");
    println!("  Use 'region' mode to extract arbitrary byte ranges for group descriptors,");
    println!("  inodes, directory blocks, or any other metadata structure.");
    println!();
    println!("CRASH REPLAY:");
    println!("  Runs deterministic crash/replay schedules and emits a JSON summary.");
    println!("  Use --out DIR to persist schedule artifacts + repro pack.");
    println!();
    println!("FSX STRESS:");
    println!(
        "  Runs weighted fsx-style read/write/truncate/fsync/fallocate/punch-hole/reopen operations."
    );
    println!(
        "  Periodically injects corruption and verifies deterministic repair + full-file integrity."
    );
    println!();
    println!("EXAMPLES:");
    println!("  ffs-harness generate-fixture my_ext4.img > conformance/fixtures/my_ext4.json");
    println!(
        "  ffs-harness generate-fixture my_ext4.img region 2048 32 > conformance/fixtures/gd.json"
    );
    println!("  ffs-harness run-crash-replay --count 500 --out artifacts/crash_replay");
    println!("  ffs-harness run-fsx-stress --ops 100000 --seed 123 --out artifacts/fsx");
    println!(
        "  ffs-harness validate-operational-manifest artifacts/e2e/run/operational_manifest.json"
    );
    println!("  ffs-harness fuse-capability-probe --out artifacts/e2e/run/fuse_capability.json");
    println!(
        "  ffs-harness validate-open-ended-inventory --out artifacts/conformance/open_ended_inventory.json"
    );
    println!(
        "  ffs-harness validate-deferred-parity-audit --out artifacts/parity/deferred_parity_audit.json"
    );
    println!(
        "  ffs-harness validate-ambition-evidence-matrix --out artifacts/ambition/evidence_matrix.json"
    );
    println!(
        "  ffs-harness validate-mounted-write-matrix --out artifacts/e2e/mounted_write_matrix.json"
    );
}

fn print_fuse_capability_probe_usage() {
    println!("Usage: ffs-harness fuse-capability-probe [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --out FILE                         Write JSON report to FILE");
    println!("  --require-mount-probe              Treat missing mount probe exit as not checked");
    println!("  --mount-probe-exit N               Exit code from an actual mount probe");
    println!("  --unmount-probe-exit N             Exit code from an actual unmount probe");
    println!("  --user-disabled                    Classify FUSE lanes as intentionally disabled");
    println!(
        "  --default-permissions-eacces       Classify btrfs DefaultPermissions root-owned EACCES"
    );
}

fn print_open_ended_inventory_usage() {
    println!("Usage: ffs-harness validate-open-ended-inventory [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --out FILE                         Write JSON report to FILE");
}

fn print_deferred_parity_audit_usage() {
    println!("Usage: ffs-harness validate-deferred-parity-audit [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --issues FILE                      Read bead JSONL from FILE");
    println!("  --report FILE                      Read audit registry markdown from FILE");
    println!("  --doc FILE                         Check a public status doc; repeatable");
    println!("  --out FILE                         Write JSON report to FILE");
}

fn print_ambition_evidence_matrix_usage() {
    println!("Usage: ffs-harness validate-ambition-evidence-matrix [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --issues FILE                      Read bead JSONL from FILE");
    println!("  --out FILE                         Write JSON report to FILE");
}

fn print_mounted_write_matrix_usage() {
    println!("Usage: ffs-harness validate-mounted-write-matrix [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --matrix FILE                      Read matrix JSON from FILE");
    println!("  --out FILE                         Write JSON validation report to FILE");
}
