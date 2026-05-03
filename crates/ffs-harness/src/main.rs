#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use ffs_harness::{
    ParityReport,
    adversarial_threat_model::{
        build_adversarial_threat_model_sample_artifact_manifest,
        fail_on_adversarial_threat_model_errors, load_adversarial_threat_model,
        validate_adversarial_threat_model,
    },
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
    mounted_recovery_matrix::{
        DEFAULT_RECOVERY_MATRIX_PATH, fail_on_mounted_recovery_matrix_errors,
        load_mounted_recovery_matrix, validate_mounted_recovery_matrix,
    },
    mounted_write_matrix::{
        DEFAULT_MATRIX_PATH, fail_on_mounted_write_matrix_errors, load_mounted_write_matrix,
        validate_mounted_write_matrix,
    },
    open_ended_inventory::validate_current_inventory,
    operational_readiness_report::{
        OperationalReadinessReportConfig, build_operational_readiness_report,
        render_operational_readiness_markdown,
    },
    performance_baseline_manifest::{
        build_performance_sample_artifact_manifest, fail_on_performance_baseline_manifest_errors,
        load_performance_baseline_manifest, validate_performance_baseline_manifest,
    },
    proof_bundle::{
        ProofBundleValidationConfig, fail_on_proof_bundle_errors, render_proof_bundle_markdown,
        validate_proof_bundle,
    },
    proof_overhead_budget::{
        evaluate_proof_overhead_budget, fail_on_proof_overhead_budget_errors,
        load_observed_proof_metrics, load_proof_overhead_budget_config,
    },
    release_gate::{
        evaluate_release_gates, fail_on_release_gate_errors, load_release_gate_policy,
        render_release_gate_markdown,
    },
    repair_writeback_serialization::{
        build_repair_writeback_serialization_sample_artifact_manifest,
        fail_on_repair_writeback_serialization_errors,
        load_repair_writeback_serialization_contract,
        render_repair_writeback_serialization_markdown,
        validate_repair_writeback_serialization_contract,
    },
    soak_canary_campaign::{
        build_soak_canary_sample_artifact_manifest, fail_on_soak_canary_campaign_errors,
        load_soak_canary_campaign_manifest, render_soak_canary_campaign_markdown,
        validate_soak_canary_campaign_manifest,
    },
    support_state_accounting::{
        SupportStateAccountingConfig, fail_on_support_state_accounting_errors,
        render_support_state_markdown, run_support_state_accounting,
    },
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
        Some("validate-support-state-accounting") => {
            validate_support_state_accounting_cmd(&args[1..])
        }
        Some("validate-proof-overhead-budget") => validate_proof_overhead_budget_cmd(&args[1..]),
        Some("validate-proof-bundle") => validate_proof_bundle_cmd(&args[1..]),
        Some("evaluate-release-gates") => evaluate_release_gates_cmd(&args[1..]),
        Some("validate-performance-baseline-manifest") => {
            validate_performance_baseline_manifest_cmd(&args[1..])
        }
        Some("validate-adversarial-threat-model") => {
            validate_adversarial_threat_model_cmd(&args[1..])
        }
        Some("validate-soak-canary-campaigns") => validate_soak_canary_campaigns_cmd(&args[1..]),
        Some("validate-repair-writeback-serialization") => {
            validate_repair_writeback_serialization_cmd(&args[1..])
        }
        Some("operational-readiness-report") => operational_readiness_report_cmd(&args[1..]),
        Some("validate-mounted-write-matrix") => validate_mounted_write_matrix_cmd(&args[1..]),
        Some("validate-mounted-recovery-matrix") => {
            validate_mounted_recovery_matrix_cmd(&args[1..])
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadinessReportFormat {
    Json,
    Markdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProofBundleFormat {
    Json,
    Markdown,
}

#[derive(Debug)]
struct ReleaseGateCmdArgs {
    bundle_path: String,
    policy_path: String,
    current_git_sha: Option<String>,
    max_age_days: Option<u64>,
    out_path: Option<String>,
    wording_out_path: Option<String>,
    format: ProofBundleFormat,
}

#[derive(Debug)]
struct PerformanceManifestCmdArgs {
    manifest_path: String,
    artifact_root: String,
    out_path: Option<String>,
    artifact_out_path: Option<String>,
}

#[derive(Debug)]
struct AdversarialThreatModelCmdArgs {
    model_path: String,
    artifact_root: String,
    out_path: Option<String>,
    artifact_out_path: Option<String>,
    wording_out_path: Option<String>,
}

#[derive(Debug)]
struct SoakCanaryCampaignCmdArgs {
    manifest_path: String,
    artifact_root: String,
    out_path: Option<String>,
    artifact_out_path: Option<String>,
    summary_out_path: Option<String>,
}

#[derive(Debug)]
struct RepairWritebackSerializationCmdArgs {
    contract_path: String,
    artifact_root: String,
    out_path: Option<String>,
    artifact_out_path: Option<String>,
    summary_out_path: Option<String>,
}

fn operational_readiness_report_cmd(args: &[String]) -> Result<()> {
    let mut config = OperationalReadinessReportConfig::new("artifacts/e2e");
    let mut out_path: Option<String> = None;
    let mut format = ReadinessReportFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--artifacts" => {
                i += 1;
                config.artifacts_dir =
                    Path::new(args.get(i).context("--artifacts requires a path")?).to_path_buf();
            }
            "--current-git-sha" => {
                i += 1;
                config.current_git_sha = Some(
                    args.get(i)
                        .context("--current-git-sha requires a value")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format = parse_readiness_report_format(
                    args.get(i).context("--format requires json or markdown")?,
                )?;
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--help" | "-h" => {
                print_operational_readiness_report_usage();
                return Ok(());
            }
            other => bail!("unknown operational-readiness-report argument: {other}"),
        }
        i += 1;
    }

    let report = build_operational_readiness_report(&config)?;
    let output = match format {
        ReadinessReportFormat::Json => serde_json::to_string_pretty(&report)?,
        ReadinessReportFormat::Markdown => render_operational_readiness_markdown(&report),
    };

    if let Some(path) = out_path {
        let path = Path::new(&path);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(path, format!("{output}\n"))
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!(
            "operational readiness report written: {} scenarios={}",
            path.display(),
            report.scenario_count
        );
    } else {
        println!("{output}");
    }
    Ok(())
}

fn parse_readiness_report_format(raw: &str) -> Result<ReadinessReportFormat> {
    match raw {
        "json" => Ok(ReadinessReportFormat::Json),
        "markdown" | "md" => Ok(ReadinessReportFormat::Markdown),
        other => bail!("invalid --format value: {other}"),
    }
}

fn validate_proof_bundle_cmd(args: &[String]) -> Result<()> {
    let mut bundle_path: Option<String> = None;
    let mut current_git_sha: Option<String> = None;
    let mut max_age_days: Option<u64> = None;
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--bundle" => {
                i += 1;
                bundle_path = Some(args.get(i).context("--bundle requires a path")?.to_owned());
            }
            "--current-git-sha" => {
                i += 1;
                current_git_sha = Some(
                    args.get(i)
                        .context("--current-git-sha requires a value")?
                        .to_owned(),
                );
            }
            "--max-age-days" => {
                i += 1;
                max_age_days = Some(
                    args.get(i)
                        .context("--max-age-days requires a value")?
                        .parse()
                        .context("invalid --max-age-days value")?,
                );
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_proof_bundle_usage();
                return Ok(());
            }
            other => bail!("unknown validate-proof-bundle argument: {other}"),
        }
        i += 1;
    }

    let bundle_path = bundle_path.context("--bundle is required")?;
    let mut config = ProofBundleValidationConfig::new(&bundle_path);
    config.current_git_sha = current_git_sha;
    config.max_age_days = max_age_days;

    let report = validate_proof_bundle(&config)?;
    let output = match format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_proof_bundle_markdown(&report),
    };

    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "proof bundle report written: {} valid={} lanes={} artifacts={}",
            path, report.valid, report.totals.lanes, report.totals.artifacts
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = summary_out_path {
        let summary = render_proof_bundle_markdown(&report);
        write_text_file(Path::new(&path), &format!("{summary}\n"))?;
        println!("proof bundle summary written: {path}");
    }

    fail_on_proof_bundle_errors(&report)
}

fn parse_proof_bundle_format(raw: &str) -> Result<ProofBundleFormat> {
    match raw {
        "json" => Ok(ProofBundleFormat::Json),
        "markdown" | "md" => Ok(ProofBundleFormat::Markdown),
        other => bail!("invalid --format value: {other}"),
    }
}

fn evaluate_release_gates_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_release_gate_cmd_args(args)? else {
        return Ok(());
    };

    let mut bundle_config = ProofBundleValidationConfig::new(&cmd_args.bundle_path);
    bundle_config.current_git_sha = cmd_args.current_git_sha;
    bundle_config.max_age_days = cmd_args.max_age_days;

    let policy = load_release_gate_policy(Path::new(&cmd_args.policy_path))?;
    let proof_report = validate_proof_bundle(&bundle_config)?;
    let report = evaluate_release_gates(&policy, &proof_report);
    let output = match cmd_args.format {
        ProofBundleFormat::Json => serde_json::to_string_pretty(&report)?,
        ProofBundleFormat::Markdown => render_release_gate_markdown(&report),
    };

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "release gate report written: {} valid={} features={} findings={}",
            path,
            report.valid,
            report.feature_reports.len(),
            report.findings.len()
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.wording_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", release_gate_wording(&report)),
        )?;
        println!("release gate wording written: {path}");
    }

    fail_on_release_gate_errors(&report)
}

fn parse_release_gate_cmd_args(args: &[String]) -> Result<Option<ReleaseGateCmdArgs>> {
    let mut bundle_path: Option<String> = None;
    let mut policy_path: Option<String> = None;
    let mut current_git_sha: Option<String> = None;
    let mut max_age_days: Option<u64> = None;
    let mut out_path: Option<String> = None;
    let mut wording_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--bundle" => {
                i += 1;
                bundle_path = Some(args.get(i).context("--bundle requires a path")?.to_owned());
            }
            "--policy" => {
                i += 1;
                policy_path = Some(args.get(i).context("--policy requires a path")?.to_owned());
            }
            "--current-git-sha" => {
                i += 1;
                current_git_sha = Some(
                    args.get(i)
                        .context("--current-git-sha requires a value")?
                        .to_owned(),
                );
            }
            "--max-age-days" => {
                i += 1;
                max_age_days = Some(
                    args.get(i)
                        .context("--max-age-days requires a value")?
                        .parse()
                        .context("invalid --max-age-days value")?,
                );
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--wording-out" => {
                i += 1;
                wording_out_path = Some(
                    args.get(i)
                        .context("--wording-out requires a path")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_release_gate_usage();
                return Ok(None);
            }
            other => bail!("unknown evaluate-release-gates argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(ReleaseGateCmdArgs {
        bundle_path: bundle_path.context("--bundle is required for release gate evaluation")?,
        policy_path: policy_path.context("--policy is required for release gate evaluation")?,
        current_git_sha,
        max_age_days,
        out_path,
        wording_out_path,
        format,
    }))
}

fn release_gate_wording(report: &ffs_harness::release_gate::ReleaseGateEvaluationReport) -> String {
    report
        .generated_wording
        .iter()
        .map(|entry| {
            format!(
                "{}\t{}\t{}\t{}",
                entry.feature_id,
                entry.docs_wording_id,
                entry.state.label(),
                entry.wording
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn validate_performance_baseline_manifest_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_performance_manifest_cmd_args(args)? else {
        return Ok(());
    };
    let manifest = load_performance_baseline_manifest(Path::new(&cmd_args.manifest_path))?;
    let report = validate_performance_baseline_manifest(&manifest, &cmd_args.artifact_root);
    let output = serde_json::to_string_pretty(&report)?;

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "performance baseline manifest report written: {} valid={} workloads={}",
            path, report.valid, report.workload_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.artifact_out_path {
        let artifact_manifest =
            build_performance_sample_artifact_manifest(&manifest, &cmd_args.artifact_root);
        write_text_file(
            Path::new(&path),
            &format!("{}\n", serde_json::to_string_pretty(&artifact_manifest)?),
        )?;
        println!("performance baseline sample artifact manifest written: {path}");
    }

    fail_on_performance_baseline_manifest_errors(&report)
}

fn parse_performance_manifest_cmd_args(
    args: &[String],
) -> Result<Option<PerformanceManifestCmdArgs>> {
    let mut manifest_path: Option<String> = None;
    let mut artifact_root = "artifacts/performance/dry-run".to_owned();
    let mut out_path: Option<String> = None;
    let mut artifact_out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                manifest_path = Some(
                    args.get(i)
                        .context("--manifest requires a path")?
                        .to_owned(),
                );
            }
            "--artifact-root" => {
                i += 1;
                args.get(i)
                    .context("--artifact-root requires a path")?
                    .clone_into(&mut artifact_root);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--artifact-out" => {
                i += 1;
                artifact_out_path = Some(
                    args.get(i)
                        .context("--artifact-out requires a path")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_performance_manifest_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-performance-baseline-manifest argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(PerformanceManifestCmdArgs {
        manifest_path: manifest_path
            .context("--manifest is required for performance manifest validation")?,
        artifact_root,
        out_path,
        artifact_out_path,
    }))
}

fn validate_adversarial_threat_model_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_adversarial_threat_model_cmd_args(args)? else {
        return Ok(());
    };
    let model = load_adversarial_threat_model(Path::new(&cmd_args.model_path))?;
    let report = validate_adversarial_threat_model(&model, &cmd_args.artifact_root);
    let output = serde_json::to_string_pretty(&report)?;

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "adversarial threat model report written: {} valid={} scenarios={}",
            path, report.valid, report.scenario_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.artifact_out_path {
        let artifact_manifest = build_adversarial_threat_model_sample_artifact_manifest(
            &model,
            &cmd_args.artifact_root,
            &report.evaluated_scenarios,
        );
        write_text_file(
            Path::new(&path),
            &format!("{}\n", serde_json::to_string_pretty(&artifact_manifest)?),
        )?;
        println!("adversarial threat model sample artifact manifest written: {path}");
    }

    if let Some(path) = cmd_args.wording_out_path {
        write_text_file(Path::new(&path), &adversarial_threat_model_wording(&report))?;
        println!("adversarial threat model wording written: {path}");
    }

    fail_on_adversarial_threat_model_errors(&report)
}

fn adversarial_threat_model_wording(
    report: &ffs_harness::adversarial_threat_model::AdversarialThreatModelReport,
) -> String {
    let mut lines = report
        .generated_security_wording
        .iter()
        .map(|entry| {
            format!(
                "{}\t{}\t{}\t{}",
                entry.feature_id, entry.docs_wording_id, entry.state, entry.wording
            )
        })
        .collect::<Vec<_>>();
    lines.push(String::new());
    lines.join("\n")
}

fn parse_adversarial_threat_model_cmd_args(
    args: &[String],
) -> Result<Option<AdversarialThreatModelCmdArgs>> {
    let mut model_path: Option<String> = None;
    let mut artifact_root = "artifacts/security/dry-run".to_owned();
    let mut out_path: Option<String> = None;
    let mut artifact_out_path: Option<String> = None;
    let mut wording_out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--model" => {
                i += 1;
                model_path = Some(args.get(i).context("--model requires a path")?.to_owned());
            }
            "--artifact-root" => {
                i += 1;
                args.get(i)
                    .context("--artifact-root requires a path")?
                    .clone_into(&mut artifact_root);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--artifact-out" => {
                i += 1;
                artifact_out_path = Some(
                    args.get(i)
                        .context("--artifact-out requires a path")?
                        .to_owned(),
                );
            }
            "--wording-out" => {
                i += 1;
                wording_out_path = Some(
                    args.get(i)
                        .context("--wording-out requires a path")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_adversarial_threat_model_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-adversarial-threat-model argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(AdversarialThreatModelCmdArgs {
        model_path: model_path.context("--model is required for threat model validation")?,
        artifact_root,
        out_path,
        artifact_out_path,
        wording_out_path,
    }))
}

fn validate_soak_canary_campaigns_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_soak_canary_campaign_cmd_args(args)? else {
        return Ok(());
    };
    let manifest = load_soak_canary_campaign_manifest(Path::new(&cmd_args.manifest_path))?;
    let report = validate_soak_canary_campaign_manifest(&manifest, &cmd_args.artifact_root);
    let output = serde_json::to_string_pretty(&report)?;

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "soak/canary campaign report written: {} valid={} profiles={} workloads={}",
            path, report.valid, report.profile_count, report.workload_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.artifact_out_path {
        let artifact_manifest = build_soak_canary_sample_artifact_manifest(
            &manifest,
            &cmd_args.artifact_root,
            &report.failure_evaluations,
        );
        write_text_file(
            Path::new(&path),
            &format!("{}\n", serde_json::to_string_pretty(&artifact_manifest)?),
        )?;
        println!("soak/canary sample artifact manifest written: {path}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &render_soak_canary_campaign_markdown(&report),
        )?;
        println!("soak/canary campaign summary written: {path}");
    }

    fail_on_soak_canary_campaign_errors(&report)
}

fn parse_soak_canary_campaign_cmd_args(
    args: &[String],
) -> Result<Option<SoakCanaryCampaignCmdArgs>> {
    let mut manifest_path: Option<String> = None;
    let mut artifact_root = "artifacts/soak/dry-run".to_owned();
    let mut out_path: Option<String> = None;
    let mut artifact_out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                manifest_path = Some(
                    args.get(i)
                        .context("--manifest requires a path")?
                        .to_owned(),
                );
            }
            "--artifact-root" => {
                i += 1;
                args.get(i)
                    .context("--artifact-root requires a path")?
                    .clone_into(&mut artifact_root);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--artifact-out" => {
                i += 1;
                artifact_out_path = Some(
                    args.get(i)
                        .context("--artifact-out requires a path")?
                        .to_owned(),
                );
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_soak_canary_campaign_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-soak-canary-campaigns argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(SoakCanaryCampaignCmdArgs {
        manifest_path: manifest_path
            .context("--manifest is required for soak/canary campaign validation")?,
        artifact_root,
        out_path,
        artifact_out_path,
        summary_out_path,
    }))
}

fn validate_repair_writeback_serialization_cmd(args: &[String]) -> Result<()> {
    let Some(cmd_args) = parse_repair_writeback_serialization_cmd_args(args)? else {
        return Ok(());
    };
    let contract =
        load_repair_writeback_serialization_contract(Path::new(&cmd_args.contract_path))?;
    let report =
        validate_repair_writeback_serialization_contract(&contract, &cmd_args.artifact_root);
    let output = serde_json::to_string_pretty(&report)?;

    if let Some(path) = cmd_args.out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "repair/writeback serialization report written: {} valid={} scenarios={} transitions={}",
            path, report.valid, report.scenario_count, report.transition_count
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = cmd_args.artifact_out_path {
        let artifact_manifest = build_repair_writeback_serialization_sample_artifact_manifest(
            &contract,
            &cmd_args.artifact_root,
            &report,
        );
        write_text_file(
            Path::new(&path),
            &format!("{}\n", serde_json::to_string_pretty(&artifact_manifest)?),
        )?;
        println!("repair/writeback sample artifact manifest written: {path}");
    }

    if let Some(path) = cmd_args.summary_out_path {
        write_text_file(
            Path::new(&path),
            &render_repair_writeback_serialization_markdown(&report),
        )?;
        println!("repair/writeback serialization summary written: {path}");
    }

    fail_on_repair_writeback_serialization_errors(&report)
}

fn parse_repair_writeback_serialization_cmd_args(
    args: &[String],
) -> Result<Option<RepairWritebackSerializationCmdArgs>> {
    let mut contract_path: Option<String> = None;
    let mut artifact_root = "artifacts/repair-writeback/dry-run".to_owned();
    let mut out_path: Option<String> = None;
    let mut artifact_out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--contract" => {
                i += 1;
                contract_path = Some(
                    args.get(i)
                        .context("--contract requires a path")?
                        .to_owned(),
                );
            }
            "--artifact-root" => {
                i += 1;
                args.get(i)
                    .context("--artifact-root requires a path")?
                    .clone_into(&mut artifact_root);
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--artifact-out" => {
                i += 1;
                artifact_out_path = Some(
                    args.get(i)
                        .context("--artifact-out requires a path")?
                        .to_owned(),
                );
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--help" | "-h" => {
                print_repair_writeback_serialization_usage();
                return Ok(None);
            }
            other => bail!("unknown validate-repair-writeback-serialization argument: {other}"),
        }
        i += 1;
    }

    Ok(Some(RepairWritebackSerializationCmdArgs {
        contract_path: contract_path
            .context("--contract is required for repair/writeback serialization validation")?,
        artifact_root,
        out_path,
        artifact_out_path,
        summary_out_path,
    }))
}

fn validate_proof_overhead_budget_cmd(args: &[String]) -> Result<()> {
    let mut budget_path: Option<String> = None;
    let mut metrics_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--budget" => {
                i += 1;
                budget_path = Some(args.get(i).context("--budget requires a path")?.to_owned());
            }
            "--metrics" => {
                i += 1;
                metrics_path = Some(args.get(i).context("--metrics requires a path")?.to_owned());
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--help" | "-h" => {
                print_proof_overhead_budget_usage();
                return Ok(());
            }
            other => bail!("unknown validate-proof-overhead-budget argument: {other}"),
        }
        i += 1;
    }

    let budget = load_proof_overhead_budget_config(Path::new(
        budget_path.as_deref().context("--budget is required")?,
    ))?;
    let metrics = load_observed_proof_metrics(Path::new(
        metrics_path.as_deref().context("--metrics is required")?,
    ))?;
    let report = evaluate_proof_overhead_budget(&budget, &metrics);
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
            "proof overhead budget report written: {} verdict={}",
            path.display(),
            report.release_gate_verdict.label()
        );
    } else {
        println!("{json}");
    }

    fail_on_proof_overhead_budget_errors(&report)
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

fn write_text_file(path: &Path, text: &str) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, text).with_context(|| format!("failed to write {}", path.display()))
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

fn validate_support_state_accounting_cmd(args: &[String]) -> Result<()> {
    let mut config = SupportStateAccountingConfig::default();
    let mut out_path: Option<String> = None;
    let mut summary_out_path: Option<String> = None;
    let mut format = ProofBundleFormat::Json;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--issues" => {
                i += 1;
                config.issues_jsonl =
                    Path::new(args.get(i).context("--issues requires a path")?).to_path_buf();
            }
            "--feature-parity" => {
                i += 1;
                config.feature_parity_markdown =
                    Path::new(args.get(i).context("--feature-parity requires a path")?)
                        .to_path_buf();
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).context("--out requires a path")?.to_owned());
            }
            "--summary-out" => {
                i += 1;
                summary_out_path = Some(
                    args.get(i)
                        .context("--summary-out requires a path")?
                        .to_owned(),
                );
            }
            "--format" => {
                i += 1;
                format =
                    parse_proof_bundle_format(args.get(i).context("--format requires a value")?)?;
            }
            "--help" | "-h" => {
                print_support_state_accounting_usage();
                return Ok(());
            }
            other => bail!("unknown validate-support-state-accounting argument: {other}"),
        }
        i += 1;
    }

    config.generated_artifact_paths = match (&out_path, &summary_out_path) {
        (Some(json), Some(markdown)) => vec![json.clone(), markdown.clone()],
        (Some(json), None) => vec![json.clone()],
        (None, Some(markdown)) => vec![markdown.clone()],
        (None, None) => config.generated_artifact_paths,
    };

    let report = run_support_state_accounting(&config)?;
    fail_on_support_state_accounting_errors(&report)?;
    let json = serde_json::to_string_pretty(&report)?;
    let output = match format {
        ProofBundleFormat::Json => json,
        ProofBundleFormat::Markdown => render_support_state_markdown(&report),
    };
    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "support-state accounting report written: {} rows={} states={}",
            path,
            report.row_count,
            report.grouped_by_support_state.len()
        );
    } else {
        println!("{output}");
    }

    if let Some(path) = summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_support_state_markdown(&report)),
        )?;
        println!("support-state accounting markdown written: {path}");
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

fn validate_mounted_recovery_matrix_cmd(args: &[String]) -> Result<()> {
    let mut matrix_path = DEFAULT_RECOVERY_MATRIX_PATH.to_owned();
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
                print_mounted_recovery_matrix_usage();
                return Ok(());
            }
            other => bail!("unknown validate-mounted-recovery-matrix argument: {other}"),
        }
        i += 1;
    }

    let matrix = load_mounted_recovery_matrix(Path::new(&matrix_path))?;
    let report = validate_mounted_recovery_matrix(&matrix);
    fail_on_mounted_recovery_matrix_errors(&report)?;
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
            "mounted recovery matrix report written: {} scenarios={}",
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
        "  ffs-harness operational-readiness-report [--artifacts DIR] [--current-git-sha SHA] [--format json|markdown] [--out FILE]"
    );
    println!(
        "  ffs-harness fuse-capability-probe [--out FILE] [--require-mount-probe] [--mount-probe-exit N] [--unmount-probe-exit N] [--user-disabled] [--default-permissions-eacces]"
    );
    println!("  ffs-harness validate-open-ended-inventory [--out FILE]");
    println!(
        "  ffs-harness validate-deferred-parity-audit [--issues FILE] [--report FILE] [--doc FILE] [--out FILE]"
    );
    println!("  ffs-harness validate-ambition-evidence-matrix [--issues FILE] [--out FILE]");
    println!(
        "  ffs-harness validate-support-state-accounting [--issues FILE] [--feature-parity FILE] [--out FILE] [--summary-out FILE]"
    );
    println!(
        "  ffs-harness validate-proof-overhead-budget --budget FILE --metrics FILE [--out FILE]"
    );
    println!(
        "  ffs-harness validate-proof-bundle --bundle FILE [--current-git-sha SHA] [--max-age-days N] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
    println!(
        "  ffs-harness evaluate-release-gates --bundle FILE --policy FILE [--current-git-sha SHA] [--max-age-days N] [--format json|markdown] [--out FILE] [--wording-out FILE]"
    );
    print_performance_baseline_manifest_usage_summary();
    print_adversarial_threat_model_usage_summary();
    print_soak_canary_campaign_usage_summary();
    print_repair_writeback_serialization_usage_summary();
    println!("  ffs-harness validate-mounted-write-matrix [--matrix FILE] [--out FILE]");
    println!("  ffs-harness validate-mounted-recovery-matrix [--matrix FILE] [--out FILE]");
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
    print_usage_examples();
}

fn print_usage_examples() {
    println!("  ffs-harness generate-fixture my_ext4.img > conformance/fixtures/my_ext4.json");
    println!(
        "  ffs-harness generate-fixture my_ext4.img region 2048 32 > conformance/fixtures/gd.json"
    );
    println!("  ffs-harness run-crash-replay --count 500 --out artifacts/crash_replay");
    println!("  ffs-harness run-fsx-stress --ops 100000 --seed 123 --out artifacts/fsx");
    println!(
        "  ffs-harness validate-operational-manifest artifacts/e2e/run/operational_manifest.json"
    );
    println!(
        "  ffs-harness operational-readiness-report --artifacts artifacts/e2e --format markdown --out artifacts/e2e/readiness.md"
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
        "  ffs-harness validate-support-state-accounting --out artifacts/parity/support_state_accounting.json --summary-out artifacts/parity/support_state_accounting.md"
    );
    println!(
        "  ffs-harness validate-proof-overhead-budget --budget artifacts/proof/budget.json --metrics artifacts/proof/metrics.json --out artifacts/proof/budget_report.json"
    );
    println!(
        "  ffs-harness validate-proof-bundle --bundle artifacts/proof/bundle/manifest.json --out artifacts/proof/bundle/report.json --summary-out artifacts/proof/bundle/summary.md"
    );
    println!(
        "  ffs-harness evaluate-release-gates --bundle artifacts/proof/bundle/manifest.json --policy artifacts/proof/release_gate_policy.json --out artifacts/proof/release_gate.json --wording-out artifacts/proof/release_gate_wording.tsv"
    );
    print_performance_baseline_manifest_example();
    print_adversarial_threat_model_example();
    print_soak_canary_campaign_example();
    print_repair_writeback_serialization_example();
    println!(
        "  ffs-harness validate-mounted-write-matrix --out artifacts/e2e/mounted_write_matrix.json"
    );
    println!(
        "  ffs-harness validate-mounted-recovery-matrix --out artifacts/e2e/mounted_recovery_matrix.json"
    );
}

fn print_performance_baseline_manifest_usage_summary() {
    println!(
        "  ffs-harness validate-performance-baseline-manifest --manifest FILE [--artifact-root DIR] [--out FILE] [--artifact-out FILE]"
    );
}

fn print_performance_baseline_manifest_example() {
    println!(
        "  ffs-harness validate-performance-baseline-manifest --manifest benchmarks/performance_baseline_manifest.json --out artifacts/performance/manifest_report.json --artifact-out artifacts/performance/sample_artifact_manifest.json"
    );
}

fn print_adversarial_threat_model_usage_summary() {
    println!(
        "  ffs-harness validate-adversarial-threat-model --model FILE [--artifact-root DIR] [--out FILE] [--artifact-out FILE] [--wording-out FILE]"
    );
}

fn print_adversarial_threat_model_example() {
    println!(
        "  ffs-harness validate-adversarial-threat-model --model security/adversarial_image_threat_model.json --out artifacts/security/threat_model_report.json --artifact-out artifacts/security/sample_artifact_manifest.json --wording-out artifacts/security/security_wording.tsv"
    );
}

fn print_soak_canary_campaign_usage_summary() {
    println!(
        "  ffs-harness validate-soak-canary-campaigns --manifest FILE [--artifact-root DIR] [--out FILE] [--artifact-out FILE] [--summary-out FILE]"
    );
}

fn print_soak_canary_campaign_example() {
    println!(
        "  ffs-harness validate-soak-canary-campaigns --manifest benchmarks/soak_canary_campaign_manifest.json --out artifacts/soak/campaign_report.json --artifact-out artifacts/soak/sample_artifact_manifest.json --summary-out artifacts/soak/campaign_summary.md"
    );
}

fn print_repair_writeback_serialization_usage_summary() {
    println!(
        "  ffs-harness validate-repair-writeback-serialization --contract FILE [--artifact-root DIR] [--out FILE] [--artifact-out FILE] [--summary-out FILE]"
    );
}

fn print_repair_writeback_serialization_example() {
    println!(
        "  ffs-harness validate-repair-writeback-serialization --contract docs/repair-writeback-serialization-contract.json --out artifacts/repair-writeback/contract_report.json --artifact-out artifacts/repair-writeback/sample_artifact_manifest.json --summary-out artifacts/repair-writeback/contract_summary.md"
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

fn print_operational_readiness_report_usage() {
    println!("Usage: ffs-harness operational-readiness-report [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --artifacts DIR                    Read manifest/result JSON under DIR");
    println!("  --current-git-sha SHA              Flag sources captured from a different SHA");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write report to FILE");
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

fn print_support_state_accounting_usage() {
    println!("Usage: ffs-harness validate-support-state-accounting [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --issues FILE                      Read bead JSONL from FILE");
    println!("  --feature-parity FILE              Read FEATURE_PARITY markdown from FILE");
    println!("  --format json|markdown             Output format (default: json)");
    println!(
        "  --out FILE                         Write selected-format support-state report to FILE"
    );
    println!("  --summary-out FILE                 Write Markdown inspection summary");
}

fn print_proof_overhead_budget_usage() {
    println!("Usage: ffs-harness validate-proof-overhead-budget [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --budget FILE                      Read proof overhead budget schema JSON");
    println!("  --metrics FILE                     Read observed proof workflow metrics JSON");
    println!("  --out FILE                         Write JSON release-gate report to FILE");
}

fn print_proof_bundle_usage() {
    println!("Usage: ffs-harness validate-proof-bundle [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --bundle FILE                      Read proof bundle manifest JSON");
    println!("  --current-git-sha SHA              Flag manifest captured from a different SHA");
    println!("  --max-age-days N                   Fail when generated_at is older than N days");
    println!("  --format json|markdown             Output format (default: json)");
    println!(
        "  --out FILE                         Write selected-format validation report to FILE"
    );
    println!("  --summary-out FILE                 Write Markdown inspection summary to FILE");
}

fn print_release_gate_usage() {
    println!("Usage: ffs-harness evaluate-release-gates [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --bundle FILE                      Read proof bundle manifest JSON");
    println!("  --policy FILE                      Read release-gate policy JSON");
    println!("  --current-git-sha SHA              Fail when bundle SHA differs");
    println!("  --max-age-days N                   Fail when bundle generated_at is stale");
    println!("  --format json|markdown             Output format (default: json)");
    println!("  --out FILE                         Write release-gate report to FILE");
    println!("  --wording-out FILE                 Write generated docs-safe wording TSV");
}

fn print_performance_manifest_usage() {
    println!("Usage: ffs-harness validate-performance-baseline-manifest [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --manifest FILE                    Read performance baseline manifest JSON");
    println!("  --artifact-root DIR                Root for dry-run expanded artifacts");
    println!("  --out FILE                         Write validation report JSON");
    println!("  --artifact-out FILE                Write sample shared QA artifact manifest JSON");
}

fn print_adversarial_threat_model_usage() {
    println!("Usage: ffs-harness validate-adversarial-threat-model [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --model FILE                       Read adversarial threat model JSON");
    println!("  --artifact-root DIR                Root for dry-run security artifacts");
    println!("  --out FILE                         Write validation report JSON");
    println!("  --artifact-out FILE                Write sample shared QA artifact manifest JSON");
    println!("  --wording-out FILE                 Write generated docs-safe wording TSV");
}

fn print_soak_canary_campaign_usage() {
    println!("Usage: ffs-harness validate-soak-canary-campaigns [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --manifest FILE                    Read soak/canary campaign manifest JSON");
    println!("  --artifact-root DIR                Root for dry-run campaign artifacts");
    println!("  --out FILE                         Write validation report JSON");
    println!("  --artifact-out FILE                Write sample shared QA artifact manifest JSON");
    println!("  --summary-out FILE                 Write Markdown campaign summary");
}

fn print_repair_writeback_serialization_usage() {
    println!("Usage: ffs-harness validate-repair-writeback-serialization [OPTIONS]");
    println!();
    println!("Options:");
    println!(
        "  --contract FILE                    Read repair/writeback serialization contract JSON"
    );
    println!("  --artifact-root DIR                Root for dry-run serialization artifacts");
    println!("  --out FILE                         Write validation report JSON");
    println!("  --artifact-out FILE                Write sample shared QA artifact manifest JSON");
    println!("  --summary-out FILE                 Write Markdown contract summary");
}

fn print_mounted_write_matrix_usage() {
    println!("Usage: ffs-harness validate-mounted-write-matrix [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --matrix FILE                      Read matrix JSON from FILE");
    println!("  --out FILE                         Write JSON validation report to FILE");
}

fn print_mounted_recovery_matrix_usage() {
    println!("Usage: ffs-harness validate-mounted-recovery-matrix [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --matrix FILE                      Read mounted recovery matrix JSON from FILE");
    println!("  --out FILE                         Write JSON validation report to FILE");
}
