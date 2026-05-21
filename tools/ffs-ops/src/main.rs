#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use ffs_harness::{
    ambition_evidence_matrix::{
        AmbitionEvidenceMatrixConfig, fail_on_ambition_evidence_matrix_errors,
        run_ambition_evidence_matrix,
    },
    artifact_manifest::parse_manifest_timestamp_epoch_days,
    docs_status_drift::{
        DocsStatusDriftConfig, fail_on_docs_status_drift_errors, render_docs_status_drift_markdown,
        run_docs_status_drift,
    },
    open_ended_inventory::{
        DEFAULT_SOURCE_SCOPE_MANIFEST_PATH, OpenEndedNoteSource, load_source_scope_manifest,
        scan_open_ended_notes, scan_source_scope_manifest, validate_current_inventory,
    },
    permissioned_campaign_broker::{
        DEFAULT_PERMISSIONED_CAMPAIGN_BROKER_MANIFEST, PermissionedCampaignBrokerValidationConfig,
        PermissionedCampaignExecutionLedgerValidationConfig, PermissionedCampaignHandoffGeneration,
        SwarmCapabilityCalibrationValidationConfig, fail_on_permissioned_campaign_broker_errors,
        fail_on_permissioned_campaign_execution_ledger_errors,
        fail_on_swarm_capability_calibration_errors, generate_permissioned_campaign_handoff_packet,
        load_permissioned_campaign_broker_manifest, load_permissioned_campaign_execution_ledger,
        load_swarm_capability_calibration_manifest, render_permissioned_campaign_broker_markdown,
        render_permissioned_campaign_execution_ledger_markdown,
        render_permissioned_campaign_handoff_markdown,
        render_swarm_capability_calibration_markdown,
        validate_permissioned_campaign_broker_manifest,
        validate_permissioned_campaign_execution_ledger,
        validate_swarm_capability_calibration_manifest,
    },
    readiness_action_autopilot::{
        ReadinessActionDryRunMetadata, ReadinessActionDryRunOutputPath,
        ReadinessActionDryRunReport, ReadinessActionPlanningInput,
        build_readiness_action_dry_run_report, default_readiness_action_autopilot_fixture_set,
        render_readiness_action_dry_run_markdown,
    },
    report_schema_inventory::{
        current_report_schema_inventory, fail_on_report_schema_inventory_errors,
        render_report_schema_inventory_markdown, validate_report_schema_inventory,
    },
};
use std::env;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Json,
    Markdown,
}

#[derive(Debug)]
struct ReadinessActionsArgs {
    input_path: Option<String>,
    out_json_path: String,
    out_markdown_path: String,
    stdout_log_path: String,
    stderr_log_path: String,
    report_id: Option<String>,
    generated_at: Option<String>,
    invocation: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let Some((command, rest)) = args.split_first() else {
        print_usage();
        return Ok(());
    };
    match command.as_str() {
        "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        "validate-ambition-evidence-matrix" => validate_ambition_evidence_matrix_cmd(rest),
        "recommend-readiness-actions" => recommend_readiness_actions_cmd(rest),
        "validate-open-ended-inventory" => validate_open_ended_inventory_cmd(rest),
        "open-ended-note-scanner" => open_ended_note_scanner_cmd(rest),
        "validate-source-scope-manifest" => validate_source_scope_manifest_cmd(rest),
        "validate-docs-status-drift" => validate_docs_status_drift_cmd(rest),
        "validate-report-schema-inventory" => validate_report_schema_inventory_cmd(rest),
        "validate-permissioned-campaign-broker" => validate_permissioned_campaign_broker_cmd(rest),
        "validate-permissioned-campaign-ledger" => validate_permissioned_campaign_ledger_cmd(rest),
        "generate-permissioned-campaign-packet" => generate_permissioned_campaign_packet_cmd(rest),
        "validate-swarm-capability-calibration" => validate_swarm_capability_calibration_cmd(rest),
        other => bail!("unknown ffs-ops command: {other}"),
    }
}

fn validate_open_ended_inventory_cmd(args: &[String]) -> Result<()> {
    let mut out_path = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                out_path = Some(require_value(args, i, "--out")?.to_owned());
                i += 2;
            }
            "--help" | "-h" => {
                print_open_ended_inventory_usage();
                return Ok(());
            }
            other => bail!("unknown validate-open-ended-inventory argument: {other}"),
        }
    }

    let report = validate_current_inventory()?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{json}\n"))?;
        println!(
            "open-ended inventory report written: {} rows={}",
            path, report.row_count
        );
    } else {
        println!("{json}");
    }
    Ok(())
}

fn open_ended_note_scanner_cmd(args: &[String]) -> Result<()> {
    let mut source_paths = Vec::new();
    let mut out_path = None;
    let mut allow_invalid = false;
    let mut reproduction_command = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--source" => {
                source_paths.push(require_value(args, i, "--source")?.to_owned());
                i += 2;
            }
            "--out" => {
                out_path = Some(require_value(args, i, "--out")?.to_owned());
                i += 2;
            }
            "--allow-invalid" => {
                allow_invalid = true;
                i += 1;
            }
            "--reproduction-command" => {
                reproduction_command =
                    Some(require_value(args, i, "--reproduction-command")?.to_owned());
                i += 2;
            }
            "--help" | "-h" => {
                print_open_ended_note_scanner_usage();
                return Ok(());
            }
            other => bail!("unknown open-ended-note-scanner argument: {other}"),
        }
    }
    if source_paths.is_empty() {
        bail!("open-ended-note-scanner requires at least one --source FILE");
    }

    let sources = source_paths
        .iter()
        .map(|source_path| {
            fs::read_to_string(source_path)
                .with_context(|| format!("failed to read {source_path}"))
                .map(|text| OpenEndedNoteSource {
                    source_path: source_path.clone(),
                    text,
                })
        })
        .collect::<Result<Vec<_>>>()?;
    let output_path = out_path.as_deref().unwrap_or("stdout");
    let reproduction_command = reproduction_command.unwrap_or_else(|| {
        open_ended_note_scanner_reproduction_command(&source_paths, out_path.as_deref())
    });
    let report = scan_open_ended_notes(&sources, output_path, &reproduction_command);
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{json}\n"))?;
        println!(
            "open-ended note scan report written: {} matches={} unresolved={} valid={}",
            path, report.match_count, report.unresolved_note_count, report.valid
        );
    } else {
        println!("{json}");
    }

    if !report.valid && !allow_invalid {
        bail!(
            "open-ended note scanner failed: {}",
            report.errors.join("; ")
        );
    }
    Ok(())
}

fn validate_source_scope_manifest_cmd(args: &[String]) -> Result<()> {
    let mut manifest_path = DEFAULT_SOURCE_SCOPE_MANIFEST_PATH.to_owned();
    let mut workspace_root = ".".to_owned();
    let mut out_path = None;
    let mut remove_source_family = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                manifest_path = require_value(args, i, "--manifest")?.to_owned();
                i += 2;
            }
            "--workspace-root" => {
                workspace_root = require_value(args, i, "--workspace-root")?.to_owned();
                i += 2;
            }
            "--out" => {
                out_path = Some(require_value(args, i, "--out")?.to_owned());
                i += 2;
            }
            "--remove-source-family" => {
                remove_source_family =
                    Some(require_value(args, i, "--remove-source-family")?.to_owned());
                i += 2;
            }
            "--help" | "-h" => {
                print_source_scope_manifest_usage();
                return Ok(());
            }
            other => bail!("unknown validate-source-scope-manifest argument: {other}"),
        }
    }

    let mut manifest = load_source_scope_manifest(&manifest_path)?;
    if let Some(source_family) = &remove_source_family {
        manifest
            .sources
            .retain(|entry| entry.source_family != *source_family);
    }
    let out = out_path.as_deref().map(Path::new);
    let reproduction_command = format!(
        "cargo run -p ffs-ops -- validate-source-scope-manifest --manifest {manifest_path} --workspace-root {workspace_root}"
    );
    let report = scan_source_scope_manifest(
        &manifest,
        Path::new(&workspace_root),
        out,
        &reproduction_command,
    );
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out {
        write_text_file(path, &format!("{json}\n"))?;
        println!(
            "source scope manifest report written: {} sources={} valid={}",
            path.display(),
            report.source_count,
            report.valid
        );
    } else {
        println!("{json}");
    }
    if !report.valid {
        bail!(
            "source scope manifest failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(())
}

fn validate_ambition_evidence_matrix_cmd(args: &[String]) -> Result<()> {
    let mut config = AmbitionEvidenceMatrixConfig::default();
    let mut out_path = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--issues" => {
                config.issues_jsonl = Path::new(require_value(args, i, "--issues")?).to_path_buf();
                i += 2;
            }
            "--out" => {
                out_path = Some(require_value(args, i, "--out")?.to_owned());
                i += 2;
            }
            "--help" | "-h" => {
                print_ambition_evidence_matrix_usage();
                return Ok(());
            }
            other => bail!("unknown validate-ambition-evidence-matrix argument: {other}"),
        }
    }
    if let Some(path) = &out_path {
        config.generated_artifact_paths = vec![path.clone()];
    }

    let report = run_ambition_evidence_matrix(&config)?;
    fail_on_ambition_evidence_matrix_errors(&report)?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{json}\n"))?;
        println!(
            "ambition evidence matrix report written: {} rows={}",
            path, report.row_count
        );
    } else {
        println!("{json}");
    }
    Ok(())
}

fn validate_docs_status_drift_cmd(args: &[String]) -> Result<()> {
    let mut config = DocsStatusDriftConfig::default();
    let mut out_path = None;
    let mut summary_out_path = None;
    let mut format = OutputFormat::Json;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--issues" => {
                config.issues_jsonl = Path::new(require_value(args, i, "--issues")?).to_path_buf();
                i += 2;
            }
            "--feature-parity" => {
                config.feature_parity_markdown =
                    Path::new(require_value(args, i, "--feature-parity")?).to_path_buf();
                i += 2;
            }
            "--snippets" => {
                config.snippets_json =
                    Some(Path::new(require_value(args, i, "--snippets")?).to_path_buf());
                i += 2;
            }
            "--out" => {
                out_path = Some(require_value(args, i, "--out")?.to_owned());
                i += 2;
            }
            "--summary-out" => {
                summary_out_path = Some(require_value(args, i, "--summary-out")?.to_owned());
                i += 2;
            }
            "--format" => {
                format = parse_output_format(require_value(args, i, "--format")?)?;
                i += 2;
            }
            "--help" | "-h" => {
                print_docs_status_drift_usage();
                return Ok(());
            }
            other => bail!("unknown validate-docs-status-drift argument: {other}"),
        }
    }
    config.generated_artifact_paths = generated_paths(&out_path, &summary_out_path);

    let report = run_docs_status_drift(&config)?;
    let json = serde_json::to_string_pretty(&report)?;
    let output = match format {
        OutputFormat::Json => json,
        OutputFormat::Markdown => render_docs_status_drift_markdown(&report),
    };
    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "docs status drift report written: {} rules={} observations={} release_gate_pass={}",
            path, report.rule_count, report.observation_count, report.release_gate_pass
        );
    } else {
        println!("{output}");
    }
    if let Some(path) = summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_docs_status_drift_markdown(&report)),
        )?;
        println!("docs status drift markdown written: {path}");
    }
    fail_on_docs_status_drift_errors(&report)
}

fn validate_report_schema_inventory_cmd(args: &[String]) -> Result<()> {
    let mut out_path = None;
    let mut summary_out_path = None;
    let mut format = OutputFormat::Json;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                out_path = Some(require_value(args, i, "--out")?.to_owned());
                i += 2;
            }
            "--summary-out" => {
                summary_out_path = Some(require_value(args, i, "--summary-out")?.to_owned());
                i += 2;
            }
            "--format" => {
                format = parse_output_format(require_value(args, i, "--format")?)?;
                i += 2;
            }
            "--help" | "-h" => {
                print_report_schema_inventory_usage();
                return Ok(());
            }
            other => bail!("unknown validate-report-schema-inventory argument: {other}"),
        }
    }

    let inventory = current_report_schema_inventory();
    let report = validate_report_schema_inventory(&inventory);
    let output = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&report)?,
        OutputFormat::Markdown => render_report_schema_inventory_markdown(&report),
    };
    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "report schema inventory written: {} valid={} rows={} product_evidence_claim={}",
            path, report.valid, report.total_rows, report.product_evidence_claim
        );
    } else {
        println!("{output}");
    }
    if let Some(path) = summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!("{}\n", render_report_schema_inventory_markdown(&report)),
        )?;
        println!("report schema inventory summary written: {path}");
    }
    fail_on_report_schema_inventory_errors(&report)
}

fn validate_permissioned_campaign_broker_cmd(args: &[String]) -> Result<()> {
    let mut manifest_path = DEFAULT_PERMISSIONED_CAMPAIGN_BROKER_MANIFEST.to_owned();
    let mut out_path = None;
    let mut summary_out_path = None;
    let mut format = OutputFormat::Json;
    let mut reference_timestamp = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                manifest_path = require_value(args, i, "--manifest")?.to_owned();
                i += 2;
            }
            "--out" => {
                out_path = Some(require_value(args, i, "--out")?.to_owned());
                i += 2;
            }
            "--summary-out" => {
                summary_out_path = Some(require_value(args, i, "--summary-out")?.to_owned());
                i += 2;
            }
            "--format" => {
                format = parse_output_format(require_value(args, i, "--format")?)?;
                i += 2;
            }
            "--reference-timestamp" => {
                reference_timestamp =
                    Some(require_value(args, i, "--reference-timestamp")?.to_owned());
                i += 2;
            }
            "--help" | "-h" => {
                print_permissioned_campaign_broker_usage();
                return Ok(());
            }
            other => bail!("unknown validate-permissioned-campaign-broker argument: {other}"),
        }
    }

    let manifest = load_permissioned_campaign_broker_manifest(Path::new(&manifest_path))?;
    let reference_epoch_days = reference_epoch_days(
        reference_timestamp.as_deref(),
        PermissionedCampaignBrokerValidationConfig::with_current_reference().reference_epoch_days,
    )?;
    let report = validate_permissioned_campaign_broker_manifest(
        &manifest,
        &PermissionedCampaignBrokerValidationConfig {
            reference_epoch_days,
        },
    );
    let output = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&report)?,
        OutputFormat::Markdown => render_permissioned_campaign_broker_markdown(&report),
    };
    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "permissioned campaign broker report written: {} valid={} issues={}",
            path, report.valid, report.issue_count
        );
    } else {
        println!("{output}");
    }
    if let Some(path) = summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!(
                "{}\n",
                render_permissioned_campaign_broker_markdown(&report)
            ),
        )?;
        println!("permissioned campaign broker summary written: {path}");
    }
    fail_on_permissioned_campaign_broker_errors(&report)
}

fn validate_permissioned_campaign_ledger_cmd(args: &[String]) -> Result<()> {
    let mut manifest_path = DEFAULT_PERMISSIONED_CAMPAIGN_BROKER_MANIFEST.to_owned();
    let mut ledger_path = None;
    let mut out_path = None;
    let mut summary_out_path = None;
    let mut format = OutputFormat::Json;
    let mut current_git_sha = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                manifest_path = require_value(args, i, "--manifest")?.to_owned();
                i += 2;
            }
            "--ledger" => {
                ledger_path = Some(require_value(args, i, "--ledger")?.to_owned());
                i += 2;
            }
            "--out" => {
                out_path = Some(require_value(args, i, "--out")?.to_owned());
                i += 2;
            }
            "--summary-out" => {
                summary_out_path = Some(require_value(args, i, "--summary-out")?.to_owned());
                i += 2;
            }
            "--format" => {
                format = parse_output_format(require_value(args, i, "--format")?)?;
                i += 2;
            }
            "--current-git-sha" => {
                current_git_sha = Some(require_value(args, i, "--current-git-sha")?.to_owned());
                i += 2;
            }
            "--help" | "-h" => {
                print_permissioned_campaign_ledger_usage();
                return Ok(());
            }
            other => bail!("unknown validate-permissioned-campaign-ledger argument: {other}"),
        }
    }

    let ledger_path = ledger_path.context("--ledger is required")?;
    let manifest = load_permissioned_campaign_broker_manifest(Path::new(&manifest_path))?;
    let ledger = load_permissioned_campaign_execution_ledger(Path::new(&ledger_path))?;
    let report = validate_permissioned_campaign_execution_ledger(
        &manifest,
        &ledger,
        &PermissionedCampaignExecutionLedgerValidationConfig { current_git_sha },
    );
    let output = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&report)?,
        OutputFormat::Markdown => render_permissioned_campaign_execution_ledger_markdown(&report),
    };
    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "permissioned campaign execution ledger report written: {} valid={} issues={}",
            path, report.valid, report.issue_count
        );
    } else {
        println!("{output}");
    }
    if let Some(path) = summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!(
                "{}\n",
                render_permissioned_campaign_execution_ledger_markdown(&report)
            ),
        )?;
        println!("permissioned campaign execution ledger summary written: {path}");
    }
    fail_on_permissioned_campaign_execution_ledger_errors(&report)
}

fn generate_permissioned_campaign_packet_cmd(args: &[String]) -> Result<()> {
    let mut manifest_path = DEFAULT_PERMISSIONED_CAMPAIGN_BROKER_MANIFEST.to_owned();
    let mut out_path = None;
    let mut summary_out_path = None;
    let mut format = OutputFormat::Json;
    let mut reference_timestamp = None;
    let mut generated_at = None;
    let mut generated_by = None;
    let mut git_sha = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                manifest_path = require_value(args, i, "--manifest")?.to_owned();
                i += 2;
            }
            "--out" => {
                out_path = Some(require_value(args, i, "--out")?.to_owned());
                i += 2;
            }
            "--summary-out" => {
                summary_out_path = Some(require_value(args, i, "--summary-out")?.to_owned());
                i += 2;
            }
            "--format" => {
                format = parse_output_format(require_value(args, i, "--format")?)?;
                i += 2;
            }
            "--reference-timestamp" => {
                reference_timestamp =
                    Some(require_value(args, i, "--reference-timestamp")?.to_owned());
                i += 2;
            }
            "--generated-at" => {
                generated_at = Some(require_value(args, i, "--generated-at")?.to_owned());
                i += 2;
            }
            "--generated-by" => {
                generated_by = Some(require_value(args, i, "--generated-by")?.to_owned());
                i += 2;
            }
            "--git-sha" => {
                git_sha = Some(require_value(args, i, "--git-sha")?.to_owned());
                i += 2;
            }
            "--help" | "-h" => {
                print_permissioned_campaign_packet_usage();
                return Ok(());
            }
            other => bail!("unknown generate-permissioned-campaign-packet argument: {other}"),
        }
    }

    let manifest = load_permissioned_campaign_broker_manifest(Path::new(&manifest_path))?;
    let reference_epoch_days = reference_epoch_days(
        reference_timestamp.as_deref(),
        PermissionedCampaignBrokerValidationConfig::with_current_reference().reference_epoch_days,
    )?;
    let packet = generate_permissioned_campaign_handoff_packet(
        &manifest,
        &PermissionedCampaignBrokerValidationConfig {
            reference_epoch_days,
        },
        PermissionedCampaignHandoffGeneration {
            generated_at: generated_at.unwrap_or_else(current_unix_timestamp_label),
            generated_by: generated_by
                .or_else(|| env::var("AGENT_NAME").ok())
                .unwrap_or_else(|| "unknown-agent".to_owned()),
            git_sha: git_sha
                .or_else(|| env::var("GIT_SHA").ok())
                .unwrap_or_else(|| "unknown".to_owned()),
        },
    )?;
    let output = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&packet)?,
        OutputFormat::Markdown => render_permissioned_campaign_handoff_markdown(&packet),
    };
    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "permissioned campaign handoff packet written: {} packet_id={}",
            path, packet.packet_id
        );
    } else {
        println!("{output}");
    }
    if let Some(path) = summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!(
                "{}\n",
                render_permissioned_campaign_handoff_markdown(&packet)
            ),
        )?;
        println!("permissioned campaign handoff summary written: {path}");
    }
    Ok(())
}

fn validate_swarm_capability_calibration_cmd(args: &[String]) -> Result<()> {
    let mut manifest_path = None;
    let mut out_path = None;
    let mut summary_out_path = None;
    let mut format = OutputFormat::Json;
    let mut reference_timestamp = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                manifest_path = Some(require_value(args, i, "--manifest")?.to_owned());
                i += 2;
            }
            "--out" => {
                out_path = Some(require_value(args, i, "--out")?.to_owned());
                i += 2;
            }
            "--summary-out" => {
                summary_out_path = Some(require_value(args, i, "--summary-out")?.to_owned());
                i += 2;
            }
            "--format" => {
                format = parse_output_format(require_value(args, i, "--format")?)?;
                i += 2;
            }
            "--reference-timestamp" => {
                reference_timestamp =
                    Some(require_value(args, i, "--reference-timestamp")?.to_owned());
                i += 2;
            }
            "--help" | "-h" => {
                print_swarm_capability_calibration_usage();
                return Ok(());
            }
            other => bail!("unknown validate-swarm-capability-calibration argument: {other}"),
        }
    }
    let manifest_path = manifest_path.context("--manifest is required")?;
    let reference_epoch_days = reference_epoch_days(
        reference_timestamp.as_deref(),
        SwarmCapabilityCalibrationValidationConfig::default().reference_epoch_days,
    )?;
    let manifest = load_swarm_capability_calibration_manifest(Path::new(&manifest_path))?;
    let report = validate_swarm_capability_calibration_manifest(
        &manifest,
        &SwarmCapabilityCalibrationValidationConfig {
            reference_epoch_days,
        },
    );
    let output = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&report)?,
        OutputFormat::Markdown => render_swarm_capability_calibration_markdown(&report),
    };
    if let Some(path) = out_path {
        write_text_file(Path::new(&path), &format!("{output}\n"))?;
        println!(
            "swarm capability calibration report written: {} valid={} classification={}",
            path, report.valid, report.classification
        );
    } else {
        println!("{output}");
    }
    if let Some(path) = summary_out_path {
        write_text_file(
            Path::new(&path),
            &format!(
                "{}\n",
                render_swarm_capability_calibration_markdown(&report)
            ),
        )?;
        println!("swarm capability calibration summary written: {path}");
    }
    fail_on_swarm_capability_calibration_errors(&report)
}

fn recommend_readiness_actions_cmd(args: &[String]) -> Result<()> {
    let Some(config) = parse_recommend_readiness_actions_args(args)? else {
        return Ok(());
    };
    let mut input = load_readiness_action_planning_input(&config)?;
    if let Some(report_id) = &config.report_id {
        input.report_id.clone_from(report_id);
    }
    if let Some(generated_at) = &config.generated_at {
        input.generated_at.clone_from(generated_at);
    }

    let metadata = readiness_action_dry_run_metadata(&config);
    let report = build_readiness_action_dry_run_report(&input, metadata);
    let json = serde_json::to_string_pretty(&report)?;
    let markdown = render_readiness_action_dry_run_markdown(&report);
    let stdout_log = readiness_action_dry_run_stdout_log(&report);
    let stderr_log = readiness_action_dry_run_stderr_log(&report);

    write_text_file(Path::new(&config.out_json_path), &format!("{json}\n"))?;
    write_text_file(
        Path::new(&config.out_markdown_path),
        &format!("{markdown}\n"),
    )?;
    write_text_file(Path::new(&config.stdout_log_path), &stdout_log)?;
    write_text_file(Path::new(&config.stderr_log_path), &stderr_log)?;

    println!("{}", readiness_action_dry_run_summary(&report));
    Ok(())
}

fn parse_recommend_readiness_actions_args(args: &[String]) -> Result<Option<ReadinessActionsArgs>> {
    let mut input_path = None;
    let mut out_json_path = None;
    let mut out_markdown_path = None;
    let mut stdout_log_path = None;
    let mut stderr_log_path = None;
    let mut report_id = None;
    let mut generated_at = None;
    let mut invocation = "ffs-ops recommend-readiness-actions".to_owned();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
                input_path = Some(require_value(args, i, "--input")?.to_owned());
                i += 2;
            }
            "--out-json" => {
                out_json_path = Some(require_value(args, i, "--out-json")?.to_owned());
                i += 2;
            }
            "--out-md" | "--out-markdown" => {
                out_markdown_path = Some(require_value(args, i, args[i].as_str())?.to_owned());
                i += 2;
            }
            "--stdout-log" => {
                stdout_log_path = Some(require_value(args, i, "--stdout-log")?.to_owned());
                i += 2;
            }
            "--stderr-log" => {
                stderr_log_path = Some(require_value(args, i, "--stderr-log")?.to_owned());
                i += 2;
            }
            "--report-id" => {
                report_id = Some(require_value(args, i, "--report-id")?.to_owned());
                i += 2;
            }
            "--generated-at" => {
                generated_at = Some(require_value(args, i, "--generated-at")?.to_owned());
                i += 2;
            }
            "--invocation" => {
                invocation = require_value(args, i, "--invocation")?.to_owned();
                i += 2;
            }
            "--help" | "-h" => {
                print_recommend_readiness_actions_usage();
                return Ok(None);
            }
            other => bail!("unknown recommend-readiness-actions argument: {other}"),
        }
    }

    Ok(Some(ReadinessActionsArgs {
        input_path,
        out_json_path: out_json_path.context("--out-json is required")?,
        out_markdown_path: out_markdown_path.context("--out-md is required")?,
        stdout_log_path: stdout_log_path.context("--stdout-log is required")?,
        stderr_log_path: stderr_log_path.context("--stderr-log is required")?,
        report_id,
        generated_at,
        invocation,
    }))
}

fn load_readiness_action_planning_input(
    config: &ReadinessActionsArgs,
) -> Result<ReadinessActionPlanningInput> {
    if let Some(input_path) = &config.input_path {
        let input = fs::read_to_string(input_path)
            .with_context(|| format!("failed to read {input_path}"))?;
        return serde_json::from_str(&input)
            .with_context(|| format!("failed to parse readiness action input {input_path}"));
    }

    Ok(ReadinessActionPlanningInput {
        report_id: "readiness_action_dry_run_report".to_owned(),
        generated_at: "1970-01-01T00:00:00Z".to_owned(),
        source_reports: default_readiness_action_autopilot_fixture_set()
            .fixtures
            .into_iter()
            .map(|fixture| fixture.report)
            .collect(),
        active_tracker_issues: Vec::new(),
    })
}

fn readiness_action_dry_run_metadata(
    config: &ReadinessActionsArgs,
) -> ReadinessActionDryRunMetadata {
    ReadinessActionDryRunMetadata {
        invocation: config.invocation.clone(),
        json_report_path: config.out_json_path.clone(),
        markdown_report_path: config.out_markdown_path.clone(),
        stdout_log_path: config.stdout_log_path.clone(),
        stderr_log_path: config.stderr_log_path.clone(),
        cleanup_status: "not_required_dry_run".to_owned(),
        output_paths: vec![
            ReadinessActionDryRunOutputPath {
                kind: "json_report".to_owned(),
                path: config.out_json_path.clone(),
            },
            ReadinessActionDryRunOutputPath {
                kind: "markdown_report".to_owned(),
                path: config.out_markdown_path.clone(),
            },
            ReadinessActionDryRunOutputPath {
                kind: "stdout_log".to_owned(),
                path: config.stdout_log_path.clone(),
            },
            ReadinessActionDryRunOutputPath {
                kind: "stderr_log".to_owned(),
                path: config.stderr_log_path.clone(),
            },
        ],
    }
}

fn readiness_action_dry_run_summary(report: &ReadinessActionDryRunReport) -> String {
    format!(
        "readiness action dry-run report written: json={} markdown={} stdout_log={} stderr_log={} recommendations={} scenarios={} suppressed_duplicates={} cleanup_status={}",
        report.command_metadata.json_report_path,
        report.command_metadata.markdown_report_path,
        report.command_metadata.stdout_log_path,
        report.command_metadata.stderr_log_path,
        report.planner_result.report.recommendations.len(),
        report.scenarios.len(),
        report.planner_result.suppressed_duplicates.len(),
        report.command_metadata.cleanup_status
    )
}

fn readiness_action_dry_run_stdout_log(report: &ReadinessActionDryRunReport) -> String {
    format!(
        "readiness-action-dry-run\nreport_id={}\ndry_run={}\nrecommendations={}\nsuppressed_duplicates={}\nscenarios={}\njson_report_path={}\nmarkdown_report_path={}\nstdout_log_path={}\nstderr_log_path={}\ncleanup_status={}\n",
        report.report_id,
        report.dry_run,
        report.planner_result.report.recommendations.len(),
        report.planner_result.suppressed_duplicates.len(),
        report.scenarios.len(),
        report.command_metadata.json_report_path,
        report.command_metadata.markdown_report_path,
        report.command_metadata.stdout_log_path,
        report.command_metadata.stderr_log_path,
        report.command_metadata.cleanup_status
    )
}

fn readiness_action_dry_run_stderr_log(report: &ReadinessActionDryRunReport) -> String {
    format!(
        "readiness-action-dry-run stderr\nno reproduction commands executed\npermissioned, destructive, and stale-evidence commands stayed dry-run only\ncleanup_status={}\n",
        report.command_metadata.cleanup_status
    )
}

fn generated_paths(out_path: &Option<String>, summary_out_path: &Option<String>) -> Vec<String> {
    match (out_path, summary_out_path) {
        (Some(json), Some(markdown)) => vec![json.clone(), markdown.clone()],
        (Some(json), None) => vec![json.clone()],
        (None, Some(markdown)) => vec![markdown.clone()],
        (None, None) => Vec::new(),
    }
}

fn reference_epoch_days(raw: Option<&str>, default_epoch_days: u32) -> Result<u32> {
    raw.map_or(Ok(default_epoch_days), |timestamp| {
        parse_manifest_timestamp_epoch_days(timestamp)
            .with_context(|| format!("invalid --reference-timestamp {timestamp}"))
    })
}

fn require_value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str> {
    args.get(index + 1)
        .map(String::as_str)
        .with_context(|| format!("{flag} requires a value"))
}

fn parse_output_format(raw: &str) -> Result<OutputFormat> {
    match raw {
        "json" => Ok(OutputFormat::Json),
        "markdown" | "md" => Ok(OutputFormat::Markdown),
        other => bail!("invalid --format value: {other}"),
    }
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

fn current_unix_timestamp_label() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_owned())
}

fn open_ended_note_scanner_reproduction_command(
    source_paths: &[String],
    out_path: Option<&str>,
) -> String {
    let mut command = "ffs-ops open-ended-note-scanner".to_owned();
    for source_path in source_paths {
        command.push_str(" --source ");
        command.push_str(source_path);
    }
    if let Some(path) = out_path {
        command.push_str(" --out ");
        command.push_str(path);
    }
    command
}

fn print_usage() {
    println!("Usage: ffs-ops <command> [OPTIONS]");
    println!();
    println!("Relocated FrankenFS operational/meta harness commands:");
    println!("  validate-ambition-evidence-matrix");
    println!("  recommend-readiness-actions");
    println!("  validate-open-ended-inventory");
    println!("  open-ended-note-scanner");
    println!("  validate-source-scope-manifest");
    println!("  validate-docs-status-drift");
    println!("  validate-report-schema-inventory");
    println!("  validate-permissioned-campaign-broker");
    println!("  validate-permissioned-campaign-ledger");
    println!("  generate-permissioned-campaign-packet");
    println!("  validate-swarm-capability-calibration");
}

fn print_open_ended_inventory_usage() {
    println!("Usage: ffs-ops validate-open-ended-inventory [--out FILE]");
}

fn print_open_ended_note_scanner_usage() {
    println!(
        "Usage: ffs-ops open-ended-note-scanner --source FILE [--source FILE ...] [--out FILE] [--allow-invalid] [--reproduction-command CMD]"
    );
}

fn print_source_scope_manifest_usage() {
    println!(
        "Usage: ffs-ops validate-source-scope-manifest [--manifest FILE] [--workspace-root DIR] [--out FILE] [--remove-source-family NAME]"
    );
}

fn print_ambition_evidence_matrix_usage() {
    println!("Usage: ffs-ops validate-ambition-evidence-matrix [--issues FILE] [--out FILE]");
}

fn print_docs_status_drift_usage() {
    println!(
        "Usage: ffs-ops validate-docs-status-drift [--issues FILE] [--feature-parity FILE] [--snippets FILE] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_report_schema_inventory_usage() {
    println!(
        "Usage: ffs-ops validate-report-schema-inventory [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_permissioned_campaign_broker_usage() {
    println!(
        "Usage: ffs-ops validate-permissioned-campaign-broker [--manifest FILE] [--format json|markdown] [--out FILE] [--summary-out FILE] [--reference-timestamp TS]"
    );
}

fn print_permissioned_campaign_ledger_usage() {
    println!(
        "Usage: ffs-ops validate-permissioned-campaign-ledger --ledger FILE [--manifest FILE] [--current-git-sha SHA] [--format json|markdown] [--out FILE] [--summary-out FILE]"
    );
}

fn print_permissioned_campaign_packet_usage() {
    println!(
        "Usage: ffs-ops generate-permissioned-campaign-packet [--manifest FILE] [--format json|markdown] [--out FILE] [--summary-out FILE] [--generated-at TS] [--generated-by NAME] [--git-sha SHA] [--reference-timestamp TS]"
    );
}

fn print_swarm_capability_calibration_usage() {
    println!(
        "Usage: ffs-ops validate-swarm-capability-calibration --manifest FILE [--format json|markdown] [--out FILE] [--summary-out FILE] [--reference-timestamp TS]"
    );
}

fn print_recommend_readiness_actions_usage() {
    println!(
        "Usage: ffs-ops recommend-readiness-actions [--input FILE] --out-json FILE --out-md FILE --stdout-log FILE --stderr-log FILE [--report-id ID] [--generated-at TS] [--invocation CMD]"
    );
}
