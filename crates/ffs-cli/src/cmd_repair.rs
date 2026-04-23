use anyhow::{bail, Context, Result};
use asupersync::Cx;
use ffs_block::{BlockDevice, ByteBlockDevice, ByteDevice, FileByteDevice};
use ffs_core::{detect_filesystem_at_path, FsFlavor, OpenFs, OpenOptions};
use ffs_ondisk::{
    map_logical_to_physical, verify_btrfs_superblock_checksum, BtrfsChunkEntry, BtrfsSuperblock,
    Ext4Superblock,
};
use ffs_repair::codec::encode_group;
use ffs_repair::recovery::{GroupRecoveryOrchestrator, RecoveryOutcome};
use ffs_repair::scrub::{ScrubReport, Scrubber, Severity};
use ffs_repair::storage::{RepairGroupLayout, RepairGroupStorage, REPAIR_DESC_SLOT_COUNT};
use ffs_repair::symbol::RepairGroupDescExt;
use ffs_types::{
    BlockNumber, ByteOffset, GroupNumber, BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions as StdOpenOptions;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::{info, info_span, warn};

use crate::{
    choose_btrfs_scrub_block_size, cli_cx, count_blocks_at_severity_or_higher,
    ext4_appears_clean_state, ext4_group_scrub_scope, ext4_recovery_detail, filesystem_name,
    repair_btrfs_parsers::{parse_btrfs_block_group_total_bytes, parse_btrfs_root_item_bytenr},
    run_ext4_mount_recovery, scrub_validator, RepairActionOutput, RepairCommandOptions,
    RepairFlags, RepairOutput, RepairScopeOutput, RepairScrubOutput,
};

pub fn repair_cmd(path: &PathBuf, options: RepairCommandOptions) -> Result<()> {
    let flags = options.flags;
    let command_span = info_span!(
        target: "ffs::cli::repair",
        "repair",
        image = %path.display(),
        full_scrub = flags.full_scrub(),
        verify_only = flags.verify_only(),
        rebuild_symbols = flags.rebuild_symbols(),
        block_group = options.block_group.unwrap_or(u32::MAX),
        max_threads = options.max_threads.unwrap_or(0),
        output_json = flags.json()
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::repair", "repair_start");

    let output = match build_repair_output(path, options) {
        Ok(output) => output,
        Err(err) => {
            if flags.json() {
                let error_msg = format!("{err:#}");
                let escaped = serde_json::to_string(&error_msg)
                    .unwrap_or_else(|_| "\"unknown_error\"".to_string());
                println!(
                    "{{\"status\":\"operational_error\",\"exit_code\":4,\"error\":{escaped}}}"
                );
            } else {
                eprintln!("repair operational error: {err:#}");
            }
            std::process::exit(4);
        }
    };

    print_repair_output(flags.json(), &output)?;

    info!(
        target: "ffs::cli::repair",
        filesystem = output.filesystem,
        action = ?output.action,
        exit_code = output.exit_code,
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "repair_complete"
    );

    if output.exit_code != 0 {
        std::process::exit(output.exit_code);
    }

    Ok(())
}

pub fn repair_worker_limit(requested: Option<u32>) -> (usize, Option<u32>) {
    let available = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let requested_raw = requested.unwrap_or(1).max(1);
    let requested_threads = usize::try_from(requested_raw).unwrap_or(usize::MAX);
    let effective = requested_threads.min(available).max(1);
    let capped = (requested_threads > effective).then_some(requested_raw);
    (effective, capped)
}

pub fn partition_scrub_range(
    start: BlockNumber,
    count: u64,
    workers: usize,
) -> Vec<(BlockNumber, u64)> {
    if count == 0 || workers == 0 {
        return Vec::new();
    }

    let workers_u64 = u64::try_from(workers).unwrap_or(u64::MAX).min(count);
    let base = count / workers_u64;
    let remainder = count % workers_u64;
    let mut cursor = start.0;
    let mut ranges = Vec::with_capacity(usize::try_from(workers_u64).unwrap_or(usize::MAX));
    for worker_idx in 0..workers_u64 {
        let width = base + u64::from(worker_idx < remainder);
        ranges.push((BlockNumber(cursor), width));
        cursor = cursor.saturating_add(width);
    }
    ranges
}

pub fn merge_scrub_reports(reports: Vec<ScrubReport>) -> ScrubReport {
    let mut merged = ScrubReport {
        findings: Vec::new(),
        blocks_scanned: 0,
        blocks_corrupt: 0,
        blocks_io_error: 0,
    };
    for report in reports {
        merged.blocks_scanned = merged.blocks_scanned.saturating_add(report.blocks_scanned);
        merged.blocks_corrupt = merged.blocks_corrupt.saturating_add(report.blocks_corrupt);
        merged.blocks_io_error = merged
            .blocks_io_error
            .saturating_add(report.blocks_io_error);
        merged.findings.extend(report.findings);
    }
    merged
}

pub const DEFAULT_REPAIR_OVERHEAD_RATIO: f64 = 1.05;
const DEFAULT_REPAIR_VALIDATION_BLOCK_COUNT: u32 = 0;
const BTRFS_EXTENT_TREE_OBJECTID: u64 = 2;
const BTRFS_ROOT_ITEM_TYPE: u8 = 132;
const BTRFS_BLOCK_GROUP_ITEM_TYPE: u8 = 192;
const BTRFS_SUPER_MIRROR_MAX: u32 = 3;
const BTRFS_SUPER_MIRROR_BASE: u64 = 16 * 1024;
const BTRFS_SUPER_BYTENR_OFFSET: usize = 0x30;
const BTRFS_SUPER_CSUM_OFFSET: usize = 0;
const BTRFS_SUPER_CSUM_LEN: usize = 4;
const BTRFS_SUPER_CSUM_DATA_OFFSET: usize = 0x20;
const REPAIR_COORDINATION_POLICY: &str = "single_host_only_v1";
pub const REPAIR_COORDINATION_SCENARIO_REPAIR: &str = "cli_repair_multi_host_guard";
pub const REPAIR_COORDINATION_SCENARIO_FSCK: &str = "cli_fsck_repair_multi_host_guard";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairCoordinationStatus {
    NotRequired,
    Claimed,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RepairCoordinationOutput {
    pub policy: String,
    pub status: RepairCoordinationStatus,
    pub operation_id: String,
    pub scenario_id: String,
    pub coordination_file: String,
    pub local_host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_process_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
    pub detail: String,
}

impl RepairCoordinationOutput {
    #[must_use]
    pub const fn is_blocked(&self) -> bool {
        matches!(self.status, RepairCoordinationStatus::Blocked)
    }
}

#[derive(Debug, Clone)]
pub struct RepairCoordinationDecision {
    pub output: RepairCoordinationOutput,
    pub writes_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairCoordinationRecord {
    pub policy: String,
    pub image_path: String,
    pub owner_host: String,
    pub owner_process_id: u32,
    pub last_command: String,
    pub last_operation_id: String,
    pub recorded_at_ns: u64,
}

fn coordination_now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        })
}

fn local_host_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "unknown-host".to_owned())
}

fn sanitize_token(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "unknown".to_owned()
    } else {
        trimmed.to_owned()
    }
}

pub fn repair_coordination_record_path(image: &Path) -> PathBuf {
    let parent = image.parent().unwrap_or_else(|| Path::new("."));
    let file_name = image
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("image");
    parent.join(format!(".{file_name}.ffs-repair-owner.json"))
}

fn repair_coordination_operation_id(command: &str, image: &Path, host: &str) -> String {
    let image_slug = image
        .file_name()
        .and_then(|name| name.to_str())
        .map_or_else(|| "image".to_owned(), sanitize_token);
    format!(
        "{command}-coordination-{}-{image_slug}",
        sanitize_token(host)
    )
}

fn build_coordination_record(
    path: &Path,
    local_host: &str,
    command: &str,
    operation_id: &str,
) -> RepairCoordinationRecord {
    RepairCoordinationRecord {
        policy: REPAIR_COORDINATION_POLICY.to_owned(),
        image_path: path.display().to_string(),
        owner_host: local_host.to_owned(),
        owner_process_id: std::process::id(),
        last_command: command.to_owned(),
        last_operation_id: operation_id.to_owned(),
        recorded_at_ns: coordination_now_ns(),
    }
}

fn write_coordination_record(
    record_path: &Path,
    record: &RepairCoordinationRecord,
    create_new: bool,
) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(record).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to serialize repair coordination record: {error}"),
        )
    })?;
    bytes.push(b'\n');
    if create_new {
        let mut file = StdOpenOptions::new()
            .create_new(true)
            .write(true)
            .open(record_path)?;
        std::io::Write::write_all(&mut file, &bytes)?;
        std::io::Write::flush(&mut file)
    } else {
        std::fs::write(record_path, bytes)
    }
}

#[derive(Debug)]
struct RepairCoordinationContext {
    target: &'static str,
    scenario_id: &'static str,
    command: &'static str,
    local_host: String,
    operation_id: String,
    coordination_file: PathBuf,
    coordination_file_display: String,
}

#[derive(Debug, Clone, Copy)]
struct RepairCoordinationLogRecord<'a> {
    outcome: &'static str,
    error_class: &'static str,
    owner_host: Option<&'a str>,
    event_name: &'static str,
}

impl RepairCoordinationContext {
    fn new(
        target: &'static str,
        scenario_id: &'static str,
        command: &'static str,
        path: &Path,
    ) -> Self {
        let local_host = local_host_name();
        let coordination_file = repair_coordination_record_path(path);
        let operation_id = repair_coordination_operation_id(command, path, &local_host);
        let coordination_file_display = coordination_file.display().to_string();
        Self {
            target,
            scenario_id,
            command,
            local_host,
            operation_id,
            coordination_file,
            coordination_file_display,
        }
    }

    fn log_info(&self, record: RepairCoordinationLogRecord<'_>) {
        macro_rules! emit {
            ($log_target:literal) => {
                if let Some(owner_host) = record.owner_host {
                    info!(
                        target: $log_target,
                        operation_id = %self.operation_id,
                        scenario_id = self.scenario_id,
                        outcome = record.outcome,
                        error_class = record.error_class,
                        coordination_file = %self.coordination_file_display,
                        local_host = %self.local_host,
                        owner_host = %owner_host,
                        command = self.command,
                        event_name = record.event_name
                    );
                } else {
                    info!(
                        target: $log_target,
                        operation_id = %self.operation_id,
                        scenario_id = self.scenario_id,
                        outcome = record.outcome,
                        error_class = record.error_class,
                        coordination_file = %self.coordination_file_display,
                        local_host = %self.local_host,
                        command = self.command,
                        event_name = record.event_name
                    );
                }
            };
        }

        match self.target {
            "ffs::cli::repair" => emit!("ffs::cli::repair"),
            "ffs::cli::fsck" => emit!("ffs::cli::fsck"),
            "ffs::test" => emit!("ffs::test"),
            _ => emit!("ffs::cli::repair"),
        }
    }

    fn log_warn(&self, error_class: &'static str, owner_host: Option<&str>) {
        macro_rules! emit {
            ($log_target:literal) => {
                if let Some(owner_host) = owner_host {
                    warn!(
                        target: $log_target,
                        operation_id = %self.operation_id,
                        scenario_id = self.scenario_id,
                        outcome = "rejected",
                        error_class,
                        coordination_file = %self.coordination_file_display,
                        local_host = %self.local_host,
                        owner_host = %owner_host,
                        command = self.command,
                        event_name = "repair_coordination_rejected"
                    );
                } else {
                    warn!(
                        target: $log_target,
                        operation_id = %self.operation_id,
                        scenario_id = self.scenario_id,
                        outcome = "rejected",
                        error_class,
                        coordination_file = %self.coordination_file_display,
                        local_host = %self.local_host,
                        command = self.command,
                        event_name = "repair_coordination_rejected"
                    );
                }
            };
        }

        match self.target {
            "ffs::cli::repair" => emit!("ffs::cli::repair"),
            "ffs::cli::fsck" => emit!("ffs::cli::fsck"),
            "ffs::test" => emit!("ffs::test"),
            _ => emit!("ffs::cli::repair"),
        }
    }

    fn decision(
        &self,
        status: RepairCoordinationStatus,
        writes_allowed: bool,
        owner_host: Option<String>,
        owner_process_id: Option<u32>,
        error_class: Option<&str>,
        detail: String,
    ) -> RepairCoordinationDecision {
        RepairCoordinationDecision {
            output: RepairCoordinationOutput {
                policy: REPAIR_COORDINATION_POLICY.to_owned(),
                status,
                operation_id: self.operation_id.clone(),
                scenario_id: self.scenario_id.to_owned(),
                coordination_file: self.coordination_file_display.clone(),
                local_host: self.local_host.clone(),
                owner_host,
                owner_process_id,
                error_class: error_class.map(str::to_owned),
                detail,
            },
            writes_allowed,
        }
    }
}

fn not_required_decision(ctx: &RepairCoordinationContext) -> RepairCoordinationDecision {
    let detail =
        "write-side repair was not requested; single-host coordination is not required".to_owned();
    ctx.log_info(RepairCoordinationLogRecord {
        outcome: "not_required",
        error_class: "none",
        owner_host: None,
        event_name: "repair_coordination_not_required",
    });
    ctx.decision(
        RepairCoordinationStatus::NotRequired,
        false,
        None,
        None,
        None,
        detail,
    )
}

fn claimed_decision(
    ctx: &RepairCoordinationContext,
    owner_host: &str,
    owner_process_id: u32,
    detail: String,
) -> RepairCoordinationDecision {
    ctx.log_info(RepairCoordinationLogRecord {
        outcome: "applied",
        error_class: "none",
        owner_host: Some(owner_host),
        event_name: "repair_coordination_applied",
    });
    ctx.decision(
        RepairCoordinationStatus::Claimed,
        true,
        Some(owner_host.to_owned()),
        Some(owner_process_id),
        None,
        detail,
    )
}

fn blocked_decision(
    ctx: &RepairCoordinationContext,
    owner_host: Option<&str>,
    owner_process_id: Option<u32>,
    error_class: &'static str,
    detail: String,
) -> RepairCoordinationDecision {
    ctx.log_warn(error_class, owner_host);
    ctx.decision(
        RepairCoordinationStatus::Blocked,
        false,
        owner_host.map(str::to_owned),
        owner_process_id,
        Some(error_class),
        detail,
    )
}

pub fn coordinate_repair_write_access(
    target: &'static str,
    scenario_id: &'static str,
    command: &'static str,
    path: &Path,
    require_write_guard: bool,
) -> RepairCoordinationDecision {
    let ctx = RepairCoordinationContext::new(target, scenario_id, command, path);

    if !require_write_guard {
        return not_required_decision(&ctx);
    }

    let new_record = build_coordination_record(path, &ctx.local_host, command, &ctx.operation_id);
    match write_coordination_record(&ctx.coordination_file, &new_record, true) {
        Ok(()) => {
            let detail = format!(
                "FrankenFS V1.x write-side repair is single-host only; claimed coordination record {} for host {}",
                ctx.coordination_file.display(),
                ctx.local_host
            );
            claimed_decision(&ctx, &ctx.local_host, new_record.owner_process_id, detail)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing_record = std::fs::read(&ctx.coordination_file)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<RepairCoordinationRecord>(&bytes).ok());

            match existing_record {
                Some(existing_record)
                    if existing_record.owner_host == ctx.local_host
                        && existing_record.policy == REPAIR_COORDINATION_POLICY =>
                {
                    if let Err(refresh_error) =
                        write_coordination_record(&ctx.coordination_file, &new_record, false)
                    {
                        let detail = format!(
                            "FrankenFS V1.x blocks write-side repair because the coordination record {} could not be refreshed for host {}: {}",
                            ctx.coordination_file.display(),
                            ctx.local_host,
                            refresh_error
                        );
                        return blocked_decision(
                            &ctx,
                            Some(&existing_record.owner_host),
                            Some(existing_record.owner_process_id),
                            "coordination_io",
                            detail,
                        );
                    }

                    let detail = format!(
                        "FrankenFS V1.x write-side repair remains pinned to host {}; refreshed coordination record {}",
                        ctx.local_host,
                        ctx.coordination_file.display()
                    );
                    claimed_decision(&ctx, &ctx.local_host, new_record.owner_process_id, detail)
                }
                Some(existing_record) => {
                    let detail = format!(
                        "FrankenFS V1.x blocks write-side repair on host {} because coordination record {} belongs to host {}. Multi-host repair is out of scope; use read-only diagnostics or hand off ownership explicitly.",
                        ctx.local_host,
                        ctx.coordination_file.display(),
                        existing_record.owner_host
                    );
                    blocked_decision(
                        &ctx,
                        Some(&existing_record.owner_host),
                        Some(existing_record.owner_process_id),
                        "multi_host_unsupported",
                        detail,
                    )
                }
                None => {
                    let detail = format!(
                        "FrankenFS V1.x blocks write-side repair because coordination record {} is unreadable or invalid. Review the record before retrying.",
                        ctx.coordination_file.display()
                    );
                    blocked_decision(&ctx, None, None, "coordination_metadata_invalid", detail)
                }
            }
        }
        Err(error) => {
            let detail = format!(
                "FrankenFS V1.x blocks write-side repair because coordination record {} could not be created: {}",
                ctx.coordination_file.display(),
                error
            );
            blocked_decision(&ctx, None, None, "coordination_io", detail)
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BtrfsRepairGroupSpec {
    pub group: u32,
    pub logical_start: u64,
    pub logical_bytes: u64,
    pub physical_start_block: BlockNumber,
    pub physical_block_count: u64,
    /// Source payload blocks (total minus repair metadata).
    pub source_block_count: u32,
    /// Repair tail layout for RaptorQ symbol storage/recovery.
    pub layout: RepairGroupLayout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ext4RepairStaleness {
    Fresh,
    Stale,
    Untracked,
}

#[derive(Debug, Clone, Copy)]
pub struct Ext4RepairGroupSpec {
    pub group: u32,
    pub scrub_start_block: BlockNumber,
    pub scrub_block_count: u64,
    pub source_first_block: BlockNumber,
    pub source_block_count: u32,
    pub layout: RepairGroupLayout,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RepairExecutionStats {
    pub recovery_attempted: bool,
    pub recovery_unrecovered_blocks: u64,
    pub symbol_rebuild_attempted: bool,
    pub symbol_rebuild_groups: u64,
    pub symbol_rebuild_failed_groups: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct BtrfsSuperblockRecoverySource {
    pub offset: u64,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BtrfsMirrorRepairOutcome {
    pub attempted: bool,
    pub repaired: u32,
}

pub fn btrfs_super_mirror_offsets(image_len: u64) -> Vec<u64> {
    let mut offsets = Vec::new();
    for mirror in 0..BTRFS_SUPER_MIRROR_MAX {
        let offset = if mirror == 0 {
            BTRFS_SUPER_INFO_OFFSET as u64
        } else {
            // Btrfs mirrors for index n >= 1 are at 64 MiB, 256 MiB, 1 GiB, 4 GiB...
            // These are powers of 4: 16 KiB << (12 + 2*(n-1)) = 16 KiB << (10 + 2n).
            let shift = 10_u32.saturating_add(mirror.saturating_mul(2));
            let Some(candidate) = BTRFS_SUPER_MIRROR_BASE.checked_shl(shift) else {
                continue;
            };
            candidate
        };
        let Some(end) =
            offset.checked_add(u64::try_from(BTRFS_SUPER_INFO_SIZE).unwrap_or(u64::MAX))
        else {
            continue;
        };
        if end <= image_len {
            offsets.push(offset);
        }
    }
    offsets
}

pub fn block_range_contains(start: BlockNumber, count: u64, target: BlockNumber) -> bool {
    if count == 0 || target.0 < start.0 {
        return false;
    }
    if count == u64::MAX {
        return true;
    }
    start.0.checked_add(count).is_none_or(|end| target.0 < end)
}

pub fn primary_btrfs_superblock_block(block_size: u32) -> BlockNumber {
    BlockNumber((BTRFS_SUPER_INFO_OFFSET as u64) / u64::from(block_size))
}

pub fn report_has_error_or_higher_for_block(report: &ScrubReport, block: BlockNumber) -> bool {
    report
        .findings
        .iter()
        .any(|finding| finding.block == block && finding.severity >= Severity::Error)
}

pub fn normalize_btrfs_superblock_for_offset(region: &mut [u8], bytenr: u64) -> Result<()> {
    if region.len() < BTRFS_SUPER_INFO_SIZE {
        bail!(
            "btrfs superblock region too short: expected {} bytes, got {}",
            BTRFS_SUPER_INFO_SIZE,
            region.len()
        );
    }
    region[BTRFS_SUPER_BYTENR_OFFSET..BTRFS_SUPER_BYTENR_OFFSET + 8]
        .copy_from_slice(&bytenr.to_le_bytes());
    let checksum = crc32c::crc32c(&region[BTRFS_SUPER_CSUM_DATA_OFFSET..BTRFS_SUPER_INFO_SIZE]);
    region[BTRFS_SUPER_CSUM_OFFSET..BTRFS_SUPER_CSUM_OFFSET + BTRFS_SUPER_CSUM_LEN]
        .copy_from_slice(&checksum.to_le_bytes());
    Ok(())
}

pub fn normalize_btrfs_superblock_as_primary(region: &mut [u8]) -> Result<()> {
    normalize_btrfs_superblock_for_offset(region, BTRFS_SUPER_INFO_OFFSET as u64)
}

pub fn append_btrfs_repair_detail(detail: &mut Option<String>, message: impl Into<String>) {
    let message = message.into();
    if let Some(existing) = detail.as_mut() {
        if !existing.contains(&message) {
            if !existing.is_empty() {
                existing.push_str("; ");
            }
            existing.push_str(&message);
        }
    } else {
        *detail = Some(message);
    }
}

#[allow(clippy::too_many_lines)]
pub fn repair_corrupt_btrfs_superblock_mirrors_from_primary(
    path: &PathBuf,
    block_size: u32,
    scrub_start: BlockNumber,
    scrub_count: u64,
    limitations: &mut Vec<String>,
) -> Result<BtrfsMirrorRepairOutcome> {
    let cx = cli_cx();
    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let image_len = byte_dev.len_bytes();
    let primary_offset = BTRFS_SUPER_INFO_OFFSET as u64;
    let block_size_u64 = u64::from(block_size);

    let mut corrupt_mirror_offsets = Vec::new();
    for offset in btrfs_super_mirror_offsets(image_len)
        .into_iter()
        .filter(|offset| *offset != primary_offset)
    {
        if offset % block_size_u64 != 0 {
            limitations.push(format!(
                "cannot evaluate btrfs superblock mirror at byte offset {offset} with scrub block size {block_size}"
            ));
            continue;
        }
        let mirror_block = BlockNumber(offset / block_size_u64);
        if !block_range_contains(scrub_start, scrub_count, mirror_block) {
            continue;
        }

        let mut mirror_region = vec![0_u8; BTRFS_SUPER_INFO_SIZE];
        if let Err(error) = byte_dev.read_exact_at(&cx, ByteOffset(offset), &mut mirror_region) {
            limitations.push(format!(
                "failed to read btrfs superblock mirror at byte offset {offset} while checking repair scope: {error}"
            ));
            corrupt_mirror_offsets.push(offset);
            continue;
        }

        let mut mirror_valid = true;
        match BtrfsSuperblock::parse_superblock_region(&mirror_region) {
            Ok(parsed) => {
                if parsed.bytenr != offset {
                    mirror_valid = false;
                    limitations.push(format!(
                        "btrfs superblock mirror at byte offset {offset} reports bytenr={} and needs repair",
                        parsed.bytenr
                    ));
                }
            }
            Err(error) => {
                mirror_valid = false;
                limitations.push(format!(
                    "btrfs superblock mirror at byte offset {offset} failed structural validation and needs repair: {error}"
                ));
            }
        }
        if let Err(error) = verify_btrfs_superblock_checksum(&mirror_region) {
            mirror_valid = false;
            limitations.push(format!(
                "btrfs superblock mirror at byte offset {offset} failed checksum validation and needs repair: {error}"
            ));
        }

        if !mirror_valid {
            corrupt_mirror_offsets.push(offset);
        }
    }

    if corrupt_mirror_offsets.is_empty() {
        return Ok(BtrfsMirrorRepairOutcome::default());
    }

    let mut outcome = BtrfsMirrorRepairOutcome {
        attempted: true,
        repaired: 0,
    };
    let mut primary_region = vec![0_u8; BTRFS_SUPER_INFO_SIZE];
    if let Err(error) = byte_dev.read_exact_at(&cx, ByteOffset(primary_offset), &mut primary_region)
    {
        limitations.push(format!(
            "failed to read primary btrfs superblock while restoring mirror copies: {error}"
        ));
        return Ok(outcome);
    }

    let parsed_primary = match BtrfsSuperblock::parse_superblock_region(&primary_region) {
        Ok(parsed) => parsed,
        Err(error) => {
            limitations.push(format!(
                "failed to parse primary btrfs superblock while restoring mirror copies: {error}"
            ));
            return Ok(outcome);
        }
    };
    if parsed_primary.bytenr != primary_offset {
        limitations.push(format!(
            "primary btrfs superblock reports bytenr={} and cannot seed mirror restoration",
            parsed_primary.bytenr
        ));
        return Ok(outcome);
    }
    if let Err(error) = verify_btrfs_superblock_checksum(&primary_region) {
        limitations.push(format!(
            "primary btrfs superblock checksum is invalid; mirror restoration skipped: {error}"
        ));
        return Ok(outcome);
    }

    let mut repaired_offsets = Vec::new();
    for offset in corrupt_mirror_offsets {
        let mut mirror_region = primary_region.clone();
        if let Err(error) = normalize_btrfs_superblock_for_offset(&mut mirror_region, offset) {
            limitations.push(format!(
                "failed to retarget btrfs superblock mirror at byte offset {offset}: {error:#}"
            ));
            continue;
        }
        if let Err(error) = BtrfsSuperblock::parse_superblock_region(&mirror_region) {
            limitations.push(format!(
                "re-encoded btrfs superblock mirror at byte offset {offset} failed validation: {error}"
            ));
            continue;
        }
        if let Err(error) = verify_btrfs_superblock_checksum(&mirror_region) {
            limitations.push(format!(
                "re-encoded btrfs superblock mirror at byte offset {offset} failed checksum validation: {error}"
            ));
            continue;
        }
        match byte_dev.write_all_at(&cx, ByteOffset(offset), &mirror_region) {
            Ok(()) => repaired_offsets.push(offset),
            Err(error) => limitations.push(format!(
                "failed to write recovered btrfs superblock mirror at byte offset {offset}: {error}"
            )),
        }
    }

    if repaired_offsets.is_empty() {
        return Ok(outcome);
    }

    byte_dev
        .sync(&cx)
        .context("failed to sync image after btrfs superblock mirror recovery")?;
    outcome.repaired = u32::try_from(repaired_offsets.len()).unwrap_or(u32::MAX);
    let offsets = repaired_offsets
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    limitations.push(format!(
        "restored {} btrfs superblock mirror(s) from primary superblock at byte offset(s): {offsets}",
        outcome.repaired
    ));
    Ok(outcome)
}

pub fn recover_primary_btrfs_superblock_from_backup(
    path: &PathBuf,
    limitations: &mut Vec<String>,
) -> Result<Option<BtrfsSuperblockRecoverySource>> {
    let cx = cli_cx();
    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let image_len = byte_dev.len_bytes();
    let primary_offset = BTRFS_SUPER_INFO_OFFSET as u64;

    let mut selected: Option<(Vec<u8>, BtrfsSuperblockRecoverySource)> = None;
    for offset in btrfs_super_mirror_offsets(image_len)
        .into_iter()
        .filter(|offset| *offset != primary_offset)
    {
        let mut region = vec![0_u8; BTRFS_SUPER_INFO_SIZE];
        if let Err(error) = byte_dev.read_exact_at(&cx, ByteOffset(offset), &mut region) {
            limitations.push(format!(
                "failed to read btrfs superblock mirror at byte offset {offset}: {error}"
            ));
            continue;
        }

        let parsed = match BtrfsSuperblock::parse_superblock_region(&region) {
            Ok(parsed) => parsed,
            Err(error) => {
                limitations.push(format!(
                    "btrfs superblock mirror at byte offset {offset} is structurally invalid: {error}"
                ));
                continue;
            }
        };
        if parsed.bytenr != offset {
            limitations.push(format!(
                "btrfs superblock mirror at byte offset {offset} reports bytenr={} and was skipped",
                parsed.bytenr
            ));
            continue;
        }
        if let Err(error) = verify_btrfs_superblock_checksum(&region) {
            limitations.push(format!(
                "btrfs superblock mirror at byte offset {offset} failed checksum validation: {error}"
            ));
            continue;
        }

        let source = BtrfsSuperblockRecoverySource {
            offset,
            generation: parsed.generation,
        };
        let keep_candidate = selected.as_ref().is_none_or(|(_, current)| {
            source.generation > current.generation
                || (source.generation == current.generation && source.offset < current.offset)
        });
        if keep_candidate {
            selected = Some((region, source));
        }
    }

    let Some((mut recovered_region, source)) = selected else {
        return Ok(None);
    };
    normalize_btrfs_superblock_as_primary(&mut recovered_region)?;
    BtrfsSuperblock::parse_superblock_region(&recovered_region)
        .context("recovered primary btrfs superblock failed structural validation")?;
    verify_btrfs_superblock_checksum(&recovered_region)
        .context("recovered primary btrfs superblock failed checksum validation")?;

    byte_dev
        .write_all_at(&cx, ByteOffset(primary_offset), &recovered_region)
        .context("failed to write recovered primary btrfs superblock")?;
    byte_dev
        .sync(&cx)
        .context("failed to sync image after primary btrfs superblock recovery")?;

    Ok(Some(source))
}

pub fn detect_flavor_with_optional_btrfs_bootstrap(
    cx: &Cx,
    path: &PathBuf,
    allow_bootstrap: bool,
    limitations: &mut Vec<String>,
) -> Result<(FsFlavor, Option<BtrfsSuperblockRecoverySource>)> {
    match detect_filesystem_at_path(cx, path) {
        Ok(flavor) => Ok((flavor, None)),
        Err(detect_error) => {
            if !allow_bootstrap {
                return Err(detect_error).with_context(|| {
                    format!("failed to detect ext4/btrfs metadata in {}", path.display())
                });
            }

            let source = match recover_primary_btrfs_superblock_from_backup(path, limitations) {
                Ok(Some(source)) => source,
                Ok(None) => {
                    return Err(detect_error).with_context(|| {
                        format!(
                            "failed to detect ext4/btrfs metadata in {}; bootstrap btrfs superblock \
                             recovery found no valid backup mirrors",
                            path.display()
                        )
                    });
                }
                Err(recover_error) => {
                    return Err(detect_error).with_context(|| {
                        format!(
                            "failed to detect ext4/btrfs metadata in {}; bootstrap btrfs superblock \
                             recovery failed: {recover_error:#}",
                            path.display()
                        )
                    });
                }
            };
            limitations.push(format!(
                "bootstrap restored primary btrfs superblock from backup mirror at byte offset {} \
                 (generation={})",
                source.offset, source.generation
            ));

            let flavor = detect_filesystem_at_path(cx, path).with_context(|| {
                format!(
                    "failed to detect ext4/btrfs metadata in {} after bootstrap btrfs superblock \
                     recovery",
                    path.display()
                )
            })?;
            Ok((flavor, Some(source)))
        }
    }
}

pub fn build_btrfs_repair_group_spec(
    group: u32,
    logical_start: u64,
    logical_bytes: u64,
    block_size: u32,
    chunks: &[BtrfsChunkEntry],
) -> Result<BtrfsRepairGroupSpec> {
    if logical_bytes == 0 {
        bail!("btrfs block group {group} has zero logical span");
    }
    let logical_end = logical_start
        .checked_add(logical_bytes.saturating_sub(1))
        .ok_or_else(|| anyhow::anyhow!("btrfs block group {group} logical range overflow"))?;
    let start_mapping = map_logical_to_physical(chunks, logical_start)
        .with_context(|| format!("failed to map btrfs group {group} logical start"))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "btrfs block group {group} logical start {logical_start} is not covered by any chunk"
            )
        })?;
    let end_mapping = map_logical_to_physical(chunks, logical_end)
        .with_context(|| format!("failed to map btrfs group {group} logical end"))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "btrfs block group {group} logical end {logical_end} is not covered by any chunk"
            )
        })?;
    if start_mapping.devid != end_mapping.devid {
        bail!(
            "btrfs block group {group} spans multiple devices (start devid={}, end devid={})",
            start_mapping.devid,
            end_mapping.devid
        );
    }
    let expected_end_physical = start_mapping
        .physical
        .checked_add(logical_bytes.saturating_sub(1))
        .ok_or_else(|| anyhow::anyhow!("btrfs block group {group} physical range overflow"))?;
    if end_mapping.physical != expected_end_physical {
        bail!(
            "btrfs block group {group} spans non-contiguous chunk mapping (start_physical={}, end_physical={}, expected_end={expected_end_physical})",
            start_mapping.physical,
            end_mapping.physical
        );
    }
    let block_size_u64 = u64::from(block_size);
    let start_block = start_mapping.physical / block_size_u64;
    let end_exclusive = expected_end_physical
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("btrfs block group {group} end overflow"))?;
    let end_block = end_exclusive.div_ceil(block_size_u64);
    let block_count = end_block.saturating_sub(start_block);
    if block_count == 0 {
        bail!("btrfs block group {group} maps to zero scrub blocks");
    }

    let blocks_per_group = u32::try_from(block_count).with_context(|| {
        format!("btrfs block group {group} block count does not fit u32 ({block_count})")
    })?;
    // Compute tail layout for RaptorQ repair symbols (same scheme as ext4).
    let source_and_repair_budget = if blocks_per_group > REPAIR_DESC_SLOT_COUNT + 1 {
        blocks_per_group.saturating_sub(REPAIR_DESC_SLOT_COUNT)
    } else {
        // Group too small for repair metadata — treat entire span as source.
        blocks_per_group
    };
    let desired_repair = RepairGroupDescExt::compute_repair_block_count(
        source_and_repair_budget,
        DEFAULT_REPAIR_OVERHEAD_RATIO,
    )
    .max(1);
    let repair_block_count = desired_repair
        .min(source_and_repair_budget.saturating_sub(1))
        .max(1);
    let source_block_count = source_and_repair_budget.saturating_sub(repair_block_count);
    let layout = RepairGroupLayout::new(
        GroupNumber(group),
        BlockNumber(start_block),
        blocks_per_group,
        DEFAULT_REPAIR_VALIDATION_BLOCK_COUNT,
        repair_block_count,
    )?;

    Ok(BtrfsRepairGroupSpec {
        group,
        logical_start,
        logical_bytes,
        physical_start_block: BlockNumber(start_block),
        physical_block_count: block_count,
        source_block_count,
        layout,
    })
}

pub fn discover_btrfs_repair_group_specs(
    path: &PathBuf,
    block_size: u32,
) -> Result<Vec<BtrfsRepairGroupSpec>> {
    let cx = cli_cx();
    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let fs = OpenFs::from_device(&cx, Box::new(byte_dev), &OpenOptions::default())
        .with_context(|| format!("failed to open btrfs image at {}", path.display()))?;
    if !fs.is_btrfs() {
        bail!("image is not btrfs");
    }
    let chunks = fs
        .btrfs_context()
        .ok_or_else(|| anyhow::anyhow!("btrfs context is unavailable"))?
        .chunks
        .clone();

    let root_entries = fs
        .walk_btrfs_root_tree(&cx)
        .context("failed to walk btrfs root tree")?;
    let extent_root_entry = root_entries
        .iter()
        .find(|entry| {
            entry.key.objectid == BTRFS_EXTENT_TREE_OBJECTID
                && entry.key.item_type == BTRFS_ROOT_ITEM_TYPE
        })
        .ok_or_else(|| anyhow::anyhow!("failed to locate btrfs extent tree root item"))?;
    let extent_root_bytenr = parse_btrfs_root_item_bytenr(&extent_root_entry.data)
        .context("failed to parse btrfs extent tree root item")?;

    let extent_entries = fs
        .walk_btrfs_tree(&cx, extent_root_bytenr)
        .with_context(|| format!("failed to walk btrfs extent tree at {extent_root_bytenr}"))?;

    let mut specs = Vec::new();
    let mut group_index = 0_u32;
    for entry in extent_entries
        .iter()
        .filter(|entry| entry.key.item_type == BTRFS_BLOCK_GROUP_ITEM_TYPE)
    {
        let payload_total =
            parse_btrfs_block_group_total_bytes(&entry.data).with_context(|| {
                format!(
                    "failed to parse btrfs block-group payload for key objectid={} offset={}",
                    entry.key.objectid, entry.key.offset
                )
            })?;
        let logical_bytes = if entry.key.offset == 0 {
            payload_total
        } else {
            entry.key.offset
        };
        let spec = build_btrfs_repair_group_spec(
            group_index,
            entry.key.objectid,
            logical_bytes,
            block_size,
            &chunks,
        )?;
        specs.push(spec);
        group_index = group_index.saturating_add(1);
    }

    if specs.is_empty() {
        bail!("no btrfs block groups discovered from extent tree");
    }

    Ok(specs)
}

pub fn build_ext4_repair_group_spec(
    sb: &Ext4Superblock,
    group: u32,
) -> Result<Ext4RepairGroupSpec> {
    let (scrub_start, scrub_count) = ext4_group_scrub_scope(sb, group)?;
    let blocks_per_group = u32::try_from(scrub_count).with_context(|| {
        format!("ext4 group {group} scrub span does not fit u32 blocks ({scrub_count})")
    })?;
    if blocks_per_group <= REPAIR_DESC_SLOT_COUNT + 1 {
        bail!(
            "ext4 group {group} is too small for repair tail layout (blocks_per_group={blocks_per_group})"
        );
    }

    let source_and_repair_budget = blocks_per_group.saturating_sub(REPAIR_DESC_SLOT_COUNT);
    let desired_repair = RepairGroupDescExt::compute_repair_block_count(
        source_and_repair_budget,
        DEFAULT_REPAIR_OVERHEAD_RATIO,
    )
    .max(1);
    let repair_block_count = desired_repair
        .min(source_and_repair_budget.saturating_sub(1))
        .max(1);
    let source_block_count = source_and_repair_budget.saturating_sub(repair_block_count);
    if source_block_count == 0 {
        bail!(
            "ext4 group {group} has no source payload blocks after reserving repair metadata \
             (blocks_per_group={blocks_per_group}, repair_blocks={repair_block_count})"
        );
    }

    let layout = RepairGroupLayout::new(
        GroupNumber(group),
        scrub_start,
        blocks_per_group,
        DEFAULT_REPAIR_VALIDATION_BLOCK_COUNT,
        repair_block_count,
    )?;

    Ok(Ext4RepairGroupSpec {
        group,
        scrub_start_block: scrub_start,
        scrub_block_count: scrub_count,
        source_first_block: scrub_start,
        source_block_count,
        layout,
    })
}

pub fn build_ext4_repair_group_specs(sb: &Ext4Superblock) -> Result<Vec<Ext4RepairGroupSpec>> {
    let mut specs = Vec::with_capacity(usize::try_from(sb.groups_count()).unwrap_or(usize::MAX));
    for group in 0..sb.groups_count() {
        specs.push(build_ext4_repair_group_spec(sb, group)?);
    }
    Ok(specs)
}

pub fn probe_ext4_repair_staleness(
    path: &PathBuf,
    block_size: u32,
    specs: &[Ext4RepairGroupSpec],
) -> Result<Vec<(u32, Ext4RepairStaleness)>> {
    let cx = cli_cx();
    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let block_dev = ByteBlockDevice::new(byte_dev, block_size)
        .with_context(|| format!("failed to create block device (block_size={block_size})"))?;

    let mut states = Vec::with_capacity(specs.len());
    for spec in specs {
        let storage = RepairGroupStorage::new(&block_dev, spec.layout);
        let state =
            storage
                .read_group_desc_ext(&cx)
                .map_or(Ext4RepairStaleness::Untracked, |desc| {
                    if desc.repair_generation == 0 {
                        Ext4RepairStaleness::Stale
                    } else {
                        match storage.read_repair_symbols(&cx) {
                            Ok(symbols) if symbols.is_empty() => Ext4RepairStaleness::Stale,
                            Ok(_) => Ext4RepairStaleness::Fresh,
                            Err(_) => Ext4RepairStaleness::Stale,
                        }
                    }
                });
        states.push((spec.group, state));
    }

    Ok(states)
}

pub fn probe_btrfs_repair_staleness(
    path: &PathBuf,
    block_size: u32,
    specs: &[BtrfsRepairGroupSpec],
) -> Result<Vec<(u32, Ext4RepairStaleness)>> {
    let cx = cli_cx();
    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let block_dev = ByteBlockDevice::new(byte_dev, block_size)
        .with_context(|| format!("failed to create block device (block_size={block_size})"))?;

    let mut states = Vec::with_capacity(specs.len());
    for spec in specs {
        let storage = RepairGroupStorage::new(&block_dev, spec.layout);
        let state =
            storage
                .read_group_desc_ext(&cx)
                .map_or(Ext4RepairStaleness::Untracked, |desc| {
                    if desc.repair_generation == 0 {
                        Ext4RepairStaleness::Stale
                    } else {
                        match storage.read_repair_symbols(&cx) {
                            Ok(symbols) if symbols.is_empty() => Ext4RepairStaleness::Stale,
                            Ok(_) => Ext4RepairStaleness::Fresh,
                            Err(_) => Ext4RepairStaleness::Stale,
                        }
                    }
                });
        states.push((spec.group, state));
    }

    Ok(states)
}

pub fn select_ext4_repair_groups(
    flags: RepairFlags,
    ext4_clean: bool,
    all_groups: &[u32],
    staleness: &[(u32, Ext4RepairStaleness)],
) -> Vec<u32> {
    if flags.full_scrub() || flags.rebuild_symbols() {
        return all_groups.to_vec();
    }

    let stale: Vec<u32> = staleness
        .iter()
        .filter_map(|(group, state)| (*state == Ext4RepairStaleness::Stale).then_some(*group))
        .collect();
    if !stale.is_empty() {
        return stale;
    }

    let has_fresh = staleness
        .iter()
        .any(|(_, state)| *state == Ext4RepairStaleness::Fresh);
    if has_fresh || ext4_clean {
        return Vec::new();
    }

    all_groups.to_vec()
}

pub fn select_btrfs_repair_groups(
    flags: RepairFlags,
    all_groups: &[u32],
    staleness: &[(u32, Ext4RepairStaleness)],
    limitations: &mut Vec<String>,
) -> Vec<u32> {
    let selected = select_ext4_repair_groups(flags, false, all_groups, staleness);
    if selected.is_empty() {
        let stale_count = staleness
            .iter()
            .filter(|(_, state)| *state == Ext4RepairStaleness::Stale)
            .count();
        let fresh_count = staleness
            .iter()
            .filter(|(_, state)| *state == Ext4RepairStaleness::Fresh)
            .count();
        let untracked_count = staleness
            .iter()
            .filter(|(_, state)| *state == Ext4RepairStaleness::Untracked)
            .count();

        if stale_count == 0 && fresh_count > 0 {
            limitations.push(
                "stale-only scope found no stale btrfs groups; running full scrub".to_owned(),
            );
        } else if stale_count == 0 && fresh_count == 0 && untracked_count > 0 {
            limitations.push(
                "stale-only scope could not infer btrfs group staleness from on-image repair metadata; running full scrub"
                    .to_owned(),
            );
        } else {
            limitations.push(
                "stale-only scope yielded no explicit btrfs candidates; running full scrub"
                    .to_owned(),
            );
        }
        return all_groups.to_vec();
    }

    if selected.len() < all_groups.len() {
        let stale_count = staleness
            .iter()
            .filter(|(_, state)| *state == Ext4RepairStaleness::Stale)
            .count();
        let fresh_count = staleness
            .iter()
            .filter(|(_, state)| *state == Ext4RepairStaleness::Fresh)
            .count();
        let untracked_count = staleness
            .iter()
            .filter(|(_, state)| *state == Ext4RepairStaleness::Untracked)
            .count();
        limitations.push(format!(
            "stale-only scope selected {}/{} btrfs groups (stale={}, fresh={}, untracked={})",
            selected.len(),
            all_groups.len(),
            stale_count,
            fresh_count,
            untracked_count
        ));
    }

    selected
}

pub fn scrub_ext4_groups_for_repair(
    path: &PathBuf,
    flavor: &FsFlavor,
    specs: &[Ext4RepairGroupSpec],
    groups: &[u32],
    max_threads: Option<u32>,
    limitations: &mut Vec<String>,
) -> Result<ScrubReport> {
    if groups.is_empty() {
        return Ok(ScrubReport {
            findings: Vec::new(),
            blocks_scanned: 0,
            blocks_corrupt: 0,
            blocks_io_error: 0,
        });
    }

    let block_size = match flavor {
        FsFlavor::Ext4(sb) => sb.block_size,
        FsFlavor::Btrfs(_) => {
            bail!("ext4 repair helper called for non-ext4 flavor");
        }
    };

    let mut reports = Vec::with_capacity(groups.len());
    for group in groups {
        let spec = specs
            .iter()
            .find(|spec| spec.group == *group)
            .ok_or_else(|| {
                anyhow::anyhow!("ext4 repair group {group} is not available in the computed layout")
            })?;
        let report = scrub_range_for_repair(
            path,
            flavor,
            block_size,
            spec.scrub_start_block,
            spec.scrub_block_count,
            max_threads,
            limitations,
        )
        .with_context(|| format!("failed to scrub ext4 group {group}"))?;
        reports.push(report);
    }

    Ok(merge_scrub_reports(reports))
}

pub fn scrub_btrfs_groups_for_repair(
    path: &PathBuf,
    flavor: &FsFlavor,
    block_size: u32,
    specs: &[BtrfsRepairGroupSpec],
    groups: &[u32],
    max_threads: Option<u32>,
    limitations: &mut Vec<String>,
) -> Result<ScrubReport> {
    if groups.is_empty() {
        return Ok(ScrubReport {
            findings: Vec::new(),
            blocks_scanned: 0,
            blocks_corrupt: 0,
            blocks_io_error: 0,
        });
    }

    let spec_by_group: BTreeMap<u32, BtrfsRepairGroupSpec> = specs
        .iter()
        .copied()
        .map(|spec| (spec.group, spec))
        .collect();
    let mut reports = Vec::with_capacity(groups.len());
    for group in groups {
        let spec = spec_by_group.get(group).ok_or_else(|| {
            anyhow::anyhow!("btrfs repair group {group} is not available in the computed layout")
        })?;
        let report = scrub_range_for_repair(
            path,
            flavor,
            block_size,
            spec.physical_start_block,
            spec.physical_block_count,
            max_threads,
            limitations,
        )
        .with_context(|| format!("failed to scrub btrfs block group {group}"))?;
        reports.push(report);
    }

    Ok(merge_scrub_reports(reports))
}

pub fn corrupt_blocks_at_error_or_higher(report: &ScrubReport) -> Vec<BlockNumber> {
    let mut blocks: Vec<BlockNumber> = report
        .findings
        .iter()
        .filter(|finding| finding.severity >= Severity::Error)
        .map(|finding| finding.block)
        .collect();
    blocks.sort_unstable_by_key(|block| block.0);
    blocks.dedup_by_key(|block| block.0);
    blocks
}

pub fn group_ext4_corrupt_blocks(
    report: &ScrubReport,
    specs: &[Ext4RepairGroupSpec],
) -> (BTreeMap<u32, Vec<BlockNumber>>, u64) {
    let mut grouped: BTreeMap<u32, Vec<BlockNumber>> = BTreeMap::new();
    let mut outside_source_ranges = 0_u64;

    for block in corrupt_blocks_at_error_or_higher(report) {
        if let Some(spec) = specs.iter().find(|spec| {
            let start = spec.source_first_block.0;
            let end = start.saturating_add(u64::from(spec.source_block_count));
            block.0 >= start && block.0 < end
        }) {
            grouped.entry(spec.group).or_default().push(block);
        } else {
            outside_source_ranges = outside_source_ranges.saturating_add(1);
        }
    }

    (grouped, outside_source_ranges)
}

#[allow(clippy::too_many_arguments)]
pub fn recover_ext4_corrupt_blocks(
    path: &PathBuf,
    block_size: u32,
    fs_uuid: [u8; 16],
    specs: &[Ext4RepairGroupSpec],
    report: &ScrubReport,
    limitations: &mut Vec<String>,
) -> Result<(u64, u64, Vec<u32>)> {
    let cx = cli_cx();
    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let block_dev = ByteBlockDevice::new(byte_dev, block_size)
        .with_context(|| format!("failed to create block device (block_size={block_size})"))?;

    let (grouped, outside_source_ranges) = group_ext4_corrupt_blocks(report, specs);
    if outside_source_ranges > 0 {
        limitations.push(format!(
            "{outside_source_ranges} corrupt block(s) were outside ext4 source repair ranges and \
             could not be reconstructed with block symbols"
        ));
    }

    let mut recovered_blocks = 0_u64;
    let mut unrecovered_blocks = 0_u64;
    let mut repaired_groups = Vec::new();

    for (group, corrupt_blocks) in grouped {
        let spec = specs
            .iter()
            .find(|spec| spec.group == group)
            .ok_or_else(|| {
                anyhow::anyhow!("ext4 recovery group {group} missing from computed repair layout")
            })?;
        let orchestrator = GroupRecoveryOrchestrator::new(
            &block_dev,
            fs_uuid,
            spec.layout,
            spec.source_first_block,
            spec.source_block_count,
        )
        .with_context(|| format!("failed to create recovery orchestrator for group {group}"))?;

        let outcome = orchestrator.recover_from_corrupt_blocks(&cx, &corrupt_blocks);
        let repaired = u64::try_from(outcome.repaired_blocks.len()).unwrap_or(u64::MAX);
        let corrupt = u64::try_from(corrupt_blocks.len()).unwrap_or(u64::MAX);
        let unrecovered = corrupt.saturating_sub(repaired);
        recovered_blocks = recovered_blocks.saturating_add(repaired);
        unrecovered_blocks = unrecovered_blocks.saturating_add(unrecovered);
        if repaired > 0 {
            repaired_groups.push(group);
        }

        if outcome.evidence.outcome != RecoveryOutcome::Recovered || unrecovered > 0 {
            let reason = outcome.evidence.reason.as_deref().unwrap_or("unspecified");
            limitations.push(format!(
                "ext4 group {group} recovery outcome={:?} recovered={repaired} unrecovered={unrecovered} reason={reason}",
                outcome.evidence.outcome
            ));
        }
    }

    Ok((recovered_blocks, unrecovered_blocks, repaired_groups))
}

/// Group corrupt blocks from a scrub report into btrfs block-group buckets.
pub fn group_btrfs_corrupt_blocks(
    report: &ScrubReport,
    specs: &[BtrfsRepairGroupSpec],
) -> (BTreeMap<u32, Vec<BlockNumber>>, u64) {
    let mut grouped: BTreeMap<u32, Vec<BlockNumber>> = BTreeMap::new();
    let mut outside_source_ranges = 0_u64;

    for block in corrupt_blocks_at_error_or_higher(report) {
        if let Some(spec) = specs.iter().find(|spec| {
            let start = spec.physical_start_block.0;
            let end = start.saturating_add(u64::from(spec.source_block_count));
            block.0 >= start && block.0 < end
        }) {
            grouped.entry(spec.group).or_default().push(block);
        } else {
            outside_source_ranges = outside_source_ranges.saturating_add(1);
        }
    }

    (grouped, outside_source_ranges)
}

/// Attempt RaptorQ symbol reconstruction for corrupt btrfs blocks.
pub fn recover_btrfs_corrupt_blocks(
    path: &PathBuf,
    block_size: u32,
    fs_uuid: [u8; 16],
    specs: &[BtrfsRepairGroupSpec],
    report: &ScrubReport,
    limitations: &mut Vec<String>,
) -> Result<(u64, u64, Vec<u32>)> {
    let cx = cli_cx();
    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let block_dev = ByteBlockDevice::new(byte_dev, block_size)
        .with_context(|| format!("failed to create block device (block_size={block_size})"))?;

    let (grouped, outside_source_ranges) = group_btrfs_corrupt_blocks(report, specs);
    if outside_source_ranges > 0 {
        limitations.push(format!(
            "{outside_source_ranges} corrupt block(s) were outside btrfs source repair ranges and \
             could not be reconstructed with block symbols"
        ));
    }

    let mut recovered_blocks = 0_u64;
    let mut unrecovered_blocks = 0_u64;
    let mut repaired_groups = Vec::new();

    for (group, corrupt_blocks) in grouped {
        let spec = specs
            .iter()
            .find(|spec| spec.group == group)
            .ok_or_else(|| {
                anyhow::anyhow!("btrfs recovery group {group} missing from computed repair layout")
            })?;
        let orchestrator = GroupRecoveryOrchestrator::new(
            &block_dev,
            fs_uuid,
            spec.layout,
            spec.physical_start_block,
            spec.source_block_count,
        )
        .with_context(|| {
            format!("failed to create recovery orchestrator for btrfs group {group}")
        })?;

        let outcome = orchestrator.recover_from_corrupt_blocks(&cx, &corrupt_blocks);
        let repaired = u64::try_from(outcome.repaired_blocks.len()).unwrap_or(u64::MAX);
        let corrupt = u64::try_from(corrupt_blocks.len()).unwrap_or(u64::MAX);
        let unrecovered = corrupt.saturating_sub(repaired);
        recovered_blocks = recovered_blocks.saturating_add(repaired);
        unrecovered_blocks = unrecovered_blocks.saturating_add(unrecovered);
        if repaired > 0 {
            repaired_groups.push(group);
        }

        if outcome.evidence.outcome != RecoveryOutcome::Recovered || unrecovered > 0 {
            let reason = outcome.evidence.reason.as_deref().unwrap_or("unspecified");
            limitations.push(format!(
                "btrfs group {group} recovery outcome={:?} recovered={repaired} unrecovered={unrecovered} reason={reason}",
                outcome.evidence.outcome
            ));
        }
    }

    Ok((recovered_blocks, unrecovered_blocks, repaired_groups))
}

/// Re-encode RaptorQ repair symbols for the given btrfs block groups after
/// recovery, mirroring the ext4 symbol-rebuild workflow.
#[allow(clippy::too_many_lines)]
pub fn rebuild_btrfs_repair_symbols(
    path: &PathBuf,
    block_size: u32,
    fs_uuid: [u8; 16],
    specs: &[BtrfsRepairGroupSpec],
    groups: &[u32],
    limitations: &mut Vec<String>,
) -> Result<(u64, u64)> {
    if groups.is_empty() {
        return Ok((0, 0));
    }

    let cx = cli_cx();
    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let block_dev = ByteBlockDevice::new(byte_dev, block_size)
        .with_context(|| format!("failed to create block device (block_size={block_size})"))?;
    let spec_by_group: BTreeMap<u32, &BtrfsRepairGroupSpec> =
        specs.iter().map(|spec| (spec.group, spec)).collect();

    let mut unique_groups = BTreeSet::new();
    unique_groups.extend(groups.iter().copied());

    let mut rebuilt_groups = 0_u64;
    let mut failed_groups = 0_u64;
    for group in unique_groups {
        let Some(spec) = spec_by_group.get(&group).copied() else {
            failed_groups = failed_groups.saturating_add(1);
            limitations.push(format!(
                "cannot rebuild symbols for btrfs group {group}: group layout is unavailable"
            ));
            continue;
        };

        let encoded = match encode_group(
            &cx,
            &block_dev,
            &fs_uuid,
            GroupNumber(group),
            spec.physical_start_block,
            spec.source_block_count,
            spec.layout.repair_block_count,
        ) {
            Ok(encoded) => encoded,
            Err(error) => {
                failed_groups = failed_groups.saturating_add(1);
                limitations.push(format!(
                    "failed to encode repair symbols for btrfs group {group}: {error}"
                ));
                continue;
            }
        };

        let Ok(symbol_size) = u16::try_from(encoded.symbol_size) else {
            failed_groups = failed_groups.saturating_add(1);
            limitations.push(format!(
                "cannot rebuild symbols for btrfs group {group}: symbol_size {} exceeds u16",
                encoded.symbol_size
            ));
            continue;
        };
        let Ok(source_block_count_u16) = u16::try_from(encoded.source_block_count) else {
            failed_groups = failed_groups.saturating_add(1);
            limitations.push(format!(
                "cannot rebuild symbols for btrfs group {group}: source_block_count {} exceeds u16",
                encoded.source_block_count
            ));
            continue;
        };

        let storage = RepairGroupStorage::new(&block_dev, spec.layout);
        let current_generation = if let Ok(desc) = storage.read_group_desc_ext(&cx) {
            desc.repair_generation
        } else {
            let bootstrap = RepairGroupDescExt {
                transfer_length: u64::from(encoded.source_block_count)
                    .saturating_mul(u64::from(encoded.symbol_size)),
                symbol_size,
                source_block_count: source_block_count_u16,
                sub_blocks: 1,
                symbol_alignment: 4,
                repair_start_block: spec.layout.repair_start_block(),
                repair_block_count: spec.layout.repair_block_count,
                repair_generation: 0,
                checksum: 0,
            };
            if let Err(error) = storage.write_group_desc_ext(&cx, &bootstrap) {
                failed_groups = failed_groups.saturating_add(1);
                limitations.push(format!(
                    "failed to bootstrap repair descriptor for btrfs group {group}: {error}"
                ));
                continue;
            }
            0
        };

        let symbols: Vec<(u32, Vec<u8>)> = encoded
            .repair_symbols
            .into_iter()
            .map(|symbol| (symbol.esi, symbol.data))
            .collect();
        let new_generation = current_generation.saturating_add(1).max(1);
        match storage.write_repair_symbols(&cx, &symbols, new_generation) {
            Ok(()) => {
                rebuilt_groups = rebuilt_groups.saturating_add(1);
            }
            Err(error) => {
                failed_groups = failed_groups.saturating_add(1);
                limitations.push(format!(
                    "failed to publish rebuilt symbols for btrfs group {group}: {error}"
                ));
            }
        }
    }

    Ok((rebuilt_groups, failed_groups))
}

#[allow(clippy::too_many_lines)]
pub fn rebuild_ext4_repair_symbols(
    path: &PathBuf,
    block_size: u32,
    fs_uuid: [u8; 16],
    specs: &[Ext4RepairGroupSpec],
    groups: &[u32],
    limitations: &mut Vec<String>,
) -> Result<(u64, u64)> {
    if groups.is_empty() {
        return Ok((0, 0));
    }

    let cx = cli_cx();
    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let block_dev = ByteBlockDevice::new(byte_dev, block_size)
        .with_context(|| format!("failed to create block device (block_size={block_size})"))?;
    let spec_by_group: BTreeMap<u32, Ext4RepairGroupSpec> = specs
        .iter()
        .copied()
        .map(|spec| (spec.group, spec))
        .collect();

    let mut unique_groups = BTreeSet::new();
    unique_groups.extend(groups.iter().copied());

    let mut rebuilt_groups = 0_u64;
    let mut failed_groups = 0_u64;
    for group in unique_groups {
        let Some(spec) = spec_by_group.get(&group).copied() else {
            failed_groups = failed_groups.saturating_add(1);
            limitations.push(format!(
                "cannot rebuild symbols for ext4 group {group}: group layout is unavailable"
            ));
            continue;
        };

        let encoded = match encode_group(
            &cx,
            &block_dev,
            &fs_uuid,
            GroupNumber(group),
            spec.source_first_block,
            spec.source_block_count,
            spec.layout.repair_block_count,
        ) {
            Ok(encoded) => encoded,
            Err(error) => {
                failed_groups = failed_groups.saturating_add(1);
                limitations.push(format!(
                    "failed to encode repair symbols for ext4 group {group}: {error}"
                ));
                continue;
            }
        };

        let Ok(symbol_size) = u16::try_from(encoded.symbol_size) else {
            failed_groups = failed_groups.saturating_add(1);
            limitations.push(format!(
                "cannot rebuild symbols for ext4 group {group}: symbol_size {} exceeds u16",
                encoded.symbol_size
            ));
            continue;
        };
        let Ok(source_block_count_u16) = u16::try_from(encoded.source_block_count) else {
            failed_groups = failed_groups.saturating_add(1);
            limitations.push(format!(
                "cannot rebuild symbols for ext4 group {group}: source_block_count {} exceeds u16",
                encoded.source_block_count
            ));
            continue;
        };

        let storage = RepairGroupStorage::new(&block_dev, spec.layout);
        let current_generation = if let Ok(desc) = storage.read_group_desc_ext(&cx) {
            desc.repair_generation
        } else {
            let bootstrap = RepairGroupDescExt {
                transfer_length: u64::from(encoded.source_block_count)
                    .saturating_mul(u64::from(encoded.symbol_size)),
                symbol_size,
                source_block_count: source_block_count_u16,
                sub_blocks: 1,
                symbol_alignment: 4,
                repair_start_block: spec.layout.repair_start_block(),
                repair_block_count: spec.layout.repair_block_count,
                repair_generation: 0,
                checksum: 0,
            };
            if let Err(error) = storage.write_group_desc_ext(&cx, &bootstrap) {
                failed_groups = failed_groups.saturating_add(1);
                limitations.push(format!(
                    "failed to bootstrap repair descriptor for ext4 group {group}: {error}"
                ));
                continue;
            }
            0
        };

        let symbols: Vec<(u32, Vec<u8>)> = encoded
            .repair_symbols
            .into_iter()
            .map(|symbol| (symbol.esi, symbol.data))
            .collect();
        let new_generation = current_generation.saturating_add(1).max(1);
        match storage.write_repair_symbols(&cx, &symbols, new_generation) {
            Ok(()) => {
                rebuilt_groups = rebuilt_groups.saturating_add(1);
            }
            Err(error) => {
                failed_groups = failed_groups.saturating_add(1);
                limitations.push(format!(
                    "failed to publish rebuilt symbols for ext4 group {group}: {error}"
                ));
            }
        }
    }

    Ok((rebuilt_groups, failed_groups))
}

pub fn scrub_range_for_repair(
    path: &PathBuf,
    flavor: &FsFlavor,
    block_size: u32,
    start: BlockNumber,
    count: u64,
    max_threads: Option<u32>,
    limitations: &mut Vec<String>,
) -> Result<ScrubReport> {
    let seed_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let seed_block_dev = ByteBlockDevice::new(seed_dev, block_size)
        .with_context(|| format!("failed to create block device (block_size={block_size})"))?;
    let available_blocks = seed_block_dev.block_count();
    let effective_count = if start.0 >= available_blocks {
        0
    } else {
        count.min(available_blocks.saturating_sub(start.0))
    };
    if effective_count == 0 {
        return Ok(ScrubReport {
            findings: Vec::new(),
            blocks_scanned: 0,
            blocks_corrupt: 0,
            blocks_io_error: 0,
        });
    }

    let (worker_limit, capped_from) = repair_worker_limit(max_threads);
    if let Some(requested) = capped_from {
        limitations.push(format!(
            "--max-threads={requested} exceeds host parallelism; capped at {worker_limit}"
        ));
    }

    if worker_limit <= 1 || effective_count <= 1 {
        let validator = scrub_validator(flavor, block_size);
        let cx = cli_cx();
        return Scrubber::new(&seed_block_dev, &*validator)
            .scrub_range(&cx, start, effective_count)
            .with_context(|| {
                format!(
                    "failed to scrub range starting at block {} for {} blocks",
                    start.0, effective_count
                )
            });
    }

    drop(seed_block_dev);
    let ranges = partition_scrub_range(start, effective_count, worker_limit);
    let mut reports = Vec::with_capacity(ranges.len());

    std::thread::scope(|scope| -> Result<()> {
        let mut handles = Vec::with_capacity(ranges.len());
        for (worker_idx, (range_start, range_count)) in ranges.into_iter().enumerate() {
            let path = path.clone();
            let shard_flavor = flavor.clone();
            handles.push(scope.spawn(move || -> Result<ScrubReport> {
                let cx = cli_cx();
                let byte_dev = FileByteDevice::open(&path)
                    .with_context(|| format!("failed to open image: {}", path.display()))?;
                let block_dev = ByteBlockDevice::new(byte_dev, block_size).with_context(|| {
                    format!("failed to create block device (block_size={block_size})")
                })?;
                let validator = scrub_validator(&shard_flavor, block_size);
                Scrubber::new(&block_dev, &*validator)
                    .scrub_range(&cx, range_start, range_count)
                    .with_context(|| {
                        format!(
                            "repair scrub worker {worker_idx} failed at block {} for {} blocks",
                            range_start.0, range_count
                        )
                    })
            }));
        }

        for handle in handles {
            let shard = handle
                .join()
                .map_err(|_| anyhow::anyhow!("repair scrub worker panicked"))??;
            reports.push(shard);
        }
        Ok(())
    })?;

    Ok(merge_scrub_reports(reports))
}

#[allow(clippy::too_many_lines)]
pub fn build_repair_output(path: &PathBuf, options: RepairCommandOptions) -> Result<RepairOutput> {
    let flags = options.flags;
    let cx = cli_cx();
    let mut limitations = Vec::new();
    let repair_coordination = coordinate_repair_write_access(
        "ffs::cli::repair",
        REPAIR_COORDINATION_SCENARIO_REPAIR,
        "repair",
        path,
        !flags.verify_only(),
    );
    if repair_coordination.output.is_blocked() {
        limitations.push(repair_coordination.output.detail.clone());
    }
    let (flavor, bootstrap_recovery_source) = detect_flavor_with_optional_btrfs_bootstrap(
        &cx,
        path,
        !flags.verify_only() && repair_coordination.writes_allowed,
        &mut limitations,
    )
    .with_context(|| {
        if repair_coordination.output.is_blocked() {
            format!(
                "repair coordination blocked any write-side bootstrap path: {}",
                repair_coordination.output.detail
            )
        } else {
            format!("failed to detect ext4/btrfs metadata in {}", path.display())
        }
    })?;
    let rebuild_symbols_requested = flags.rebuild_symbols() && !flags.verify_only();
    if flags.rebuild_symbols() && flags.verify_only() {
        limitations.push("--rebuild-symbols is ignored when --verify-only is set".to_owned());
    }

    let ext4_recovery = if flags.verify_only() || !repair_coordination.writes_allowed {
        None
    } else {
        match &flavor {
            FsFlavor::Ext4(_) => Some(run_ext4_mount_recovery(path)?),
            FsFlavor::Btrfs(_) => None,
        }
    };
    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let image_len = byte_dev.len_bytes();

    let (scope, report, execution_stats) = match &flavor {
        FsFlavor::Ext4(sb) => {
            let specs = build_ext4_repair_group_specs(sb)
                .context("failed to compute ext4 repair group layout")?;
            let all_groups: Vec<u32> = specs.iter().map(|spec| spec.group).collect();
            let selected_groups = if let Some(group) = options.block_group {
                vec![group]
            } else {
                let staleness = probe_ext4_repair_staleness(path, sb.block_size, &specs)
                    .context("failed to inspect ext4 repair symbol staleness")?;
                let selection_flags = RepairFlags::empty()
                    .with_full_scrub(flags.full_scrub())
                    .with_rebuild_symbols(rebuild_symbols_requested);
                let selected = select_ext4_repair_groups(
                    selection_flags,
                    ext4_appears_clean_state(sb.state),
                    &all_groups,
                    &staleness,
                );

                if !selection_flags.full_scrub() && !selection_flags.rebuild_symbols() {
                    let stale_count = staleness
                        .iter()
                        .filter(|(_, state)| *state == Ext4RepairStaleness::Stale)
                        .count();
                    let fresh_count = staleness
                        .iter()
                        .filter(|(_, state)| *state == Ext4RepairStaleness::Fresh)
                        .count();
                    let untracked_count = staleness
                        .iter()
                        .filter(|(_, state)| *state == Ext4RepairStaleness::Untracked)
                        .count();

                    if selected.is_empty() {
                        if stale_count == 0 && fresh_count > 0 {
                            limitations.push(
                                "stale-only scope found no stale ext4 groups; scrub skipped (use --full-scrub to force)"
                                    .to_owned(),
                            );
                        } else if stale_count == 0
                            && fresh_count == 0
                            && ext4_appears_clean_state(sb.state)
                        {
                            limitations.push(
                                "stale-only scope found no tracked repair metadata and filesystem is clean; scrub skipped (use --full-scrub to force)"
                                    .to_owned(),
                            );
                        } else if stale_count == 0 && fresh_count == 0 && untracked_count > 0 {
                            limitations.push(
                                "stale-only scope could not infer group staleness from on-image repair metadata; running full scrub because filesystem is not clean"
                                    .to_owned(),
                            );
                        }
                    } else if selected.len() < all_groups.len() {
                        limitations.push(format!(
                            "stale-only scope selected {}/{} ext4 groups (stale={}, fresh={}, untracked={})",
                            selected.len(),
                            all_groups.len(),
                            stale_count,
                            fresh_count,
                            untracked_count
                        ));
                    }
                }

                if selected.is_empty() && !ext4_appears_clean_state(sb.state) {
                    limitations.push(
                        "stale-only scope yielded no explicit candidates on a non-clean filesystem; running full scrub"
                            .to_owned(),
                    );
                    all_groups
                } else {
                    selected
                }
            };

            let scope = if let Some(group) = options.block_group {
                let spec = specs
                    .iter()
                    .find(|spec| spec.group == group)
                    .ok_or_else(|| anyhow::anyhow!("ext4 block group {group} is unavailable"))?;
                RepairScopeOutput::Ext4BlockGroup {
                    group,
                    start_block: spec.scrub_start_block.0,
                    block_count: spec.scrub_block_count,
                }
            } else {
                RepairScopeOutput::Full
            };

            let selected_set: BTreeSet<u32> = selected_groups.iter().copied().collect();
            let selected_specs: Vec<Ext4RepairGroupSpec> = specs
                .iter()
                .copied()
                .filter(|spec| selected_set.contains(&spec.group))
                .collect();
            let mut report = scrub_ext4_groups_for_repair(
                path,
                &flavor,
                &specs,
                &selected_groups,
                options.max_threads,
                &mut limitations,
            )
            .context("failed to scrub ext4 image")?;

            let mut stats = RepairExecutionStats::default();
            if repair_coordination.writes_allowed
                && !selected_specs.is_empty()
                && count_blocks_at_severity_or_higher(&report, Severity::Error) > 0
            {
                let (_recovered, unrecovered, repaired_groups) = recover_ext4_corrupt_blocks(
                    path,
                    sb.block_size,
                    sb.uuid,
                    &selected_specs,
                    &report,
                    &mut limitations,
                )
                .context("failed to run ext4 block-symbol recovery")?;
                stats.recovery_attempted = true;
                stats.recovery_unrecovered_blocks = unrecovered;

                if !repaired_groups.is_empty() {
                    let (rebuilt, failed) = rebuild_ext4_repair_symbols(
                        path,
                        sb.block_size,
                        sb.uuid,
                        &selected_specs,
                        &repaired_groups,
                        &mut limitations,
                    )
                    .context("failed to refresh ext4 repair symbols after recovery")?;
                    stats.symbol_rebuild_attempted = true;
                    stats.symbol_rebuild_groups =
                        stats.symbol_rebuild_groups.saturating_add(rebuilt);
                    stats.symbol_rebuild_failed_groups =
                        stats.symbol_rebuild_failed_groups.saturating_add(failed);
                }
            }

            if repair_coordination.writes_allowed
                && rebuild_symbols_requested
                && !selected_specs.is_empty()
            {
                let (rebuilt, failed) = rebuild_ext4_repair_symbols(
                    path,
                    sb.block_size,
                    sb.uuid,
                    &selected_specs,
                    &selected_groups,
                    &mut limitations,
                )
                .context("failed to rebuild ext4 repair symbols")?;
                stats.symbol_rebuild_attempted = true;
                stats.symbol_rebuild_groups = stats.symbol_rebuild_groups.saturating_add(rebuilt);
                stats.symbol_rebuild_failed_groups =
                    stats.symbol_rebuild_failed_groups.saturating_add(failed);
            }

            if repair_coordination.writes_allowed
                && (stats.recovery_attempted || stats.symbol_rebuild_attempted)
            {
                report = scrub_ext4_groups_for_repair(
                    path,
                    &flavor,
                    &specs,
                    &selected_groups,
                    options.max_threads,
                    &mut limitations,
                )
                .context("failed to verify ext4 image after repair writes")?;
            }

            if stats.symbol_rebuild_failed_groups > 0 {
                limitations.push(format!(
                    "symbol re-encoding failed for {} ext4 group(s)",
                    stats.symbol_rebuild_failed_groups
                ));
            }

            (scope, report, stats)
        }
        FsFlavor::Btrfs(sb) => {
            let block_size = choose_btrfs_scrub_block_size(image_len, sb.nodesize, sb.sectorsize)
                .with_context(|| {
                    format!(
                        "failed to derive aligned btrfs scrub block size (len_bytes={image_len}, nodesize={}, sectorsize={})",
                        sb.nodesize, sb.sectorsize
                    )
                })?;
            let mut scoped_btrfs_groups = Vec::new();
            let mut scoped_btrfs_specs = Vec::new();
            let (scope, scrub_start, scrub_count) = if let Some(group) = options.block_group {
                let specs = discover_btrfs_repair_group_specs(path, block_size)
                    .context("failed to discover btrfs block groups for scoped repair")?;
                let spec = specs
                    .iter()
                    .find(|spec| spec.group == group)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "btrfs block group {group} is unavailable (valid range: 0..{})",
                            specs.len().saturating_sub(1)
                        )
                    })?;
                (
                    RepairScopeOutput::BtrfsBlockGroup {
                        group,
                        logical_start: spec.logical_start,
                        logical_bytes: spec.logical_bytes,
                        start_block: spec.physical_start_block.0,
                        block_count: spec.physical_block_count,
                    },
                    spec.physical_start_block,
                    spec.physical_block_count,
                )
            } else {
                if !flags.full_scrub() && !rebuild_symbols_requested {
                    match discover_btrfs_repair_group_specs(path, block_size) {
                        Ok(specs) if !specs.is_empty() => {
                            let all_groups: Vec<u32> =
                                specs.iter().map(|spec| spec.group).collect();
                            match probe_btrfs_repair_staleness(path, block_size, &specs) {
                                Ok(staleness) => {
                                    let selected = select_btrfs_repair_groups(
                                        RepairFlags::empty(),
                                        &all_groups,
                                        &staleness,
                                        &mut limitations,
                                    );
                                    if selected.len() < all_groups.len() {
                                        let selected_set: BTreeSet<u32> =
                                            selected.iter().copied().collect();
                                        scoped_btrfs_specs = specs
                                            .iter()
                                            .copied()
                                            .filter(|spec| selected_set.contains(&spec.group))
                                            .collect();
                                        if scoped_btrfs_specs.len() == selected.len() {
                                            scoped_btrfs_groups = selected;
                                        } else {
                                            scoped_btrfs_specs.clear();
                                            limitations.push(
                                                "stale-only btrfs group selection could not be mapped to discovered group layouts; running full scrub"
                                                    .to_owned(),
                                            );
                                        }
                                    }
                                }
                                Err(error) => {
                                    limitations.push(format!(
                                        "failed to inspect btrfs repair symbol staleness: {error:#}; running full scrub"
                                    ));
                                }
                            }
                        }
                        Ok(_) => limitations.push(
                            "no btrfs block groups discovered for stale-only selection; running full scrub"
                                .to_owned(),
                        ),
                        Err(error) => limitations.push(format!(
                            "failed to discover btrfs block groups for stale-only selection: {error:#}; running full scrub"
                        )),
                    }
                }
                (RepairScopeOutput::Full, BlockNumber(0), u64::MAX)
            };

            let mut report = if scoped_btrfs_groups.is_empty() {
                scrub_range_for_repair(
                    path,
                    &flavor,
                    block_size,
                    scrub_start,
                    scrub_count,
                    options.max_threads,
                    &mut limitations,
                )
                .context("failed to scrub btrfs image")?
            } else {
                scrub_btrfs_groups_for_repair(
                    path,
                    &flavor,
                    block_size,
                    &scoped_btrfs_specs,
                    &scoped_btrfs_groups,
                    options.max_threads,
                    &mut limitations,
                )
                .context("failed to scrub selected btrfs block groups")?
            };

            let mut stats = RepairExecutionStats {
                recovery_attempted: bootstrap_recovery_source.is_some(),
                ..RepairExecutionStats::default()
            };
            let mut verify_after_repair_writes = false;
            let primary_superblock = primary_btrfs_superblock_block(block_size);
            let superblock_in_scope = if scoped_btrfs_specs.is_empty() {
                block_range_contains(scrub_start, scrub_count, primary_superblock)
            } else {
                scoped_btrfs_specs.iter().any(|spec| {
                    block_range_contains(
                        spec.physical_start_block,
                        spec.physical_block_count,
                        primary_superblock,
                    )
                })
            };
            if repair_coordination.writes_allowed
                && superblock_in_scope
                && report_has_error_or_higher_for_block(&report, primary_superblock)
            {
                stats.recovery_attempted = true;
                match recover_primary_btrfs_superblock_from_backup(path, &mut limitations) {
                    Ok(Some(source)) => {
                        verify_after_repair_writes = true;
                        limitations.push(format!(
                            "restored primary btrfs superblock from backup mirror at byte offset {} (generation={})",
                            source.offset, source.generation
                        ));
                    }
                    Ok(None) => {
                        limitations.push(
                            "btrfs superblock corruption detected, but no valid backup superblock mirror was available for restoration"
                                .to_owned(),
                        );
                    }
                    Err(error) => {
                        limitations.push(format!(
                            "btrfs superblock recovery attempt failed: {error:#}"
                        ));
                    }
                }
            }

            if repair_coordination.writes_allowed && superblock_in_scope {
                let (mirror_scope_start, mirror_scope_count) = if scoped_btrfs_specs.is_empty() {
                    (scrub_start, scrub_count)
                } else {
                    (primary_superblock, 1)
                };
                match repair_corrupt_btrfs_superblock_mirrors_from_primary(
                    path,
                    block_size,
                    mirror_scope_start,
                    mirror_scope_count,
                    &mut limitations,
                ) {
                    Ok(mirror_outcome) => {
                        if mirror_outcome.attempted {
                            stats.recovery_attempted = true;
                            if mirror_outcome.repaired > 0 {
                                verify_after_repair_writes = true;
                            }
                        }
                    }
                    Err(error) => {
                        stats.recovery_attempted = true;
                        limitations.push(format!(
                            "btrfs superblock mirror recovery attempt failed: {error:#}"
                        ));
                    }
                }
            }

            // Attempt RaptorQ block-symbol recovery for non-superblock corruption.
            let mut btrfs_repaired_groups: Vec<u32> = Vec::new();
            let mut btrfs_specs_for_rebuild: Vec<BtrfsRepairGroupSpec> = Vec::new();
            if repair_coordination.writes_allowed
                && count_blocks_at_severity_or_higher(&report, Severity::Error) > 0
            {
                match discover_btrfs_repair_group_specs(path, block_size) {
                    Ok(btrfs_specs) if !btrfs_specs.is_empty() => {
                        btrfs_specs_for_rebuild.clone_from(&btrfs_specs);
                        match recover_btrfs_corrupt_blocks(
                            path,
                            block_size,
                            sb.fsid,
                            &btrfs_specs,
                            &report,
                            &mut limitations,
                        ) {
                            Ok((recovered, unrecovered, repaired_groups)) => {
                                stats.recovery_attempted = true;
                                stats.recovery_unrecovered_blocks = unrecovered;
                                btrfs_repaired_groups = repaired_groups;
                                if recovered > 0 {
                                    verify_after_repair_writes = true;
                                }
                            }
                            Err(error) => {
                                stats.recovery_attempted = true;
                                limitations.push(format!(
                                    "btrfs block-symbol recovery attempt failed: {error:#}"
                                ));
                            }
                        }
                    }
                    Ok(_) => {
                        limitations.push(
                            "no btrfs block groups discovered; block-symbol recovery skipped"
                                .to_owned(),
                        );
                    }
                    Err(error) => {
                        limitations.push(format!(
                            "failed to discover btrfs repair group layout: {error:#}"
                        ));
                    }
                }
            }

            // Rebuild repair symbols for repaired groups or on explicit request.
            if repair_coordination.writes_allowed {
                let rebuild_groups = if rebuild_symbols_requested {
                    // --rebuild-symbols: discover all groups and rebuild.
                    if btrfs_specs_for_rebuild.is_empty() {
                        match discover_btrfs_repair_group_specs(path, block_size) {
                            Ok(specs) => btrfs_specs_for_rebuild = specs,
                            Err(error) => {
                                limitations.push(format!(
                                    "failed to discover btrfs repair groups: {error:#}"
                                ));
                            }
                        }
                    }
                    btrfs_specs_for_rebuild
                        .iter()
                        .map(|spec| spec.group)
                        .collect::<Vec<_>>()
                } else {
                    btrfs_repaired_groups
                };
                if !rebuild_groups.is_empty() {
                    stats.symbol_rebuild_attempted = true;
                    match rebuild_btrfs_repair_symbols(
                        path,
                        block_size,
                        sb.fsid,
                        &btrfs_specs_for_rebuild,
                        &rebuild_groups,
                        &mut limitations,
                    ) {
                        Ok((rebuilt, failed)) => {
                            stats.symbol_rebuild_groups = rebuilt;
                            stats.symbol_rebuild_failed_groups = failed;
                            if rebuilt > 0 {
                                verify_after_repair_writes = true;
                            }
                        }
                        Err(error) => {
                            limitations
                                .push(format!("btrfs symbol rebuild attempt failed: {error:#}"));
                        }
                    }
                }
            }

            if repair_coordination.writes_allowed && verify_after_repair_writes {
                report = if scoped_btrfs_groups.is_empty() {
                    scrub_range_for_repair(
                        path,
                        &flavor,
                        block_size,
                        scrub_start,
                        scrub_count,
                        options.max_threads,
                        &mut limitations,
                    )
                    .context("failed to verify btrfs image after repairs")?
                } else {
                    scrub_btrfs_groups_for_repair(
                        path,
                        &flavor,
                        block_size,
                        &scoped_btrfs_specs,
                        &scoped_btrfs_groups,
                        options.max_threads,
                        &mut limitations,
                    )
                    .context("failed to verify selected btrfs block groups after repairs")?
                };
            }

            (scope, report, stats)
        }
    };
    let scrub = repair_scrub_from_report(&report);
    let action = if flags.verify_only() {
        RepairActionOutput::VerifyOnly
    } else if repair_coordination.output.is_blocked() {
        RepairActionOutput::RepairBlocked
    } else if ext4_recovery.is_some()
        || execution_stats.recovery_attempted
        || execution_stats.symbol_rebuild_attempted
    {
        RepairActionOutput::RepairRequested
    } else if scrub.error_or_higher > 0 {
        limitations.push(
            "repair found actionable corruption, but no write-side workflow is available for the detected corruption class"
                .to_owned(),
        );
        RepairActionOutput::RepairRequested
    } else {
        RepairActionOutput::NoCorruptionDetected
    };

    if execution_stats.recovery_unrecovered_blocks > 0 {
        limitations.push(format!(
            "{} corrupt block(s) remained unrecovered after block-symbol reconstruction attempts",
            execution_stats.recovery_unrecovered_blocks
        ));
    }

    let exit_code = if repair_coordination.output.is_blocked() {
        2
    } else {
        i32::from(
            scrub.error_or_higher > 0
                || execution_stats.recovery_unrecovered_blocks > 0
                || execution_stats.symbol_rebuild_failed_groups > 0,
        )
    };

    Ok(RepairOutput {
        filesystem: filesystem_name(&flavor).to_owned(),
        scope,
        action,
        scrub,
        repair_coordination: repair_coordination.output,
        ext4_recovery,
        exit_code,
        limitations,
    })
}

pub fn repair_scrub_from_report(report: &ScrubReport) -> RepairScrubOutput {
    RepairScrubOutput {
        scanned: report.blocks_scanned,
        corrupt: report.blocks_corrupt,
        error_or_higher: count_blocks_at_severity_or_higher(report, Severity::Error),
        io_error: report.blocks_io_error,
    }
}

pub fn print_repair_output(json: bool, output: &RepairOutput) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(output).context("serialize repair output")?
        );
        return Ok(());
    }

    println!("FrankenFS Repair");
    println!("filesystem: {}", output.filesystem);
    match &output.scope {
        RepairScopeOutput::Full => println!("scope: full"),
        RepairScopeOutput::Ext4BlockGroup {
            group,
            start_block,
            block_count,
        } => {
            println!(
                "scope: ext4 group {} (blocks {}..{})",
                group,
                start_block,
                start_block.saturating_add(*block_count).saturating_sub(1)
            );
        }
        RepairScopeOutput::BtrfsBlockGroup {
            group,
            logical_start,
            logical_bytes,
            start_block,
            block_count,
        } => {
            println!(
                "scope: btrfs group {} (logical {}..{}, physical blocks {}..{})",
                group,
                logical_start,
                logical_start
                    .saturating_add(*logical_bytes)
                    .saturating_sub(1),
                start_block,
                start_block.saturating_add(*block_count).saturating_sub(1)
            );
        }
    }
    println!("action: {:?}", output.action);
    println!(
        "scrub: scanned={} corrupt={} error_or_higher={} io_errors={}",
        output.scrub.scanned,
        output.scrub.corrupt,
        output.scrub.error_or_higher,
        output.scrub.io_error
    );
    if let Some(recovery) = &output.ext4_recovery {
        println!("ext4_recovery: {}", ext4_recovery_detail(recovery));
    }
    println!(
        "repair_coordination: status={:?} policy={} operation_id={} scenario_id={}",
        output.repair_coordination.status,
        output.repair_coordination.policy,
        output.repair_coordination.operation_id,
        output.repair_coordination.scenario_id
    );
    println!(
        "repair_coordination_detail: {} (coordination_file={}, local_host={})",
        output.repair_coordination.detail,
        output.repair_coordination.coordination_file,
        output.repair_coordination.local_host
    );
    if let Some(owner_host) = &output.repair_coordination.owner_host {
        println!("repair_coordination_owner_host: {owner_host}");
    }
    if let Some(owner_process_id) = output.repair_coordination.owner_process_id {
        println!("repair_coordination_owner_process_id: {owner_process_id}");
    }
    if let Some(error_class) = &output.repair_coordination.error_class {
        println!("repair_coordination_error_class: {error_class}");
    }
    println!("exit_code: {}", output.exit_code);
    if !output.limitations.is_empty() {
        println!("limitations:");
        for limitation in &output.limitations {
            println!("  - {limitation}");
        }
    }

    Ok(())
}
