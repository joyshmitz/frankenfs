#![forbid(unsafe_code)]

mod cmd_evidence;
mod cmd_repair;

use cmd_repair::{
    DEFAULT_REPAIR_OVERHEAD_RATIO, Ext4RepairStaleness, REPAIR_COORDINATION_SCENARIO_FSCK,
    RepairCoordinationOutput, append_btrfs_repair_detail, block_range_contains,
    build_ext4_repair_group_specs, coordinate_repair_write_access,
    detect_flavor_with_optional_btrfs_bootstrap, discover_btrfs_repair_group_specs,
    primary_btrfs_superblock_block, probe_btrfs_repair_staleness, probe_ext4_repair_staleness,
    recover_btrfs_corrupt_blocks, recover_primary_btrfs_superblock_from_backup,
    repair_corrupt_btrfs_superblock_mirrors_from_primary, report_has_error_or_higher_for_block,
    scrub_range_for_repair,
};

use anyhow::{Context, Result, bail};
use asupersync::Cx;
use clap::{Parser, Subcommand, ValueEnum};
use ffs_block::{BlockDevice, ByteBlockDevice, ByteDevice, FileByteDevice};
use ffs_btrfs::{
    BTRFS_FS_TREE_OBJECTID, BTRFS_ITEM_INODE_ITEM, BTRFS_ITEM_ROOT_ITEM, BtrfsInodeItem,
    parse_inode_item, parse_root_item,
};
use ffs_core::{
    CrashRecoveryOutcome, Ext4JournalReplayMode, FsFlavor, FsOps, OpenFs, OpenOptions,
    detect_filesystem_at_path,
};
use ffs_fuse::{MountConfig, MountOptions, mount_managed};
use ffs_harness::ParityReport;
use ffs_ondisk::{
    BtrfsSuperblock, Ext4DirEntry, Ext4Extent, Ext4ExtentHeader, Ext4ExtentIndex, Ext4GroupDesc,
    Ext4ImageReader, Ext4Inode, Ext4Superblock, ExtentTree, parse_dx_root, parse_extent_tree,
    parse_inode_extent_tree,
};
use ffs_repair::scrub::{
    BlockValidator, BtrfsSuperblockValidator, BtrfsTreeBlockValidator, CompositeValidator,
    Ext4SuperblockValidator, ScrubReport, Scrubber, Severity, ZeroCheckValidator,
};
use ffs_types::{
    BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE, BlockNumber, EXT4_SUPERBLOCK_OFFSET,
    EXT4_SUPERBLOCK_SIZE, GroupNumber, InodeNumber, MountMode,
};
use serde::Serialize;
use std::collections::BTreeSet;
use std::env::VarError;
use std::fmt::Write;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::{debug, error, info, info_span, warn};
use tracing_subscriber::EnvFilter;

// ── Production Cx acquisition ───────────────────────────────────────────────

#[must_use]
pub fn cli_cx() -> Cx {
    Cx::for_request()
}

// ── CLI definition ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum LogFormat {
    Human,
    Json,
}

impl LogFormat {
    const ENV_KEY: &'static str = "FFS_LOG_FORMAT";

    fn parse(raw: &str) -> Result<Self> {
        <Self as ValueEnum>::from_str(raw.trim(), true).map_err(|_| {
            anyhow::anyhow!(
                "invalid {key}={raw:?}; expected one of: human, json",
                key = Self::ENV_KEY
            )
        })
    }

    fn from_env() -> Result<Option<Self>> {
        match std::env::var(Self::ENV_KEY) {
            Ok(value) => Ok(Some(Self::parse(&value)?)),
            Err(VarError::NotPresent) => Ok(None),
            Err(VarError::NotUnicode(_)) => {
                bail!("{key} contains non-UTF-8 bytes", key = Self::ENV_KEY)
            }
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Json => "json",
        }
    }
}

const DEFAULT_MANAGED_UNMOUNT_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum MountRuntimeMode {
    Standard,
    Managed,
    #[value(name = "per-core")]
    PerCore,
}

impl MountRuntimeMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Managed => "managed",
            Self::PerCore => "per-core",
        }
    }

    const fn scenario_id(self, read_write: bool) -> &'static str {
        match (self, read_write) {
            (Self::Standard, false) => "cli_mount_runtime_standard_ro",
            (Self::Standard, true) => "cli_mount_runtime_standard_rw",
            (Self::Managed, false) => "cli_mount_runtime_managed_ro",
            (Self::Managed, true) => "cli_mount_runtime_managed_rw",
            (Self::PerCore, false) => "cli_mount_runtime_per_core_ro",
            (Self::PerCore, true) => "cli_mount_runtime_per_core_rw",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MountRuntimeConfig {
    mode: MountRuntimeMode,
    managed_unmount_timeout_secs: Option<u64>,
}

impl MountRuntimeConfig {
    fn validate(self) -> Result<Self> {
        if self.mode == MountRuntimeMode::Standard && self.managed_unmount_timeout_secs.is_some() {
            bail!("--managed-unmount-timeout-secs requires --runtime-mode managed or per-core");
        }
        Ok(self)
    }

    fn managed_unmount_timeout_secs(self) -> u64 {
        self.managed_unmount_timeout_secs
            .unwrap_or(DEFAULT_MANAGED_UNMOUNT_TIMEOUT_SECS)
    }
}

fn default_env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
}

fn env_bool(key: &str, default: bool) -> Result<bool> {
    match std::env::var(key) {
        Ok(value) => {
            let value = value.trim();
            if value == "1"
                || value.eq_ignore_ascii_case("true")
                || value.eq_ignore_ascii_case("yes")
                || value.eq_ignore_ascii_case("on")
            {
                Ok(true)
            } else if value == "0"
                || value.eq_ignore_ascii_case("false")
                || value.eq_ignore_ascii_case("no")
                || value.eq_ignore_ascii_case("off")
            {
                Ok(false)
            } else {
                bail!("invalid {key}={value:?}; expected one of: 1,0,true,false,yes,no,on,off")
            }
        }
        Err(VarError::NotPresent) => Ok(default),
        Err(VarError::NotUnicode(_)) => bail!("{key} contains non-UTF-8 bytes"),
    }
}

fn init_logging(log_format_override: Option<LogFormat>) -> Result<LogFormat> {
    let format = log_format_override
        .or(LogFormat::from_env()?)
        .unwrap_or(LogFormat::Human);

    match format {
        LogFormat::Human => tracing_subscriber::fmt()
            .with_env_filter(default_env_filter())
            .with_target(true)
            .with_level(true)
            .compact()
            .try_init()
            .map_err(|err| anyhow::anyhow!("failed to initialize human logger: {err}"))?,
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(true)
            .with_env_filter(default_env_filter())
            .with_target(true)
            .with_level(true)
            .try_init()
            .map_err(|err| anyhow::anyhow!("failed to initialize JSON logger: {err}"))?,
    }

    Ok(format)
}

#[derive(Parser)]
#[command(name = "ffs", about = "FrankenFS — memory-safe filesystem toolkit")]
struct Cli {
    /// Log output format (`human` or `json`).
    ///
    /// Precedence: `--log-format` > `FFS_LOG_FORMAT` > `human`.
    #[arg(long, value_enum, global = true)]
    log_format: Option<LogFormat>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect a filesystem image (ext4 or btrfs).
    Inspect {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
        /// List all btrfs subvolumes.
        #[arg(long)]
        subvolumes: bool,
        /// List all btrfs snapshots.
        #[arg(long)]
        snapshots: bool,
    },
    /// Show MVCC and EBR version statistics for a filesystem image.
    MvccStats {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Show filesystem information (superblock + optional detailed sections).
    Info {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Include ext4 block group table.
        #[arg(long)]
        groups: bool,
        /// Include MVCC engine status.
        #[arg(long)]
        mvcc: bool,
        /// Include repair subsystem status.
        #[arg(long)]
        repair: bool,
        /// Include journal status.
        #[arg(long)]
        journal: bool,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Dump low-level filesystem metadata.
    Dump {
        #[command(subcommand)]
        command: DumpCommand,
    },
    /// Run offline filesystem checks.
    Fsck {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Attempt repair actions when possible.
        #[arg(long, short = 'r')]
        repair: bool,
        /// Force a full check even if the filesystem appears clean.
        #[arg(long, short = 'f')]
        force: bool,
        /// Emit detailed phase progress.
        #[arg(long, short = 'v')]
        verbose: bool,
        /// Restrict checks to one ext4 group or btrfs block-group index.
        #[arg(long)]
        block_group: Option<u32>,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Trigger manual repair workflows.
    Repair {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Scrub all groups (default behavior is stale-only intent).
        #[arg(long)]
        full_scrub: bool,
        /// Restrict to one ext4 group or btrfs block-group index.
        #[arg(long)]
        block_group: Option<u32>,
        /// Force re-encoding of repair symbols.
        #[arg(long)]
        rebuild_symbols: bool,
        /// Verify only; do not attempt repair writes.
        #[arg(long)]
        verify_only: bool,
        /// Maximum worker threads for repair workflow.
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
        max_threads: Option<u32>,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Mount a filesystem image via FUSE.
    Mount {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Mountpoint directory.
        mountpoint: PathBuf,
        /// Runtime execution mode.
        ///
        /// Active controls by mode:
        /// - `standard` (default): blocking `ffs_fuse::mount` path. Process exits
        ///   on unmount or signal.
        /// - `managed`: background mount with lifecycle control, graceful Ctrl+C
        ///   shutdown, and final metrics logging.
        /// - `per-core`: managed mount with thread-per-core dispatch. Sets worker
        ///   threads to match detected cores and logs per-core metrics on shutdown.
        /// - Kernel FUSE `writeback_cache` mode is intentionally unsupported in
        ///   V1.x; durability boundaries are explicit `fsync` / `fsyncdir`.
        #[arg(long = "runtime-mode", value_enum, default_value_t = MountRuntimeMode::Standard)]
        runtime_mode: MountRuntimeMode,
        /// Graceful unmount timeout for managed/per-core modes (seconds).
        ///
        /// Invalid when used with `--runtime-mode standard`.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        managed_unmount_timeout_secs: Option<u64>,
        /// Allow other users to access the mount.
        #[arg(long)]
        allow_other: bool,
        /// Mount read-write (default is read-only).
        #[arg(long)]
        rw: bool,
        /// Enable native MVCC mode (allows repair symbols, version store, BLAKE3).
        ///
        /// By default FrankenFS mounts in compatibility mode where only standard
        /// ext4/btrfs on-disk structures are written. Native mode enables
        /// FrankenFS-specific features: MVCC version chains, RaptorQ repair
        /// symbols, and BLAKE3 checksums.
        #[arg(long)]
        native: bool,
        /// Mount a specific btrfs subvolume by name.
        ///
        /// Not yet supported — passing this flag will return an error.
        #[arg(long)]
        subvol: Option<String>,
        /// Mount a specific btrfs snapshot by name.
        ///
        /// Not yet supported — passing this flag will return an error.
        #[arg(long)]
        snapshot: Option<String>,
    },
    /// Run a read-only integrity scan (scrub) on a filesystem image.
    Scrub {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Show feature parity coverage report.
    Parity {
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Display the repair evidence ledger (JSONL).
    Evidence {
        /// Path to the evidence ledger JSONL or metrics snapshot JSON file.
        ledger: PathBuf,
        /// Output in JSON format (array of records).
        #[arg(long)]
        json: bool,
        /// Filter by event type (e.g., corruption_detected, repair_succeeded).
        #[arg(long)]
        event_type: Option<String>,
        /// Show only the last N records.
        #[arg(long)]
        tail: Option<usize>,
        /// Preset query:
        /// replay-anomalies, repair-failures, pressure-transitions, contention,
        /// metrics, cache, mvcc, repair-live.
        #[arg(long)]
        preset: Option<String>,
        /// Show aggregated summary instead of individual records.
        #[arg(long)]
        summary: bool,
    },
    /// Create a new ext4 filesystem image.
    ///
    /// Wraps `mkfs.ext4` to create a properly formatted ext4 image,
    /// then verifies the result via FrankenFS parsing.
    Mkfs {
        /// Output path for the new image file.
        output: PathBuf,
        /// Image size in megabytes.
        #[arg(long, default_value = "64")]
        size_mb: u64,
        /// Block size in bytes (1024, 2048, or 4096).
        #[arg(long, default_value = "4096")]
        block_size: u32,
        /// Volume label.
        #[arg(long, default_value = "frankenfs")]
        label: String,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum DumpCommand {
    /// Dump superblock fields.
    Superblock {
        /// Path to the filesystem image.
        image: PathBuf,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
        /// Include a raw hex dump of the on-disk structure.
        #[arg(long)]
        hex: bool,
    },
    /// Dump one ext4 group descriptor.
    Group {
        /// Block group index.
        group: u32,
        /// Path to the filesystem image.
        image: PathBuf,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
        /// Include a raw hex dump of the on-disk structure.
        #[arg(long)]
        hex: bool,
    },
    /// Dump one ext4 or btrfs inode.
    Inode {
        /// Inode number.
        inode: u64,
        /// Path to the filesystem image.
        image: PathBuf,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
        /// Include a raw hex dump of the on-disk structure.
        #[arg(long)]
        hex: bool,
    },
    /// Dump one ext4 inode's full extent tree.
    Extents {
        /// Inode number.
        inode: u64,
        /// Path to the filesystem image.
        image: PathBuf,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
        /// Include raw hex dumps of extent nodes.
        #[arg(long)]
        hex: bool,
    },
    /// Dump one ext4 directory inode's entries (and htree metadata if indexed).
    Dir {
        /// Inode number.
        inode: u64,
        /// Path to the filesystem image.
        image: PathBuf,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
        /// Include raw hex dumps of directory data blocks.
        #[arg(long)]
        hex: bool,
    },
}

impl Command {
    const fn name(&self) -> &'static str {
        match self {
            Self::Inspect { .. } => "inspect",
            Self::MvccStats { .. } => "mvcc-stats",
            Self::Info { .. } => "info",
            Self::Dump { .. } => "dump",
            Self::Fsck { .. } => "fsck",
            Self::Repair { .. } => "repair",
            Self::Mount { .. } => "mount",
            Self::Scrub { .. } => "scrub",
            Self::Parity { .. } => "parity",
            Self::Evidence { .. } => "evidence",
            Self::Mkfs { .. } => "mkfs",
        }
    }
}

// ── Serializable outputs ────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(tag = "filesystem", rename_all = "lowercase")]
enum InspectOutput {
    Ext4 {
        block_size: u32,
        inodes_count: u32,
        blocks_count: u64,
        volume_name: String,
        free_blocks_total: u64,
        free_inodes_total: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        free_space_mismatch: Option<FreeSpaceMismatch>,
        #[serde(skip_serializing_if = "Option::is_none")]
        orphan_diagnostics: Option<Ext4OrphanDiagnosticsOutput>,
    },
    Btrfs {
        sectorsize: u32,
        nodesize: u32,
        generation: u64,
        label: String,
    },
}

/// Optional field indicating a mismatch between bitmap and group descriptor counts.
#[derive(Debug, Serialize)]
struct FreeSpaceMismatch {
    gd_free_blocks: u64,
    gd_free_inodes: u64,
}

#[derive(Debug, Serialize)]
struct Ext4OrphanDiagnosticsOutput {
    count: u32,
    sample_inodes: Vec<u64>,
}

#[derive(Debug, Serialize)]
struct MvccStatsOutput {
    block_versions: BlockVersionStatsOutput,
    ebr_versions: EbrVersionStatsOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    wal_replay: Option<WalReplayInfoOutput>,
}

#[derive(Debug, Serialize)]
struct BlockVersionStatsOutput {
    tracked_blocks: usize,
    max_chain_length: usize,
    chains_over_cap: usize,
    chains_over_critical: usize,
    chain_cap: Option<usize>,
    critical_chain_length: Option<usize>,
}

#[derive(Debug, Serialize)]
struct EbrVersionStatsOutput {
    #[serde(rename = "retired_versions")]
    retired: u64,
    #[serde(rename = "reclaimed_versions")]
    reclaimed: u64,
    #[serde(rename = "pending_versions")]
    pending: u64,
}

#[derive(Debug, Serialize)]
struct InfoOutput {
    filesystem: String,
    superblock: SuperblockInfoOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups: Option<GroupsInfoOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mvcc: Option<MvccInfoOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repair: Option<RepairInfoOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    journal: Option<JournalInfoOutput>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum GroupsInfoOutput {
    Ext4 { entries: Vec<Ext4GroupInfoOutput> },
    Btrfs { entries: Vec<BtrfsGroupInfoOutput> },
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum SuperblockInfoOutput {
    Ext4 {
        uuid: String,
        label: String,
        block_size: u32,
        blocks_total: u64,
        blocks_free: u64,
        blocks_reserved: u64,
        inodes_total: u32,
        inodes_free: u32,
        blocks_per_group: u32,
        inodes_per_group: u32,
        groups_count: u32,
        mount_count: u16,
        max_mount_count: u16,
        state_flags: Vec<String>,
        feature_compat: String,
        feature_incompat: String,
        feature_ro_compat: String,
        checksum_type: String,
        checksum_seed: u32,
        mtime: u32,
        wtime: u32,
        lastcheck: u32,
        mkfs_time: u32,
    },
    Btrfs {
        fsid: String,
        label: String,
        sectorsize: u32,
        nodesize: u32,
        generation: u64,
        total_bytes: u64,
        bytes_used: u64,
        bytes_free: u64,
        num_devices: u64,
        csum_type: String,
        compat_flags_hex: String,
        compat_ro_flags_hex: String,
        incompat_flags_hex: String,
    },
}

#[derive(Debug, Serialize)]
struct Ext4GroupInfoOutput {
    group: u32,
    block_start: u64,
    block_end_inclusive: u64,
    free_blocks: u32,
    inode_start: u64,
    inode_end_inclusive: u64,
    free_inodes: u32,
    flags_raw: u16,
    flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct BtrfsGroupInfoOutput {
    chunk_index: u32,
    logical_start: u64,
    logical_end_inclusive: u64,
    logical_bytes: u64,
    chunk_type_raw: u64,
    chunk_type_flags: Vec<String>,
    owner: u64,
    stripe_len: u64,
    sector_size: u32,
    stripe_count: u16,
    stripes: Vec<BtrfsStripeInfoOutput>,
}

#[derive(Debug, Clone, Serialize)]
struct BtrfsStripeInfoOutput {
    stripe_index: u16,
    devid: u64,
    physical_start: u64,
    physical_end_inclusive: u64,
    device_uuid: String,
}

#[derive(Debug, Serialize)]
struct MvccInfoOutput {
    current_commit_seq: u64,
    active_snapshot_count: usize,
    oldest_active_snapshot: Option<u64>,
    total_versioned_blocks: usize,
    max_chain_depth: usize,
    average_chain_depth: String,
    blocks_pending_gc: u64,
    ssi_conflict_count: Option<u64>,
    abort_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wal_replay: Option<WalReplayInfoOutput>,
}

/// WAL replay health telemetry for CLI output.
#[derive(Debug, Serialize)]
struct WalReplayInfoOutput {
    /// Classified replay outcome (Clean, EmptyLog, TruncatedTail, CorruptTail, etc.).
    outcome: String,
    /// Whether the replay completed without discarded records.
    is_clean: bool,
    /// Number of commits successfully replayed.
    commits_replayed: u64,
    /// Number of block versions restored.
    versions_replayed: u64,
    /// Number of WAL records discarded (corrupt or truncated).
    records_discarded: u64,
    /// Byte offset where valid WAL data ends.
    wal_valid_bytes: u64,
    /// Total WAL file size in bytes.
    wal_total_bytes: u64,
    /// Whether a checkpoint was used during recovery.
    used_checkpoint: bool,
    /// Highest commit sequence from checkpoint, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    checkpoint_commit_seq: Option<u64>,
}

#[derive(Debug, Serialize)]
struct RepairInfoOutput {
    configured_overhead_ratio: f64,
    metrics_available: bool,
    note: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups_total: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups_fresh: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups_stale: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups_untracked: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
struct InfoCommandOptions {
    sections: InfoSections,
    json: bool,
}

#[derive(Debug, Clone, Copy)]
struct InfoSections(u8);

impl InfoSections {
    const GROUPS: u8 = 1 << 0;
    const MVCC: u8 = 1 << 1;
    const REPAIR: u8 = 1 << 2;
    const JOURNAL: u8 = 1 << 3;

    const fn empty() -> Self {
        Self(0)
    }

    const fn with_groups(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::GROUPS;
        }
        self
    }

    const fn with_mvcc(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::MVCC;
        }
        self
    }

    const fn with_repair(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::REPAIR;
        }
        self
    }

    const fn with_journal(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::JOURNAL;
        }
        self
    }

    const fn groups(self) -> bool {
        (self.0 & Self::GROUPS) != 0
    }

    const fn mvcc(self) -> bool {
        (self.0 & Self::MVCC) != 0
    }

    const fn repair(self) -> bool {
        (self.0 & Self::REPAIR) != 0
    }

    const fn journal(self) -> bool {
        (self.0 & Self::JOURNAL) != 0
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum JournalInfoOutput {
    Ext4 {
        journal_inode: u32,
        external_journal_dev: u32,
        journal_uuid: String,
        journal_size_bytes: Option<u64>,
        replayed_transactions: u32,
        replayed_blocks: u64,
        scanned_blocks: u64,
        descriptor_blocks: u64,
        commit_blocks: u64,
        revoke_blocks: u64,
        skipped_revoked_blocks: u64,
        incomplete_transactions: u64,
    },
    Unsupported {
        reason: String,
    },
}

#[derive(Debug, Serialize)]
struct DumpSuperblockOutput {
    filesystem: String,
    superblock: SuperblockInfoOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_hex: Option<String>,
}

#[derive(Debug, Serialize)]
struct DumpGroupOutput {
    filesystem: String,
    group: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    descriptor: Option<Ext4GroupDesc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    btrfs_chunk: Option<BtrfsGroupInfoOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_hex: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DumpInodeOutput {
    filesystem: String,
    inode: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ext4_parsed: Option<Ext4Inode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    btrfs_parsed: Option<DumpBtrfsInodeParsedOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_hex: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DumpBtrfsInodeParsedOutput {
    size: u64,
    nbytes: u64,
    nlink: u32,
    uid: u32,
    gid: u32,
    mode: u32,
    rdev: u64,
    atime_sec: u64,
    atime_nsec: u32,
    ctime_sec: u64,
    ctime_nsec: u32,
    mtime_sec: u64,
    mtime_nsec: u32,
    otime_sec: u64,
    otime_nsec: u32,
}

impl From<BtrfsInodeItem> for DumpBtrfsInodeParsedOutput {
    fn from(value: BtrfsInodeItem) -> Self {
        Self {
            size: value.size,
            nbytes: value.nbytes,
            nlink: value.nlink,
            uid: value.uid,
            gid: value.gid,
            mode: value.mode,
            rdev: value.rdev,
            atime_sec: value.atime_sec,
            atime_nsec: value.atime_nsec,
            ctime_sec: value.ctime_sec,
            ctime_nsec: value.ctime_nsec,
            mtime_sec: value.mtime_sec,
            mtime_nsec: value.mtime_nsec,
            otime_sec: value.otime_sec,
            otime_nsec: value.otime_nsec,
        }
    }
}

#[derive(Debug, Serialize)]
struct DumpExtentOutput {
    filesystem: String,
    inode: u64,
    root_depth: u16,
    nodes: Vec<DumpExtentNodeOutput>,
    flattened_extents: Vec<DumpExtentEntryOutput>,
}

#[derive(Debug, Serialize)]
struct DumpExtentNodeOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    source_block: Option<u64>,
    header: Ext4ExtentHeader,
    #[serde(flatten)]
    node: DumpExtentNodeKindOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_hex: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "node_kind", rename_all = "lowercase")]
enum DumpExtentNodeKindOutput {
    Leaf { extents: Vec<DumpExtentEntryOutput> },
    Index { indexes: Vec<Ext4ExtentIndex> },
}

#[derive(Debug, Serialize)]
struct DumpExtentEntryOutput {
    logical_block: u32,
    physical_start: u64,
    physical_end_inclusive: u64,
    raw_len: u16,
    actual_len: u16,
    initialized: bool,
}

#[derive(Debug, Serialize)]
struct DumpDirOutput {
    filesystem: String,
    inode: u64,
    entries: Vec<DumpDirEntryOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    htree: Option<DumpDxRootOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_hex_blocks: Option<Vec<DumpHexBlockOutput>>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DumpDirEntryOutput {
    index: usize,
    inode: u64,
    rec_len: u32,
    file_type: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct DumpDxRootOutput {
    hash_version: u8,
    indirect_levels: u8,
    entries: Vec<DumpDxEntryOutput>,
}

#[derive(Debug, Serialize)]
struct DumpDxEntryOutput {
    hash: u32,
    block: u32,
}

#[derive(Debug, Serialize)]
struct DumpHexBlockOutput {
    logical_block: u32,
    physical_block: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    item_kind: Option<String>,
    hex: String,
}

#[derive(Debug, Clone, Copy)]
struct FsckCommandOptions {
    flags: FsckFlags,
    block_group: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
struct FsckFlags(u8);

impl FsckFlags {
    const REPAIR: u8 = 1 << 0;
    const FORCE: u8 = 1 << 1;
    const VERBOSE: u8 = 1 << 2;
    const JSON: u8 = 1 << 3;

    const fn empty() -> Self {
        Self(0)
    }

    const fn with_repair(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::REPAIR;
        }
        self
    }

    const fn with_force(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::FORCE;
        }
        self
    }

    const fn with_verbose(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::VERBOSE;
        }
        self
    }

    const fn with_json(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::JSON;
        }
        self
    }

    const fn repair(self) -> bool {
        (self.0 & Self::REPAIR) != 0
    }

    const fn force(self) -> bool {
        (self.0 & Self::FORCE) != 0
    }

    const fn verbose(self) -> bool {
        (self.0 & Self::VERBOSE) != 0
    }

    const fn json(self) -> bool {
        (self.0 & Self::JSON) != 0
    }
}

#[derive(Debug, Serialize)]
struct FsckOutput {
    filesystem: String,
    scope: FsckScopeOutput,
    phases: Vec<FsckPhaseOutput>,
    scrub: FsckScrubOutput,
    repair_status: FsckRepairStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    repair_coordination: Option<RepairCoordinationOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ext4_recovery: Option<Ext4RecoveryOutput>,
    outcome: FsckOutcome,
    exit_code: i32,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum FsckScopeOutput {
    Full,
    Ext4BlockGroup {
        group: u32,
        start_block: u64,
        block_count: u64,
    },
    BtrfsBlockGroup {
        group: u32,
        logical_start: u64,
        logical_bytes: u64,
        start_block: u64,
        block_count: u64,
    },
}

#[derive(Debug, Serialize)]
struct FsckPhaseOutput {
    phase: String,
    status: String,
    detail: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum FsckRepairStatus {
    NotRequested,
    RequestedPerformed,
    RequestedNotPerformed,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum FsckOutcome {
    Clean,
    ErrorsFound,
}

#[derive(Debug, Serialize)]
pub struct FsckScrubOutput {
    pub scanned: u64,
    pub corrupt: u64,
    pub error_or_higher: u64,
    pub io_error: u64,
}

#[derive(Debug, Serialize)]
pub struct Ext4RecoveryOutput {
    pub recovery_performed: bool,
    #[serde(flatten)]
    pub crash_recovery: CrashRecoveryOutcome,
}

#[derive(Debug, Clone, Copy)]
pub struct RepairCommandOptions {
    pub flags: RepairFlags,
    pub block_group: Option<u32>,
    pub max_threads: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
pub struct RepairFlags(u8);

impl RepairFlags {
    const FULL_SCRUB: u8 = 1 << 0;
    const REBUILD_SYMBOLS: u8 = 1 << 1;
    const VERIFY_ONLY: u8 = 1 << 2;
    const JSON: u8 = 1 << 3;

    const fn empty() -> Self {
        Self(0)
    }

    const fn with_full_scrub(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::FULL_SCRUB;
        }
        self
    }

    const fn with_rebuild_symbols(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::REBUILD_SYMBOLS;
        }
        self
    }

    const fn with_verify_only(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::VERIFY_ONLY;
        }
        self
    }

    const fn with_json(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= Self::JSON;
        }
        self
    }

    const fn full_scrub(self) -> bool {
        (self.0 & Self::FULL_SCRUB) != 0
    }

    const fn rebuild_symbols(self) -> bool {
        (self.0 & Self::REBUILD_SYMBOLS) != 0
    }

    const fn verify_only(self) -> bool {
        (self.0 & Self::VERIFY_ONLY) != 0
    }

    const fn json(self) -> bool {
        (self.0 & Self::JSON) != 0
    }
}

#[derive(Debug, Serialize)]
pub struct RepairOutput {
    pub filesystem: String,
    pub scope: RepairScopeOutput,
    pub action: RepairActionOutput,
    pub scrub: RepairScrubOutput,
    pub repair_coordination: RepairCoordinationOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext4_recovery: Option<Ext4RecoveryOutput>,
    pub exit_code: i32,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RepairScopeOutput {
    Full,
    Ext4BlockGroup {
        group: u32,
        start_block: u64,
        block_count: u64,
    },
    BtrfsBlockGroup {
        group: u32,
        logical_start: u64,
        logical_bytes: u64,
        start_block: u64,
        block_count: u64,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairActionOutput {
    VerifyOnly,
    RepairBlocked,
    RepairRequested,
    NoCorruptionDetected,
}

#[derive(Debug, Serialize)]
pub struct RepairScrubOutput {
    pub scanned: u64,
    pub corrupt: u64,
    pub error_or_higher: u64,
    pub io_error: u64,
}

// ── Main ────────────────────────────────────────────────────────────────────

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

#[allow(clippy::too_many_lines)]
fn run() -> Result<()> {
    let cli = Cli::parse();
    let log_format = init_logging(cli.log_format)?;
    let command_name = cli.command.name();
    let run_span = info_span!(
        target: "ffs::cli",
        "command",
        command = command_name,
        log_format = log_format.as_str()
    );
    let _run_guard = run_span.enter();
    let started = Instant::now();

    info!(
        target: "ffs::cli",
        command = command_name,
        log_format = log_format.as_str(),
        "command_start"
    );

    let result = match cli.command {
        Command::Inspect {
            image,
            json,
            subvolumes,
            snapshots,
        } => inspect(&image, json, subvolumes, snapshots),
        Command::MvccStats { image, json } => mvcc_stats_cmd(&image, json),
        Command::Info {
            image,
            groups,
            mvcc,
            repair,
            journal,
            json,
        } => info_cmd(
            &image,
            InfoCommandOptions {
                sections: InfoSections::empty()
                    .with_groups(groups)
                    .with_mvcc(mvcc)
                    .with_repair(repair)
                    .with_journal(journal),
                json,
            },
        ),
        Command::Dump { command } => dump_cmd(&command),
        Command::Fsck {
            image,
            repair,
            force,
            verbose,
            block_group,
            json,
        } => fsck_cmd(
            &image,
            FsckCommandOptions {
                flags: FsckFlags::empty()
                    .with_repair(repair)
                    .with_force(force)
                    .with_verbose(verbose)
                    .with_json(json),
                block_group,
            },
        ),
        Command::Repair {
            image,
            full_scrub,
            block_group,
            rebuild_symbols,
            verify_only,
            max_threads,
            json,
        } => cmd_repair::repair_cmd(
            &image,
            RepairCommandOptions {
                flags: RepairFlags::empty()
                    .with_full_scrub(full_scrub)
                    .with_rebuild_symbols(rebuild_symbols)
                    .with_verify_only(verify_only)
                    .with_json(json),
                block_group,
                max_threads,
            },
        ),
        Command::Mount {
            image,
            mountpoint,
            runtime_mode,
            managed_unmount_timeout_secs,
            allow_other,
            rw,
            native,
            subvol,
            snapshot,
        } => {
            validate_btrfs_mount_selection(subvol.as_deref(), snapshot.as_deref())?;
            mount_cmd(
                &image,
                &mountpoint,
                allow_other,
                rw,
                native,
                runtime_mode,
                managed_unmount_timeout_secs,
            )
        }
        Command::Scrub { image, json } => scrub_cmd(&image, json),
        Command::Parity { json } => parity(json),
        Command::Evidence {
            ledger,
            json,
            event_type,
            tail,
            preset,
            summary,
        } => cmd_evidence::evidence_cmd(
            &ledger,
            json,
            event_type.as_deref(),
            tail,
            preset.as_deref(),
            summary,
        ),
        Command::Mkfs {
            output,
            size_mb,
            block_size,
            label,
            json,
        } => mkfs_cmd(&output, size_mb, block_size, &label, json),
    };

    let duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    if let Err(err) = &result {
        error!(
            target: "ffs::cli",
            command = command_name,
            duration_us,
            error = %err,
            "command_failed"
        );
    } else {
        info!(
            target: "ffs::cli",
            command = command_name,
            duration_us,
            "command_succeeded"
        );
    }

    result
}

fn inspect(path: &PathBuf, json: bool, list_subvolumes: bool, list_snapshots: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::inspect",
        "inspect",
        image = %path.display(),
        output_json = json
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::inspect", "inspect_start");

    let cx = cli_cx();
    let open_opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;

    // Handle --subvolumes and --snapshots for btrfs
    if (list_subvolumes || list_snapshots) && matches!(&flavor, FsFlavor::Btrfs(_)) {
        return inspect_btrfs_subvolumes(&cx, path, &flavor, json, list_subvolumes, list_snapshots);
    }
    if (list_subvolumes || list_snapshots) && matches!(&flavor, FsFlavor::Ext4(_)) {
        anyhow::bail!("--subvolumes and --snapshots are only supported for btrfs images");
    }

    let output = match &flavor {
        FsFlavor::Ext4(sb) => inspect_ext4_output(
            &cx,
            path,
            &open_opts,
            sb.block_size,
            sb.inodes_count,
            sb.blocks_count,
            &sb.volume_name,
        )?,
        FsFlavor::Btrfs(sb) => InspectOutput::Btrfs {
            sectorsize: sb.sectorsize,
            nodesize: sb.nodesize,
            generation: sb.generation,
            label: sb.label.clone(),
        },
    };

    info!(
        target: "ffs::cli::inspect",
        filesystem = match &flavor {
            FsFlavor::Ext4(_) => "ext4",
            FsFlavor::Btrfs(_) => "btrfs",
        },
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "inspect_detected_filesystem"
    );

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize output")?
        );
    } else {
        print_inspect_output(&output);
    }

    info!(
        target: "ffs::cli::inspect",
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "inspect_complete"
    );

    Ok(())
}

fn print_inspect_output(output: &InspectOutput) {
    println!("FrankenFS Inspector");
    match output {
        InspectOutput::Ext4 {
            block_size,
            inodes_count,
            blocks_count,
            volume_name,
            free_blocks_total,
            free_inodes_total,
            free_space_mismatch,
            orphan_diagnostics,
        } => {
            println!("filesystem: ext4");
            println!("block_size: {block_size}");
            println!("inodes_count: {inodes_count}");
            println!("blocks_count: {blocks_count}");
            println!("volume_name: {volume_name}");
            println!("free_blocks: {free_blocks_total}");
            println!("free_inodes: {free_inodes_total}");
            if let Some(mismatch) = free_space_mismatch {
                println!(
                    "WARNING: mismatch with group descriptors (gd_free_blocks={}, gd_free_inodes={})",
                    mismatch.gd_free_blocks, mismatch.gd_free_inodes
                );
            }
            if let Some(orphan_diag) = orphan_diagnostics {
                println!(
                    "orphans: count={} sample_inodes={:?}",
                    orphan_diag.count, orphan_diag.sample_inodes
                );
            }
        }
        InspectOutput::Btrfs {
            sectorsize,
            nodesize,
            generation,
            label,
        } => {
            println!("filesystem: btrfs");
            println!("sectorsize: {sectorsize}");
            println!("nodesize: {nodesize}");
            println!("generation: {generation}");
            println!("label: {label}");
        }
    }
}

fn build_wal_replay_info(open_fs: &OpenFs) -> Option<WalReplayInfoOutput> {
    open_fs.mvcc_wal_recovery().map(|report| {
        let outcome_str = format!("{:?}", report.outcome);
        let is_clean = report.outcome.is_clean();
        WalReplayInfoOutput {
            outcome: outcome_str,
            is_clean,
            commits_replayed: report.commits_replayed,
            versions_replayed: report.versions_replayed,
            records_discarded: report.records_discarded,
            wal_valid_bytes: report.wal_valid_bytes,
            wal_total_bytes: report.wal_total_bytes,
            used_checkpoint: report.used_checkpoint,
            checkpoint_commit_seq: report.checkpoint_commit_seq,
        }
    })
}

fn print_wal_replay_info(wal: &WalReplayInfoOutput, indent: &str) {
    println!("{indent}outcome: {}", wal.outcome);
    println!("{indent}is_clean: {}", wal.is_clean);
    println!("{indent}commits_replayed: {}", wal.commits_replayed);
    println!("{indent}versions_replayed: {}", wal.versions_replayed);
    println!("{indent}records_discarded: {}", wal.records_discarded);
    println!("{indent}wal_valid_bytes: {}", wal.wal_valid_bytes);
    println!("{indent}wal_total_bytes: {}", wal.wal_total_bytes);
    println!("{indent}used_checkpoint: {}", wal.used_checkpoint);
    if let Some(cp_seq) = wal.checkpoint_commit_seq {
        println!("{indent}checkpoint_commit_seq: {cp_seq}");
    }
}

/// Emit structured log event for WAL recovery telemetry.
///
/// The `tracing::info!` macro requires a string literal for `target:`, so callers
/// should invoke this macro-style helper at the call site instead. This function
/// provides a fallback using a generic target for contexts where the exact
/// target is not critical.
fn log_wal_recovery_telemetry(wal: &WalReplayInfoOutput) {
    info!(
        target: "ffs::cli",
        outcome = %wal.outcome,
        is_clean = wal.is_clean,
        commits_replayed = wal.commits_replayed,
        versions_replayed = wal.versions_replayed,
        records_discarded = wal.records_discarded,
        wal_valid_bytes = wal.wal_valid_bytes,
        wal_total_bytes = wal.wal_total_bytes,
        used_checkpoint = wal.used_checkpoint,
        "wal_recovery_telemetry"
    );
}

fn mvcc_stats_cmd(path: &PathBuf, json: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::mvcc_stats",
        "mvcc_stats",
        image = %path.display(),
        output_json = json
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::mvcc_stats", "mvcc_stats_start");

    let cx = cli_cx();
    let open_opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    let open_fs = OpenFs::open_with_options(&cx, path, &open_opts)
        .with_context(|| format!("failed to open image: {}", path.display()))?;

    let mvcc_guard = open_fs.mvcc_store().read();
    let block_stats = mvcc_guard.block_version_stats();
    let ebr_stats = mvcc_guard.ebr_stats();
    drop(mvcc_guard);

    let output = MvccStatsOutput {
        block_versions: BlockVersionStatsOutput {
            tracked_blocks: block_stats.tracked_blocks,
            max_chain_length: block_stats.max_chain_length,
            chains_over_cap: block_stats.chains_over_cap,
            chains_over_critical: block_stats.chains_over_critical,
            chain_cap: block_stats.chain_cap,
            critical_chain_length: block_stats.critical_chain_length,
        },
        ebr_versions: EbrVersionStatsOutput {
            retired: ebr_stats.retired_versions,
            reclaimed: ebr_stats.reclaimed_versions,
            pending: ebr_stats.pending_versions(),
        },
        wal_replay: build_wal_replay_info(&open_fs),
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize mvcc stats output")?
        );
    } else {
        println!("FrankenFS MVCC/EBR Stats");
        println!("block_versions:");
        println!("  tracked_blocks: {}", output.block_versions.tracked_blocks);
        println!(
            "  max_chain_length: {}",
            output.block_versions.max_chain_length
        );
        println!(
            "  chains_over_cap: {}",
            output.block_versions.chains_over_cap
        );
        println!(
            "  chains_over_critical: {}",
            output.block_versions.chains_over_critical
        );
        println!("  chain_cap: {:?}", output.block_versions.chain_cap);
        println!(
            "  critical_chain_length: {:?}",
            output.block_versions.critical_chain_length
        );
        println!("ebr_versions:");
        println!("  retired_versions: {}", output.ebr_versions.retired);
        println!("  reclaimed_versions: {}", output.ebr_versions.reclaimed);
        println!("  pending_versions: {}", output.ebr_versions.pending);
        if let Some(wal) = &output.wal_replay {
            println!("wal_replay:");
            print_wal_replay_info(wal, "  ");
        }
    }

    if let Some(wal) = &output.wal_replay {
        log_wal_recovery_telemetry(wal);
    }

    info!(
        target: "ffs::cli::mvcc_stats",
        tracked_blocks = output.block_versions.tracked_blocks,
        max_chain_length = output.block_versions.max_chain_length,
        pending_versions = output.ebr_versions.pending,
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "mvcc_stats_complete"
    );

    Ok(())
}

fn info_cmd(path: &PathBuf, options: InfoCommandOptions) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::info",
        "info",
        image = %path.display(),
        include_groups = options.sections.groups(),
        include_mvcc = options.sections.mvcc(),
        include_repair = options.sections.repair(),
        include_journal = options.sections.journal(),
        output_json = options.json
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::info", "info_start");

    let cx = cli_cx();
    let open_opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    let open_fs = OpenFs::open_with_options(&cx, path, &open_opts)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let output = build_info_output(path, &cx, &open_fs, options)?;

    print_info_output(options.json, &output)?;

    info!(
        target: "ffs::cli::info",
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        limitations = output.limitations.len(),
        "info_complete"
    );

    Ok(())
}

fn build_info_output(
    path: &PathBuf,
    cx: &Cx,
    open_fs: &OpenFs,
    options: InfoCommandOptions,
) -> Result<InfoOutput> {
    let mut limitations = Vec::new();

    let groups_output = if options.sections.groups() {
        match &open_fs.flavor {
            FsFlavor::Ext4(sb) => Some(GroupsInfoOutput::Ext4 {
                entries: build_ext4_group_info(path, sb)?,
            }),
            FsFlavor::Btrfs(sb) => Some(GroupsInfoOutput::Btrfs {
                entries: build_btrfs_group_info(open_fs, sb, &mut limitations),
            }),
        }
    } else {
        None
    };

    let mvcc_output = if options.sections.mvcc() {
        Some(build_mvcc_info(open_fs))
    } else {
        None
    };

    let repair_output = if options.sections.repair() {
        Some(build_repair_info(path, open_fs, &mut limitations))
    } else {
        None
    };

    let journal_output = if options.sections.journal() {
        match &open_fs.flavor {
            FsFlavor::Ext4(sb) => Some(build_ext4_journal_info(cx, open_fs, sb)),
            FsFlavor::Btrfs(_) => Some(JournalInfoOutput::Unsupported {
                reason: "btrfs journal status is not applicable (btrfs is copy-on-write)"
                    .to_owned(),
            }),
        }
    } else {
        None
    };

    Ok(InfoOutput {
        filesystem: filesystem_name(&open_fs.flavor).to_owned(),
        superblock: superblock_info_for(&open_fs.flavor),
        groups: groups_output,
        mvcc: mvcc_output,
        repair: repair_output,
        journal: journal_output,
        limitations,
    })
}

#[must_use]
pub fn filesystem_name(flavor: &FsFlavor) -> &'static str {
    match flavor {
        FsFlavor::Ext4(_) => "ext4",
        FsFlavor::Btrfs(_) => "btrfs",
    }
}

fn superblock_info_for(flavor: &FsFlavor) -> SuperblockInfoOutput {
    match flavor {
        FsFlavor::Ext4(sb) => {
            let checksum_type = if sb.checksum_type == 1 {
                "crc32c".to_owned()
            } else {
                format!("unknown({})", sb.checksum_type)
            };

            SuperblockInfoOutput::Ext4 {
                uuid: format_uuid(&sb.uuid),
                label: sb.volume_name.clone(),
                block_size: sb.block_size,
                blocks_total: sb.blocks_count,
                blocks_free: sb.free_blocks_count,
                blocks_reserved: sb.reserved_blocks_count,
                inodes_total: sb.inodes_count,
                inodes_free: sb.free_inodes_count,
                blocks_per_group: sb.blocks_per_group,
                inodes_per_group: sb.inodes_per_group,
                groups_count: sb.groups_count(),
                mount_count: sb.mnt_count,
                max_mount_count: sb.max_mnt_count,
                state_flags: ext4_state_flag_names(sb.state),
                feature_compat: format!("{}", sb.feature_compat),
                feature_incompat: format!("{}", sb.feature_incompat),
                feature_ro_compat: format!("{}", sb.feature_ro_compat),
                checksum_type,
                checksum_seed: sb.csum_seed(),
                mtime: sb.mtime,
                wtime: sb.wtime,
                lastcheck: sb.lastcheck,
                mkfs_time: sb.mkfs_time,
            }
        }
        FsFlavor::Btrfs(sb) => SuperblockInfoOutput::Btrfs {
            fsid: format_uuid(&sb.fsid),
            label: sb.label.clone(),
            sectorsize: sb.sectorsize,
            nodesize: sb.nodesize,
            generation: sb.generation,
            total_bytes: sb.total_bytes,
            bytes_used: sb.bytes_used,
            bytes_free: sb.total_bytes.saturating_sub(sb.bytes_used),
            num_devices: sb.num_devices,
            csum_type: btrfs_checksum_type_name(sb.csum_type),
            compat_flags_hex: format!("0x{:016x}", sb.compat_flags),
            compat_ro_flags_hex: format!("0x{:016x}", sb.compat_ro_flags),
            incompat_flags_hex: format!("0x{:016x}", sb.incompat_flags),
        },
    }
}

fn build_ext4_group_info(path: &PathBuf, sb: &Ext4Superblock) -> Result<Vec<Ext4GroupInfoOutput>> {
    let groups_count = sb.groups_count();
    let mut groups = Vec::with_capacity(usize::try_from(groups_count).unwrap_or(0));
    let inodes_total = u64::from(sb.inodes_count);

    for group in 0..groups_count {
        let (desc, _raw_desc) = read_ext4_group_desc_from_path(path, sb, group)?;

        let block_start = u64::from(sb.first_data_block)
            .saturating_add(u64::from(group).saturating_mul(u64::from(sb.blocks_per_group)));
        let block_end_exclusive = block_start
            .saturating_add(u64::from(sb.blocks_per_group))
            .min(sb.blocks_count);

        let inode_start = u64::from(group)
            .saturating_mul(u64::from(sb.inodes_per_group))
            .saturating_add(1);
        let inode_end_exclusive = inode_start
            .saturating_add(u64::from(sb.inodes_per_group))
            .min(inodes_total.saturating_add(1));

        groups.push(Ext4GroupInfoOutput {
            group,
            block_start,
            block_end_inclusive: block_end_exclusive.saturating_sub(1),
            free_blocks: desc.free_blocks_count,
            inode_start,
            inode_end_inclusive: inode_end_exclusive.saturating_sub(1),
            free_inodes: desc.free_inodes_count,
            flags_raw: desc.flags,
            flags: ext4_group_flag_names(desc.flags),
        });
    }

    Ok(groups)
}

fn build_btrfs_group_info(
    open_fs: &OpenFs,
    _sb: &BtrfsSuperblock,
    limitations: &mut Vec<String>,
) -> Vec<BtrfsGroupInfoOutput> {
    let Some(ctx) = open_fs.btrfs_context() else {
        limitations.push("btrfs chunk mapping context is unavailable".to_owned());
        return Vec::new();
    };

    let mut entries = Vec::with_capacity(ctx.chunks.len());
    for (chunk_index, chunk) in ctx.chunks.iter().enumerate() {
        let logical_end_inclusive = chunk
            .key
            .offset
            .saturating_add(chunk.length.saturating_sub(1));

        let stripes = chunk
            .stripes
            .iter()
            .enumerate()
            .map(|(stripe_index, stripe)| BtrfsStripeInfoOutput {
                stripe_index: u16::try_from(stripe_index).unwrap_or(u16::MAX),
                devid: stripe.devid,
                physical_start: stripe.offset,
                physical_end_inclusive: stripe
                    .offset
                    .saturating_add(chunk.length.saturating_sub(1)),
                device_uuid: format_uuid(&stripe.dev_uuid),
            })
            .collect();

        entries.push(BtrfsGroupInfoOutput {
            chunk_index: u32::try_from(chunk_index).unwrap_or(u32::MAX),
            logical_start: chunk.key.offset,
            logical_end_inclusive,
            logical_bytes: chunk.length,
            chunk_type_raw: chunk.chunk_type,
            chunk_type_flags: btrfs_chunk_type_flag_names(chunk.chunk_type),
            owner: chunk.owner,
            stripe_len: chunk.stripe_len,
            sector_size: chunk.sector_size,
            stripe_count: chunk.num_stripes,
            stripes,
        });
    }

    entries
}

fn build_mvcc_info(open_fs: &OpenFs) -> MvccInfoOutput {
    let mvcc_guard = open_fs.mvcc_store().read();
    let current_commit_seq = mvcc_guard.current_snapshot().high.0;
    let active_snapshot_count = mvcc_guard.active_snapshot_count();
    let oldest_active_snapshot = mvcc_guard.watermark().map(|seq| seq.0);
    let block_stats = mvcc_guard.block_version_stats();
    let total_versioned_entries = mvcc_guard.version_count();
    let ebr_stats = mvcc_guard.ebr_stats();
    let txn_outcomes = mvcc_guard.transaction_outcome_stats();
    drop(mvcc_guard);

    let wal_replay = build_wal_replay_info(open_fs);
    if let Some(wal) = &wal_replay {
        log_wal_recovery_telemetry(wal);
    }

    MvccInfoOutput {
        current_commit_seq,
        active_snapshot_count,
        oldest_active_snapshot,
        total_versioned_blocks: block_stats.tracked_blocks,
        max_chain_depth: block_stats.max_chain_length,
        average_chain_depth: format_ratio_thousandths(
            total_versioned_entries,
            block_stats.tracked_blocks,
        ),
        blocks_pending_gc: ebr_stats.pending_versions(),
        ssi_conflict_count: Some(txn_outcomes.ssi_conflicts),
        abort_count: Some(txn_outcomes.aborted_transactions),
        wal_replay,
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct RepairStalenessSummary {
    total: u32,
    fresh: u32,
    stale: u32,
    untracked: u32,
}

fn summarize_repair_staleness(states: &[(u32, Ext4RepairStaleness)]) -> RepairStalenessSummary {
    let mut summary = RepairStalenessSummary {
        total: u32::try_from(states.len()).unwrap_or(u32::MAX),
        ..RepairStalenessSummary::default()
    };

    for (_, state) in states {
        match state {
            Ext4RepairStaleness::Fresh => {
                summary.fresh = summary.fresh.saturating_add(1);
            }
            Ext4RepairStaleness::Stale => {
                summary.stale = summary.stale.saturating_add(1);
            }
            Ext4RepairStaleness::Untracked => {
                summary.untracked = summary.untracked.saturating_add(1);
            }
        }
    }

    summary
}

fn unavailable_repair_info(note: &str) -> RepairInfoOutput {
    RepairInfoOutput {
        configured_overhead_ratio: DEFAULT_REPAIR_OVERHEAD_RATIO,
        metrics_available: false,
        note: note.to_owned(),
        groups_total: None,
        groups_fresh: None,
        groups_stale: None,
        groups_untracked: None,
    }
}

fn build_repair_info(
    path: &PathBuf,
    open_fs: &OpenFs,
    limitations: &mut Vec<String>,
) -> RepairInfoOutput {
    match &open_fs.flavor {
        FsFlavor::Ext4(sb) => {
            match build_ext4_repair_group_specs(sb).and_then(|specs| {
                probe_ext4_repair_staleness(path, sb.block_size, &specs)
                    .map(|states| summarize_repair_staleness(&states))
            }) {
                Ok(summary) => RepairInfoOutput {
                    configured_overhead_ratio: DEFAULT_REPAIR_OVERHEAD_RATIO,
                    metrics_available: true,
                    note: "live ext4 repair-group descriptor/symbol status".to_owned(),
                    groups_total: Some(summary.total),
                    groups_fresh: Some(summary.fresh),
                    groups_stale: Some(summary.stale),
                    groups_untracked: Some(summary.untracked),
                },
                Err(error) => {
                    limitations.push(format!(
                        "repair metrics probe failed for ext4 image: {error:#}"
                    ));
                    unavailable_repair_info(
                        "live ext4 repair metrics unavailable (see limitations)",
                    )
                }
            }
        }
        FsFlavor::Btrfs(sb) => {
            let metrics = std::fs::metadata(path)
                .with_context(|| format!("failed to inspect image metadata: {}", path.display()))
                .map(|meta| meta.len())
                .and_then(|image_len| {
                    choose_btrfs_scrub_block_size(image_len, sb.nodesize, sb.sectorsize)
                        .with_context(|| {
                            format!(
                                "failed to determine btrfs scrub block size (len_bytes={image_len}, nodesize={}, sectorsize={})",
                                sb.nodesize, sb.sectorsize
                            )
                        })
                })
                .and_then(|block_size| {
                    discover_btrfs_repair_group_specs(path, block_size).and_then(|specs| {
                        probe_btrfs_repair_staleness(path, block_size, &specs)
                            .map(|states| summarize_repair_staleness(&states))
                    })
                });

            match metrics {
                Ok(summary) => RepairInfoOutput {
                    configured_overhead_ratio: DEFAULT_REPAIR_OVERHEAD_RATIO,
                    metrics_available: true,
                    note: "live btrfs repair-group descriptor/symbol status".to_owned(),
                    groups_total: Some(summary.total),
                    groups_fresh: Some(summary.fresh),
                    groups_stale: Some(summary.stale),
                    groups_untracked: Some(summary.untracked),
                },
                Err(error) => {
                    limitations.push(format!(
                        "repair metrics probe failed for btrfs image: {error:#}"
                    ));
                    unavailable_repair_info(
                        "live btrfs repair metrics unavailable (see limitations)",
                    )
                }
            }
        }
    }
}

fn build_ext4_journal_info(cx: &Cx, open_fs: &OpenFs, sb: &Ext4Superblock) -> JournalInfoOutput {
    let journal_size_bytes = if sb.journal_inum == 0 {
        None
    } else {
        open_fs
            .read_inode(cx, InodeNumber(u64::from(sb.journal_inum)))
            .ok()
            .map(|inode| inode.size)
    };

    let replayed_transactions = open_fs.ext4_journal_replay().map_or(0_u32, |replay| {
        u32::try_from(replay.committed_sequences.len()).unwrap_or(u32::MAX)
    });
    let replayed_blocks = open_fs
        .ext4_journal_replay()
        .map_or(0_u64, |replay| replay.stats.replayed_blocks);
    let scanned_blocks = open_fs
        .ext4_journal_replay()
        .map_or(0_u64, |replay| replay.stats.scanned_blocks);
    let descriptor_blocks = open_fs
        .ext4_journal_replay()
        .map_or(0_u64, |replay| replay.stats.descriptor_blocks);
    let commit_blocks = open_fs
        .ext4_journal_replay()
        .map_or(0_u64, |replay| replay.stats.commit_blocks);
    let revoke_blocks = open_fs
        .ext4_journal_replay()
        .map_or(0_u64, |replay| replay.stats.revoke_blocks);
    let skipped_revoked_blocks = open_fs
        .ext4_journal_replay()
        .map_or(0_u64, |replay| replay.stats.skipped_revoked_blocks);
    let incomplete_transactions = open_fs
        .ext4_journal_replay()
        .map_or(0_u64, |replay| replay.stats.incomplete_transactions);

    JournalInfoOutput::Ext4 {
        journal_inode: sb.journal_inum,
        external_journal_dev: sb.journal_dev,
        journal_uuid: format_uuid(&sb.journal_uuid),
        journal_size_bytes,
        replayed_transactions,
        replayed_blocks,
        scanned_blocks,
        descriptor_blocks,
        commit_blocks,
        revoke_blocks,
        skipped_revoked_blocks,
        incomplete_transactions,
    }
}

fn print_info_output(json: bool, output: &InfoOutput) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(output).context("serialize info output")?
        );
        return Ok(());
    }

    println!("FrankenFS Filesystem Info");
    println!("filesystem: {}", output.filesystem);
    print_superblock_info(&output.superblock);

    if let Some(groups) = &output.groups {
        print_groups_info(groups);
    }

    if let Some(mvcc) = &output.mvcc {
        print_mvcc_info(mvcc);
    }

    if let Some(repair) = &output.repair {
        print_repair_info(repair);
    }

    if let Some(journal) = &output.journal {
        print_journal_info(journal);
    }

    if !output.limitations.is_empty() {
        print_limitations(&output.limitations);
    }

    Ok(())
}

fn print_groups_info(groups: &GroupsInfoOutput) {
    match groups {
        GroupsInfoOutput::Ext4 { entries } => {
            println!();
            println!("groups: {}", entries.len());
            for group in entries {
                println!(
                    "  group={} blocks={}..{} free_blocks={} inodes={}..{} free_inodes={} flags={}",
                    group.group,
                    group.block_start,
                    group.block_end_inclusive,
                    group.free_blocks,
                    group.inode_start,
                    group.inode_end_inclusive,
                    group.free_inodes,
                    group.flags.join("|")
                );
            }
        }
        GroupsInfoOutput::Btrfs { entries } => {
            println!();
            println!("chunks: {}", entries.len());
            for chunk in entries {
                println!(
                    "  chunk={} logical={}..{} bytes={} type={} stripes={} flags={}",
                    chunk.chunk_index,
                    chunk.logical_start,
                    chunk.logical_end_inclusive,
                    chunk.logical_bytes,
                    chunk.chunk_type_raw,
                    chunk.stripe_count,
                    chunk.chunk_type_flags.join("|")
                );
                for stripe in &chunk.stripes {
                    println!(
                        "    stripe={} devid={} physical={}..{}",
                        stripe.stripe_index,
                        stripe.devid,
                        stripe.physical_start,
                        stripe.physical_end_inclusive
                    );
                }
            }
        }
    }
}

fn print_mvcc_info(mvcc: &MvccInfoOutput) {
    println!();
    println!("mvcc:");
    println!("  current_commit_seq: {}", mvcc.current_commit_seq);
    println!("  active_snapshot_count: {}", mvcc.active_snapshot_count);
    println!(
        "  oldest_active_snapshot: {}",
        mvcc.oldest_active_snapshot
            .map_or_else(|| "none".to_owned(), |value| value.to_string())
    );
    println!("  total_versioned_blocks: {}", mvcc.total_versioned_blocks);
    println!("  max_chain_depth: {}", mvcc.max_chain_depth);
    println!("  average_chain_depth: {}", mvcc.average_chain_depth);
    println!("  blocks_pending_gc: {}", mvcc.blocks_pending_gc);
    if let Some(ssi_conflict_count) = mvcc.ssi_conflict_count {
        println!("  ssi_conflict_count: {ssi_conflict_count}");
    }
    if let Some(abort_count) = mvcc.abort_count {
        println!("  abort_count: {abort_count}");
    }
    if let Some(wal) = &mvcc.wal_replay {
        println!("  wal_replay:");
        print_wal_replay_info(wal, "    ");
    }
}

fn print_repair_info(repair: &RepairInfoOutput) {
    println!();
    println!("repair:");
    println!(
        "  configured_overhead_ratio: {:.3}",
        repair.configured_overhead_ratio
    );
    println!("  metrics_available: {}", repair.metrics_available);
    println!("  note: {}", repair.note);
    if let Some(groups_total) = repair.groups_total {
        println!("  groups_total: {groups_total}");
    }
    if let Some(groups_fresh) = repair.groups_fresh {
        println!("  groups_fresh: {groups_fresh}");
    }
    if let Some(groups_stale) = repair.groups_stale {
        println!("  groups_stale: {groups_stale}");
    }
    if let Some(groups_untracked) = repair.groups_untracked {
        println!("  groups_untracked: {groups_untracked}");
    }
}

fn print_journal_info(journal: &JournalInfoOutput) {
    println!();
    match journal {
        JournalInfoOutput::Ext4 {
            journal_inode,
            external_journal_dev,
            journal_uuid,
            journal_size_bytes,
            replayed_transactions,
            replayed_blocks,
            scanned_blocks,
            descriptor_blocks,
            commit_blocks,
            revoke_blocks,
            skipped_revoked_blocks,
            incomplete_transactions,
        } => {
            println!("journal:");
            println!("  inode: {journal_inode}");
            println!("  external_dev: {external_journal_dev}");
            println!("  uuid: {journal_uuid}");
            println!(
                "  size_bytes: {}",
                journal_size_bytes.map_or_else(|| "unknown".to_owned(), |value| value.to_string())
            );
            println!("  replayed_transactions: {replayed_transactions}");
            println!("  replayed_blocks: {replayed_blocks}");
            println!("  scanned_blocks: {scanned_blocks}");
            println!("  descriptor_blocks: {descriptor_blocks}");
            println!("  commit_blocks: {commit_blocks}");
            println!("  revoke_blocks: {revoke_blocks}");
            println!("  skipped_revoked_blocks: {skipped_revoked_blocks}");
            println!("  incomplete_transactions: {incomplete_transactions}");
        }
        JournalInfoOutput::Unsupported { reason } => {
            println!("journal: unsupported ({reason})");
        }
    }
}

fn print_limitations(limitations: &[String]) {
    println!();
    println!("limitations:");
    for limitation in limitations {
        println!("  - {limitation}");
    }
}

fn print_superblock_info(superblock: &SuperblockInfoOutput) {
    match superblock {
        SuperblockInfoOutput::Ext4 {
            uuid,
            label,
            block_size,
            blocks_total,
            blocks_free,
            blocks_reserved,
            inodes_total,
            inodes_free,
            blocks_per_group,
            inodes_per_group,
            groups_count,
            mount_count,
            max_mount_count,
            state_flags,
            feature_compat,
            feature_incompat,
            feature_ro_compat,
            checksum_type,
            checksum_seed,
            mtime,
            wtime,
            lastcheck,
            mkfs_time,
        } => {
            println!("superblock (ext4):");
            println!("  uuid: {uuid}");
            println!("  label: {label}");
            println!("  block_size: {block_size}");
            println!("  blocks_total: {blocks_total}");
            println!("  blocks_free: {blocks_free}");
            println!("  blocks_reserved: {blocks_reserved}");
            println!("  inodes_total: {inodes_total}");
            println!("  inodes_free: {inodes_free}");
            println!("  blocks_per_group: {blocks_per_group}");
            println!("  inodes_per_group: {inodes_per_group}");
            println!("  groups_count: {groups_count}");
            println!("  mount_count: {mount_count}");
            println!("  max_mount_count: {max_mount_count}");
            println!("  state_flags: {}", state_flags.join("|"));
            println!("  feature_compat: {feature_compat}");
            println!("  feature_incompat: {feature_incompat}");
            println!("  feature_ro_compat: {feature_ro_compat}");
            println!("  checksum_type: {checksum_type}");
            println!("  checksum_seed: {checksum_seed}");
            println!("  mtime: {mtime}");
            println!("  wtime: {wtime}");
            println!("  lastcheck: {lastcheck}");
            println!("  mkfs_time: {mkfs_time}");
        }
        SuperblockInfoOutput::Btrfs {
            fsid,
            label,
            sectorsize,
            nodesize,
            generation,
            total_bytes,
            bytes_used,
            bytes_free,
            num_devices,
            csum_type,
            compat_flags_hex,
            compat_ro_flags_hex,
            incompat_flags_hex,
        } => {
            println!("superblock (btrfs):");
            println!("  fsid: {fsid}");
            println!("  label: {label}");
            println!("  sectorsize: {sectorsize}");
            println!("  nodesize: {nodesize}");
            println!("  generation: {generation}");
            println!("  total_bytes: {total_bytes}");
            println!("  bytes_used: {bytes_used}");
            println!("  bytes_free: {bytes_free}");
            println!("  num_devices: {num_devices}");
            println!("  checksum_type: {csum_type}");
            println!("  compat_flags: {compat_flags_hex}");
            println!("  compat_ro_flags: {compat_ro_flags_hex}");
            println!("  incompat_flags: {incompat_flags_hex}");
        }
    }
}

fn ext4_state_flag_names(state: u16) -> Vec<String> {
    const EXT4_VALID_FS: u16 = 0x0001;
    const EXT4_ERROR_FS: u16 = 0x0002;
    const EXT4_ORPHAN_FS: u16 = 0x0004;

    let mut names = Vec::new();
    if (state & EXT4_VALID_FS) != 0 {
        names.push("VALID_FS".to_owned());
    }
    if (state & EXT4_ERROR_FS) != 0 {
        names.push("ERROR_FS".to_owned());
    }
    if (state & EXT4_ORPHAN_FS) != 0 {
        names.push("ORPHAN_FS".to_owned());
    }

    let known = EXT4_VALID_FS | EXT4_ERROR_FS | EXT4_ORPHAN_FS;
    let unknown = state & !known;
    if unknown != 0 {
        names.push(format!("UNKNOWN(0x{unknown:04X})"));
    }
    if names.is_empty() {
        names.push("NONE".to_owned());
    }
    names
}

#[must_use]
pub fn ext4_appears_clean_state(state: u16) -> bool {
    const EXT4_VALID_FS: u16 = 0x0001;
    const EXT4_ERROR_FS: u16 = 0x0002;
    const EXT4_ORPHAN_FS: u16 = 0x0004;

    (state & EXT4_VALID_FS) != 0 && (state & EXT4_ERROR_FS) == 0 && (state & EXT4_ORPHAN_FS) == 0
}

fn ext4_group_flag_names(flags: u16) -> Vec<String> {
    const EXT4_BG_INODE_UNINIT: u16 = 0x0001;
    const EXT4_BG_BLOCK_UNINIT: u16 = 0x0002;
    const EXT4_BG_INODE_ZEROED: u16 = 0x0004;

    let mut names = Vec::new();
    if (flags & EXT4_BG_INODE_UNINIT) != 0 {
        names.push("INODE_UNINIT".to_owned());
    }
    if (flags & EXT4_BG_BLOCK_UNINIT) != 0 {
        names.push("BLOCK_UNINIT".to_owned());
    }
    if (flags & EXT4_BG_INODE_ZEROED) != 0 {
        names.push("INODE_ZEROED".to_owned());
    }

    let known = EXT4_BG_INODE_UNINIT | EXT4_BG_BLOCK_UNINIT | EXT4_BG_INODE_ZEROED;
    let unknown = flags & !known;
    if unknown != 0 {
        names.push(format!("UNKNOWN(0x{unknown:04X})"));
    }
    if names.is_empty() {
        names.push("NONE".to_owned());
    }
    names
}

fn btrfs_chunk_type_flag_names(chunk_type: u64) -> Vec<String> {
    const BTRFS_BLOCK_GROUP_DATA: u64 = 1;
    const BTRFS_BLOCK_GROUP_SYSTEM: u64 = 2;
    const BTRFS_BLOCK_GROUP_METADATA: u64 = 4;

    let mut flags = Vec::new();
    if (chunk_type & BTRFS_BLOCK_GROUP_DATA) != 0 {
        flags.push("DATA".to_owned());
    }
    if (chunk_type & BTRFS_BLOCK_GROUP_SYSTEM) != 0 {
        flags.push("SYSTEM".to_owned());
    }
    if (chunk_type & BTRFS_BLOCK_GROUP_METADATA) != 0 {
        flags.push("METADATA".to_owned());
    }

    let known = BTRFS_BLOCK_GROUP_DATA | BTRFS_BLOCK_GROUP_SYSTEM | BTRFS_BLOCK_GROUP_METADATA;
    let unknown = chunk_type & !known;
    if unknown != 0 {
        flags.push(format!("UNKNOWN(0x{unknown:016x})"));
    }
    if flags.is_empty() {
        flags.push("NONE".to_owned());
    }
    flags
}

fn btrfs_checksum_type_name(csum_type: u16) -> String {
    if csum_type == ffs_types::BTRFS_CSUM_TYPE_CRC32C {
        "crc32c".to_owned()
    } else {
        format!("unknown({csum_type})")
    }
}

fn format_uuid(bytes: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn format_ratio_thousandths(numerator: usize, denominator: usize) -> String {
    if denominator == 0 {
        return "0.000".to_owned();
    }

    let numerator_u128 = u128::try_from(numerator).unwrap_or(u128::MAX);
    let denominator_u128 = u128::try_from(denominator).unwrap_or(1);
    let milli = numerator_u128
        .saturating_mul(1000)
        .saturating_div(denominator_u128);
    let whole = milli / 1000;
    let fractional = milli % 1000;
    format!("{whole}.{fractional:03}")
}

fn dump_cmd(command: &DumpCommand) -> Result<()> {
    match command {
        DumpCommand::Superblock { image, json, hex } => dump_superblock_cmd(image, *json, *hex),
        DumpCommand::Group {
            group,
            image,
            json,
            hex,
        } => dump_group_cmd(*group, image, *json, *hex),
        DumpCommand::Inode {
            inode,
            image,
            json,
            hex,
        } => dump_inode_cmd(*inode, image, *json, *hex),
        DumpCommand::Extents {
            inode,
            image,
            json,
            hex,
        } => dump_extents_cmd(*inode, image, *json, *hex),
        DumpCommand::Dir {
            inode,
            image,
            json,
            hex,
        } => dump_dir_cmd(*inode, image, *json, *hex),
    }
}

fn dump_superblock_cmd(path: &PathBuf, json: bool, hex: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::dump::superblock",
        "dump_superblock",
        image = %path.display(),
        output_json = json,
        include_hex = hex
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::dump::superblock", "dump_superblock_start");

    let cx = cli_cx();
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;

    let raw_hex = if hex {
        let (offset, len, label) = match &flavor {
            FsFlavor::Ext4(_) => (
                EXT4_SUPERBLOCK_OFFSET,
                EXT4_SUPERBLOCK_SIZE,
                "ext4 superblock",
            ),
            FsFlavor::Btrfs(_) => (
                BTRFS_SUPER_INFO_OFFSET,
                BTRFS_SUPER_INFO_SIZE,
                "btrfs superblock",
            ),
        };
        let bytes = read_file_region(path, offset, len, label)?;
        Some(bytes_to_hex_dump(&bytes))
    } else {
        None
    };

    let output = DumpSuperblockOutput {
        filesystem: filesystem_name(&flavor).to_owned(),
        superblock: superblock_info_for(&flavor),
        raw_hex,
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize dump superblock output")?
        );
    } else {
        println!("FrankenFS Dump: superblock");
        println!("filesystem: {}", output.filesystem);
        print_superblock_info(&output.superblock);
        if let Some(raw_hex) = &output.raw_hex {
            println!();
            println!("raw_hex:");
            println!("{raw_hex}");
        }
    }

    info!(
        target: "ffs::cli::dump::superblock",
        filesystem = output.filesystem,
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "dump_superblock_complete"
    );

    Ok(())
}

fn dump_group_cmd(group: u32, path: &PathBuf, json: bool, hex: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::dump::group",
        "dump_group",
        image = %path.display(),
        group,
        output_json = json,
        include_hex = hex
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::dump::group", "dump_group_start");

    let output = build_dump_group_output(path, group, hex)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize dump group output")?
        );
    } else {
        println!("FrankenFS Dump: group");
        println!("filesystem: {}", output.filesystem);
        println!("group: {}", output.group);
        if let Some(descriptor) = &output.descriptor {
            println!("descriptor:");
            println!("  block_bitmap: {}", descriptor.block_bitmap);
            println!("  inode_bitmap: {}", descriptor.inode_bitmap);
            println!("  inode_table: {}", descriptor.inode_table);
            println!("  free_blocks_count: {}", descriptor.free_blocks_count);
            println!("  free_inodes_count: {}", descriptor.free_inodes_count);
            println!("  used_dirs_count: {}", descriptor.used_dirs_count);
            println!("  itable_unused: {}", descriptor.itable_unused);
            println!("  flags: 0x{:04X}", descriptor.flags);
            println!("  checksum: 0x{:04X}", descriptor.checksum);
        }
        if let Some(chunk) = &output.btrfs_chunk {
            println!("chunk:");
            println!(
                "  logical: {}..{} (bytes={})",
                chunk.logical_start, chunk.logical_end_inclusive, chunk.logical_bytes
            );
            println!(
                "  type: {} ({})",
                chunk.chunk_type_raw,
                chunk.chunk_type_flags.join("|")
            );
            println!("  owner: {}", chunk.owner);
            println!("  stripe_len: {}", chunk.stripe_len);
            println!("  sector_size: {}", chunk.sector_size);
            println!("  stripes: {}", chunk.stripe_count);
            for stripe in &chunk.stripes {
                println!(
                    "    stripe={} devid={} physical={}..{}",
                    stripe.stripe_index,
                    stripe.devid,
                    stripe.physical_start,
                    stripe.physical_end_inclusive
                );
            }
        }

        if let Some(raw_hex) = &output.raw_hex {
            println!();
            println!("raw_hex:");
            println!("{raw_hex}");
        }
        if !output.limitations.is_empty() {
            println!();
            println!("limitations:");
            for limitation in &output.limitations {
                println!("  - {limitation}");
            }
        }
    }

    info!(
        target: "ffs::cli::dump::group",
        group,
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "dump_group_complete"
    );

    Ok(())
}

fn build_dump_group_output(path: &PathBuf, group: u32, hex: bool) -> Result<DumpGroupOutput> {
    let cx = cli_cx();
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;

    match flavor {
        FsFlavor::Ext4(sb) => {
            let (desc, raw_desc) = read_ext4_group_desc_from_path(path, &sb, group)?;
            let raw_hex = if hex {
                Some(bytes_to_hex_dump(&raw_desc))
            } else {
                None
            };
            Ok(DumpGroupOutput {
                filesystem: "ext4".to_owned(),
                group,
                descriptor: Some(desc),
                btrfs_chunk: None,
                raw_hex,
                limitations: Vec::new(),
            })
        }
        FsFlavor::Btrfs(sb) => {
            let open_fs = OpenFs::open_with_options(&cx, path, &OpenOptions::default())
                .with_context(|| format!("failed to open image: {}", path.display()))?;
            let mut limitations = Vec::new();
            let entries = build_btrfs_group_info(&open_fs, &sb, &mut limitations);
            let index = usize::try_from(group)
                .with_context(|| format!("group index {group} does not fit usize"))?;
            let chunk = entries.get(index).cloned().ok_or_else(|| {
                anyhow::anyhow!(
                    "btrfs chunk index {} is out of range (available chunks: {})",
                    group,
                    entries.len()
                )
            })?;
            if hex {
                limitations
                    .push("raw hex for btrfs chunk dump is not currently available".to_owned());
            }
            Ok(DumpGroupOutput {
                filesystem: "btrfs".to_owned(),
                group,
                descriptor: None,
                btrfs_chunk: Some(chunk),
                raw_hex: None,
                limitations,
            })
        }
    }
}

fn dump_inode_cmd(inode: u64, path: &PathBuf, json: bool, hex: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::dump::inode",
        "dump_inode",
        image = %path.display(),
        inode,
        output_json = json,
        include_hex = hex
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::dump::inode", "dump_inode_start");

    let output = build_dump_inode_output(path, inode, hex)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize dump inode output")?
        );
    } else {
        println!("FrankenFS Dump: inode");
        println!("filesystem: {}", output.filesystem);
        println!("inode: {}", output.inode);

        if let Some(parsed) = &output.ext4_parsed {
            println!("mode: 0x{:04X}", parsed.mode);
            println!("uid: {}", parsed.uid);
            println!("gid: {}", parsed.gid);
            println!("size: {}", parsed.size);
            println!("links_count: {}", parsed.links_count);
            println!("blocks: {}", parsed.blocks);
            println!("flags: 0x{:08X}", parsed.flags);
            println!("generation: {}", parsed.generation);
            println!("file_acl: {}", parsed.file_acl);
            println!("atime: {}", parsed.atime);
            println!("ctime: {}", parsed.ctime);
            println!("mtime: {}", parsed.mtime);
            println!("dtime: {}", parsed.dtime);
            println!("extra_isize: {}", parsed.extra_isize);
            println!("checksum: 0x{:08X}", parsed.checksum);
            println!("projid: {}", parsed.projid);
        }

        if let Some(parsed) = &output.btrfs_parsed {
            println!("mode: 0o{:o}", parsed.mode);
            println!("uid: {}", parsed.uid);
            println!("gid: {}", parsed.gid);
            println!("size: {}", parsed.size);
            println!("nbytes: {}", parsed.nbytes);
            println!("nlink: {}", parsed.nlink);
            println!("rdev: {}", parsed.rdev);
            println!("atime: {}.{:09}", parsed.atime_sec, parsed.atime_nsec);
            println!("ctime: {}.{:09}", parsed.ctime_sec, parsed.ctime_nsec);
            println!("mtime: {}.{:09}", parsed.mtime_sec, parsed.mtime_nsec);
            println!("otime: {}.{:09}", parsed.otime_sec, parsed.otime_nsec);
        }

        if !output.limitations.is_empty() {
            println!("limitations:");
            for limitation in &output.limitations {
                println!("  - {limitation}");
            }
        }

        if let Some(raw_hex) = &output.raw_hex {
            println!();
            println!("raw_hex:");
            println!("{raw_hex}");
        }
    }

    info!(
        target: "ffs::cli::dump::inode",
        inode,
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "dump_inode_complete"
    );

    Ok(())
}

fn build_dump_inode_output(path: &PathBuf, inode: u64, hex: bool) -> Result<DumpInodeOutput> {
    let cx = cli_cx();
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;
    match flavor {
        FsFlavor::Ext4(sb) => {
            let inode_number = InodeNumber(inode);
            let (parsed, raw_inode) = read_ext4_inode_from_path(path, &sb, inode_number)
                .with_context(|| format!("failed to read inode {inode}"))?;
            let raw_hex = if hex {
                Some(bytes_to_hex_dump(&raw_inode))
            } else {
                None
            };
            Ok(DumpInodeOutput {
                filesystem: "ext4".to_owned(),
                inode,
                ext4_parsed: Some(parsed),
                btrfs_parsed: None,
                raw_hex,
                limitations: Vec::new(),
            })
        }
        FsFlavor::Btrfs(sb) => {
            let open_fs = OpenFs::open(&cx, path)
                .with_context(|| format!("failed to open image: {}", path.display()))?;
            let root_items = open_fs
                .walk_btrfs_root_tree(&cx)
                .context("failed to walk btrfs root tree")?;
            let fs_tree_root_item = root_items
                .iter()
                .find(|item| {
                    item.key.objectid == BTRFS_FS_TREE_OBJECTID
                        && item.key.item_type == BTRFS_ITEM_ROOT_ITEM
                })
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "failed to locate btrfs FS tree root item (objectid={BTRFS_FS_TREE_OBJECTID})"
                    )
                })?;
            let fs_tree_root = parse_root_item(&fs_tree_root_item.data)
                .context("failed to parse btrfs FS tree root item")?;
            let fs_tree_entries = open_fs
                .walk_btrfs_tree(&cx, fs_tree_root.bytenr)
                .with_context(|| {
                    format!("failed to walk btrfs FS tree at {}", fs_tree_root.bytenr)
                })?;
            let canonical_inode = if inode == 1 {
                sb.root_dir_objectid
            } else {
                inode
            };
            let inode_item = fs_tree_entries
                .iter()
                .find(|item| {
                    item.key.objectid == canonical_inode
                        && item.key.item_type == BTRFS_ITEM_INODE_ITEM
                        && item.key.offset == 0
                })
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "failed to locate btrfs inode item for objectid {canonical_inode}"
                    )
                })?;
            let parsed = parse_inode_item(&inode_item.data).with_context(|| {
                format!("failed to parse btrfs inode item for objectid {canonical_inode}")
            })?;
            let mut limitations = Vec::new();
            if inode == 1 && canonical_inode != 1 {
                limitations.push(format!(
                    "inode 1 maps to btrfs root objectid {canonical_inode}"
                ));
            }
            let raw_hex = if hex {
                Some(bytes_to_hex_dump(&inode_item.data))
            } else {
                None
            };
            Ok(DumpInodeOutput {
                filesystem: "btrfs".to_owned(),
                inode,
                ext4_parsed: None,
                btrfs_parsed: Some(parsed.into()),
                raw_hex,
                limitations,
            })
        }
    }
}

#[allow(clippy::too_many_lines)]
fn dump_extents_cmd(inode: u64, path: &PathBuf, json: bool, hex: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::dump::extents",
        "dump_extents",
        image = %path.display(),
        inode,
        output_json = json,
        include_hex = hex
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::dump::extents", "dump_extents_start");

    let (image, reader) = load_ext4_reader(path, "dump extents")?;
    let inode_number = InodeNumber(inode);
    let parsed_inode = reader
        .read_inode(&image, inode_number)
        .with_context(|| format!("failed to read inode {inode}"))?;
    let (root_header, _) = parse_inode_extent_tree(&parsed_inode)
        .with_context(|| format!("inode {inode} is not extent-backed"))?;

    let mut nodes = Vec::new();
    collect_extent_nodes(
        &reader,
        &image,
        None,
        &parsed_inode.extent_bytes,
        root_header.depth,
        hex,
        &mut nodes,
    )?;

    let flattened_extents = reader
        .collect_extents(&image, &parsed_inode)
        .with_context(|| format!("failed to collect extents for inode {inode}"))?
        .into_iter()
        .map(dump_extent_entry)
        .collect();

    let output = DumpExtentOutput {
        filesystem: "ext4".to_owned(),
        inode,
        root_depth: root_header.depth,
        nodes,
        flattened_extents,
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize dump extents output")?
        );
    } else {
        println!("FrankenFS Dump: extents");
        println!("filesystem: {}", output.filesystem);
        println!("inode: {}", output.inode);
        println!("root_depth: {}", output.root_depth);
        println!("nodes: {}", output.nodes.len());

        for node in &output.nodes {
            let source = node
                .source_block
                .map_or_else(|| "inode_root".to_owned(), |block| block.to_string());
            println!(
                "  node source={} depth={} entries={} max_entries={} generation={}",
                source,
                node.header.depth,
                node.header.entries,
                node.header.max_entries,
                node.header.generation
            );
            match &node.node {
                DumpExtentNodeKindOutput::Leaf { extents } => {
                    for extent in extents {
                        println!(
                            "    leaf logical={} physical={}..{} len={} initialized={}",
                            extent.logical_block,
                            extent.physical_start,
                            extent.physical_end_inclusive,
                            extent.actual_len,
                            extent.initialized
                        );
                    }
                }
                DumpExtentNodeKindOutput::Index { indexes } => {
                    for index in indexes {
                        println!(
                            "    index logical={} child_block={}",
                            index.logical_block, index.leaf_block
                        );
                    }
                }
            }
            if let Some(raw_hex) = &node.raw_hex {
                println!("    raw_hex:");
                println!("{raw_hex}");
            }
        }
    }

    info!(
        target: "ffs::cli::dump::extents",
        inode,
        nodes = output.nodes.len(),
        flattened_extents = output.flattened_extents.len(),
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "dump_extents_complete"
    );

    Ok(())
}

#[allow(clippy::too_many_lines)]
fn dump_dir_cmd(inode: u64, path: &PathBuf, json: bool, hex: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::dump::dir",
        "dump_dir",
        image = %path.display(),
        inode,
        output_json = json,
        include_hex = hex
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::dump::dir", "dump_dir_start");

    let output = build_dump_dir_output(path, inode, hex)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize dump dir output")?
        );
    } else {
        println!("FrankenFS Dump: dir");
        println!("filesystem: {}", output.filesystem);
        println!("inode: {}", output.inode);
        println!("entries: {}", output.entries.len());
        for entry in &output.entries {
            println!(
                "  index={} inode={} rec_len={} type={} name={}",
                entry.index, entry.inode, entry.rec_len, entry.file_type, entry.name
            );
        }

        if let Some(htree) = &output.htree {
            println!();
            println!("htree:");
            println!("  hash_version: {}", htree.hash_version);
            println!("  indirect_levels: {}", htree.indirect_levels);
            for entry in &htree.entries {
                println!("  entry hash=0x{:08X} block={}", entry.hash, entry.block);
            }
        }

        if let Some(raw_hex_blocks) = &output.raw_hex_blocks {
            println!();
            println!("raw_hex_blocks: {}", raw_hex_blocks.len());
            for block in raw_hex_blocks {
                println!(
                    "  logical_block={} physical_block={}{}",
                    block.logical_block,
                    block.physical_block,
                    block
                        .item_kind
                        .as_ref()
                        .map(|kind| format!(" item_kind={kind}"))
                        .unwrap_or_default()
                );
                println!("{}", block.hex);
            }
        }

        if !output.limitations.is_empty() {
            println!();
            println!("limitations:");
            for limitation in &output.limitations {
                println!("  - {limitation}");
            }
        }
    }

    info!(
        target: "ffs::cli::dump::dir",
        inode,
        entries = output.entries.len(),
        has_htree = output.htree.is_some(),
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "dump_dir_complete"
    );

    Ok(())
}

fn build_dump_dir_output(path: &PathBuf, inode: u64, hex: bool) -> Result<DumpDirOutput> {
    let cx = cli_cx();
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;
    match flavor {
        FsFlavor::Ext4(_) => build_ext4_dump_dir_output(path, inode, hex),
        FsFlavor::Btrfs(_) => build_btrfs_dump_dir_output(path, inode, hex),
    }
}

fn build_ext4_dump_dir_output(path: &PathBuf, inode: u64, hex: bool) -> Result<DumpDirOutput> {
    let (image, reader) = load_ext4_reader(path, "dump dir")?;
    let inode_number = InodeNumber(inode);
    let parsed_inode = reader
        .read_inode(&image, inode_number)
        .with_context(|| format!("failed to read inode {inode}"))?;
    let entries = reader
        .read_dir(&image, &parsed_inode)
        .with_context(|| format!("failed to read directory entries for inode {inode}"))?;

    let htree = match reader
        .resolve_extent(&image, &parsed_inode, 0)
        .with_context(|| format!("failed to resolve first directory block for inode {inode}"))?
    {
        Some(physical_block) => {
            let block = reader
                .read_block(&image, BlockNumber(physical_block))
                .with_context(|| format!("failed to read directory block {physical_block}"))?;
            parse_dx_root(block).ok().map(|root| DumpDxRootOutput {
                hash_version: root.hash_version,
                indirect_levels: root.indirect_levels,
                entries: root
                    .entries
                    .iter()
                    .map(|entry| DumpDxEntryOutput {
                        hash: entry.hash,
                        block: entry.block,
                    })
                    .collect(),
            })
        }
        None => None,
    };

    let raw_hex_blocks = if hex {
        Some(read_ext4_directory_hex_blocks(
            &image,
            &reader,
            &parsed_inode,
        )?)
    } else {
        None
    };

    let mut limitations = Vec::new();
    limitations.push(
        "directory entry byte offsets are not exposed by parser APIs; `index` preserves on-disk iteration order"
            .to_owned(),
    );
    if htree.is_none() {
        limitations.push(
            "htree metadata is only shown for indexed directories with a parseable dx root"
                .to_owned(),
        );
    }

    Ok(DumpDirOutput {
        filesystem: "ext4".to_owned(),
        inode,
        entries: entries
            .iter()
            .enumerate()
            .map(|(index, entry)| dump_dir_entry(index, entry))
            .collect(),
        htree,
        raw_hex_blocks,
        limitations,
    })
}

fn build_btrfs_dump_dir_output(path: &PathBuf, inode: u64, hex: bool) -> Result<DumpDirOutput> {
    let cx = cli_cx();
    let open_fs = OpenFs::open(&cx, path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let entries = open_fs
        .readdir(&cx, InodeNumber(inode), 0)
        .with_context(|| format!("failed to read btrfs directory entries for inode {inode}"))?;
    let mut limitations = vec![
        "btrfs directory dump uses VFS readdir projection; on-disk rec_len offsets are not available"
            .to_owned(),
        "htree metadata is ext4-specific and not available for btrfs directories".to_owned(),
    ];
    let raw_hex_blocks = if hex {
        let items = open_fs
            .walk_btrfs_dir_entry_items(&cx, inode)
            .context("failed to read btrfs directory items")?;
        let blocks: Vec<DumpHexBlockOutput> = items
            .iter()
            .enumerate()
            .map(|(idx, (item_type, key_offset, raw))| {
                #[allow(clippy::cast_possible_truncation)]
                DumpHexBlockOutput {
                    logical_block: idx as u32,
                    physical_block: *key_offset,
                    item_kind: Some(
                        match *item_type {
                            ffs_btrfs::BTRFS_ITEM_DIR_ITEM => "dir_item",
                            ffs_btrfs::BTRFS_ITEM_DIR_INDEX => "dir_index",
                            _ => "unknown",
                        }
                        .to_owned(),
                    ),
                    hex: bytes_to_hex_dump(raw),
                }
            })
            .collect();
        limitations.push(
            "btrfs hex dump shows raw DIR_ITEM/DIR_INDEX payloads from B-tree leaves; \
             logical_block is the item index, physical_block is the key offset"
                .to_owned(),
        );
        Some(blocks)
    } else {
        None
    };
    Ok(DumpDirOutput {
        filesystem: "btrfs".to_owned(),
        inode,
        entries: entries
            .iter()
            .enumerate()
            .map(|(index, entry)| DumpDirEntryOutput {
                index,
                inode: entry.ino.0,
                rec_len: 0,
                file_type: format!("{:?}", entry.kind).to_ascii_lowercase(),
                name: entry.name_str(),
            })
            .collect(),
        htree: None,
        raw_hex_blocks,
        limitations,
    })
}

fn load_ext4_reader(path: &PathBuf, action: &str) -> Result<(Vec<u8>, Ext4ImageReader)> {
    let cx = cli_cx();
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;
    if !matches!(flavor, FsFlavor::Ext4(_)) {
        bail!("{action} currently supports ext4 images only");
    }

    let image = std::fs::read(path)
        .with_context(|| format!("failed to read filesystem image: {}", path.display()))?;
    let reader = Ext4ImageReader::new(&image).context("failed to parse ext4 superblock")?;
    Ok((image, reader))
}

fn read_ext4_group_desc_from_path(
    path: &PathBuf,
    sb: &Ext4Superblock,
    group: u32,
) -> Result<(Ext4GroupDesc, Vec<u8>)> {
    let group_number = GroupNumber(group);
    let offset_u64 = sb
        .group_desc_offset(group_number)
        .ok_or_else(|| anyhow::anyhow!("group descriptor offset overflow for group {group}"))?;
    let offset = usize::try_from(offset_u64)
        .with_context(|| format!("group descriptor offset does not fit usize for group {group}"))?;
    let desc_size = sb.group_desc_size();
    let raw_desc = read_file_region(
        path,
        offset,
        usize::from(desc_size),
        "ext4 group descriptor",
    )
    .with_context(|| format!("failed to read ext4 group descriptor {group}"))?;
    let desc = Ext4GroupDesc::parse_from_bytes(&raw_desc, desc_size)
        .with_context(|| format!("failed to parse ext4 group descriptor {group}"))?;
    Ok((desc, raw_desc))
}

fn read_ext4_inode_from_path(
    path: &PathBuf,
    sb: &Ext4Superblock,
    inode: InodeNumber,
) -> Result<(Ext4Inode, Vec<u8>)> {
    let location = sb
        .locate_inode(inode)
        .with_context(|| format!("failed to locate inode {}", inode.0))?;
    let (group_desc, _raw_group_desc) = read_ext4_group_desc_from_path(path, sb, location.group.0)
        .with_context(|| format!("failed to read group descriptor {}", location.group.0))?;
    let inode_offset = sb
        .inode_device_offset(&location, group_desc.inode_table)
        .with_context(|| format!("failed to compute inode offset for inode {}", inode.0))?;
    let offset = usize::try_from(inode_offset)
        .with_context(|| format!("inode offset does not fit usize for inode {}", inode.0))?;
    let inode_size = usize::from(sb.inode_size);
    let raw_inode = read_file_region(path, offset, inode_size, "ext4 inode")
        .with_context(|| format!("failed to read raw inode bytes for inode {}", inode.0))?;
    let parsed = Ext4Inode::parse_from_bytes(&raw_inode)
        .with_context(|| format!("failed to parse inode {}", inode.0))?;
    Ok((parsed, raw_inode))
}

fn read_file_region(path: &PathBuf, offset: usize, len: usize, label: &str) -> Result<Vec<u8>> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open filesystem image: {}", path.display()))?;
    let file_len = file
        .metadata()
        .with_context(|| format!("failed to stat filesystem image: {}", path.display()))?
        .len();
    let offset_u64 = u64::try_from(offset)
        .with_context(|| format!("{label} offset does not fit in u64 (offset={offset})"))?;
    let len_u64 = u64::try_from(len)
        .with_context(|| format!("{label} length does not fit in u64 (len={len})"))?;
    let end = offset_u64
        .checked_add(len_u64)
        .ok_or_else(|| anyhow::anyhow!("{label} region overflow (offset={offset}, len={len})"))?;
    if end > file_len {
        bail!("{label} region out of bounds (offset={offset}, len={len}, image_len={file_len})");
    }

    file.seek(SeekFrom::Start(offset_u64))
        .with_context(|| format!("failed to seek to {label} offset {offset}"))?;
    let mut bytes = vec![0_u8; len];
    file.read_exact(&mut bytes)
        .with_context(|| format!("failed to read {label} bytes"))?;
    Ok(bytes)
}

fn bytes_to_hex_dump(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (line, chunk) in bytes.chunks(16).enumerate() {
        let offset = line.saturating_mul(16);
        write!(&mut out, "{offset:08x}:").expect("write to String cannot fail");
        for byte in chunk {
            write!(&mut out, " {byte:02x}").expect("write to String cannot fail");
        }
        out.push('\n');
    }
    out
}

fn dump_extent_entry(extent: Ext4Extent) -> DumpExtentEntryOutput {
    let actual_len = extent.actual_len();
    let initialized = !extent.is_unwritten();
    DumpExtentEntryOutput {
        logical_block: extent.logical_block,
        physical_start: extent.physical_start,
        physical_end_inclusive: extent
            .physical_start
            .saturating_add(u64::from(actual_len))
            .saturating_sub(1),
        raw_len: extent.raw_len,
        actual_len,
        initialized,
    }
}

fn collect_extent_nodes(
    reader: &Ext4ImageReader,
    image: &[u8],
    source_block: Option<u64>,
    raw_node: &[u8],
    expected_depth: u16,
    include_hex: bool,
    nodes: &mut Vec<DumpExtentNodeOutput>,
) -> Result<()> {
    let (header, tree) = parse_extent_tree(raw_node).context("failed to parse extent tree node")?;
    if header.depth != expected_depth {
        bail!(
            "extent tree depth mismatch: expected {expected_depth}, parsed {}",
            header.depth
        );
    }

    let raw_hex = include_hex.then(|| bytes_to_hex_dump(raw_node));

    match tree {
        ExtentTree::Leaf(extents) => {
            nodes.push(DumpExtentNodeOutput {
                source_block,
                header,
                node: DumpExtentNodeKindOutput::Leaf {
                    extents: extents.into_iter().map(dump_extent_entry).collect(),
                },
                raw_hex,
            });
        }
        ExtentTree::Index(indexes) => {
            nodes.push(DumpExtentNodeOutput {
                source_block,
                header,
                node: DumpExtentNodeKindOutput::Index {
                    indexes: indexes.clone(),
                },
                raw_hex,
            });

            let next_depth = expected_depth
                .checked_sub(1)
                .ok_or_else(|| anyhow::anyhow!("invalid extent depth transition from 0"))?;
            for index in indexes {
                let child = reader
                    .read_block(image, BlockNumber(index.leaf_block))
                    .with_context(|| {
                        format!(
                            "failed to read extent child block {} (logical={})",
                            index.leaf_block, index.logical_block
                        )
                    })?;
                collect_extent_nodes(
                    reader,
                    image,
                    Some(index.leaf_block),
                    child,
                    next_depth,
                    include_hex,
                    nodes,
                )?;
            }
        }
    }

    Ok(())
}

fn dump_dir_entry(index: usize, entry: &Ext4DirEntry) -> DumpDirEntryOutput {
    DumpDirEntryOutput {
        index,
        inode: u64::from(entry.inode),
        rec_len: entry.rec_len,
        file_type: format!("{:?}", entry.file_type).to_ascii_lowercase(),
        name: entry.name_str(),
    }
}

fn read_ext4_directory_hex_blocks(
    image: &[u8],
    reader: &Ext4ImageReader,
    inode: &Ext4Inode,
) -> Result<Vec<DumpHexBlockOutput>> {
    let block_size = u64::from(reader.sb.block_size);
    let block_count_u64 = inode.size.div_ceil(block_size);
    let block_count = u32::try_from(block_count_u64).with_context(|| {
        format!("directory block count exceeds supported range: {block_count_u64}")
    })?;

    let mut blocks = Vec::new();
    for logical_block in 0..block_count {
        if let Some(physical_block) = reader
            .resolve_extent(image, inode, logical_block)
            .with_context(|| format!("failed to resolve directory block {logical_block}"))?
        {
            let block = reader
                .read_block(image, BlockNumber(physical_block))
                .with_context(|| format!("failed to read directory block {physical_block}"))?;
            blocks.push(DumpHexBlockOutput {
                logical_block,
                physical_block,
                item_kind: None,
                hex: bytes_to_hex_dump(block),
            });
        }
    }

    Ok(blocks)
}

fn inspect_btrfs_subvolumes(
    cx: &Cx,
    path: &Path,
    _flavor: &FsFlavor,
    json: bool,
    list_subvolumes: bool,
    list_snapshots: bool,
) -> Result<()> {
    let fs = OpenFs::open(cx, path).with_context(|| format!("open {}", path.display()))?;

    // Walk the root tree to get all leaf entries
    let root_entries = fs
        .walk_btrfs_root_tree(cx)
        .context("walk btrfs root tree")?;

    if list_subvolumes {
        let subvols = ffs_btrfs::enumerate_subvolumes(&root_entries);
        if json {
            #[derive(serde::Serialize)]
            struct SubvolEntry {
                id: u64,
                parent_id: u64,
                name: String,
                generation: u64,
                read_only: bool,
            }
            let entries: Vec<SubvolEntry> = subvols
                .iter()
                .map(|s| SubvolEntry {
                    id: s.id,
                    parent_id: s.parent_id,
                    name: s.name.clone(),
                    generation: s.generation,
                    read_only: s.read_only,
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&entries).context("serialize")?
            );
        } else {
            println!("Subvolumes ({} found):", subvols.len());
            println!(
                "{:<8} {:<8} {:<12} {:<5} Name",
                "ID", "Parent", "Generation", "RO"
            );
            for s in &subvols {
                println!(
                    "{:<8} {:<8} {:<12} {:<5} {}",
                    s.id,
                    s.parent_id,
                    s.generation,
                    if s.read_only { "yes" } else { "no" },
                    s.name
                );
            }
        }
    }

    if list_snapshots {
        let snapshots = ffs_btrfs::enumerate_snapshots(&root_entries);
        if json {
            #[derive(serde::Serialize)]
            struct SnapEntry {
                id: u64,
                source_id: u64,
                name: String,
                generation: u64,
            }
            let entries: Vec<SnapEntry> = snapshots
                .iter()
                .map(|s| SnapEntry {
                    id: s.id,
                    source_id: s.source_id,
                    name: s.name.clone(),
                    generation: s.generation,
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&entries).context("serialize")?
            );
        } else {
            println!("Snapshots ({} found):", snapshots.len());
            println!("{:<8} {:<8} {:<12} Name", "ID", "Source", "Generation");
            for s in &snapshots {
                println!(
                    "{:<8} {:<8} {:<12} {}",
                    s.id, s.source_id, s.generation, s.name
                );
            }
        }
    }

    Ok(())
}

fn inspect_ext4_output(
    cx: &Cx,
    path: &PathBuf,
    open_opts: &OpenOptions,
    block_size: u32,
    inodes_count: u32,
    blocks_count: u64,
    volume_name: &str,
) -> Result<InspectOutput> {
    // Open the filesystem to read bitmaps for free space and orphan diagnostics.
    let open_fs = OpenFs::open_with_options(cx, path, open_opts)
        .with_context(|| format!("failed to open ext4 image: {}", path.display()))?;
    let summary = open_fs
        .free_space_summary(cx)
        .context("failed to compute free space summary")?;
    let orphans = open_fs
        .read_ext4_orphan_list(cx)
        .context("failed to read ext4 orphan list")?;
    let orphan_diagnostics = if orphans.inodes.is_empty() {
        None
    } else {
        Some(Ext4OrphanDiagnosticsOutput {
            count: u32::try_from(orphans.count()).unwrap_or(u32::MAX),
            sample_inodes: orphans.inodes.iter().take(16).map(|ino| ino.0).collect(),
        })
    };

    let mismatch = if summary.blocks_mismatch || summary.inodes_mismatch {
        Some(FreeSpaceMismatch {
            gd_free_blocks: summary.gd_free_blocks_total,
            gd_free_inodes: summary.gd_free_inodes_total,
        })
    } else {
        None
    };

    Ok(InspectOutput::Ext4 {
        block_size,
        inodes_count,
        blocks_count,
        volume_name: volume_name.to_owned(),
        free_blocks_total: summary.free_blocks_total,
        free_inodes_total: summary.free_inodes_total,
        free_space_mismatch: mismatch,
        orphan_diagnostics,
    })
}

const fn ext4_mount_replay_mode(read_write: bool) -> Ext4JournalReplayMode {
    if read_write {
        Ext4JournalReplayMode::Apply
    } else {
        Ext4JournalReplayMode::SimulateOverlay
    }
}

fn mount_operation_id(
    image_path: &Path,
    mountpoint: &Path,
    runtime_mode: MountRuntimeMode,
    read_write: bool,
) -> String {
    let read_write_mode = if read_write { "rw" } else { "ro" };
    let material = format!(
        "{}|{}|{}|{}",
        runtime_mode.as_str(),
        read_write_mode,
        image_path.display(),
        mountpoint.display()
    );
    let digest = crc32c::crc32c(material.as_bytes());
    format!("mount-{digest:08x}")
}

fn log_mount_runtime_selected(
    operation_id: &str,
    scenario_id: &str,
    runtime: MountRuntimeConfig,
    allow_other: bool,
    auto_unmount: bool,
    read_write: bool,
) {
    info!(
        target: "ffs::cli::mount",
        operation_id,
        scenario_id,
        outcome = "runtime_mode_selected",
        runtime_mode = runtime.mode.as_str(),
        allow_other,
        auto_unmount,
        read_write,
        managed_unmount_timeout_secs = runtime.managed_unmount_timeout_secs(),
        "mount_runtime_mode_selected"
    );
}

fn log_mount_runtime_rejected(
    operation_id: &str,
    scenario_id: &str,
    runtime: MountRuntimeConfig,
    read_write: bool,
    error_class: &'static str,
    reason: &str,
) {
    error!(
        target: "ffs::cli::mount",
        operation_id,
        scenario_id,
        outcome = "runtime_mode_rejected",
        error_class,
        runtime_mode = runtime.mode.as_str(),
        read_write,
        managed_unmount_timeout_secs = runtime.managed_unmount_timeout_secs(),
        reason,
        "mount_runtime_mode_rejected"
    );
}

fn emit_mount_banner(
    open_fs: &OpenFs,
    mountpoint: &Path,
    read_write: bool,
    runtime_mode: MountRuntimeMode,
) {
    let mode_str = if read_write { "rw" } else { "ro" };
    let runtime = runtime_mode.as_str();
    match &open_fs.flavor {
        FsFlavor::Ext4(sb) => {
            eprintln!(
                "Mounting ext4 image (block_size={}, blocks={}, {mode_str}, runtime={runtime}) at {}",
                sb.block_size,
                sb.blocks_count,
                mountpoint.display()
            );
        }
        FsFlavor::Btrfs(sb) => {
            eprintln!(
                "Mounting btrfs image (sectorsize={}, nodesize={}, label={:?}, {mode_str}, runtime={runtime}) at {}",
                sb.sectorsize,
                sb.nodesize,
                sb.label,
                mountpoint.display()
            );
        }
    }
}

fn emit_crash_recovery_details(recovery: &CrashRecoveryOutcome) {
    if !recovery.recovery_performed() {
        return;
    }

    eprintln!(
        "  crash recovery: unclean shutdown detected (state=0x{:04X}, errors={}, orphans={})",
        recovery.raw_state, recovery.had_errors, recovery.had_orphans
    );
    if recovery.journal_txns_replayed > 0 {
        eprintln!(
            "  journal replay: {} transactions, {} blocks replayed",
            recovery.journal_txns_replayed, recovery.journal_blocks_replayed
        );
    }
    if recovery.mvcc_reset {
        eprintln!("  mvcc: version store reset (in-flight transactions discarded)");
    }
}

fn emit_optional_recovery_banner(open_fs: &OpenFs) {
    if let Some(recovery) = open_fs.crash_recovery() {
        emit_crash_recovery_details(recovery);
    }
}

fn mount_with_fuse(
    open_fs: OpenFs,
    mountpoint: &Path,
    read_write: bool,
    allow_other: bool,
    auto_unmount: bool,
) -> Result<()> {
    let opts = MountOptions {
        read_only: !read_write,
        allow_other,
        auto_unmount,
        worker_threads: 0,
    };

    let fs_ops: Box<dyn FsOps> = Box::new(open_fs);
    ffs_fuse::mount(fs_ops, mountpoint, &opts)
        .with_context(|| format!("FUSE mount failed at {}", mountpoint.display()))
}

/// Parameters shared by managed and per-core mount paths.
struct ManagedMountParams<'a> {
    mountpoint: &'a Path,
    read_write: bool,
    allow_other: bool,
    auto_unmount: bool,
    unmount_timeout_secs: u64,
    operation_id: &'a str,
    scenario_id: &'a str,
}

fn mount_with_managed_fuse(open_fs: OpenFs, params: &ManagedMountParams<'_>) -> Result<()> {
    let config = MountConfig {
        options: MountOptions {
            read_only: !params.read_write,
            allow_other: params.allow_other,
            auto_unmount: params.auto_unmount,
            worker_threads: 0,
        },
        unmount_timeout: std::time::Duration::from_secs(params.unmount_timeout_secs),
    };

    info!(
        target: "ffs::cli::mount",
        operation_id = params.operation_id,
        scenario_id = params.scenario_id,
        outcome = "managed_mount_starting",
        unmount_timeout_secs = params.unmount_timeout_secs,
        thread_count = config.options.resolved_thread_count(),
        "managed_mount_start"
    );

    let fs_ops: Box<dyn FsOps> = Box::new(open_fs);
    let handle = mount_managed(fs_ops, params.mountpoint, &config).with_context(|| {
        format!(
            "FUSE managed mount failed at {}",
            params.mountpoint.display()
        )
    })?;

    wire_ctrlc_shutdown(&handle)?;

    info!(
        target: "ffs::cli::mount",
        operation_id = params.operation_id,
        scenario_id = params.scenario_id,
        outcome = "managed_mount_active",
        "managed_mount_waiting_for_shutdown"
    );

    let metrics = handle.wait();
    log_mount_shutdown_metrics(params.operation_id, params.scenario_id, &metrics);
    Ok(())
}

fn mount_with_per_core_fuse(open_fs: OpenFs, params: &ManagedMountParams<'_>) -> Result<()> {
    use ffs_fuse::per_core::{PerCoreConfig, PerCoreDispatcher};

    let per_core_config = PerCoreConfig::default();
    let dispatcher = PerCoreDispatcher::new(per_core_config.clone());

    info!(
        target: "ffs::cli::mount",
        operation_id = params.operation_id,
        scenario_id = params.scenario_id,
        outcome = "per_core_mount_starting",
        num_cores = dispatcher.num_cores(),
        cache_blocks_per_core = per_core_config.cache_blocks_per_core,
        total_cache_blocks = per_core_config.total_cache_blocks(),
        steal_threshold = per_core_config.steal_threshold,
        advisory_affinity = per_core_config.advisory_affinity,
        "per_core_mount_start"
    );

    let config = MountConfig {
        options: MountOptions {
            read_only: !params.read_write,
            allow_other: params.allow_other,
            auto_unmount: params.auto_unmount,
            worker_threads: dispatcher.num_cores() as usize,
        },
        unmount_timeout: std::time::Duration::from_secs(params.unmount_timeout_secs),
    };

    let fs_ops: Box<dyn FsOps> = Box::new(open_fs);
    let handle = mount_managed(fs_ops, params.mountpoint, &config).with_context(|| {
        format!(
            "FUSE per-core mount failed at {}",
            params.mountpoint.display()
        )
    })?;

    wire_ctrlc_shutdown(&handle)?;

    info!(
        target: "ffs::cli::mount",
        operation_id = params.operation_id,
        scenario_id = params.scenario_id,
        outcome = "per_core_mount_active",
        "per_core_mount_waiting_for_shutdown"
    );

    let metrics = handle.wait();

    let aggregate = dispatcher.aggregate_metrics();
    debug!(
        target: "ffs::cli::mount",
        operation_id = params.operation_id,
        scenario_id = params.scenario_id,
        imbalance_ratio = aggregate.imbalance_ratio(),
        total_requests = aggregate.total_requests,
        total_cache_hits = aggregate.total_cache_hits,
        total_cache_misses = aggregate.total_cache_misses,
        "per_core_aggregate_metrics"
    );

    info!(
        target: "ffs::cli::mount",
        operation_id = params.operation_id,
        scenario_id = params.scenario_id,
        outcome = "per_core_mount_shutdown",
        requests_total = metrics.requests_total,
        requests_ok = metrics.requests_ok,
        requests_err = metrics.requests_err,
        bytes_read = metrics.bytes_read,
        num_cores = dispatcher.num_cores(),
        imbalance_ratio = aggregate.imbalance_ratio(),
        "per_core_mount_shutdown_complete"
    );

    Ok(())
}

fn wire_ctrlc_shutdown(handle: &ffs_fuse::MountHandle) -> Result<()> {
    let shutdown = handle.shutdown_flag().clone();
    ctrlc::set_handler(move || {
        shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
    })
    .context("failed to set Ctrl+C handler")
}

fn log_mount_shutdown_metrics(
    operation_id: &str,
    scenario_id: &str,
    metrics: &ffs_fuse::MetricsSnapshot,
) {
    info!(
        target: "ffs::cli::mount",
        operation_id,
        scenario_id,
        outcome = "managed_mount_shutdown",
        requests_total = metrics.requests_total,
        requests_ok = metrics.requests_ok,
        requests_err = metrics.requests_err,
        bytes_read = metrics.bytes_read,
        requests_throttled = metrics.requests_throttled,
        requests_shed = metrics.requests_shed,
        "managed_mount_shutdown_complete"
    );
}

#[allow(clippy::too_many_lines)]
fn mount_cmd(
    image_path: &Path,
    mountpoint: &Path,
    allow_other: bool,
    rw: bool,
    native: bool,
    runtime_mode: MountRuntimeMode,
    managed_unmount_timeout_secs: Option<u64>,
) -> Result<()> {
    let auto_unmount = env_bool("FFS_AUTO_UNMOUNT", true)?;
    let requested_runtime = MountRuntimeConfig {
        mode: runtime_mode,
        managed_unmount_timeout_secs,
    };
    let operation_id = mount_operation_id(image_path, mountpoint, requested_runtime.mode, rw);
    let scenario_id = requested_runtime.mode.scenario_id(rw);
    let command_span = info_span!(
        target: "ffs::cli::mount",
        "mount",
        operation_id = %operation_id,
        scenario_id,
        image = %image_path.display(),
        mountpoint = %mountpoint.display(),
        runtime_mode = requested_runtime.mode.as_str(),
        managed_unmount_timeout_secs = requested_runtime.managed_unmount_timeout_secs,
        allow_other,
        auto_unmount,
        read_write = rw
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(
        target: "ffs::cli::mount",
        operation_id = %operation_id,
        scenario_id,
        "mount_start"
    );

    let runtime = match requested_runtime.validate() {
        Ok(runtime) => runtime,
        Err(error) => {
            let reason = error.to_string();
            log_mount_runtime_rejected(
                &operation_id,
                scenario_id,
                requested_runtime,
                rw,
                "invalid_runtime_mode_flags",
                &reason,
            );
            return Err(error);
        }
    };

    log_mount_runtime_selected(
        &operation_id,
        scenario_id,
        runtime,
        allow_other,
        auto_unmount,
        rw,
    );

    let cx = cli_cx();
    let mount_mode = if native {
        MountMode::Native
    } else {
        MountMode::Compat
    };
    let open_opts = OpenOptions {
        ext4_journal_replay_mode: ext4_mount_replay_mode(rw),
        mount_mode,
        ..OpenOptions::default()
    };
    let mut open_fs = OpenFs::open_with_options(&cx, image_path, &open_opts)
        .with_context(|| format!("failed to open filesystem image: {}", image_path.display()))?;
    emit_mount_banner(&open_fs, mountpoint, rw, runtime.mode);
    emit_optional_recovery_banner(&open_fs);

    if rw {
        open_fs
            .enable_writes(&cx)
            .context("failed to enable write support")?;
    }

    match runtime.mode {
        MountRuntimeMode::Standard => {
            mount_with_fuse(open_fs, mountpoint, rw, allow_other, auto_unmount)?;
        }
        MountRuntimeMode::Managed | MountRuntimeMode::PerCore => {
            let params = ManagedMountParams {
                mountpoint,
                read_write: rw,
                allow_other,
                auto_unmount,
                unmount_timeout_secs: runtime.managed_unmount_timeout_secs(),
                operation_id: &operation_id,
                scenario_id,
            };
            if runtime.mode == MountRuntimeMode::PerCore {
                mount_with_per_core_fuse(open_fs, &params)?;
            } else {
                mount_with_managed_fuse(open_fs, &params)?;
            }
        }
    }

    info!(
        target: "ffs::cli::mount",
        operation_id = %operation_id,
        scenario_id,
        outcome = "runtime_mode_completed",
        runtime_mode = runtime.mode.as_str(),
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "mount_complete"
    );

    Ok(())
}

fn validate_btrfs_mount_selection(subvol: Option<&str>, snapshot: Option<&str>) -> Result<()> {
    if subvol.is_some() || snapshot.is_some() {
        let subvol = subvol.unwrap_or("(none)");
        let snapshot = snapshot.unwrap_or("(none)");
        bail!(
            "btrfs subvolume/snapshot mounting is not yet supported (subvol={subvol}, snapshot={snapshot}); \
             use `ffs inspect --subvolumes/--snapshots` to list and mount the default root subvolume"
        );
    }
    Ok(())
}

// ── Scrub command ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct ScrubOutput {
    blocks_scanned: u64,
    blocks_corrupt: u64,
    blocks_error_or_higher: u64,
    blocks_io_error: u64,
    findings: Vec<ScrubFindingOutput>,
}

#[derive(Debug, Serialize)]
struct ScrubFindingOutput {
    block: u64,
    kind: String,
    severity: String,
    detail: String,
}

pub fn choose_btrfs_scrub_block_size(
    image_len: u64,
    nodesize: u32,
    sectorsize: u32,
) -> Result<u32> {
    if nodesize == 0 || !nodesize.is_power_of_two() {
        bail!("invalid btrfs nodesize={nodesize}; expected non-zero power-of-two");
    }

    // Btrfs superblock region must fit; scrub block size must hold it.
    let super_info_size = u32::try_from(ffs_types::BTRFS_SUPER_INFO_SIZE)
        .map_err(|_| anyhow::anyhow!("btrfs superblock size does not fit in u32"))?;
    let min_block_size = if sectorsize.is_power_of_two() {
        sectorsize.max(super_info_size)
    } else {
        super_info_size
    };

    if min_block_size > nodesize {
        bail!(
            "invalid btrfs geometry: sectorsize={sectorsize} nodesize={nodesize} (expected sectorsize <= nodesize)"
        );
    }

    let mut candidate = nodesize;
    while candidate >= min_block_size {
        if image_len % u64::from(candidate) == 0 {
            return Ok(candidate);
        }
        candidate /= 2;
    }

    bail!(
        "image length is not aligned to any supported btrfs scrub block size: len_bytes={image_len}, nodesize={nodesize}, sectorsize={sectorsize}"
    )
}

#[must_use]
pub fn count_blocks_at_severity_or_higher(report: &ScrubReport, min: Severity) -> u64 {
    report
        .findings
        .iter()
        .filter(|finding| finding.severity >= min)
        .map(|finding| finding.block.0)
        .collect::<BTreeSet<_>>()
        .len() as u64
}

#[must_use]
pub fn scrub_validator(flavor: &FsFlavor, block_size: u32) -> Box<dyn BlockValidator> {
    match flavor {
        FsFlavor::Ext4(_) => Box::new(CompositeValidator::new(vec![
            Box::new(ZeroCheckValidator),
            Box::new(Ext4SuperblockValidator::new(block_size)),
        ])),
        FsFlavor::Btrfs(sb) => Box::new(CompositeValidator::new(vec![
            Box::new(ZeroCheckValidator),
            Box::new(BtrfsSuperblockValidator::new(block_size)),
            Box::new(BtrfsTreeBlockValidator::new(
                block_size,
                sb.fsid,
                sb.csum_type,
            )),
        ])),
    }
}

fn print_scrub_output(json: bool, output: &ScrubOutput, report: &ScrubReport) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(output).context("serialize scrub report")?
        );
    } else {
        println!("FrankenFS Scrub Report");
        println!(
            "scanned {} blocks: {} corrupt, {} error+, {} io_errors, {} findings",
            output.blocks_scanned,
            output.blocks_corrupt,
            output.blocks_error_or_higher,
            output.blocks_io_error,
            output.findings.len(),
        );
        if !report.findings.is_empty() {
            println!();
            for finding in &report.findings {
                println!("  {finding}");
            }
        }
    }

    Ok(())
}

fn scrub_cmd(path: &PathBuf, json: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::scrub",
        "scrub",
        image = %path.display(),
        output_json = json
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::scrub", "scrub_start");

    let cx = cli_cx();

    // Detect filesystem to get the block size.
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;

    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let image_len = byte_dev.len_bytes();

    let block_size = match &flavor {
        FsFlavor::Ext4(sb) => sb.block_size,
        FsFlavor::Btrfs(sb) => choose_btrfs_scrub_block_size(image_len, sb.nodesize, sb.sectorsize)
            .with_context(|| {
                format!(
                    "failed to derive aligned btrfs scrub block size (len_bytes={image_len}, nodesize={}, sectorsize={})",
                    sb.nodesize, sb.sectorsize
                )
            })?,
    };

    let block_dev = ByteBlockDevice::new(byte_dev, block_size)
        .with_context(|| format!("failed to create block device (block_size={block_size})"))?;

    let validator = scrub_validator(&flavor, block_size);

    if !json {
        let fs_name = match &flavor {
            FsFlavor::Ext4(_) => "ext4",
            FsFlavor::Btrfs(_) => "btrfs",
        };
        eprintln!(
            "Scrubbing {fs_name} image: {} ({} blocks, block_size={block_size})",
            path.display(),
            block_dev.block_count(),
        );
    }

    let report = Scrubber::new(&block_dev, &*validator)
        .scrub_all(&cx)
        .with_context(|| "scrub failed")?;

    let blocks_error_or_higher = count_blocks_at_severity_or_higher(&report, Severity::Error);

    let output = ScrubOutput {
        blocks_scanned: report.blocks_scanned,
        blocks_corrupt: report.blocks_corrupt,
        blocks_error_or_higher,
        blocks_io_error: report.blocks_io_error,
        findings: report
            .findings
            .iter()
            .map(|f| ScrubFindingOutput {
                block: f.block.0,
                kind: f.kind.to_string(),
                severity: f.severity.to_string(),
                detail: f.detail.clone(),
            })
            .collect(),
    };

    print_scrub_output(json, &output, &report)?;

    let has_error_findings = report.count_at_severity(Severity::Error) > 0;

    info!(
        target: "ffs::cli::scrub",
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        blocks_scanned = output.blocks_scanned,
        blocks_corrupt = output.blocks_corrupt,
        blocks_error_or_higher = output.blocks_error_or_higher,
        has_error_findings,
        "scrub_complete"
    );

    // Exit with non-zero status if corruption found at Error or above.
    if has_error_findings {
        std::process::exit(2);
    }

    Ok(())
}

fn fsck_cmd(path: &PathBuf, options: FsckCommandOptions) -> Result<()> {
    let flags = options.flags;
    let command_span = info_span!(
        target: "ffs::cli::fsck",
        "fsck",
        image = %path.display(),
        repair = flags.repair(),
        force = flags.force(),
        verbose = flags.verbose(),
        block_group = options.block_group.unwrap_or(u32::MAX),
        output_json = flags.json()
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::fsck", "fsck_start");

    let output = match build_fsck_output(path, options) {
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
                eprintln!("fsck operational error: {err:#}");
            }
            std::process::exit(4);
        }
    };

    print_fsck_output(flags.json(), &output)?;

    info!(
        target: "ffs::cli::fsck",
        filesystem = output.filesystem,
        outcome = ?output.outcome,
        repair_status = ?output.repair_status,
        exit_code = output.exit_code,
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "fsck_complete"
    );

    if output.exit_code != 0 {
        std::process::exit(output.exit_code);
    }

    Ok(())
}

#[allow(clippy::too_many_lines)]
fn build_fsck_output(path: &PathBuf, options: FsckCommandOptions) -> Result<FsckOutput> {
    let flags = options.flags;
    let cx = cli_cx();
    let mut phases = Vec::new();
    let mut limitations = Vec::new();
    let repair_coordination = coordinate_repair_write_access(
        "ffs::cli::fsck",
        REPAIR_COORDINATION_SCENARIO_FSCK,
        "fsck",
        path,
        flags.repair(),
    );
    if repair_coordination.output.is_blocked() {
        limitations.push(repair_coordination.output.detail.clone());
    }
    let (flavor, bootstrap_recovery_source) = detect_flavor_with_optional_btrfs_bootstrap(
        &cx,
        path,
        flags.repair() && repair_coordination.writes_allowed,
        &mut limitations,
    )?;
    let mut ext4_recovery = None;
    let mut btrfs_repair_attempted = bootstrap_recovery_source.is_some();
    let mut btrfs_repair_performed = bootstrap_recovery_source.is_some();
    let mut btrfs_repair_detail = bootstrap_recovery_source.map(|source| {
        format!(
            "bootstrap restored primary btrfs superblock from backup mirror at byte offset {} \
             (generation={})",
            source.offset, source.generation
        )
    });
    if flags.repair() && repair_coordination.writes_allowed {
        if let FsFlavor::Ext4(_) = &flavor {
            ext4_recovery = Some(run_ext4_mount_recovery(path)?);
        }
    }

    phases.push(FsckPhaseOutput {
        phase: "superblock_validation".to_owned(),
        status: "ok".to_owned(),
        detail: match &flavor {
            FsFlavor::Ext4(sb) => format!(
                "ext4 superblock parsed (block_size={}, blocks={}, inodes={})",
                sb.block_size, sb.blocks_count, sb.inodes_count
            ),
            FsFlavor::Btrfs(sb) => format!(
                "btrfs superblock parsed (sectorsize={}, nodesize={}, generation={})",
                sb.sectorsize, sb.nodesize, sb.generation
            ),
        },
    });

    let image = std::fs::read(path)
        .with_context(|| format!("failed to read filesystem image: {}", path.display()))?;
    let byte_dev = FileByteDevice::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let image_len = byte_dev.len_bytes();

    let (scope, report, block_size, scrub_skipped_detail) = match &flavor {
        FsFlavor::Ext4(sb) => {
            let reader = Ext4ImageReader::new(&image).context("failed to parse ext4 superblock")?;
            let desc_status = validate_ext4_group_descriptors(&reader, &image, options.block_group);
            phases.push(desc_status);

            let block_size = sb.block_size;
            let block_dev = ByteBlockDevice::new(byte_dev, block_size).with_context(|| {
                format!("failed to create block device (block_size={block_size})")
            })?;
            let validator = scrub_validator(&flavor, block_size);

            let skip_full_scrub = options.block_group.is_none()
                && !flags.force()
                && ext4_appears_clean_state(sb.state);

            let (scope, report, skipped_detail) = if let Some(group) = options.block_group {
                let (start, count) = ext4_group_scrub_scope(sb, group)?;
                if flags.verbose() && !flags.json() {
                    eprintln!(
                        "fsck: ext4 group {} -> scrub blocks {}..{}",
                        group,
                        start.0,
                        start.0.saturating_add(count).saturating_sub(1)
                    );
                }
                let report = Scrubber::new(&block_dev, &*validator)
                    .scrub_range(&cx, start, count)
                    .with_context(|| format!("failed to scrub ext4 group {group}"))?;
                (
                    FsckScopeOutput::Ext4BlockGroup {
                        group,
                        start_block: start.0,
                        block_count: count,
                    },
                    report,
                    None,
                )
            } else if skip_full_scrub {
                let detail = format!(
                    "filesystem appears clean (state_flags={}); skipped block-level scrub; pass --force for full scrub",
                    ext4_state_flag_names(sb.state).join("|")
                );
                if flags.verbose() && !flags.json() {
                    eprintln!("fsck: {detail}");
                }
                limitations.push(
                    "filesystem appears clean; skipped block-level scrub (use --force for full scrub)"
                        .to_owned(),
                );
                (
                    FsckScopeOutput::Full,
                    ScrubReport {
                        findings: Vec::new(),
                        blocks_scanned: 0,
                        blocks_corrupt: 0,
                        blocks_io_error: 0,
                    },
                    Some(detail),
                )
            } else {
                if flags.verbose() && !flags.json() {
                    eprintln!(
                        "fsck: ext4 full scrub across {} blocks",
                        block_dev.block_count()
                    );
                }
                let report = Scrubber::new(&block_dev, &*validator)
                    .scrub_all(&cx)
                    .context("failed to scrub ext4 image")?;
                (FsckScopeOutput::Full, report, None)
            };
            (scope, report, block_size, skipped_detail)
        }
        FsFlavor::Btrfs(sb) => {
            phases.push(FsckPhaseOutput {
                phase: "group_descriptor_validation".to_owned(),
                status: "skipped".to_owned(),
                detail: "ext4-specific group descriptor checks do not apply to btrfs".to_owned(),
            });

            let block_size = choose_btrfs_scrub_block_size(image_len, sb.nodesize, sb.sectorsize)
                .with_context(|| {
                    format!(
                        "failed to derive aligned btrfs scrub block size (len_bytes={image_len}, nodesize={}, sectorsize={})",
                        sb.nodesize, sb.sectorsize
                    )
                })?;
            let (scope, scrub_start, scrub_count, mut report) = if let Some(group) =
                options.block_group
            {
                let specs = discover_btrfs_repair_group_specs(path, block_size)
                    .context("failed to discover btrfs block groups for scoped fsck")?;
                let spec = specs
                    .iter()
                    .find(|spec| spec.group == group)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "btrfs block group {group} is unavailable (valid range: 0..{})",
                            specs.len().saturating_sub(1)
                        )
                    })?;
                if flags.verbose() && !flags.json() {
                    eprintln!(
                        "fsck: btrfs group {} -> logical {}..{}, physical blocks {}..{}",
                        group,
                        spec.logical_start,
                        spec.logical_start
                            .saturating_add(spec.logical_bytes)
                            .saturating_sub(1),
                        spec.physical_start_block.0,
                        spec.physical_start_block
                            .0
                            .saturating_add(spec.physical_block_count)
                            .saturating_sub(1)
                    );
                }
                let report = scrub_range_for_repair(
                    path,
                    &flavor,
                    block_size,
                    spec.physical_start_block,
                    spec.physical_block_count,
                    None,
                    &mut limitations,
                )
                .with_context(|| format!("failed to scrub btrfs group {group}"))?;
                (
                    FsckScopeOutput::BtrfsBlockGroup {
                        group,
                        logical_start: spec.logical_start,
                        logical_bytes: spec.logical_bytes,
                        start_block: spec.physical_start_block.0,
                        block_count: spec.physical_block_count,
                    },
                    spec.physical_start_block,
                    spec.physical_block_count,
                    report,
                )
            } else {
                let block_dev = ByteBlockDevice::new(byte_dev, block_size).with_context(|| {
                    format!("failed to create block device (block_size={block_size})")
                })?;
                let validator = scrub_validator(&flavor, block_size);
                if flags.verbose() && !flags.json() {
                    eprintln!(
                        "fsck: btrfs full scrub across {} blocks (block_size={block_size})",
                        block_dev.block_count()
                    );
                }
                let report = Scrubber::new(&block_dev, &*validator)
                    .scrub_all(&cx)
                    .context("failed to scrub btrfs image")?;
                (FsckScopeOutput::Full, BlockNumber(0), u64::MAX, report)
            };

            if flags.repair() && repair_coordination.writes_allowed {
                let mut verify_after_repair_writes = false;
                let primary_superblock = primary_btrfs_superblock_block(block_size);
                let superblock_in_scope =
                    block_range_contains(scrub_start, scrub_count, primary_superblock);
                if superblock_in_scope
                    && report_has_error_or_higher_for_block(&report, primary_superblock)
                {
                    btrfs_repair_attempted = true;
                    match recover_primary_btrfs_superblock_from_backup(path, &mut limitations) {
                        Ok(Some(source)) => {
                            btrfs_repair_performed = true;
                            verify_after_repair_writes = true;
                            let detail = format!(
                                "restored primary btrfs superblock from backup mirror at byte offset {} (generation={})",
                                source.offset, source.generation
                            );
                            append_btrfs_repair_detail(&mut btrfs_repair_detail, detail.clone());
                            limitations.push(detail);
                        }
                        Ok(None) => {
                            let detail =
                                "btrfs superblock corruption detected, but no valid backup superblock mirror was available for restoration"
                                    .to_owned();
                            append_btrfs_repair_detail(&mut btrfs_repair_detail, detail.clone());
                            limitations.push(detail);
                        }
                        Err(error) => {
                            let detail =
                                format!("btrfs superblock recovery attempt failed: {error:#}");
                            append_btrfs_repair_detail(&mut btrfs_repair_detail, detail.clone());
                            limitations.push(detail);
                        }
                    }
                }

                match repair_corrupt_btrfs_superblock_mirrors_from_primary(
                    path,
                    block_size,
                    scrub_start,
                    scrub_count,
                    &mut limitations,
                ) {
                    Ok(mirror_outcome) => {
                        if mirror_outcome.attempted {
                            btrfs_repair_attempted = true;
                            if mirror_outcome.repaired > 0 {
                                btrfs_repair_performed = true;
                                verify_after_repair_writes = true;
                                append_btrfs_repair_detail(
                                    &mut btrfs_repair_detail,
                                    format!(
                                        "restored {} btrfs superblock mirror(s) from primary superblock",
                                        mirror_outcome.repaired
                                    ),
                                );
                            } else {
                                append_btrfs_repair_detail(
                                    &mut btrfs_repair_detail,
                                    "btrfs superblock mirror corruption detected but restoration from primary did not complete",
                                );
                            }
                        }
                    }
                    Err(error) => {
                        btrfs_repair_attempted = true;
                        let detail =
                            format!("btrfs superblock mirror recovery attempt failed: {error:#}");
                        append_btrfs_repair_detail(&mut btrfs_repair_detail, detail.clone());
                        limitations.push(detail);
                    }
                }

                // Attempt RaptorQ block-symbol recovery for non-superblock
                // corruption in the fsck --repair path.
                if count_blocks_at_severity_or_higher(&report, Severity::Error) > 0 {
                    match discover_btrfs_repair_group_specs(path, block_size) {
                        Ok(btrfs_specs) if !btrfs_specs.is_empty() => {
                            match recover_btrfs_corrupt_blocks(
                                path,
                                block_size,
                                sb.fsid,
                                &btrfs_specs,
                                &report,
                                &mut limitations,
                            ) {
                                Ok((recovered, _unrecovered, _repaired_groups)) => {
                                    if recovered > 0 {
                                        btrfs_repair_attempted = true;
                                        btrfs_repair_performed = true;
                                        verify_after_repair_writes = true;
                                        append_btrfs_repair_detail(
                                            &mut btrfs_repair_detail,
                                            format!(
                                                "recovered {recovered} btrfs block(s) via RaptorQ symbol reconstruction"
                                            ),
                                        );
                                    }
                                }
                                Err(error) => {
                                    btrfs_repair_attempted = true;
                                    let detail = format!(
                                        "btrfs block-symbol recovery attempt failed: {error:#}"
                                    );
                                    append_btrfs_repair_detail(
                                        &mut btrfs_repair_detail,
                                        detail.clone(),
                                    );
                                    limitations.push(detail);
                                }
                            }
                        }
                        Ok(_) => {
                            limitations.push(
                                "no btrfs block groups discovered; fsck block-symbol recovery skipped"
                                    .to_owned(),
                            );
                        }
                        Err(error) => {
                            limitations.push(format!(
                                "failed to discover btrfs repair group layout for fsck: {error:#}"
                            ));
                        }
                    }
                }

                if !btrfs_repair_performed && btrfs_repair_detail.is_none() {
                    if superblock_in_scope {
                        btrfs_repair_detail = Some(
                            "no primary btrfs superblock corruption detected in selected fsck scope"
                                .to_owned(),
                        );
                    } else {
                        btrfs_repair_detail = Some(
                            "repair scope does not include the primary btrfs superblock".to_owned(),
                        );
                    }
                }

                if verify_after_repair_writes {
                    report = scrub_range_for_repair(
                        path,
                        &flavor,
                        block_size,
                        scrub_start,
                        scrub_count,
                        None,
                        &mut limitations,
                    )
                    .context("failed to verify btrfs image after fsck repairs")?;
                }
            }

            (scope, report, block_size, None)
        }
    };
    let scrub = scrub_report_to_phase(&report);
    let scrub_phase_status = if scrub_skipped_detail.is_some() {
        "skipped"
    } else if scrub.error_or_higher == 0 {
        "ok"
    } else {
        "error"
    };
    let scrub_phase_detail = scrub_skipped_detail.unwrap_or_else(|| {
        format!(
            "scanned={} corrupt={} error_or_higher={} io_errors={}",
            scrub.scanned, scrub.corrupt, scrub.error_or_higher, scrub.io_error
        )
    });
    phases.push(FsckPhaseOutput {
        phase: "checksum_scrub".to_owned(),
        status: scrub_phase_status.to_owned(),
        detail: scrub_phase_detail,
    });

    let repair_status = if flags.repair() {
        if repair_coordination.output.is_blocked() {
            phases.push(FsckPhaseOutput {
                phase: "repair".to_owned(),
                status: "error".to_owned(),
                detail: repair_coordination.output.detail.clone(),
            });
            FsckRepairStatus::RequestedNotPerformed
        } else if let Some(recovery) = &ext4_recovery {
            phases.push(FsckPhaseOutput {
                phase: "repair".to_owned(),
                status: "ok".to_owned(),
                detail: ext4_recovery_detail(recovery),
            });
            FsckRepairStatus::RequestedPerformed
        } else if matches!(flavor, FsFlavor::Btrfs(_)) {
            let (status, detail, performed) = if btrfs_repair_performed {
                (
                    "ok".to_owned(),
                    btrfs_repair_detail.unwrap_or_else(|| {
                        "restored primary btrfs superblock from backup mirror".to_owned()
                    }),
                    true,
                )
            } else if btrfs_repair_attempted {
                (
                    "error".to_owned(),
                    btrfs_repair_detail.unwrap_or_else(|| {
                        "btrfs superblock corruption detected but recovery did not complete"
                            .to_owned()
                    }),
                    false,
                )
            } else {
                (
                    "skipped".to_owned(),
                    btrfs_repair_detail.unwrap_or_else(|| {
                        "repair requested but no primary btrfs superblock corruption was detected in scope"
                            .to_owned()
                    }),
                    false,
                )
            };
            phases.push(FsckPhaseOutput {
                phase: "repair".to_owned(),
                status,
                detail,
            });
            if performed {
                FsckRepairStatus::RequestedPerformed
            } else {
                FsckRepairStatus::RequestedNotPerformed
            }
        } else {
            phases.push(FsckPhaseOutput {
                phase: "repair".to_owned(),
                status: "skipped".to_owned(),
                detail:
                    "repair requested but no write-side workflow is available for this filesystem flavor"
                        .to_owned(),
            });
            FsckRepairStatus::RequestedNotPerformed
        }
    } else {
        FsckRepairStatus::NotRequested
    };

    limitations.push(format!(
        "fsck currently covers superblock/group-descriptor validation plus block-level scrub checks (block_size={block_size})"
    ));

    let outcome = if scrub.error_or_higher > 0 {
        FsckOutcome::ErrorsFound
    } else {
        FsckOutcome::Clean
    };
    let exit_code = if repair_coordination.output.is_blocked() {
        2
    } else {
        match outcome {
            FsckOutcome::Clean => 0,
            FsckOutcome::ErrorsFound => 1,
        }
    };

    Ok(FsckOutput {
        filesystem: filesystem_name(&flavor).to_owned(),
        scope,
        phases,
        scrub,
        repair_status,
        repair_coordination: flags.repair().then_some(repair_coordination.output),
        ext4_recovery,
        outcome,
        exit_code,
        limitations,
    })
}

fn validate_ext4_group_descriptors(
    reader: &Ext4ImageReader,
    image: &[u8],
    only_group: Option<u32>,
) -> FsckPhaseOutput {
    if let Some(group) = only_group {
        return match reader.read_group_desc(image, GroupNumber(group)) {
            Ok(_) => FsckPhaseOutput {
                phase: "group_descriptor_validation".to_owned(),
                status: "ok".to_owned(),
                detail: format!("validated ext4 group descriptor {group}"),
            },
            Err(err) => FsckPhaseOutput {
                phase: "group_descriptor_validation".to_owned(),
                status: "error".to_owned(),
                detail: format!("group {group} failed validation: {err}"),
            },
        };
    }

    let groups = reader.sb.groups_count();
    for group in 0..groups {
        if let Err(err) = reader.read_group_desc(image, GroupNumber(group)) {
            return FsckPhaseOutput {
                phase: "group_descriptor_validation".to_owned(),
                status: "error".to_owned(),
                detail: format!("group {group} failed validation: {err}"),
            };
        }
    }

    FsckPhaseOutput {
        phase: "group_descriptor_validation".to_owned(),
        status: "ok".to_owned(),
        detail: format!("validated {groups} ext4 group descriptors"),
    }
}

pub fn ext4_group_scrub_scope(sb: &Ext4Superblock, group: u32) -> Result<(BlockNumber, u64)> {
    let groups = sb.groups_count();
    if group >= groups {
        bail!("block group {group} out of range (groups_count={groups})");
    }

    let start = u64::from(sb.first_data_block)
        .saturating_add(u64::from(group).saturating_mul(u64::from(sb.blocks_per_group)));
    let end_exclusive = start
        .saturating_add(u64::from(sb.blocks_per_group))
        .min(sb.blocks_count);
    let count = end_exclusive.saturating_sub(start);

    Ok((BlockNumber(start), count))
}

fn scrub_report_to_phase(report: &ScrubReport) -> FsckScrubOutput {
    FsckScrubOutput {
        scanned: report.blocks_scanned,
        corrupt: report.blocks_corrupt,
        error_or_higher: count_blocks_at_severity_or_higher(report, Severity::Error),
        io_error: report.blocks_io_error,
    }
}

pub fn run_ext4_mount_recovery(path: &PathBuf) -> Result<Ext4RecoveryOutput> {
    let cx = cli_cx();
    let open = OpenFs::open_with_options(
        &cx,
        path,
        &OpenOptions {
            skip_validation: false,
            ext4_journal_replay_mode: Ext4JournalReplayMode::Apply,
            ..OpenOptions::default()
        },
    )
    .with_context(|| {
        format!(
            "failed to open ext4 image for repair workflow: {}",
            path.display()
        )
    })?;

    let outcome = open.crash_recovery().cloned().ok_or_else(|| {
        anyhow::anyhow!("ext4 repair workflow expected crash recovery outcome but found none")
    })?;
    Ok(Ext4RecoveryOutput {
        recovery_performed: outcome.recovery_performed(),
        crash_recovery: outcome,
    })
}

#[must_use]
pub fn ext4_recovery_detail(recovery: &Ext4RecoveryOutput) -> String {
    format!(
        "recovery_performed={} clean={} had_errors={} had_orphans={} journal_txns_replayed={} journal_blocks_replayed={}",
        recovery.recovery_performed,
        recovery.crash_recovery.was_clean,
        recovery.crash_recovery.had_errors,
        recovery.crash_recovery.had_orphans,
        recovery.crash_recovery.journal_txns_replayed,
        recovery.crash_recovery.journal_blocks_replayed
    )
}

fn print_fsck_output(json: bool, output: &FsckOutput) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(output).context("serialize fsck output")?
        );
        return Ok(());
    }

    println!("FrankenFS FSCK");
    println!("filesystem: {}", output.filesystem);
    match &output.scope {
        FsckScopeOutput::Full => println!("scope: full"),
        FsckScopeOutput::Ext4BlockGroup {
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
        FsckScopeOutput::BtrfsBlockGroup {
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
    println!("phases:");
    for phase in &output.phases {
        println!(
            "  - {}: {} ({})",
            phase.phase.replace('_', " "),
            phase.status,
            phase.detail
        );
    }
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
    println!("repair_status: {:?}", output.repair_status);
    if let Some(coordination) = &output.repair_coordination {
        println!(
            "repair_coordination: status={:?} policy={} operation_id={} scenario_id={}",
            coordination.status,
            coordination.policy,
            coordination.operation_id,
            coordination.scenario_id
        );
        println!(
            "repair_coordination_detail: {} (coordination_file={}, local_host={})",
            coordination.detail, coordination.coordination_file, coordination.local_host
        );
        if let Some(owner_host) = &coordination.owner_host {
            println!("repair_coordination_owner_host: {owner_host}");
        }
        if let Some(owner_process_id) = coordination.owner_process_id {
            println!("repair_coordination_owner_process_id: {owner_process_id}");
        }
        if let Some(error_class) = &coordination.error_class {
            println!("repair_coordination_error_class: {error_class}");
        }
    }
    println!("outcome: {:?}", output.outcome);
    println!("exit_code: {}", output.exit_code);
    if !output.limitations.is_empty() {
        println!("limitations:");
        for limitation in &output.limitations {
            println!("  - {limitation}");
        }
    }

    Ok(())
}

fn parity(json: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::parity",
        "parity",
        output_json = json
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::parity", "parity_start");

    let report = ParityReport::current();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).context("serialize parity report")?
        );
    } else {
        println!("FrankenFS Feature Parity Report");
        println!();
        for domain in &report.domains {
            println!(
                "  {:<35} {:>2}/{:<2}  ({:.1}%)",
                domain.domain, domain.implemented, domain.total, domain.coverage_percent
            );
        }
        println!();
        println!(
            "  {:<35} {:>2}/{:<2}  ({:.1}%)",
            "OVERALL",
            report.overall_implemented,
            report.overall_total,
            report.overall_coverage_percent
        );
    }

    info!(
        target: "ffs::cli::parity",
        overall_coverage_percent = report.overall_coverage_percent,
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "parity_complete"
    );

    Ok(())
}

// ── Mkfs command ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct MkfsOutput {
    path: String,
    size_bytes: u64,
    block_size: u32,
    label: String,
    block_count: u64,
    groups_count: u32,
    inodes_count: u32,
}

fn mkfs_cmd(output: &Path, size_mb: u64, block_size: u32, label: &str, json: bool) -> Result<()> {
    mkfs_cmd_with_program(
        output,
        size_mb,
        block_size,
        label,
        json,
        Path::new("mkfs.ext4"),
    )
}

fn emit_mkfs_output(result: &MkfsOutput, size_mb: u64, json: bool) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(result).context("serialize mkfs output")?
        );
    } else {
        println!("FrankenFS mkfs");
        println!("  Path:        {}", result.path);
        println!(
            "  Size:        {} MiB ({} bytes)",
            size_mb, result.size_bytes
        );
        println!("  Block size:  {}", result.block_size);
        println!("  Label:       {}", result.label);
        println!("  Blocks:      {}", result.block_count);
        println!("  Groups:      {}", result.groups_count);
        println!("  Inodes:      {}", result.inodes_count);
        println!("Image created successfully.");
    }

    Ok(())
}

fn validate_mkfs_params(output: &Path, size_mb: u64, block_size: u32) -> Result<u64> {
    if ![1024, 2048, 4096].contains(&block_size) {
        bail!("block_size must be 1024, 2048, or 4096 (got {block_size})");
    }
    if size_mb == 0 {
        bail!("size_mb must be > 0");
    }
    let output_str = output.as_os_str().to_string_lossy();
    if output_str.starts_with('-') {
        bail!("output path must not start with '-' (use ./ or an absolute path): {output_str}");
    }
    size_mb
        .checked_mul(1024 * 1024)
        .ok_or_else(|| anyhow::anyhow!("size_mb too large to represent bytes"))
}

fn create_sparse_image(output: &Path, size_bytes: u64) -> Result<()> {
    let f = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
    {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!("output file already exists: {}", output.display());
        }
        Err(err) => {
            return Err(err).with_context(|| format!("create image file {}", output.display()));
        }
    };
    f.set_len(size_bytes)
        .with_context(|| format!("set image size to {size_bytes}"))?;
    drop(f);
    Ok(())
}

fn run_mkfs_program(
    mkfs_program: &Path,
    output: &Path,
    block_size: u32,
    label: &str,
) -> Result<()> {
    let mkfs_output = std::process::Command::new(mkfs_program)
        .arg("-F")
        .arg("-b")
        .arg(block_size.to_string())
        .arg("-L")
        .arg(label)
        .arg(output)
        .output()
        .with_context(|| {
            format!(
                "failed to run {} for {} (output image preserved at {})",
                mkfs_program.display(),
                output.display(),
                output.display()
            )
        })?;

    if !mkfs_output.status.success() {
        let stderr = String::from_utf8_lossy(&mkfs_output.stderr);
        let stderr = stderr.trim();
        let status = mkfs_output.status;
        let failure_detail = if stderr.is_empty() {
            format!("exit status {status}")
        } else {
            format!("exit status {status}: {stderr}")
        };
        bail!(
            "mkfs.ext4 failed for {}. Preserved partial image at {}. {}",
            output.display(),
            output.display(),
            failure_detail
        );
    }
    Ok(())
}

fn mkfs_cmd_with_program(
    output: &Path,
    size_mb: u64,
    block_size: u32,
    label: &str,
    json: bool,
    mkfs_program: &Path,
) -> Result<()> {
    let size_bytes = validate_mkfs_params(output, size_mb, block_size)?;
    create_sparse_image(output, size_bytes)?;
    run_mkfs_program(mkfs_program, output, block_size, label)?;

    // Verify the new image by opening it with FrankenFS.
    let cx = cli_cx();
    let fs = OpenFs::open(&cx, output)
        .with_context(|| format!("verify new image at {}", output.display()))?;

    let (result, actual_label) = match &fs.flavor {
        FsFlavor::Ext4(sb) => {
            let actual_label = sb.volume_name.clone();
            (
                MkfsOutput {
                    path: output.display().to_string(),
                    size_bytes,
                    block_size: sb.block_size,
                    label: actual_label.clone(),
                    block_count: sb.blocks_count,
                    groups_count: sb.groups_count(),
                    inodes_count: sb.inodes_count,
                },
                actual_label,
            )
        }
        FsFlavor::Btrfs(_) => {
            bail!(
                "mkfs.ext4 verification opened {} as btrfs; refusing to continue",
                output.display()
            );
        }
    };

    if actual_label != label {
        warn!(
            target: "ffs::cli",
            requested_label = %label,
            resolved_label = %actual_label,
            "mkfs label adjusted by mkfs.ext4"
        );
    }

    emit_mkfs_output(&result, size_mb, json)?;

    info!(
        target: "ffs::cli",
        path = %output.display(),
        size_bytes,
        block_size,
        label = %actual_label,
        "mkfs_complete"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        BTRFS_FS_TREE_OBJECTID, BTRFS_ITEM_INODE_ITEM, BTRFS_ITEM_ROOT_ITEM, BtrfsInodeItem, Cli,
        Command, DumpCommand, Ext4JournalReplayMode, FsckCommandOptions, FsckFlags,
        InfoCommandOptions, InfoSections, LogFormat, MountRuntimeConfig, MountRuntimeMode,
        RepairCommandOptions, RepairFlags, btrfs_chunk_type_flag_names, build_ext4_group_info,
        build_fsck_output, build_info_output, choose_btrfs_scrub_block_size,
        ext4_appears_clean_state, ext4_mount_replay_mode, format_ratio_thousandths,
        log_mount_runtime_rejected, log_mount_runtime_selected, mount_cmd, mount_operation_id,
        read_ext4_group_desc_from_path, read_ext4_inode_from_path, read_file_region,
        summarize_repair_staleness, unavailable_repair_info, validate_btrfs_mount_selection,
    };
    use crate::cmd_evidence::{
        EvidenceHistogramBucket, EvidenceHistogramSnapshot, EvidenceMvccRuntimeMetricsSnapshot,
        load_evidence_records, load_metrics_report_for_test,
    };
    use crate::cmd_repair::{
        Ext4RepairStaleness, REPAIR_COORDINATION_SCENARIO_REPAIR, RepairCoordinationRecord,
        RepairCoordinationStatus, btrfs_super_mirror_offsets, build_btrfs_repair_group_spec,
        build_repair_output, coordinate_repair_write_access, merge_scrub_reports,
        normalize_btrfs_superblock_as_primary, partition_scrub_range,
        repair_coordination_record_path, repair_worker_limit, select_btrfs_repair_groups,
        select_ext4_repair_groups,
    };
    use clap::Parser;
    use ffs_block::CacheRuntimeMetricsSnapshot;
    use ffs_repair::evidence::{EvidenceEventType, EvidenceRecord};
    use ffs_repair::pipeline::RepairRuntimeMetricsSnapshot;
    use serde_json::Value;
    use std::io::{self, Seek, SeekFrom, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tracing::{info, info_span};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct SharedLogBuffer {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedLogBuffer {
        fn as_string(&self) -> String {
            let bytes = self.bytes.lock().expect("log buffer lock poisoned").clone();
            String::from_utf8(bytes).expect("log buffer must be utf-8")
        }
    }

    struct SharedLogWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for SharedLogWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.bytes
                .lock()
                .expect("log buffer lock poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for SharedLogBuffer {
        type Writer = SharedLogWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            SharedLogWriter {
                bytes: Arc::clone(&self.bytes),
            }
        }
    }

    fn log_contract_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        let mutex = LOCK.get_or_init(|| std::sync::Mutex::new(()));
        mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn parse_first_json_line(buffer: &SharedLogBuffer) -> Value {
        let logs = buffer.as_string();
        let line = logs
            .lines()
            .find(|line| !line.trim().is_empty())
            .expect("expected at least one log line");
        serde_json::from_str(line).expect("line should parse as JSON")
    }

    #[allow(clippy::cast_possible_truncation)]
    fn build_test_ext4_image_with_state(state: u16) -> Vec<u8> {
        const BLOCK_SIZE_LOG: u32 = 2; // 4K blocks
        let block_size = 1024_u32 << BLOCK_SIZE_LOG;
        let image_size: u32 = 128 * 1024;
        let mut image = vec![0_u8; image_size as usize];
        let sb_off = ffs_types::EXT4_SUPERBLOCK_OFFSET;

        // Core superblock fields needed by parser + geometry checks.
        image[sb_off + 0x38..sb_off + 0x3A]
            .copy_from_slice(&ffs_types::EXT4_SUPER_MAGIC.to_le_bytes());
        image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&BLOCK_SIZE_LOG.to_le_bytes());
        let blocks_count = image_size / block_size;
        image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
        image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes()); // inodes_count
        image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&0_u32.to_le_bytes()); // first_data_block
        image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes()); // blocks_per_group
        image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes()); // inodes_per_group
        image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes()); // inode_size
        image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes()); // rev_level
        image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes()); // first_ino
        let filetype: u32 = 0x0002;
        let extents: u32 = 0x0040;
        image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&(filetype | extents).to_le_bytes());
        image[sb_off + 0x3A..sb_off + 0x3C].copy_from_slice(&state.to_le_bytes());

        // Minimal group descriptor so group-descriptor validation succeeds.
        let gdt_off = block_size as usize;
        image[gdt_off + 0x08..gdt_off + 0x0C].copy_from_slice(&5_u32.to_le_bytes()); // inode table block

        image
    }

    fn build_test_btrfs_superblock(bytenr: u64, generation: u64) -> Vec<u8> {
        let mut sb = vec![0_u8; super::BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&ffs_types::BTRFS_MAGIC.to_le_bytes());
        sb[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
        sb[0x48..0x50].copy_from_slice(&generation.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes()); // sectorsize
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes()); // nodesize
        sb[0x9C..0xA0].copy_from_slice(&4096_u32.to_le_bytes()); // stripesize
        sb[0xC4..0xC6].copy_from_slice(&ffs_types::BTRFS_CSUM_TYPE_CRC32C.to_le_bytes());
        let checksum = crc32c::crc32c(&sb[0x20..super::BTRFS_SUPER_INFO_SIZE]);
        sb[0..4].copy_from_slice(&checksum.to_le_bytes());
        sb
    }

    #[allow(clippy::cast_possible_truncation)]
    fn build_test_btrfs_superblock_with_single_chunk(
        bytenr: u64,
        generation: u64,
        logical_start: u64,
        logical_length: u64,
        physical_start: u64,
        chunk_type: u64,
    ) -> Vec<u8> {
        const BTRFS_SYS_CHUNK_ARRAY_OFFSET_TEST: usize = 0x32B;
        let mut sb = build_test_btrfs_superblock(bytenr, generation);

        // One sys_chunk_array entry:
        // disk_key (17) + chunk_fixed (48) + 1 stripe (32) = 97 bytes.
        let mut entry = Vec::with_capacity(97);

        // disk_key
        entry.extend_from_slice(&256_u64.to_le_bytes()); // objectid
        entry.push(228_u8); // CHUNK_ITEM_KEY
        entry.extend_from_slice(&logical_start.to_le_bytes());

        // chunk fixed fields
        entry.extend_from_slice(&logical_length.to_le_bytes()); // length
        entry.extend_from_slice(&2_u64.to_le_bytes()); // owner (chunk tree)
        entry.extend_from_slice(&(64 * 1024_u64).to_le_bytes()); // stripe_len
        entry.extend_from_slice(&chunk_type.to_le_bytes()); // type flags
        entry.extend_from_slice(&4096_u32.to_le_bytes()); // io_align
        entry.extend_from_slice(&4096_u32.to_le_bytes()); // io_width
        entry.extend_from_slice(&4096_u32.to_le_bytes()); // sector_size
        entry.extend_from_slice(&1_u16.to_le_bytes()); // num_stripes
        entry.extend_from_slice(&0_u16.to_le_bytes()); // sub_stripes

        // one stripe
        entry.extend_from_slice(&1_u64.to_le_bytes()); // devid
        entry.extend_from_slice(&physical_start.to_le_bytes()); // physical offset
        entry.extend_from_slice(&[0_u8; 16]); // dev_uuid

        let array_size = u32::try_from(entry.len()).expect("chunk entry length fits in u32");
        sb[0xA0..0xA4].copy_from_slice(&array_size.to_le_bytes());
        let array_start = BTRFS_SYS_CHUNK_ARRAY_OFFSET_TEST;
        let array_end = array_start + entry.len();
        sb[array_start..array_end].copy_from_slice(&entry);

        // Recompute checksum after mutating sys_chunk_array.
        let checksum = crc32c::crc32c(&sb[0x20..super::BTRFS_SUPER_INFO_SIZE]);
        sb[0..4].copy_from_slice(&checksum.to_le_bytes());
        sb
    }

    fn write_btrfs_leaf_header(
        image: &mut [u8],
        leaf_offset: usize,
        logical_bytenr: u64,
        owner: u64,
        item_count: u32,
    ) {
        image[leaf_offset + 0x30..leaf_offset + 0x38]
            .copy_from_slice(&logical_bytenr.to_le_bytes());
        image[leaf_offset + 0x50..leaf_offset + 0x58].copy_from_slice(&1_u64.to_le_bytes());
        image[leaf_offset + 0x58..leaf_offset + 0x60].copy_from_slice(&owner.to_le_bytes());
        image[leaf_offset + 0x60..leaf_offset + 0x64].copy_from_slice(&item_count.to_le_bytes());
        image[leaf_offset + 0x64] = 0;
    }

    #[allow(clippy::too_many_arguments)]
    fn write_btrfs_leaf_item(
        image: &mut [u8],
        leaf_offset: usize,
        item_index: usize,
        objectid: u64,
        item_type: u8,
        key_offset: u64,
        data_offset: u32,
        data_size: u32,
    ) {
        const BTRFS_LEAF_HEADER_SIZE: usize = 101;
        const BTRFS_LEAF_ITEM_SIZE: usize = 25;
        let item_offset = leaf_offset + BTRFS_LEAF_HEADER_SIZE + item_index * BTRFS_LEAF_ITEM_SIZE;
        let data_offset_rel = data_offset
            .checked_sub(u32::try_from(BTRFS_LEAF_HEADER_SIZE).expect("header size fits"))
            .expect("test item payload must live after the leaf header");
        image[item_offset..item_offset + 8].copy_from_slice(&objectid.to_le_bytes());
        image[item_offset + 8] = item_type;
        image[item_offset + 9..item_offset + 17].copy_from_slice(&key_offset.to_le_bytes());
        image[item_offset + 17..item_offset + 21].copy_from_slice(&data_offset_rel.to_le_bytes());
        image[item_offset + 21..item_offset + 25].copy_from_slice(&data_size.to_le_bytes());
    }

    #[allow(clippy::cast_possible_truncation)]
    fn build_test_btrfs_image_with_root_inode_item() -> Vec<u8> {
        let image_size: usize = 512 * 1024;
        let mut image = vec![0_u8; image_size];
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let root_tree_logical = 0x4_000_u64;
        let fs_tree_logical = 0x8_000_u64;
        let root_dir_objectid = 256_u64;

        let mut sb = build_test_btrfs_superblock_with_single_chunk(
            primary_offset as u64,
            11,
            0,
            image_size as u64,
            0,
            2,
        );
        sb[0x50..0x58].copy_from_slice(&root_tree_logical.to_le_bytes());
        sb[0x80..0x88].copy_from_slice(&root_dir_objectid.to_le_bytes());
        sb[0x88..0x90].copy_from_slice(&1_u64.to_le_bytes());
        sb[0xC6] = 0;
        let checksum = crc32c::crc32c(&sb[0x20..super::BTRFS_SUPER_INFO_SIZE]);
        sb[0..4].copy_from_slice(&checksum.to_le_bytes());
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&sb);

        let root_leaf_offset = usize::try_from(root_tree_logical).expect("root tree offset fits");
        write_btrfs_leaf_header(&mut image, root_leaf_offset, root_tree_logical, 1, 1);
        let root_item_offset = 3000_u32;
        let root_item_size = 239_u32;
        write_btrfs_leaf_item(
            &mut image,
            root_leaf_offset,
            0,
            BTRFS_FS_TREE_OBJECTID,
            BTRFS_ITEM_ROOT_ITEM,
            0,
            root_item_offset,
            root_item_size,
        );
        let mut root_item =
            vec![0_u8; usize::try_from(root_item_size).expect("root item size fits")];
        root_item[168..176].copy_from_slice(&root_dir_objectid.to_le_bytes());
        root_item[176..184].copy_from_slice(&fs_tree_logical.to_le_bytes());
        let root_item_last = root_item.len() - 1;
        root_item[root_item_last] = 0;
        let root_data_start =
            root_leaf_offset + usize::try_from(root_item_offset).expect("root item offset fits");
        image[root_data_start..root_data_start + root_item.len()].copy_from_slice(&root_item);

        let fs_leaf_offset = usize::try_from(fs_tree_logical).expect("fs tree offset fits");
        write_btrfs_leaf_header(
            &mut image,
            fs_leaf_offset,
            fs_tree_logical,
            BTRFS_FS_TREE_OBJECTID,
            1,
        );
        let inode_item = BtrfsInodeItem {
            generation: 1,
            size: 4096,
            nbytes: 4096,
            nlink: 2,
            uid: 1000,
            gid: 1000,
            mode: 0o040_755,
            rdev: 0,
            atime_sec: 10,
            atime_nsec: 0,
            ctime_sec: 10,
            ctime_nsec: 0,
            mtime_sec: 10,
            mtime_nsec: 0,
            otime_sec: 10,
            otime_nsec: 0,
        };
        let inode_bytes = inode_item.to_bytes();
        let inode_data_offset = 3200_u32;
        write_btrfs_leaf_item(
            &mut image,
            fs_leaf_offset,
            0,
            root_dir_objectid,
            BTRFS_ITEM_INODE_ITEM,
            0,
            inode_data_offset,
            u32::try_from(inode_bytes.len()).expect("inode size fits"),
        );
        let inode_data_start =
            fs_leaf_offset + usize::try_from(inode_data_offset).expect("inode offset fits");
        image[inode_data_start..inode_data_start + inode_bytes.len()].copy_from_slice(&inode_bytes);

        image
    }

    fn encode_btrfs_dir_index_entry(name: &[u8], child_objectid: u64, file_type: u8) -> Vec<u8> {
        let mut entry = vec![0_u8; 30 + name.len()];
        entry[0..8].copy_from_slice(&child_objectid.to_le_bytes());
        entry[8] = BTRFS_ITEM_INODE_ITEM;
        entry[9..17].copy_from_slice(&0_u64.to_le_bytes());
        entry[17..25].copy_from_slice(&1_u64.to_le_bytes());
        entry[25..27].copy_from_slice(&0_u16.to_le_bytes());
        let name_len = u16::try_from(name.len()).expect("test name length should fit in u16");
        entry[27..29].copy_from_slice(&name_len.to_le_bytes());
        entry[29] = file_type;
        entry[30..30 + name.len()].copy_from_slice(name);
        entry
    }

    #[allow(clippy::too_many_lines)]
    fn build_test_btrfs_image_with_dir_index_entry() -> Vec<u8> {
        let image_size: usize = 512 * 1024;
        let mut image = vec![0_u8; image_size];
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let root_tree_logical = 0x4_000_u64;
        let fs_tree_logical = 0x8_000_u64;
        let root_dir_objectid = 256_u64;
        let child_objectid = 257_u64;

        let mut sb = build_test_btrfs_superblock_with_single_chunk(
            primary_offset as u64,
            11,
            0,
            image_size as u64,
            0,
            2,
        );
        sb[0x50..0x58].copy_from_slice(&root_tree_logical.to_le_bytes());
        sb[0x80..0x88].copy_from_slice(&root_dir_objectid.to_le_bytes());
        sb[0x88..0x90].copy_from_slice(&1_u64.to_le_bytes());
        sb[0xC6] = 0;
        let checksum = crc32c::crc32c(&sb[0x20..super::BTRFS_SUPER_INFO_SIZE]);
        sb[0..4].copy_from_slice(&checksum.to_le_bytes());
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&sb);

        let root_leaf_offset = usize::try_from(root_tree_logical).expect("root tree offset fits");
        write_btrfs_leaf_header(&mut image, root_leaf_offset, root_tree_logical, 1, 1);
        let root_item_offset = 3000_u32;
        let root_item_size = 239_u32;
        write_btrfs_leaf_item(
            &mut image,
            root_leaf_offset,
            0,
            BTRFS_FS_TREE_OBJECTID,
            BTRFS_ITEM_ROOT_ITEM,
            0,
            root_item_offset,
            root_item_size,
        );
        let mut root_item =
            vec![0_u8; usize::try_from(root_item_size).expect("root item size fits")];
        root_item[168..176].copy_from_slice(&root_dir_objectid.to_le_bytes());
        root_item[176..184].copy_from_slice(&fs_tree_logical.to_le_bytes());
        let root_item_last = root_item.len() - 1;
        root_item[root_item_last] = 0;
        let root_data_start =
            root_leaf_offset + usize::try_from(root_item_offset).expect("root item offset fits");
        image[root_data_start..root_data_start + root_item.len()].copy_from_slice(&root_item);

        let fs_leaf_offset = usize::try_from(fs_tree_logical).expect("fs tree offset fits");
        write_btrfs_leaf_header(
            &mut image,
            fs_leaf_offset,
            fs_tree_logical,
            BTRFS_FS_TREE_OBJECTID,
            3,
        );

        let root_inode = BtrfsInodeItem {
            generation: 1,
            size: 4096,
            nbytes: 4096,
            nlink: 2,
            uid: 1000,
            gid: 1000,
            mode: 0o040_755,
            rdev: 0,
            atime_sec: 10,
            atime_nsec: 0,
            ctime_sec: 10,
            ctime_nsec: 0,
            mtime_sec: 10,
            mtime_nsec: 0,
            otime_sec: 10,
            otime_nsec: 0,
        };
        let child_inode = BtrfsInodeItem {
            mode: 0o100_644,
            nlink: 1,
            size: 0,
            nbytes: 0,
            ..root_inode
        };

        let root_inode_bytes = root_inode.to_bytes();
        let dir_index_bytes = encode_btrfs_dir_index_entry(
            b"hello.txt",
            child_objectid,
            ffs_btrfs::BTRFS_FT_REG_FILE,
        );
        let child_inode_bytes = child_inode.to_bytes();

        let mut data_cursor = 16 * 1024;
        data_cursor -= root_inode_bytes.len();
        write_btrfs_leaf_item(
            &mut image,
            fs_leaf_offset,
            0,
            root_dir_objectid,
            BTRFS_ITEM_INODE_ITEM,
            0,
            u32::try_from(data_cursor).expect("root inode offset fits"),
            u32::try_from(root_inode_bytes.len()).expect("root inode size fits"),
        );
        image[fs_leaf_offset + data_cursor..fs_leaf_offset + data_cursor + root_inode_bytes.len()]
            .copy_from_slice(&root_inode_bytes);

        data_cursor -= dir_index_bytes.len();
        write_btrfs_leaf_item(
            &mut image,
            fs_leaf_offset,
            1,
            root_dir_objectid,
            ffs_btrfs::BTRFS_ITEM_DIR_INDEX,
            2,
            u32::try_from(data_cursor).expect("dir index offset fits"),
            u32::try_from(dir_index_bytes.len()).expect("dir index size fits"),
        );
        image[fs_leaf_offset + data_cursor..fs_leaf_offset + data_cursor + dir_index_bytes.len()]
            .copy_from_slice(&dir_index_bytes);

        data_cursor -= child_inode_bytes.len();
        write_btrfs_leaf_item(
            &mut image,
            fs_leaf_offset,
            2,
            child_objectid,
            BTRFS_ITEM_INODE_ITEM,
            0,
            u32::try_from(data_cursor).expect("child inode offset fits"),
            u32::try_from(child_inode_bytes.len()).expect("child inode size fits"),
        );
        image[fs_leaf_offset + data_cursor..fs_leaf_offset + data_cursor + child_inode_bytes.len()]
            .copy_from_slice(&child_inode_bytes);

        image
    }

    fn test_btrfs_chunk_entry(
        logical_start: u64,
        length: u64,
        physical_start: u64,
    ) -> ffs_ondisk::BtrfsChunkEntry {
        ffs_ondisk::BtrfsChunkEntry {
            key: ffs_ondisk::BtrfsKey {
                objectid: 0,
                item_type: 0,
                offset: logical_start,
            },
            length,
            owner: 0,
            stripe_len: 0,
            chunk_type: 0,
            io_align: 0,
            io_width: 0,
            sector_size: 4096,
            num_stripes: 1,
            sub_stripes: 1,
            stripes: vec![ffs_ondisk::BtrfsStripe {
                devid: 1,
                offset: physical_start,
                dev_uuid: [0_u8; 16],
            }],
        }
    }

    fn write_sparse_test_image(path: &std::path::Path, image: &[u8]) -> io::Result<()> {
        let mut file = std::fs::File::create(path)?;
        file.set_len(u64::try_from(image.len()).expect("test image length should fit into u64"))?;

        let mut run_start: Option<usize> = None;
        for (idx, byte) in image.iter().enumerate() {
            if *byte == 0 {
                if let Some(start) = run_start.take() {
                    file.seek(SeekFrom::Start(
                        u64::try_from(start).expect("run start should fit into u64"),
                    ))?;
                    file.write_all(&image[start..idx])?;
                }
            } else if run_start.is_none() {
                run_start = Some(idx);
            }
        }

        if let Some(start) = run_start {
            file.seek(SeekFrom::Start(
                u64::try_from(start).expect("run start should fit into u64"),
            ))?;
            file.write_all(&image[start..])?;
        }

        file.sync_all()
    }

    fn with_temp_image_path<T>(image: &[u8], f: impl FnOnce(PathBuf) -> T) -> T {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        path.push(format!(
            "ffs-cli-fsck-force-{}-{ts}-{count}.img",
            std::process::id()
        ));
        write_sparse_test_image(&path, image).expect("write test filesystem image");
        let result = f(path.clone());
        let _ = std::fs::remove_file(path);
        result
    }

    fn test_local_host_name() -> String {
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

    fn write_test_coordination_record(image: &std::path::Path, owner_host: &str) -> PathBuf {
        let record_path = repair_coordination_record_path(image);
        let record = RepairCoordinationRecord {
            policy: "single_host_only_v1".to_owned(),
            image_path: image.display().to_string(),
            owner_host: owner_host.to_owned(),
            owner_process_id: 4242,
            last_command: "repair".to_owned(),
            last_operation_id: "repair-coordination-test".to_owned(),
            recorded_at_ns: 7,
        };
        let mut bytes =
            serde_json::to_vec_pretty(&record).expect("coordination record should serialize");
        bytes.push(b'\n');
        std::fs::write(&record_path, bytes).expect("write coordination record");
        record_path
    }

    #[test]
    fn read_file_region_reads_exact_window() {
        let image: Vec<u8> = (0_u8..64).collect();
        with_temp_image_path(&image, |path| {
            let region = read_file_region(&path, 16, 8, "test window")
                .expect("region read should succeed for in-bounds window");
            assert_eq!(region, image[16..24]);
        });
    }

    #[test]
    fn read_file_region_rejects_out_of_bounds_window() {
        let image = vec![0_u8; 32];
        with_temp_image_path(&image, |path| {
            let err = read_file_region(&path, 24, 16, "test window")
                .expect_err("region read should fail for out-of-bounds window");
            let message = format!("{err:#}");
            assert!(
                message.contains("out of bounds"),
                "expected out-of-bounds error, got: {message}"
            );
        });
    }

    #[test]
    fn load_evidence_records_skips_invalid_lines_and_filters_by_event_type() {
        let ledger = concat!(
            "{\"timestamp_ns\":1,\"event_type\":\"corruption_detected\",\"block_group\":1}\n",
            "{not-json\n",
            "\n",
            "{\"timestamp_ns\":2,\"event_type\":\"repair_failed\",\"block_group\":2}\n",
            "{\"timestamp_ns\":3,\"event_type\":\"repair_failed\",\"block_group\":3}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records = load_evidence_records(&path, Some("repair_failed"), None, None)
                .expect("filtered evidence read should succeed");
            assert_eq!(records.len(), 2);
            assert!(
                records
                    .iter()
                    .all(|record| record.event_type == EvidenceEventType::RepairFailed)
            );
            assert_eq!(records[0].block_group, 2);
            assert_eq!(records[1].block_group, 3);
        });
    }

    #[test]
    fn load_evidence_records_tail_keeps_last_filtered_records() {
        let ledger = concat!(
            "{\"timestamp_ns\":1,\"event_type\":\"repair_failed\",\"block_group\":1}\n",
            "{\"timestamp_ns\":2,\"event_type\":\"corruption_detected\",\"block_group\":2}\n",
            "{\"timestamp_ns\":3,\"event_type\":\"repair_failed\",\"block_group\":3}\n",
            "{\"timestamp_ns\":4,\"event_type\":\"repair_failed\",\"block_group\":4}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records = load_evidence_records(&path, Some("repair_failed"), Some(2), None)
                .expect("tailed evidence read should succeed");
            assert_eq!(records.len(), 2);
            assert_eq!(records[0].timestamp_ns, 3);
            assert_eq!(records[1].timestamp_ns, 4);
            assert_eq!(records[0].block_group, 3);
            assert_eq!(records[1].block_group, 4);
        });
    }

    #[test]
    fn load_evidence_records_tail_zero_returns_empty() {
        let ledger = concat!(
            "{\"timestamp_ns\":1,\"event_type\":\"repair_failed\",\"block_group\":1}\n",
            "{\"timestamp_ns\":2,\"event_type\":\"repair_failed\",\"block_group\":2}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records = load_evidence_records(&path, Some("repair_failed"), Some(0), None)
                .expect("tail=0 evidence read should succeed");
            assert!(
                records.is_empty(),
                "tail=0 should suppress all returned records"
            );
        });
    }

    #[test]
    fn load_evidence_records_skips_non_utf8_lines() {
        let mut ledger = Vec::new();
        ledger.extend_from_slice(
            b"{\"timestamp_ns\":1,\"event_type\":\"repair_failed\",\"block_group\":1}\n",
        );
        ledger.extend_from_slice(&[0xFF, 0xFE, 0x00, b'\n']);
        ledger.extend_from_slice(
            b"{\"timestamp_ns\":2,\"event_type\":\"repair_failed\",\"block_group\":2}\n",
        );

        with_temp_image_path(&ledger, |path| {
            let records = load_evidence_records(&path, Some("repair_failed"), None, None)
                .expect("evidence read should tolerate non-utf8 torn lines");
            assert_eq!(records.len(), 2);
            assert_eq!(records[0].timestamp_ns, 1);
            assert_eq!(records[1].timestamp_ns, 2);
        });
    }

    #[test]
    fn load_evidence_records_preset_filters_multiple_types() {
        let ledger = concat!(
            "{\"timestamp_ns\":1,\"event_type\":\"wal_recovery\",\"block_group\":0}\n",
            "{\"timestamp_ns\":2,\"event_type\":\"corruption_detected\",\"block_group\":1}\n",
            "{\"timestamp_ns\":3,\"event_type\":\"txn_aborted\",\"block_group\":0}\n",
            "{\"timestamp_ns\":4,\"event_type\":\"serialization_conflict\",\"block_group\":0}\n",
            "{\"timestamp_ns\":5,\"event_type\":\"flush_batch\",\"block_group\":0}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            // replay-anomalies preset: wal_recovery + txn_aborted + serialization_conflict
            let records = load_evidence_records(&path, None, None, Some("replay-anomalies"))
                .expect("preset filter should work");
            assert_eq!(records.len(), 3);
            assert_eq!(records[0].event_type, EvidenceEventType::WalRecovery);
            assert_eq!(records[1].event_type, EvidenceEventType::TxnAborted);
            assert_eq!(
                records[2].event_type,
                EvidenceEventType::SerializationConflict
            );
        });
    }

    #[test]
    fn load_evidence_records_preset_repair_failures_selects_correctly() {
        let ledger = concat!(
            "{\"timestamp_ns\":1,\"event_type\":\"corruption_detected\",\"block_group\":1}\n",
            "{\"timestamp_ns\":2,\"event_type\":\"repair_attempted\",\"block_group\":1}\n",
            "{\"timestamp_ns\":3,\"event_type\":\"repair_failed\",\"block_group\":1}\n",
            "{\"timestamp_ns\":4,\"event_type\":\"wal_recovery\",\"block_group\":0}\n",
            "{\"timestamp_ns\":5,\"event_type\":\"scrub_cycle_complete\",\"block_group\":1}\n",
            "{\"timestamp_ns\":6,\"event_type\":\"repair_succeeded\",\"block_group\":1}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records = load_evidence_records(&path, None, None, Some("repair-failures"))
                .expect("repair-failures preset should work");
            assert_eq!(records.len(), 5);
            // wal_recovery should be excluded
            assert!(
                records
                    .iter()
                    .all(|r| r.event_type != EvidenceEventType::WalRecovery)
            );
        });
    }

    #[test]
    fn load_evidence_records_preset_pressure_transitions() {
        let ledger = concat!(
            "{\"timestamp_ns\":1,\"event_type\":\"backpressure_activated\",\"block_group\":0}\n",
            "{\"timestamp_ns\":2,\"event_type\":\"flush_batch\",\"block_group\":0}\n",
            "{\"timestamp_ns\":3,\"event_type\":\"durability_policy_changed\",\"block_group\":0}\n",
            "{\"timestamp_ns\":4,\"event_type\":\"refresh_policy_changed\",\"block_group\":1}\n",
            "{\"timestamp_ns\":5,\"event_type\":\"repair_failed\",\"block_group\":2}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records = load_evidence_records(&path, None, None, Some("pressure-transitions"))
                .expect("pressure-transitions preset should work");
            assert_eq!(records.len(), 4);
            // repair_failed should be excluded
            assert!(
                records
                    .iter()
                    .all(|r| r.event_type != EvidenceEventType::RepairFailed)
            );
        });
    }

    #[test]
    fn load_evidence_records_preset_contention_selects_correctly() {
        let ledger = concat!(
            "{\"timestamp_ns\":1,\"event_type\":\"merge_proof_checked\",\"block_group\":0}\n",
            "{\"timestamp_ns\":2,\"event_type\":\"merge_applied\",\"block_group\":1}\n",
            "{\"timestamp_ns\":3,\"event_type\":\"policy_switched\",\"block_group\":0}\n",
            "{\"timestamp_ns\":4,\"event_type\":\"repair_failed\",\"block_group\":2}\n",
            "{\"timestamp_ns\":5,\"event_type\":\"contention_sample\",\"block_group\":0}\n",
            "{\"timestamp_ns\":6,\"event_type\":\"merge_rejected\",\"block_group\":1}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records = load_evidence_records(&path, None, None, Some("contention"))
                .expect("contention preset should work");
            assert_eq!(records.len(), 5);
            assert!(
                records
                    .iter()
                    .all(|r| r.event_type != EvidenceEventType::RepairFailed)
            );
            assert_eq!(records[0].event_type, EvidenceEventType::MergeProofChecked);
            assert_eq!(records[1].event_type, EvidenceEventType::MergeApplied);
            assert_eq!(records[2].event_type, EvidenceEventType::PolicySwitched);
            assert_eq!(records[3].event_type, EvidenceEventType::ContentionSample);
            assert_eq!(records[4].event_type, EvidenceEventType::MergeRejected);
        });
    }

    #[test]
    fn load_evidence_records_preset_tail_keeps_last_matching_records() {
        let ledger = concat!(
            "{\"timestamp_ns\":1,\"event_type\":\"repair_failed\",\"block_group\":1}\n",
            "{\"timestamp_ns\":2,\"event_type\":\"wal_recovery\",\"block_group\":0}\n",
            "{\"timestamp_ns\":3,\"event_type\":\"repair_succeeded\",\"block_group\":1}\n",
            "{\"timestamp_ns\":4,\"event_type\":\"flush_batch\",\"block_group\":0}\n",
            "{\"timestamp_ns\":5,\"event_type\":\"scrub_cycle_complete\",\"block_group\":1}\n",
            "{\"timestamp_ns\":6,\"event_type\":\"durability_policy_changed\",\"block_group\":0}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records = load_evidence_records(&path, None, Some(2), Some("repair-failures"))
                .expect("preset+tail evidence read should succeed");
            assert_eq!(records.len(), 2);
            assert_eq!(records[0].timestamp_ns, 3);
            assert_eq!(records[1].timestamp_ns, 5);
            assert_eq!(records[0].event_type, EvidenceEventType::RepairSucceeded);
            assert_eq!(records[1].event_type, EvidenceEventType::ScrubCycleComplete);
        });
    }

    #[test]
    fn load_evidence_records_preset_tail_keeps_last_matching_records_for_remaining_ledger_presets()
    {
        let cases = [
            (
                "replay-anomalies",
                concat!(
                    "{\"timestamp_ns\":1,\"event_type\":\"wal_recovery\",\"block_group\":0}\n",
                    "{\"timestamp_ns\":2,\"event_type\":\"repair_failed\",\"block_group\":1}\n",
                    "{\"timestamp_ns\":3,\"event_type\":\"txn_aborted\",\"block_group\":0}\n",
                    "{\"timestamp_ns\":4,\"event_type\":\"flush_batch\",\"block_group\":0}\n",
                    "{\"timestamp_ns\":5,\"event_type\":\"serialization_conflict\",\"block_group\":0}\n",
                    "{\"timestamp_ns\":6,\"event_type\":\"repair_succeeded\",\"block_group\":1}\n",
                ),
                &[
                    EvidenceEventType::TxnAborted,
                    EvidenceEventType::SerializationConflict,
                ][..],
                &[3_u64, 5_u64][..],
            ),
            (
                "pressure-transitions",
                concat!(
                    "{\"timestamp_ns\":1,\"event_type\":\"backpressure_activated\",\"block_group\":0}\n",
                    "{\"timestamp_ns\":2,\"event_type\":\"repair_failed\",\"block_group\":1}\n",
                    "{\"timestamp_ns\":3,\"event_type\":\"flush_batch\",\"block_group\":0}\n",
                    "{\"timestamp_ns\":4,\"event_type\":\"refresh_policy_changed\",\"block_group\":1}\n",
                    "{\"timestamp_ns\":5,\"event_type\":\"repair_succeeded\",\"block_group\":1}\n",
                    "{\"timestamp_ns\":6,\"event_type\":\"durability_policy_changed\",\"block_group\":0}\n",
                ),
                &[
                    EvidenceEventType::RefreshPolicyChanged,
                    EvidenceEventType::DurabilityPolicyChanged,
                ][..],
                &[4_u64, 6_u64][..],
            ),
            (
                "contention",
                concat!(
                    "{\"timestamp_ns\":1,\"event_type\":\"merge_proof_checked\",\"block_group\":0}\n",
                    "{\"timestamp_ns\":2,\"event_type\":\"repair_failed\",\"block_group\":1}\n",
                    "{\"timestamp_ns\":3,\"event_type\":\"merge_applied\",\"block_group\":0}\n",
                    "{\"timestamp_ns\":4,\"event_type\":\"policy_switched\",\"block_group\":0}\n",
                    "{\"timestamp_ns\":5,\"event_type\":\"flush_batch\",\"block_group\":0}\n",
                    "{\"timestamp_ns\":6,\"event_type\":\"contention_sample\",\"block_group\":0}\n",
                ),
                &[
                    EvidenceEventType::PolicySwitched,
                    EvidenceEventType::ContentionSample,
                ][..],
                &[4_u64, 6_u64][..],
            ),
        ];

        for (preset, ledger, expected_types, expected_timestamps) in cases {
            with_temp_image_path(ledger.as_bytes(), |path| {
                let records = load_evidence_records(&path, None, Some(2), Some(preset))
                    .expect("preset+tail evidence read should succeed");
                assert_eq!(records.len(), 2, "preset {preset}");
                assert_eq!(
                    records
                        .iter()
                        .map(|record| record.timestamp_ns)
                        .collect::<Vec<_>>(),
                    expected_timestamps,
                    "preset {preset}"
                );
                assert_eq!(
                    records
                        .iter()
                        .map(|record| record.event_type)
                        .collect::<Vec<_>>(),
                    expected_types,
                    "preset {preset}"
                );
            });
        }
    }

    #[test]
    fn preset_event_types_returns_none_for_unknown() {
        use crate::cmd_evidence::{KNOWN_PRESETS, preset_event_types};
        assert!(preset_event_types("nonexistent").is_none());
        for name in KNOWN_PRESETS {
            assert!(
                preset_event_types(name).is_some(),
                "known preset {name} should return Some"
            );
        }
    }

    fn test_histogram(count: u64, sum: u64) -> EvidenceHistogramSnapshot {
        EvidenceHistogramSnapshot {
            buckets: vec![
                EvidenceHistogramBucket { le: 10, count: 1 },
                EvidenceHistogramBucket {
                    le: 100,
                    count: count.saturating_sub(1),
                },
            ],
            inf_count: 0,
            sum,
            count,
        }
    }

    #[test]
    fn load_metrics_report_metrics_preset_reads_bundle() {
        let bundle = serde_json::json!({
            "metrics": {
                "requests_total": 100,
                "requests_ok": 97,
                "requests_err": 3,
                "bytes_read": 8192,
                "requests_throttled": 4,
                "requests_shed": 1
            },
            "cache": {
                "cache_hits": 80,
                "cache_misses": 20,
                "cache_evictions": 5,
                "cache_dirty_count": 9,
                "writeback_queue_depth": 3,
                "hit_rate": 0.8
            },
            "mvcc": {
                "active_snapshots": 2,
                "commit_rate": 15.0,
                "conflict_rate": 0.125,
                "abort_rate": 0.125,
                "version_chain_max_length": 6,
                "prune_throughput": 42.0,
                "commit_attempts_total": 80,
                "commit_successes_total": 70,
                "conflicts_total": 10,
                "aborts_total": 10,
                "pruned_versions_total": 120,
                "commit_latency_us": {
                    "buckets": [{"le": 10, "count": 1}, {"le": 100, "count": 7}],
                    "inf_count": 0,
                    "sum": 800,
                    "count": 8
                },
                "conflict_resolution_latency_us": {
                    "buckets": [{"le": 10, "count": 1}, {"le": 100, "count": 3}],
                    "inf_count": 0,
                    "sum": 250,
                    "count": 4
                }
            },
            "repair_live": {
                "groups_scrubbed": 12,
                "corruption_detected": 2,
                "decode_attempts": 5,
                "decode_successes": 4,
                "symbol_refresh_count": 8,
                "symbol_staleness_max_seconds": 12.5
            }
        });

        with_temp_image_path(
            serde_json::to_string_pretty(&bundle)
                .expect("serialize bundle")
                .as_bytes(),
            |path| {
                let report =
                    load_metrics_report_for_test(&path, "metrics").expect("load metrics report");
                let value = serde_json::to_value(report).expect("serialize report");
                assert_eq!(value["preset"], "metrics");
                assert_eq!(value["metrics"]["requests_total"], 100);
                assert_eq!(value["cache"]["cache_hits"], 80);
                assert_eq!(value["mvcc"]["commit_attempts_total"], 80);
                assert_eq!(value["repair_live"]["decode_successes"], 4);
                assert_eq!(value["analyses"]["repair_freshness"], "fresh");
                assert_eq!(value["analyses"]["mvcc_contention_level"], "high");
            },
        );
    }

    #[test]
    fn load_metrics_report_cache_preset_reads_direct_snapshot() {
        let snapshot = CacheRuntimeMetricsSnapshot {
            cache_hits: 90,
            cache_misses: 10,
            cache_evictions: 3,
            cache_dirty_count: 40,
            writeback_queue_depth: 12,
            hit_rate: 0.9,
        };
        with_temp_image_path(
            serde_json::to_string_pretty(&snapshot)
                .expect("serialize cache snapshot")
                .as_bytes(),
            |path| {
                let report =
                    load_metrics_report_for_test(&path, "cache").expect("load cache report");
                let value = serde_json::to_value(report).expect("serialize report");
                assert_eq!(value["preset"], "cache");
                assert_eq!(value["snapshot"]["cache_hits"], 90);
                assert_eq!(value["miss_rate"], 0.1);
                assert_eq!(value["dirty_pressure"], "high");
                assert_eq!(value["writeback_pressure"], "queued");
            },
        );
    }

    #[test]
    fn load_metrics_report_cache_preset_reads_bundle_member() {
        let bundle = serde_json::json!({
            "cache": {
                "cache_hits": 120,
                "cache_misses": 30,
                "cache_evictions": 7,
                "cache_dirty_count": 16,
                "writeback_queue_depth": 6,
                "hit_rate": 0.8
            }
        });

        with_temp_image_path(
            serde_json::to_string_pretty(&bundle)
                .expect("serialize bundle")
                .as_bytes(),
            |path| {
                let report =
                    load_metrics_report_for_test(&path, "cache").expect("load cache report");
                let value = serde_json::to_value(report).expect("serialize report");
                assert_eq!(value["preset"], "cache");
                assert_eq!(value["snapshot"]["cache_hits"], 120);
                assert_eq!(value["snapshot"]["cache_misses"], 30);
                assert_eq!(value["miss_rate"], 0.2);
                assert_eq!(value["dirty_pressure"], "elevated");
                assert_eq!(value["writeback_pressure"], "active");
            },
        );
    }

    #[test]
    fn load_metrics_report_mvcc_preset_reads_direct_snapshot() {
        let snapshot = EvidenceMvccRuntimeMetricsSnapshot {
            active_snapshots: 3,
            commit_rate: 10.0,
            conflict_rate: 0.05,
            abort_rate: 0.02,
            version_chain_max_length: 4,
            prune_throughput: 11.0,
            commit_attempts_total: 50,
            commit_successes_total: 45,
            conflicts_total: 2,
            aborts_total: 1,
            pruned_versions_total: 99,
            commit_latency_us: test_histogram(5, 200),
            conflict_resolution_latency_us: test_histogram(2, 50),
        };
        with_temp_image_path(
            serde_json::to_string_pretty(&snapshot)
                .expect("serialize mvcc snapshot")
                .as_bytes(),
            |path| {
                let report = load_metrics_report_for_test(&path, "mvcc").expect("load mvcc report");
                let value = serde_json::to_value(report).expect("serialize report");
                assert_eq!(value["preset"], "mvcc");
                assert_eq!(value["snapshot"]["active_snapshots"], 3);
                assert_eq!(value["commit_success_rate"], 0.9);
                assert_eq!(value["contention_level"], "elevated");
            },
        );
    }

    #[test]
    fn load_metrics_report_mvcc_preset_reads_bundle_member() {
        let bundle = serde_json::json!({
            "mvcc": {
                "active_snapshots": 4,
                "commit_rate": 12.0,
                "conflict_rate": 0.2,
                "abort_rate": 0.05,
                "version_chain_max_length": 9,
                "prune_throughput": 17.0,
                "commit_attempts_total": 100,
                "commit_successes_total": 72,
                "conflicts_total": 18,
                "aborts_total": 5,
                "pruned_versions_total": 144,
                "commit_latency_us": {
                    "buckets": [{"le": 10, "count": 2}, {"le": 100, "count": 6}],
                    "inf_count": 0,
                    "sum": 420,
                    "count": 8
                },
                "conflict_resolution_latency_us": {
                    "buckets": [{"le": 10, "count": 1}, {"le": 100, "count": 4}],
                    "inf_count": 0,
                    "sum": 190,
                    "count": 5
                }
            }
        });

        with_temp_image_path(
            serde_json::to_string_pretty(&bundle)
                .expect("serialize bundle")
                .as_bytes(),
            |path| {
                let report = load_metrics_report_for_test(&path, "mvcc").expect("load mvcc report");
                let value = serde_json::to_value(report).expect("serialize report");
                assert_eq!(value["preset"], "mvcc");
                assert_eq!(value["snapshot"]["active_snapshots"], 4);
                assert_eq!(value["snapshot"]["commit_attempts_total"], 100);
                assert_eq!(value["commit_success_rate"], 0.72);
                assert_eq!(value["contention_level"], "high");
            },
        );
    }

    #[test]
    fn load_metrics_report_repair_live_reads_direct_snapshot() {
        let snapshot = RepairRuntimeMetricsSnapshot {
            groups_scrubbed: 20,
            corruption_detected: 5,
            decode_attempts: 8,
            decode_successes: 6,
            symbol_refresh_count: 14,
            symbol_staleness_max_seconds: 120.0,
        };
        with_temp_image_path(
            serde_json::to_string_pretty(&snapshot)
                .expect("serialize repair snapshot")
                .as_bytes(),
            |path| {
                let report = load_metrics_report_for_test(&path, "repair-live")
                    .expect("load repair-live report");
                let value = serde_json::to_value(report).expect("serialize report");
                assert_eq!(value["preset"], "repair-live");
                assert_eq!(value["snapshot"]["groups_scrubbed"], 20);
                assert_eq!(value["decode_success_rate"], 0.75);
                assert_eq!(value["freshness"], "aging");
            },
        );
    }

    #[test]
    fn load_metrics_report_repair_live_reads_bundle_member() {
        let bundle = serde_json::json!({
            "repair_live": {
                "groups_scrubbed": 15,
                "corruption_detected": 3,
                "decode_attempts": 9,
                "decode_successes": 3,
                "symbol_refresh_count": 11,
                "symbol_staleness_max_seconds": 601.0
            }
        });

        with_temp_image_path(
            serde_json::to_string_pretty(&bundle)
                .expect("serialize bundle")
                .as_bytes(),
            |path| {
                let report = load_metrics_report_for_test(&path, "repair-live")
                    .expect("load repair-live report");
                let value = serde_json::to_value(report).expect("serialize report");
                assert_eq!(value["preset"], "repair-live");
                assert_eq!(value["snapshot"]["groups_scrubbed"], 15);
                assert_eq!(value["snapshot"]["decode_successes"], 3);
                assert_eq!(value["decode_success_rate"], 0.333_333_333_333_333_3);
                assert_eq!(value["freshness"], "stale");
            },
        );
    }

    #[test]
    fn load_metrics_report_rejects_unsupported_preset() {
        with_temp_image_path(b"{}", |path| {
            let err = load_metrics_report_for_test(&path, "not-a-real-preset")
                .expect_err("unsupported metrics preset should fail");
            assert!(
                err.to_string().contains(
                    "metrics report requested for unsupported preset 'not-a-real-preset'"
                )
            );
        });
    }

    #[test]
    fn evidence_metrics_preset_rejects_summary_flag() {
        let bundle = serde_json::json!({
            "metrics": {
                "requests_total": 1,
                "requests_ok": 1,
                "requests_err": 0,
                "bytes_read": 64,
                "requests_throttled": 0,
                "requests_shed": 0
            }
        });

        with_temp_image_path(
            serde_json::to_string_pretty(&bundle)
                .expect("serialize bundle")
                .as_bytes(),
            |path| {
                let err = crate::cmd_evidence::evidence_cmd(
                    &path,
                    false,
                    None,
                    None,
                    Some("metrics"),
                    true,
                )
                .expect_err("metrics preset should reject --summary");
                assert!(
                    err.to_string()
                        .contains("--summary is only supported for ledger-backed evidence presets")
                );
            },
        );
    }

    #[test]
    fn evidence_metrics_preset_rejects_tail_flag() {
        let bundle = serde_json::json!({
            "metrics": {
                "requests_total": 1,
                "requests_ok": 1,
                "requests_err": 0,
                "bytes_read": 64,
                "requests_throttled": 0,
                "requests_shed": 0
            }
        });

        with_temp_image_path(
            serde_json::to_string_pretty(&bundle)
                .expect("serialize bundle")
                .as_bytes(),
            |path| {
                let err = crate::cmd_evidence::evidence_cmd(
                    &path,
                    false,
                    None,
                    Some(5),
                    Some("metrics"),
                    false,
                )
                .expect_err("metrics preset should reject --tail");
                assert!(
                    err.to_string()
                        .contains("--tail is only supported for ledger-backed evidence presets")
                );
            },
        );
    }

    #[test]
    fn evidence_summary_aggregates_correctly() {
        let ledger = concat!(
            "{\"timestamp_ns\":100,\"event_type\":\"wal_recovery\",\"block_group\":0,",
            "\"wal_recovery\":{\"commits_replayed\":5,\"versions_replayed\":10,",
            "\"records_discarded\":2,\"wal_valid_bytes\":1000,\"wal_total_bytes\":1024,",
            "\"used_checkpoint\":false}}\n",
            "{\"timestamp_ns\":200,\"event_type\":\"txn_aborted\",\"block_group\":0}\n",
            "{\"timestamp_ns\":300,\"event_type\":\"corruption_detected\",\"block_group\":1,",
            "\"corruption\":{\"blocks_affected\":3,\"corruption_kind\":\"crc\",",
            "\"severity\":\"error\",\"detail\":\"bad crc\"}}\n",
            "{\"timestamp_ns\":400,\"event_type\":\"repair_succeeded\",\"block_group\":1}\n",
            "{\"timestamp_ns\":500,\"event_type\":\"backpressure_activated\",\"block_group\":0}\n",
            "{\"timestamp_ns\":600,\"event_type\":\"flush_batch\",\"block_group\":0,",
            "\"flush_batch\":{\"blocks_flushed\":42,\"bytes_written\":172032,",
            "\"flush_duration_us\":500}}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records =
                load_evidence_records(&path, None, None, None).expect("load should succeed");
            let summary = crate::cmd_evidence::build_summary_for_test(&records, None);
            assert_eq!(summary.total_records, 6);
            assert_eq!(summary.time_span_ns, Some((100, 600)));
            assert_eq!(summary.block_groups_seen, vec![1]);

            let replay = summary.replay_summary.as_ref().expect("replay summary");
            assert_eq!(replay.recovery_count, 1);
            assert_eq!(replay.total_commits_replayed, 5);
            assert_eq!(replay.total_records_discarded, 2);
            assert_eq!(replay.aborts, 1);

            let repair = summary.repair_summary.as_ref().expect("repair summary");
            assert_eq!(repair.corruptions_detected, 1);
            assert_eq!(repair.repairs_succeeded, 1);
            assert_eq!(repair.total_blocks_corrupt, 3);

            let pressure = summary.pressure_summary.as_ref().expect("pressure summary");
            assert_eq!(pressure.backpressure_events, 1);
            assert_eq!(pressure.flush_batches, 1);
            assert_eq!(pressure.total_blocks_flushed, 42);
        });
    }

    #[test]
    fn evidence_summary_json_schema_has_required_fields() {
        let ledger = "{\"timestamp_ns\":100,\"event_type\":\"repair_failed\",\"block_group\":1}\n";
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records =
                load_evidence_records(&path, None, None, None).expect("load should succeed");
            let summary =
                crate::cmd_evidence::build_summary_for_test(&records, Some("repair-failures"));
            let json_val = serde_json::to_value(&summary).expect("serialize summary");
            // Required top-level fields
            assert!(json_val.get("total_records").is_some());
            assert!(json_val.get("event_type_counts").is_some());
            assert!(json_val.get("block_groups_seen").is_some());
            assert!(json_val.get("preset").is_some());
            // Conditional fields omitted when empty
            assert!(json_val.get("replay_summary").is_none());
            assert!(json_val.get("pressure_summary").is_none());
        });
    }

    #[test]
    fn evidence_summary_normalizes_block_groups() {
        let ledger = concat!(
            "{\"timestamp_ns\":100,\"event_type\":\"repair_failed\",\"block_group\":7}\n",
            "{\"timestamp_ns\":200,\"event_type\":\"repair_succeeded\",\"block_group\":0}\n",
            "{\"timestamp_ns\":300,\"event_type\":\"repair_attempted\",\"block_group\":3}\n",
            "{\"timestamp_ns\":400,\"event_type\":\"scrub_cycle_complete\",\"block_group\":7}\n",
            "{\"timestamp_ns\":500,\"event_type\":\"corruption_detected\",\"block_group\":3}\n",
        );
        with_temp_image_path(ledger.as_bytes(), |path| {
            let records =
                load_evidence_records(&path, None, None, None).expect("load should succeed");
            let summary =
                crate::cmd_evidence::build_summary_for_test(&records, Some("repair-failures"));
            assert_eq!(summary.block_groups_seen, vec![3, 7]);
        });
    }

    #[test]
    fn evidence_record_json_schema_stability() {
        // Verify that EvidenceRecord JSON contains expected top-level keys.
        let json_str = r#"{"timestamp_ns":1,"event_type":"repair_failed","block_group":2}"#;
        let record: EvidenceRecord = serde_json::from_str(json_str).expect("parse");
        let round_trip = serde_json::to_value(&record).expect("serialize");
        assert!(round_trip.get("timestamp_ns").is_some());
        assert!(round_trip.get("event_type").is_some());
        assert!(round_trip.get("block_group").is_some());
        // event_type is serialized as snake_case
        assert_eq!(round_trip["event_type"], "repair_failed");
    }

    #[test]
    fn build_ext4_group_info_reads_descriptors_from_disk_regions() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        let sb =
            super::Ext4Superblock::parse_from_image(&image).expect("parse test ext4 superblock");
        let expected_groups = usize::try_from(sb.groups_count()).expect("groups_count fits usize");

        with_temp_image_path(&image, |path| {
            let groups = build_ext4_group_info(&path, &sb).expect("build ext4 group info");
            assert_eq!(groups.len(), expected_groups);
            assert_eq!(groups[0].group, 0);
        });
    }

    #[test]
    fn read_ext4_group_desc_from_path_reads_single_descriptor_window() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        let sb =
            super::Ext4Superblock::parse_from_image(&image).expect("parse test ext4 superblock");

        with_temp_image_path(&image, |path| {
            let (desc, raw) = read_ext4_group_desc_from_path(&path, &sb, 0)
                .expect("read ext4 group descriptor from path");
            assert_eq!(desc.inode_table, 5);
            assert_eq!(raw.len(), usize::from(sb.group_desc_size()));
        });
    }

    #[test]
    fn read_ext4_inode_from_path_reads_inode_window() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        let sb =
            super::Ext4Superblock::parse_from_image(&image).expect("parse test ext4 superblock");

        with_temp_image_path(&image, |path| {
            let (inode, raw) = read_ext4_inode_from_path(&path, &sb, ffs_types::InodeNumber(2))
                .expect("read ext4 inode from path");
            assert_eq!(raw.len(), usize::from(sb.inode_size));
            assert_eq!(inode.mode, 0);
        });
    }

    #[test]
    fn log_format_parser_supports_human_and_json() {
        assert_eq!(
            LogFormat::parse("human").expect("parse human"),
            LogFormat::Human
        );
        assert_eq!(
            LogFormat::parse("JSON").expect("parse json"),
            LogFormat::Json
        );
        assert!(LogFormat::parse("invalid").is_err());
    }

    #[test]
    fn json_log_serializes_domain_fields() {
        let _guard = log_contract_guard();
        let buffer = SharedLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(true)
            .with_max_level(tracing::Level::INFO)
            .with_writer(buffer.clone())
            .finish();

        let dispatch = tracing::Dispatch::new(subscriber);
        let _default = tracing::dispatcher::set_default(&dispatch);
        tracing::callsite::rebuild_interest_cache();

        info!(
            target: "ffs::test",
            event_name = "transaction_commit",
            txn_id = 42_u64,
            write_set_size = 3_u64,
            duration_us = 900_u64,
            "transaction_commit"
        );

        let json = parse_first_json_line(&buffer);
        assert_eq!(json["event_name"], "transaction_commit");
        assert_eq!(json["txn_id"], 42);
        assert_eq!(json["write_set_size"], 3);
        assert_eq!(json["duration_us"], 900);
        assert_eq!(json["target"], "ffs::test");
        assert_eq!(json["level"], "INFO");
    }

    #[test]
    fn json_log_preserves_span_context() {
        let _guard = log_contract_guard();
        let buffer = SharedLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(true)
            .with_max_level(tracing::Level::INFO)
            .with_writer(buffer.clone())
            .finish();

        let dispatch = tracing::Dispatch::new(subscriber);
        let _default = tracing::dispatcher::set_default(&dispatch);
        tracing::callsite::rebuild_interest_cache();

        {
            let span = info_span!("mount", image = "/tmp/ext4.img", mode = "ro");
            let _guard = span.enter();
            info!(target: "ffs::test", action = "mount_begin", "mount_begin");
        }

        let json = parse_first_json_line(&buffer);
        assert_eq!(json["action"], "mount_begin");
        assert_eq!(json["span"]["name"], "mount");
        assert_eq!(json["span"]["image"], "/tmp/ext4.img");
        assert_eq!(json["span"]["mode"], "ro");
    }

    #[test]
    fn ext4_mount_replay_mode_is_persistent_for_rw() {
        assert_eq!(ext4_mount_replay_mode(true), Ext4JournalReplayMode::Apply);
        assert_eq!(
            ext4_mount_replay_mode(false),
            Ext4JournalReplayMode::SimulateOverlay
        );
    }

    #[test]
    fn mount_runtime_config_rejects_timeout_for_standard_mode() {
        let err = MountRuntimeConfig {
            mode: MountRuntimeMode::Standard,
            managed_unmount_timeout_secs: Some(15),
        }
        .validate()
        .expect_err("standard mode with managed timeout should fail");
        let message = format!("{err:#}");
        assert!(
            message.contains(
                "--managed-unmount-timeout-secs requires --runtime-mode managed or per-core"
            ),
            "unexpected validation message: {message}"
        );
    }

    #[test]
    fn mount_runtime_config_accepts_managed_timeout() {
        let cfg = MountRuntimeConfig {
            mode: MountRuntimeMode::Managed,
            managed_unmount_timeout_secs: Some(45),
        }
        .validate()
        .expect("managed mode with timeout should validate");
        assert_eq!(cfg.managed_unmount_timeout_secs(), 45);
    }

    #[test]
    fn mount_runtime_mode_scenario_ids_are_stable() {
        assert_eq!(
            MountRuntimeMode::Standard.scenario_id(false),
            "cli_mount_runtime_standard_ro"
        );
        assert_eq!(
            MountRuntimeMode::Managed.scenario_id(true),
            "cli_mount_runtime_managed_rw"
        );
        assert_eq!(
            MountRuntimeMode::PerCore.scenario_id(false),
            "cli_mount_runtime_per_core_ro"
        );
    }

    #[test]
    fn mount_operation_id_reflects_runtime_mode() {
        let image = PathBuf::from("/tmp/fs.img");
        let mountpoint = PathBuf::from("/tmp/mnt");
        let standard = mount_operation_id(&image, &mountpoint, MountRuntimeMode::Standard, false);
        let managed = mount_operation_id(&image, &mountpoint, MountRuntimeMode::Managed, false);
        assert_ne!(
            standard, managed,
            "operation ids should differ when runtime mode differs"
        );
    }

    #[test]
    fn mount_runtime_selection_log_contains_required_fields() {
        let _guard = log_contract_guard();
        let buffer = SharedLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(true)
            .with_max_level(tracing::Level::INFO)
            .with_writer(buffer.clone())
            .finish();

        let dispatch = tracing::Dispatch::new(subscriber);
        let _default = tracing::dispatcher::set_default(&dispatch);
        tracing::callsite::rebuild_interest_cache();

        let runtime = MountRuntimeConfig {
            mode: MountRuntimeMode::Standard,
            managed_unmount_timeout_secs: None,
        }
        .validate()
        .expect("runtime config should validate");
        log_mount_runtime_selected(
            "mount-op-test",
            runtime.mode.scenario_id(false),
            runtime,
            false,
            true,
            false,
        );

        let json = parse_first_json_line(&buffer);
        assert_eq!(json["operation_id"], "mount-op-test");
        assert_eq!(json["scenario_id"], "cli_mount_runtime_standard_ro");
        assert_eq!(json["outcome"], "runtime_mode_selected");
        assert_eq!(json["runtime_mode"], "standard");
        assert_eq!(json["managed_unmount_timeout_secs"], 30);
    }

    #[test]
    fn mount_runtime_rejection_log_contains_error_class_fields() {
        let _guard = log_contract_guard();
        let buffer = SharedLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(true)
            .with_max_level(tracing::Level::ERROR)
            .with_writer(buffer.clone())
            .finish();

        let dispatch = tracing::Dispatch::new(subscriber);
        let _default = tracing::dispatcher::set_default(&dispatch);
        tracing::callsite::rebuild_interest_cache();

        let runtime = MountRuntimeConfig {
            mode: MountRuntimeMode::Managed,
            managed_unmount_timeout_secs: Some(12),
        }
        .validate()
        .expect("managed runtime config should validate");
        log_mount_runtime_rejected(
            "mount-op-reject",
            runtime.mode.scenario_id(true),
            runtime,
            true,
            "runtime_mode_unavailable",
            "managed mode not yet wired",
        );

        let json = parse_first_json_line(&buffer);
        assert_eq!(json["operation_id"], "mount-op-reject");
        assert_eq!(json["scenario_id"], "cli_mount_runtime_managed_rw");
        assert_eq!(json["outcome"], "runtime_mode_rejected");
        assert_eq!(json["error_class"], "runtime_mode_unavailable");
        assert_eq!(json["reason"], "managed mode not yet wired");
        assert_eq!(json["runtime_mode"], "managed");
    }

    #[test]
    fn repair_coordination_claim_log_contains_required_fields() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let _guard = log_contract_guard();
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        let buffer = SharedLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(true)
            .with_max_level(tracing::Level::INFO)
            .with_writer(buffer.clone())
            .finish();

        let dispatch = tracing::Dispatch::new(subscriber);
        let _default = tracing::dispatcher::set_default(&dispatch);
        tracing::callsite::rebuild_interest_cache();

        with_temp_image_path(&image, |path| {
            let decision = coordinate_repair_write_access(
                "ffs::test",
                REPAIR_COORDINATION_SCENARIO_REPAIR,
                "repair",
                &path,
                true,
            );
            assert!(decision.writes_allowed);
        });

        let json = parse_first_json_line(&buffer);
        assert_eq!(json["scenario_id"], REPAIR_COORDINATION_SCENARIO_REPAIR);
        assert_eq!(json["outcome"], "applied");
        assert_eq!(json["error_class"], "none");
        assert_eq!(json["command"], "repair");
        assert_eq!(json["level"], "INFO");
        assert_eq!(json["target"], "ffs::test");
        assert!(
            json["operation_id"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        assert!(
            json["coordination_file"]
                .as_str()
                .is_some_and(|value| { value.ends_with(".ffs-repair-owner.json") })
        );
        assert_eq!(json["local_host"], json["owner_host"]);
    }

    #[test]
    fn repair_coordination_rejection_log_contains_error_class_fields() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let _guard = log_contract_guard();
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        let buffer = SharedLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(true)
            .with_max_level(tracing::Level::INFO)
            .with_writer(buffer.clone())
            .finish();

        let dispatch = tracing::Dispatch::new(subscriber);
        let _default = tracing::dispatcher::set_default(&dispatch);
        tracing::callsite::rebuild_interest_cache();

        with_temp_image_path(&image, |path| {
            write_test_coordination_record(&path, "remote-host");
            let decision = coordinate_repair_write_access(
                "ffs::test",
                REPAIR_COORDINATION_SCENARIO_REPAIR,
                "repair",
                &path,
                true,
            );
            assert!(!decision.writes_allowed);
        });

        let json = parse_first_json_line(&buffer);
        assert_eq!(json["scenario_id"], REPAIR_COORDINATION_SCENARIO_REPAIR);
        assert_eq!(json["outcome"], "rejected");
        assert_eq!(json["error_class"], "multi_host_unsupported");
        assert_eq!(json["command"], "repair");
        assert_eq!(json["level"], "WARN");
        assert_eq!(json["target"], "ffs::test");
        assert_eq!(json["owner_host"], "remote-host");
        assert!(
            json["operation_id"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
    }

    #[test]
    fn mount_cmd_managed_mode_fails_at_image_open_not_validation() {
        let _guard = log_contract_guard();
        let err = mount_cmd(
            &PathBuf::from("/definitely/missing.img"),
            &PathBuf::from("/definitely/missing-mountpoint"),
            false,
            false,
            false,
            MountRuntimeMode::Managed,
            Some(30),
        )
        .expect_err("managed mode with missing image should fail at open");
        let message = format!("{err:#}");
        // Managed mode is wired — the error should come from image open, not
        // from a "not wired" rejection.
        assert!(
            message.contains("failed to open filesystem image"),
            "expected image-open failure, got: {message}"
        );
    }

    #[test]
    fn mount_cmd_per_core_mode_fails_at_image_open_not_validation() {
        let _guard = log_contract_guard();
        let err = mount_cmd(
            &PathBuf::from("/definitely/missing.img"),
            &PathBuf::from("/definitely/missing-mountpoint"),
            false,
            false,
            false,
            MountRuntimeMode::PerCore,
            None,
        )
        .expect_err("per-core mode with missing image should fail at open");
        let message = format!("{err:#}");
        assert!(
            message.contains("failed to open filesystem image"),
            "expected image-open failure, got: {message}"
        );
    }

    #[test]
    fn mount_rejects_subvol_flag() {
        let err = validate_btrfs_mount_selection(Some("home"), None)
            .expect_err("subvol mount should be rejected until supported");
        let message = err.to_string();
        assert!(
            message.contains("not yet supported"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn mount_rejects_snapshot_flag() {
        let err = validate_btrfs_mount_selection(None, Some("snap-1"))
            .expect_err("snapshot mount should be rejected until supported");
        let message = err.to_string();
        assert!(
            message.contains("not yet supported"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn cli_parses_mount_per_core_runtime() {
        let cli = Cli::try_parse_from([
            "ffs",
            "mount",
            "--runtime-mode",
            "per-core",
            "/tmp/fs.img",
            "/tmp/mnt",
        ])
        .expect("mount command with per-core runtime should parse");

        match cli.command {
            Command::Mount {
                runtime_mode,
                managed_unmount_timeout_secs,
                ..
            } => {
                assert_eq!(runtime_mode, MountRuntimeMode::PerCore);
                assert_eq!(managed_unmount_timeout_secs, None);
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn mount_default_mode_is_standard_and_stable() {
        // Verify that the default runtime mode for mount is Standard.
        // This is a stability contract: changing the default is a breaking change.
        let cli = Cli::try_parse_from(["ffs", "mount", "/img", "/mnt"])
            .expect("mount should parse with defaults");
        match cli.command {
            Command::Mount { runtime_mode, .. } => {
                assert_eq!(
                    runtime_mode,
                    MountRuntimeMode::Standard,
                    "default mount runtime mode must remain standard"
                );
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn mount_native_flag_defaults_to_false() {
        let cli = Cli::try_parse_from(["ffs", "mount", "/img", "/mnt"])
            .expect("mount should parse with defaults");
        match cli.command {
            Command::Mount { native, .. } => {
                assert!(!native, "default native flag must be false (compat mode)");
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn mount_native_flag_opt_in() {
        let cli = Cli::try_parse_from(["ffs", "mount", "--native", "/img", "/mnt"])
            .expect("mount with --native should parse");
        match cli.command {
            Command::Mount { native, .. } => {
                assert!(native, "--native flag should set native to true");
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn mount_runtime_config_default_timeout_is_30s() {
        let cfg = MountRuntimeConfig {
            mode: MountRuntimeMode::Managed,
            managed_unmount_timeout_secs: None,
        }
        .validate()
        .expect("managed without explicit timeout should validate");
        assert_eq!(
            cfg.managed_unmount_timeout_secs(),
            30,
            "default managed unmount timeout must be 30s"
        );
    }

    #[test]
    fn mount_per_core_config_rejects_timeout_with_standard() {
        // Per-core timeout is also rejected in standard mode (same validation path).
        let err = MountRuntimeConfig {
            mode: MountRuntimeMode::Standard,
            managed_unmount_timeout_secs: Some(42),
        }
        .validate()
        .expect_err("standard mode with timeout should be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("--managed-unmount-timeout-secs requires"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn mount_per_core_config_accepts_timeout() {
        let cfg = MountRuntimeConfig {
            mode: MountRuntimeMode::PerCore,
            managed_unmount_timeout_secs: Some(60),
        }
        .validate()
        .expect("per-core mode with timeout should validate");
        assert_eq!(cfg.managed_unmount_timeout_secs(), 60);
    }

    #[test]
    fn mount_scenario_ids_cover_all_mode_rw_combinations() {
        // Exhaustive check that all (mode, rw) pairs produce distinct scenario IDs.
        let mut ids = std::collections::HashSet::new();
        for mode in [
            MountRuntimeMode::Standard,
            MountRuntimeMode::Managed,
            MountRuntimeMode::PerCore,
        ] {
            for rw in [false, true] {
                let id = mode.scenario_id(rw);
                assert!(
                    ids.insert(id),
                    "duplicate scenario_id: {id} for mode={mode:?} rw={rw}"
                );
            }
        }
        assert_eq!(ids.len(), 6, "expected 6 distinct scenario IDs");
    }

    #[test]
    fn mount_operation_ids_differ_by_rw() {
        let image = PathBuf::from("/tmp/fs.img");
        let mountpoint = PathBuf::from("/tmp/mnt");
        let ro = mount_operation_id(&image, &mountpoint, MountRuntimeMode::Standard, false);
        let rw = mount_operation_id(&image, &mountpoint, MountRuntimeMode::Standard, true);
        assert_ne!(
            ro, rw,
            "operation ids should differ when read_write differs"
        );
    }

    #[test]
    fn cli_parses_info_command_with_all_flags() {
        let cli = Cli::try_parse_from([
            "ffs",
            "info",
            "--groups",
            "--mvcc",
            "--repair",
            "--journal",
            "--json",
            "/tmp/fs.img",
        ])
        .expect("info command should parse");

        match cli.command {
            Command::Info {
                image,
                groups,
                mvcc,
                repair,
                journal,
                json,
            } => {
                assert_eq!(image, std::path::PathBuf::from("/tmp/fs.img"));
                assert!(groups);
                assert!(mvcc);
                assert!(repair);
                assert!(journal);
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Info { .. }),
                "expected info command"
            ),
        }
    }

    #[test]
    fn cli_parses_inspect_with_json() {
        let cli = Cli::try_parse_from(["ffs", "inspect", "--json", "/tmp/fs.img"])
            .expect("inspect command should parse");

        match cli.command {
            Command::Inspect { image, json, .. } => {
                assert_eq!(image, PathBuf::from("/tmp/fs.img"));
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Inspect { .. }),
                "expected inspect command"
            ),
        }
    }

    #[test]
    fn cli_parses_mvcc_stats_minimal() {
        let cli = Cli::try_parse_from(["ffs", "mvcc-stats", "/tmp/fs.img"])
            .expect("mvcc-stats command should parse");

        match cli.command {
            Command::MvccStats { image, json } => {
                assert_eq!(image, PathBuf::from("/tmp/fs.img"));
                assert!(!json);
            }
            other => assert!(
                matches!(other, Command::MvccStats { .. }),
                "expected mvcc-stats command"
            ),
        }
    }

    #[test]
    fn cli_parses_info_command_without_optional_flags() {
        let cli = Cli::try_parse_from(["ffs", "info", "/tmp/fs.img"])
            .expect("minimal info command should parse");

        match cli.command {
            Command::Info {
                groups,
                mvcc,
                repair,
                journal,
                json,
                ..
            } => {
                assert!(!groups);
                assert!(!mvcc);
                assert!(!repair);
                assert!(!journal);
                assert!(!json);
            }
            other => assert!(
                matches!(other, Command::Info { .. }),
                "expected info command"
            ),
        }
    }

    #[test]
    fn cli_parses_dump_superblock_command_with_flags() {
        let cli = Cli::try_parse_from([
            "ffs",
            "dump",
            "superblock",
            "--json",
            "--hex",
            "/tmp/fs.img",
        ])
        .expect("dump superblock command should parse");

        match cli.command {
            Command::Dump { command } => match command {
                DumpCommand::Superblock { image, json, hex } => {
                    assert_eq!(image, std::path::PathBuf::from("/tmp/fs.img"));
                    assert!(json);
                    assert!(hex);
                }
                other => assert!(
                    matches!(other, DumpCommand::Superblock { .. }),
                    "expected dump superblock command"
                ),
            },
            other => assert!(
                matches!(other, Command::Dump { .. }),
                "expected dump command"
            ),
        }
    }

    #[test]
    fn cli_parses_dump_group_command() {
        let cli = Cli::try_parse_from(["ffs", "dump", "group", "7", "/tmp/fs.img"])
            .expect("dump group command should parse");

        match cli.command {
            Command::Dump { command } => match command {
                DumpCommand::Group {
                    group,
                    image,
                    json,
                    hex,
                } => {
                    assert_eq!(group, 7);
                    assert_eq!(image, std::path::PathBuf::from("/tmp/fs.img"));
                    assert!(!json);
                    assert!(!hex);
                }
                other => assert!(
                    matches!(other, DumpCommand::Group { .. }),
                    "expected dump group command"
                ),
            },
            other => assert!(
                matches!(other, Command::Dump { .. }),
                "expected dump command"
            ),
        }
    }

    #[test]
    fn cli_parses_dump_inode_command_with_flags() {
        let cli = Cli::try_parse_from([
            "ffs",
            "dump",
            "inode",
            "42",
            "--json",
            "--hex",
            "/tmp/fs.img",
        ])
        .expect("dump inode command should parse");

        match cli.command {
            Command::Dump { command } => match command {
                DumpCommand::Inode {
                    inode,
                    image,
                    json,
                    hex,
                } => {
                    assert_eq!(inode, 42);
                    assert_eq!(image, PathBuf::from("/tmp/fs.img"));
                    assert!(json);
                    assert!(hex);
                }
                other => assert!(
                    matches!(other, DumpCommand::Inode { .. }),
                    "expected dump inode command"
                ),
            },
            other => assert!(
                matches!(other, Command::Dump { .. }),
                "expected dump command"
            ),
        }
    }

    #[test]
    fn cli_parses_dump_extents_command_minimal() {
        let cli = Cli::try_parse_from(["ffs", "dump", "extents", "11", "/tmp/fs.img"])
            .expect("dump extents command should parse");

        match cli.command {
            Command::Dump { command } => match command {
                DumpCommand::Extents {
                    inode,
                    image,
                    json,
                    hex,
                } => {
                    assert_eq!(inode, 11);
                    assert_eq!(image, PathBuf::from("/tmp/fs.img"));
                    assert!(!json);
                    assert!(!hex);
                }
                other => assert!(
                    matches!(other, DumpCommand::Extents { .. }),
                    "expected dump extents command"
                ),
            },
            other => assert!(
                matches!(other, Command::Dump { .. }),
                "expected dump command"
            ),
        }
    }

    #[test]
    fn cli_parses_dump_dir_command_with_hex() {
        let cli = Cli::try_parse_from(["ffs", "dump", "dir", "2", "--hex", "/tmp/fs.img"])
            .expect("dump dir command should parse");

        match cli.command {
            Command::Dump { command } => match command {
                DumpCommand::Dir {
                    inode,
                    image,
                    json,
                    hex,
                } => {
                    assert_eq!(inode, 2);
                    assert_eq!(image, PathBuf::from("/tmp/fs.img"));
                    assert!(!json);
                    assert!(hex);
                }
                other => assert!(
                    matches!(other, DumpCommand::Dir { .. }),
                    "expected dump dir command"
                ),
            },
            other => assert!(
                matches!(other, Command::Dump { .. }),
                "expected dump command"
            ),
        }
    }

    #[test]
    fn cli_parses_fsck_with_all_flags() {
        let cli = Cli::try_parse_from([
            "ffs",
            "fsck",
            "-r",
            "-f",
            "-v",
            "--block-group",
            "3",
            "--json",
            "/tmp/fs.img",
        ])
        .expect("fsck command should parse");

        match cli.command {
            Command::Fsck {
                image,
                repair,
                force,
                verbose,
                block_group,
                json,
            } => {
                assert_eq!(image, std::path::PathBuf::from("/tmp/fs.img"));
                assert!(repair);
                assert!(force);
                assert!(verbose);
                assert_eq!(block_group, Some(3));
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Fsck { .. }),
                "expected fsck command"
            ),
        }
    }

    #[test]
    fn cli_parses_fsck_minimal() {
        let cli = Cli::try_parse_from(["ffs", "fsck", "/tmp/fs.img"]).expect("fsck should parse");

        match cli.command {
            Command::Fsck {
                image,
                repair,
                force,
                verbose,
                block_group,
                json,
            } => {
                assert_eq!(image, std::path::PathBuf::from("/tmp/fs.img"));
                assert!(!repair);
                assert!(!force);
                assert!(!verbose);
                assert_eq!(block_group, None);
                assert!(!json);
            }
            other => assert!(
                matches!(other, Command::Fsck { .. }),
                "expected fsck command"
            ),
        }
    }

    #[test]
    fn cli_parses_repair_with_all_flags() {
        let cli = Cli::try_parse_from([
            "ffs",
            "repair",
            "--full-scrub",
            "--block-group",
            "9",
            "--rebuild-symbols",
            "--verify-only",
            "--max-threads",
            "4",
            "--json",
            "/tmp/fs.img",
        ])
        .expect("repair command should parse");

        match cli.command {
            Command::Repair {
                image,
                full_scrub,
                block_group,
                rebuild_symbols,
                verify_only,
                max_threads,
                json,
            } => {
                assert_eq!(image, std::path::PathBuf::from("/tmp/fs.img"));
                assert!(full_scrub);
                assert_eq!(block_group, Some(9));
                assert!(rebuild_symbols);
                assert!(verify_only);
                assert_eq!(max_threads, Some(4));
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Repair { .. }),
                "expected repair command"
            ),
        }
    }

    #[test]
    fn cli_parses_repair_minimal() {
        let cli =
            Cli::try_parse_from(["ffs", "repair", "/tmp/fs.img"]).expect("repair should parse");

        match cli.command {
            Command::Repair {
                image,
                full_scrub,
                block_group,
                rebuild_symbols,
                verify_only,
                max_threads,
                json,
            } => {
                assert_eq!(image, std::path::PathBuf::from("/tmp/fs.img"));
                assert!(!full_scrub);
                assert_eq!(block_group, None);
                assert!(!rebuild_symbols);
                assert!(!verify_only);
                assert_eq!(max_threads, None);
                assert!(!json);
            }
            other => assert!(
                matches!(other, Command::Repair { .. }),
                "expected repair command"
            ),
        }
    }

    #[test]
    fn cli_parses_mount_with_all_flags() {
        let cli = Cli::try_parse_from([
            "ffs",
            "mount",
            "--runtime-mode",
            "standard",
            "--allow-other",
            "--rw",
            "/tmp/fs.img",
            "/tmp/mnt",
        ])
        .expect("mount command should parse");

        match cli.command {
            Command::Mount {
                image,
                mountpoint,
                runtime_mode,
                managed_unmount_timeout_secs,
                allow_other,
                rw,
                native,
                ..
            } => {
                assert_eq!(image, PathBuf::from("/tmp/fs.img"));
                assert_eq!(mountpoint, PathBuf::from("/tmp/mnt"));
                assert_eq!(runtime_mode, MountRuntimeMode::Standard);
                assert_eq!(managed_unmount_timeout_secs, None);
                assert!(allow_other);
                assert!(rw);
                assert!(!native);
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn cli_parses_mount_minimal() {
        let cli = Cli::try_parse_from(["ffs", "mount", "/tmp/fs.img", "/tmp/mnt"])
            .expect("mount command should parse");

        match cli.command {
            Command::Mount {
                image,
                mountpoint,
                runtime_mode,
                managed_unmount_timeout_secs,
                allow_other,
                rw,
                native,
                ..
            } => {
                assert_eq!(image, PathBuf::from("/tmp/fs.img"));
                assert_eq!(mountpoint, PathBuf::from("/tmp/mnt"));
                assert_eq!(runtime_mode, MountRuntimeMode::Standard);
                assert_eq!(managed_unmount_timeout_secs, None);
                assert!(!allow_other);
                assert!(!rw);
                assert!(!native);
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn cli_parses_mount_managed_runtime_with_timeout() {
        let cli = Cli::try_parse_from([
            "ffs",
            "mount",
            "--runtime-mode",
            "managed",
            "--managed-unmount-timeout-secs",
            "42",
            "/tmp/fs.img",
            "/tmp/mnt",
        ])
        .expect("mount command with managed runtime should parse");

        match cli.command {
            Command::Mount {
                image,
                mountpoint,
                runtime_mode,
                managed_unmount_timeout_secs,
                allow_other,
                rw,
                native,
                ..
            } => {
                assert_eq!(image, PathBuf::from("/tmp/fs.img"));
                assert_eq!(mountpoint, PathBuf::from("/tmp/mnt"));
                assert_eq!(runtime_mode, MountRuntimeMode::Managed);
                assert_eq!(managed_unmount_timeout_secs, Some(42));
                assert!(!allow_other);
                assert!(!rw);
                assert!(!native);
            }
            other => assert!(
                matches!(other, Command::Mount { .. }),
                "expected mount command"
            ),
        }
    }

    #[test]
    fn cli_parses_scrub_with_json() {
        let cli = Cli::try_parse_from(["ffs", "scrub", "--json", "/tmp/fs.img"])
            .expect("scrub command should parse");

        match cli.command {
            Command::Scrub { image, json } => {
                assert_eq!(image, PathBuf::from("/tmp/fs.img"));
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Scrub { .. }),
                "expected scrub command"
            ),
        }
    }

    #[test]
    fn cli_parses_scrub_minimal() {
        let cli = Cli::try_parse_from(["ffs", "scrub", "/tmp/fs.img"]).expect("scrub should parse");

        match cli.command {
            Command::Scrub { image, json } => {
                assert_eq!(image, PathBuf::from("/tmp/fs.img"));
                assert!(!json);
            }
            other => assert!(
                matches!(other, Command::Scrub { .. }),
                "expected scrub command"
            ),
        }
    }

    #[test]
    fn cli_parses_parity_with_json() {
        let cli =
            Cli::try_parse_from(["ffs", "parity", "--json"]).expect("parity command should parse");

        match cli.command {
            Command::Parity { json } => {
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Parity { .. }),
                "expected parity command"
            ),
        }
    }

    #[test]
    fn cli_parses_parity_minimal() {
        let cli = Cli::try_parse_from(["ffs", "parity"]).expect("parity command should parse");

        match cli.command {
            Command::Parity { json } => {
                assert!(!json);
            }
            other => assert!(
                matches!(other, Command::Parity { .. }),
                "expected parity command"
            ),
        }
    }

    #[test]
    fn cli_parses_evidence_with_all_flags() {
        let cli = Cli::try_parse_from([
            "ffs",
            "evidence",
            "--json",
            "--event-type",
            "repair_succeeded",
            "--tail",
            "25",
            "/tmp/evidence.jsonl",
        ])
        .expect("evidence command should parse");

        match cli.command {
            Command::Evidence {
                ledger,
                json,
                event_type,
                tail,
                preset,
                summary,
            } => {
                assert_eq!(ledger, PathBuf::from("/tmp/evidence.jsonl"));
                assert!(json);
                assert_eq!(event_type.as_deref(), Some("repair_succeeded"));
                assert_eq!(tail, Some(25));
                assert_eq!(preset, None);
                assert!(!summary);
            }
            other => assert!(
                matches!(other, Command::Evidence { .. }),
                "expected evidence command"
            ),
        }
    }

    #[test]
    fn cli_parses_evidence_minimal() {
        let cli = Cli::try_parse_from(["ffs", "evidence", "/tmp/evidence.jsonl"])
            .expect("evidence command should parse");

        match cli.command {
            Command::Evidence {
                ledger,
                json,
                event_type,
                tail,
                preset,
                summary,
            } => {
                assert_eq!(ledger, PathBuf::from("/tmp/evidence.jsonl"));
                assert!(!json);
                assert_eq!(event_type, None);
                assert_eq!(tail, None);
                assert_eq!(preset, None);
                assert!(!summary);
            }
            other => assert!(
                matches!(other, Command::Evidence { .. }),
                "expected evidence command"
            ),
        }
    }

    #[test]
    fn cli_parses_evidence_with_preset() {
        let cli = Cli::try_parse_from([
            "ffs",
            "evidence",
            "--preset",
            "replay-anomalies",
            "--summary",
            "/tmp/evidence.jsonl",
        ])
        .expect("evidence command should parse");

        match cli.command {
            Command::Evidence {
                ledger,
                json,
                event_type,
                tail,
                preset,
                summary,
            } => {
                assert_eq!(ledger, PathBuf::from("/tmp/evidence.jsonl"));
                assert!(!json);
                assert_eq!(event_type, None);
                assert_eq!(tail, None);
                assert_eq!(preset.as_deref(), Some("replay-anomalies"));
                assert!(summary);
            }
            other => assert!(
                matches!(other, Command::Evidence { .. }),
                "expected evidence command"
            ),
        }
    }

    #[test]
    fn cli_parses_evidence_preset_repair_failures() {
        let cli = Cli::try_parse_from([
            "ffs",
            "evidence",
            "--preset",
            "repair-failures",
            "--json",
            "/tmp/evidence.jsonl",
        ])
        .expect("evidence command should parse");

        match cli.command {
            Command::Evidence { preset, json, .. } => {
                assert_eq!(preset.as_deref(), Some("repair-failures"));
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Evidence { .. }),
                "expected evidence command"
            ),
        }
    }

    #[test]
    fn cli_parses_evidence_preset_pressure_transitions() {
        let cli = Cli::try_parse_from([
            "ffs",
            "evidence",
            "--preset",
            "pressure-transitions",
            "--tail",
            "10",
            "/tmp/evidence.jsonl",
        ])
        .expect("evidence command should parse");

        match cli.command {
            Command::Evidence { preset, tail, .. } => {
                assert_eq!(preset.as_deref(), Some("pressure-transitions"));
                assert_eq!(tail, Some(10));
            }
            other => assert!(
                matches!(other, Command::Evidence { .. }),
                "expected evidence command"
            ),
        }
    }

    #[test]
    fn cli_parses_evidence_preset_contention() {
        let cli = Cli::try_parse_from([
            "ffs",
            "evidence",
            "--preset",
            "contention",
            "--summary",
            "/tmp/evidence.jsonl",
        ])
        .expect("evidence command should parse");

        match cli.command {
            Command::Evidence {
                ledger,
                preset,
                summary,
                ..
            } => {
                assert_eq!(ledger, PathBuf::from("/tmp/evidence.jsonl"));
                assert_eq!(preset.as_deref(), Some("contention"));
                assert!(summary);
            }
            other => assert!(
                matches!(other, Command::Evidence { .. }),
                "expected evidence command"
            ),
        }
    }

    #[test]
    fn cli_parses_evidence_preset_metrics() {
        let cli = Cli::try_parse_from([
            "ffs",
            "evidence",
            "--preset",
            "metrics",
            "--json",
            "/tmp/metrics.json",
        ])
        .expect("evidence metrics command should parse");

        match cli.command {
            Command::Evidence {
                ledger,
                preset,
                json,
                ..
            } => {
                assert_eq!(ledger, PathBuf::from("/tmp/metrics.json"));
                assert_eq!(preset.as_deref(), Some("metrics"));
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Evidence { .. }),
                "expected evidence command"
            ),
        }
    }

    #[test]
    fn cli_parses_evidence_preset_cache() {
        let cli = Cli::try_parse_from([
            "ffs",
            "evidence",
            "--preset",
            "cache",
            "--json",
            "/tmp/cache-metrics.json",
        ])
        .expect("evidence cache command should parse");

        match cli.command {
            Command::Evidence {
                ledger,
                preset,
                json,
                ..
            } => {
                assert_eq!(ledger, PathBuf::from("/tmp/cache-metrics.json"));
                assert_eq!(preset.as_deref(), Some("cache"));
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Evidence { .. }),
                "expected evidence command"
            ),
        }
    }

    #[test]
    fn cli_parses_evidence_preset_mvcc() {
        let cli = Cli::try_parse_from([
            "ffs",
            "evidence",
            "--preset",
            "mvcc",
            "--json",
            "/tmp/mvcc-metrics.json",
        ])
        .expect("evidence mvcc command should parse");

        match cli.command {
            Command::Evidence {
                ledger,
                preset,
                json,
                ..
            } => {
                assert_eq!(ledger, PathBuf::from("/tmp/mvcc-metrics.json"));
                assert_eq!(preset.as_deref(), Some("mvcc"));
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Evidence { .. }),
                "expected evidence command"
            ),
        }
    }

    #[test]
    fn cli_parses_evidence_preset_repair_live() {
        let cli = Cli::try_parse_from([
            "ffs",
            "evidence",
            "--preset",
            "repair-live",
            "--json",
            "/tmp/repair-live-metrics.json",
        ])
        .expect("evidence repair-live command should parse");

        match cli.command {
            Command::Evidence {
                ledger,
                preset,
                json,
                ..
            } => {
                assert_eq!(ledger, PathBuf::from("/tmp/repair-live-metrics.json"));
                assert_eq!(preset.as_deref(), Some("repair-live"));
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Evidence { .. }),
                "expected evidence command"
            ),
        }
    }

    #[test]
    fn cli_parses_mkfs_with_all_flags() {
        let cli = Cli::try_parse_from([
            "ffs",
            "mkfs",
            "--size-mb",
            "128",
            "--block-size",
            "2048",
            "--label",
            "testvol",
            "--json",
            "/tmp/new.img",
        ])
        .expect("mkfs command should parse");

        match cli.command {
            Command::Mkfs {
                output,
                size_mb,
                block_size,
                label,
                json,
            } => {
                assert_eq!(output, PathBuf::from("/tmp/new.img"));
                assert_eq!(size_mb, 128);
                assert_eq!(block_size, 2048);
                assert_eq!(label, "testvol");
                assert!(json);
            }
            other => assert!(
                matches!(other, Command::Mkfs { .. }),
                "expected mkfs command"
            ),
        }
    }

    #[test]
    fn cli_parses_mkfs_minimal_uses_defaults() {
        let cli = Cli::try_parse_from(["ffs", "mkfs", "/tmp/new.img"])
            .expect("mkfs command should parse");

        match cli.command {
            Command::Mkfs {
                output,
                size_mb,
                block_size,
                label,
                json,
            } => {
                assert_eq!(output, PathBuf::from("/tmp/new.img"));
                assert_eq!(size_mb, 64);
                assert_eq!(block_size, 4096);
                assert_eq!(label, "frankenfs");
                assert!(!json);
            }
            other => assert!(
                matches!(other, Command::Mkfs { .. }),
                "expected mkfs command"
            ),
        }
    }

    #[test]
    fn cli_rejects_mount_without_mountpoint() {
        let result = Cli::try_parse_from(["ffs", "mount", "/tmp/fs.img"]);
        assert!(result.is_err(), "mount requires an image and mountpoint");
    }

    #[test]
    fn cli_rejects_scrub_without_image() {
        let result = Cli::try_parse_from(["ffs", "scrub"]);
        assert!(result.is_err(), "scrub requires an image path");
    }

    #[test]
    fn cli_rejects_parity_with_unexpected_positional() {
        let result = Cli::try_parse_from(["ffs", "parity", "/tmp/extra"]);
        assert!(result.is_err(), "parity should not accept positional args");
    }

    #[test]
    fn cli_rejects_evidence_non_numeric_tail() {
        let result = Cli::try_parse_from([
            "ffs",
            "evidence",
            "--tail",
            "not-a-number",
            "/tmp/evidence.jsonl",
        ]);
        assert!(result.is_err(), "evidence --tail must be numeric");
    }

    #[test]
    fn cli_rejects_mkfs_non_numeric_size_mb() {
        let result =
            Cli::try_parse_from(["ffs", "mkfs", "--size-mb", "sixty-four", "/tmp/new.img"]);
        assert!(result.is_err(), "mkfs --size-mb must be numeric");
    }

    #[test]
    fn mkfs_cmd_rejects_size_mb_overflow() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        let mut output = std::env::temp_dir();
        output.push(format!("ffs-cli-mkfs-overflow-{}-{ts}", std::process::id()));
        let too_large = u64::MAX / (1024 * 1024) + 1;

        let err = super::mkfs_cmd_with_program(
            &output,
            too_large,
            1024,
            "overflow",
            false,
            std::path::Path::new("mkfs.ext4"),
        )
        .expect_err("oversized mkfs requests should be rejected");
        let message = format!("{err:#}");
        assert!(
            message.contains("size_mb too large"),
            "expected overflow guardrail, got: {message}"
        );
        assert!(
            !output.exists(),
            "overflow check should run before creating the image file"
        );
    }

    #[test]
    fn mkfs_cmd_rejects_dash_prefixed_output() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        let output = PathBuf::from(format!("-ffs-cli-mkfs-dash-{}-{ts}", std::process::id()));

        let err = super::mkfs_cmd_with_program(
            &output,
            8,
            1024,
            "dash",
            false,
            std::path::Path::new("mkfs.ext4"),
        )
        .expect_err("dash-prefixed output should be rejected");
        let message = format!("{err:#}");
        assert!(
            message.contains("must not start with '-'"),
            "expected dash-prefixed output guardrail, got: {message}"
        );
        assert!(
            !output.exists(),
            "dash-prefixed output guardrail should run before creating the image file"
        );
    }

    #[test]
    fn mkfs_cmd_rejects_existing_output_without_truncation() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        let mut output = std::env::temp_dir();
        output.push(format!("ffs-cli-mkfs-exists-{}-{ts}", std::process::id()));

        let payload = b"already-here";
        std::fs::write(&output, payload).expect("seed existing output");

        let err = super::mkfs_cmd_with_program(
            &output,
            8,
            1024,
            "exists",
            false,
            std::path::Path::new("mkfs.ext4"),
        )
        .expect_err("existing output path should be rejected");
        let message = format!("{err:#}");
        assert!(
            message.contains("output file already exists"),
            "expected existing-output guardrail, got: {message}"
        );
        assert_eq!(
            std::fs::metadata(&output)
                .expect("stat existing output")
                .len(),
            payload.len() as u64,
            "existing output must not be truncated"
        );

        let _ = std::fs::remove_file(&output);
    }

    #[test]
    fn mkfs_cmd_preserves_output_image_when_mkfs_ext4_fails() {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();

        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "ffs-cli-mkfs-failure-{}-{ts}-{count}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).expect("create temporary mkfs test directory");

        let mut fake_mkfs = dir.clone();
        fake_mkfs.push("mkfs.ext4");
        std::fs::write(
            &fake_mkfs,
            "#!/bin/sh\nprintf 'simulated mkfs failure\\n' >&2\nexit 1\n",
        )
        .expect("write fake mkfs.ext4");
        let mut perms = std::fs::metadata(&fake_mkfs)
            .expect("stat fake mkfs.ext4")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_mkfs, perms).expect("chmod fake mkfs.ext4");

        let mut output = dir.clone();
        output.push("preserved.img");

        let err = super::mkfs_cmd_with_program(&output, 8, 1024, "failtest", false, &fake_mkfs)
            .expect_err("fake mkfs.ext4 failure should bubble up");
        let message = format!("{err:#}");
        assert!(
            message.contains("Preserved partial image"),
            "expected preserved-image guidance, got: {message}"
        );
        assert!(
            message.contains(&output.display().to_string()),
            "expected output path in error, got: {message}"
        );
        assert!(
            output.exists(),
            "mkfs failure must leave the sparse image in place"
        );
        assert_eq!(
            std::fs::metadata(&output)
                .expect("stat preserved output image")
                .len(),
            8 * 1024 * 1024,
            "preserved image should retain the requested size"
        );

        let _ = std::fs::remove_file(&output);
        let _ = std::fs::remove_file(&fake_mkfs);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn repair_worker_limit_defaults_to_single() {
        let (workers, capped) = repair_worker_limit(None);
        assert_eq!(workers, 1);
        assert_eq!(capped, None);
    }

    #[test]
    fn partition_scrub_range_covers_exact_range() {
        let ranges = partition_scrub_range(super::BlockNumber(10), 11, 3);
        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges[0], (super::BlockNumber(10), 4));
        assert_eq!(ranges[1], (super::BlockNumber(14), 4));
        assert_eq!(ranges[2], (super::BlockNumber(18), 3));
    }

    #[test]
    fn merge_scrub_reports_accumulates_counts() {
        let merged = merge_scrub_reports(vec![
            super::ScrubReport {
                findings: Vec::new(),
                blocks_scanned: 10,
                blocks_corrupt: 2,
                blocks_io_error: 1,
            },
            super::ScrubReport {
                findings: Vec::new(),
                blocks_scanned: 7,
                blocks_corrupt: 0,
                blocks_io_error: 3,
            },
        ]);
        assert_eq!(merged.blocks_scanned, 17);
        assert_eq!(merged.blocks_corrupt, 2);
        assert_eq!(merged.blocks_io_error, 4);
    }

    #[test]
    fn ext4_clean_state_detection_matches_expected_flags() {
        assert!(ext4_appears_clean_state(0x0001));
        assert!(!ext4_appears_clean_state(0x0000));
        assert!(!ext4_appears_clean_state(0x0001 | 0x0002));
        assert!(!ext4_appears_clean_state(0x0001 | 0x0004));
    }

    #[test]
    fn summarize_repair_staleness_reports_zero_for_empty_input() {
        let summary = summarize_repair_staleness(&[]);
        assert_eq!(summary.total, 0);
        assert_eq!(summary.fresh, 0);
        assert_eq!(summary.stale, 0);
        assert_eq!(summary.untracked, 0);
    }

    #[test]
    fn summarize_repair_staleness_counts_mixed_states() {
        let staleness = vec![
            (0, Ext4RepairStaleness::Fresh),
            (1, Ext4RepairStaleness::Stale),
            (2, Ext4RepairStaleness::Untracked),
            (3, Ext4RepairStaleness::Fresh),
            (4, Ext4RepairStaleness::Stale),
        ];
        let summary = summarize_repair_staleness(&staleness);
        assert_eq!(summary.total, 5);
        assert_eq!(summary.fresh, 2);
        assert_eq!(summary.stale, 2);
        assert_eq!(summary.untracked, 1);
    }

    #[test]
    fn summarize_repair_staleness_counts_states_regardless_of_group_ids() {
        let staleness = vec![
            (42, Ext4RepairStaleness::Stale),
            (7, Ext4RepairStaleness::Fresh),
            (42, Ext4RepairStaleness::Fresh),
            (999, Ext4RepairStaleness::Untracked),
            (1, Ext4RepairStaleness::Stale),
        ];
        let summary = summarize_repair_staleness(&staleness);
        assert_eq!(summary.total, 5);
        assert_eq!(summary.fresh, 2);
        assert_eq!(summary.stale, 2);
        assert_eq!(summary.untracked, 1);
    }

    #[test]
    fn build_info_output_ext4_repair_metrics_fallback_sets_limitation() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);

        with_temp_image_path(&image, |path| {
            let cx = super::cli_cx();
            let open_opts = super::OpenOptions {
                ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
                ..super::OpenOptions::default()
            };
            let open_fs = super::OpenFs::open_with_options(&cx, &path, &open_opts)
                .expect("open ext4 image for info repair fallback test");

            // Keep `open_fs` valid but force the probe path to fail.
            let missing_path = path.with_extension("missing");
            let output = build_info_output(
                &missing_path,
                &cx,
                &open_fs,
                InfoCommandOptions {
                    sections: InfoSections::empty().with_repair(true),
                    json: false,
                },
            )
            .expect("build info output with repair section");

            let repair = output.repair.expect("repair section should be present");
            assert!(!repair.metrics_available);
            assert_eq!(
                repair.note,
                "live ext4 repair metrics unavailable (see limitations)"
            );
            assert_eq!(repair.groups_total, None);
            assert_eq!(repair.groups_fresh, None);
            assert_eq!(repair.groups_stale, None);
            assert_eq!(repair.groups_untracked, None);
            assert!(output.limitations.iter().any(|limitation| {
                limitation.contains("repair metrics probe failed for ext4 image")
            }));
        });
    }

    #[test]
    fn build_info_output_btrfs_groups_reports_chunk_layout() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let mut image = vec![0_u8; 2 * 1024 * 1024];
        let sb = build_test_btrfs_superblock_with_single_chunk(
            primary_offset as u64,
            11,
            0x0,
            0x10000,
            0x20000,
            1 | 4, // DATA|METADATA
        );
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&sb);

        with_temp_image_path(&image, |path| {
            let cx = super::cli_cx();
            let open_fs =
                super::OpenFs::open_with_options(&cx, &path, &super::OpenOptions::default())
                    .expect("open btrfs image for info groups test");

            let output = build_info_output(
                &path,
                &cx,
                &open_fs,
                InfoCommandOptions {
                    sections: InfoSections::empty().with_groups(true),
                    json: false,
                },
            )
            .expect("build info output with btrfs groups");

            let groups = output.groups.expect("groups section should be present");
            match groups {
                super::GroupsInfoOutput::Btrfs { entries } => {
                    assert_eq!(entries.len(), 1);
                    let chunk = &entries[0];
                    assert_eq!(chunk.chunk_index, 0);
                    assert_eq!(chunk.logical_start, 0);
                    assert_eq!(chunk.logical_end_inclusive, 0x0_FFFF);
                    assert_eq!(chunk.logical_bytes, 0x10000);
                    assert_eq!(chunk.chunk_type_raw, 5);
                    assert_eq!(chunk.chunk_type_flags, vec!["DATA", "METADATA"]);
                    assert_eq!(chunk.stripe_count, 1);
                    assert_eq!(chunk.stripes.len(), 1);
                    assert_eq!(chunk.stripes[0].devid, 1);
                    assert_eq!(chunk.stripes[0].physical_start, 0x20000);
                    assert_eq!(chunk.stripes[0].physical_end_inclusive, 0x2_FFFF);
                }
                other @ super::GroupsInfoOutput::Ext4 { .. } => assert!(
                    matches!(other, super::GroupsInfoOutput::Btrfs { .. }),
                    "expected btrfs groups output"
                ),
            }

            assert!(!output.limitations.iter().any(|limitation| {
                limitation.contains("--groups is currently implemented for ext4 images only")
            }));
        });
    }

    #[test]
    fn build_dump_group_output_btrfs_returns_chunk_mapping() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let mut image = vec![0_u8; 2 * 1024 * 1024];
        let sb = build_test_btrfs_superblock_with_single_chunk(
            primary_offset as u64,
            11,
            0x0,
            0x10000,
            0x20000,
            1 | 2, // DATA|SYSTEM
        );
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&sb);

        with_temp_image_path(&image, |path| {
            let output = super::build_dump_group_output(&path, 0, true)
                .expect("build dump group output for btrfs image");
            assert_eq!(output.filesystem, "btrfs");
            assert_eq!(output.group, 0);
            assert!(output.descriptor.is_none());
            assert!(output.raw_hex.is_none());
            assert!(
                output
                    .limitations
                    .iter()
                    .any(|limitation| limitation.contains("raw hex for btrfs chunk dump"))
            );

            let chunk = output
                .btrfs_chunk
                .expect("btrfs chunk should be present in dump output");
            assert_eq!(chunk.chunk_index, 0);
            assert_eq!(chunk.logical_start, 0);
            assert_eq!(chunk.logical_end_inclusive, 0x0_FFFF);
            assert_eq!(chunk.logical_bytes, 0x10000);
            assert_eq!(chunk.chunk_type_flags, vec!["DATA", "SYSTEM"]);
            assert_eq!(chunk.stripe_count, 1);
            assert_eq!(chunk.stripes.len(), 1);
            assert_eq!(chunk.stripes[0].physical_start, 0x20000);
            assert_eq!(chunk.stripes[0].physical_end_inclusive, 0x2_FFFF);
        });
    }

    #[test]
    fn build_dump_inode_output_btrfs_reads_root_inode_alias() {
        let image = build_test_btrfs_image_with_root_inode_item();
        with_temp_image_path(&image, |path| {
            let output = super::build_dump_inode_output(&path, 1, true)
                .expect("build dump inode output for btrfs image");

            assert_eq!(output.filesystem, "btrfs");
            assert!(output.ext4_parsed.is_none());
            let parsed = output
                .btrfs_parsed
                .as_ref()
                .expect("btrfs parsed inode should be present");
            assert_eq!(parsed.mode, 0o040_755);
            assert_eq!(parsed.uid, 1000);
            assert_eq!(parsed.gid, 1000);
            assert_eq!(parsed.nlink, 2);
            assert!(output.raw_hex.as_ref().is_some_and(|raw| !raw.is_empty()));
            assert!(
                output.limitations.iter().any(|limitation| {
                    limitation.contains("inode 1 maps to btrfs root objectid")
                })
            );
        });
    }

    #[test]
    fn build_dump_dir_output_btrfs_returns_vfs_directory_projection() {
        let image = build_test_btrfs_image_with_root_inode_item();
        with_temp_image_path(&image, |path| {
            let output = super::build_dump_dir_output(&path, 1, true)
                .expect("build dump dir output for btrfs image");

            assert_eq!(output.filesystem, "btrfs");
            assert_eq!(output.inode, 1);
            assert!(output.htree.is_none());
            // The root-only fixture has no on-disk directory-entry items.
            assert!(output.raw_hex_blocks.is_some());
            assert!(
                output
                    .raw_hex_blocks
                    .as_ref()
                    .is_some_and(std::vec::Vec::is_empty)
            );
            assert!(output.entries.iter().all(|entry| entry.rec_len == 0));
            assert!(output.entries.iter().any(|entry| entry.name == "."));
            assert!(output.entries.iter().any(|entry| entry.name == ".."));
            assert!(output.limitations.iter().any(|limitation| {
                limitation.contains("btrfs hex dump shows raw DIR_ITEM/DIR_INDEX payloads")
            }));
        });
    }

    #[test]
    fn build_dump_dir_output_btrfs_hex_returns_dir_index_payloads() {
        let image = build_test_btrfs_image_with_dir_index_entry();
        with_temp_image_path(&image, |path| {
            let output = super::build_dump_dir_output(&path, 1, true)
                .expect("build dump dir output for btrfs directory image");

            let raw_hex_blocks = output
                .raw_hex_blocks
                .as_ref()
                .expect("btrfs hex dump should include raw blocks");
            assert!(!raw_hex_blocks.is_empty());
            assert!(
                raw_hex_blocks
                    .iter()
                    .any(|block| block.item_kind.as_deref() == Some("dir_index"))
            );
            assert!(
                raw_hex_blocks
                    .iter()
                    .all(|block| !block.hex.trim().is_empty())
            );
            assert!(output.entries.iter().any(|entry| entry.name == "hello.txt"));
        });
    }

    #[test]
    fn build_info_output_mvcc_includes_transaction_counters_without_placeholder_limitation() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);

        with_temp_image_path(&image, |path| {
            let cx = super::cli_cx();
            let open_opts = super::OpenOptions {
                ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
                ..super::OpenOptions::default()
            };
            let open_fs = super::OpenFs::open_with_options(&cx, &path, &open_opts)
                .expect("open ext4 image for info mvcc test");

            let output = build_info_output(
                &path,
                &cx,
                &open_fs,
                InfoCommandOptions {
                    sections: InfoSections::empty().with_mvcc(true),
                    json: false,
                },
            )
            .expect("build info output with mvcc section");

            let mvcc = output.mvcc.expect("mvcc section should be present");
            assert_eq!(mvcc.ssi_conflict_count, Some(0));
            assert_eq!(mvcc.abort_count, Some(0));
            assert!(!output.limitations.iter().any(|limitation| {
                limitation.contains("transaction/SSI counters are not yet wired")
            }));
        });
    }

    #[test]
    fn btrfs_chunk_type_flag_names_reports_known_and_unknown_bits() {
        assert_eq!(btrfs_chunk_type_flag_names(0), vec!["NONE"]);
        assert_eq!(btrfs_chunk_type_flag_names(3), vec!["DATA", "SYSTEM"]);

        let flags = btrfs_chunk_type_flag_names(1 | (1_u64 << 9));
        assert!(flags.iter().any(|flag| flag == "DATA"));
        assert!(
            flags
                .iter()
                .any(|flag| flag.starts_with("UNKNOWN(0x0000000000000200)"))
        );
    }

    #[test]
    fn unavailable_repair_info_clears_group_metrics() {
        let info =
            unavailable_repair_info("live ext4 repair metrics unavailable (see limitations)");
        assert!(!info.metrics_available);
        assert_eq!(
            info.note,
            "live ext4 repair metrics unavailable (see limitations)"
        );
        assert_eq!(info.groups_total, None);
        assert_eq!(info.groups_fresh, None);
        assert_eq!(info.groups_stale, None);
        assert_eq!(info.groups_untracked, None);
        assert!(
            (info.configured_overhead_ratio - super::DEFAULT_REPAIR_OVERHEAD_RATIO).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn unavailable_repair_info_supports_btrfs_fallback_note() {
        let info =
            unavailable_repair_info("live btrfs repair metrics unavailable (see limitations)");
        assert!(!info.metrics_available);
        assert_eq!(
            info.note,
            "live btrfs repair metrics unavailable (see limitations)"
        );
        assert_eq!(info.groups_total, None);
    }

    #[test]
    fn fsck_skips_clean_ext4_scrub_without_force() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        let output = with_temp_image_path(&image, |path| {
            build_fsck_output(
                &path,
                FsckCommandOptions {
                    flags: FsckFlags::empty(),
                    block_group: None,
                },
            )
            .expect("build fsck output for clean ext4 image")
        });

        assert_eq!(output.scrub.scanned, 0);
        assert_eq!(output.scrub.corrupt, 0);
        assert_eq!(output.scrub.error_or_higher, 0);
        let scrub_phase = output
            .phases
            .iter()
            .find(|phase| phase.phase == "checksum_scrub")
            .expect("checksum_scrub phase should be present");
        assert_eq!(scrub_phase.status, "skipped");
        assert!(scrub_phase.detail.contains("pass --force for full scrub"));
        assert!(
            output
                .limitations
                .iter()
                .any(|limitation| limitation.contains("skipped block-level scrub"))
        );
    }

    #[test]
    fn fsck_force_runs_full_scrub_for_clean_ext4() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        let output = with_temp_image_path(&image, |path| {
            build_fsck_output(
                &path,
                FsckCommandOptions {
                    flags: FsckFlags::empty().with_force(true),
                    block_group: None,
                },
            )
            .expect("build fsck output for forced clean ext4 image")
        });

        assert!(output.scrub.scanned > 0);
        let scrub_phase = output
            .phases
            .iter()
            .find(|phase| phase.phase == "checksum_scrub")
            .expect("checksum_scrub phase should be present");
        assert_eq!(scrub_phase.status, "ok");
        assert!(
            !output
                .limitations
                .iter()
                .any(|limitation| limitation.contains("skipped block-level scrub"))
        );
    }

    #[test]
    fn repair_selection_prefers_explicit_stale_groups() {
        let all = vec![0, 1, 2, 3];
        let staleness = vec![
            (0, Ext4RepairStaleness::Fresh),
            (1, Ext4RepairStaleness::Stale),
            (2, Ext4RepairStaleness::Untracked),
            (3, Ext4RepairStaleness::Stale),
        ];
        let selected = select_ext4_repair_groups(RepairFlags::empty(), true, &all, &staleness);
        assert_eq!(selected, vec![1, 3]);
    }

    #[test]
    fn repair_selection_skips_when_clean_and_untracked() {
        let all = vec![0, 1];
        let staleness = vec![
            (0, Ext4RepairStaleness::Untracked),
            (1, Ext4RepairStaleness::Untracked),
        ];
        let selected = select_ext4_repair_groups(RepairFlags::empty(), true, &all, &staleness);
        assert!(selected.is_empty());
    }

    #[test]
    fn repair_selection_runs_full_when_dirty_and_untracked() {
        let all = vec![0, 1, 2];
        let staleness = vec![
            (0, Ext4RepairStaleness::Untracked),
            (1, Ext4RepairStaleness::Untracked),
            (2, Ext4RepairStaleness::Untracked),
        ];
        let selected = select_ext4_repair_groups(RepairFlags::empty(), false, &all, &staleness);
        assert_eq!(selected, all);
    }

    #[test]
    fn repair_selection_rebuild_symbols_forces_full_scope() {
        let all = vec![0, 1, 2];
        let staleness = vec![
            (0, Ext4RepairStaleness::Fresh),
            (1, Ext4RepairStaleness::Stale),
            (2, Ext4RepairStaleness::Untracked),
        ];
        let selected = select_ext4_repair_groups(
            RepairFlags::empty().with_rebuild_symbols(true),
            true,
            &all,
            &staleness,
        );
        assert_eq!(selected, all);
    }

    #[test]
    fn btrfs_repair_selection_prefers_stale_groups() {
        let all = vec![0, 1, 2, 3];
        let staleness = vec![
            (0, Ext4RepairStaleness::Fresh),
            (1, Ext4RepairStaleness::Stale),
            (2, Ext4RepairStaleness::Untracked),
            (3, Ext4RepairStaleness::Stale),
        ];
        let mut limitations = Vec::new();

        let selected =
            select_btrfs_repair_groups(RepairFlags::empty(), &all, &staleness, &mut limitations);

        assert_eq!(selected, vec![1, 3]);
        assert!(
            limitations
                .iter()
                .any(|limitation| limitation.contains("selected 2/4 btrfs groups"))
        );
    }

    #[test]
    fn btrfs_repair_selection_falls_back_to_full_when_all_fresh() {
        let all = vec![0, 1, 2];
        let staleness = vec![
            (0, Ext4RepairStaleness::Fresh),
            (1, Ext4RepairStaleness::Fresh),
            (2, Ext4RepairStaleness::Fresh),
        ];
        let mut limitations = Vec::new();

        let selected =
            select_btrfs_repair_groups(RepairFlags::empty(), &all, &staleness, &mut limitations);

        assert_eq!(selected, all);
        assert!(limitations.iter().any(|limitation| {
            limitation.contains("found no stale btrfs groups; running full scrub")
        }));
    }

    #[test]
    fn repair_verify_only_ignores_rebuild_symbols_write_path() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);
        let output = with_temp_image_path(&image, |path| {
            build_repair_output(
                &path,
                RepairCommandOptions {
                    flags: RepairFlags::empty()
                        .with_verify_only(true)
                        .with_rebuild_symbols(true),
                    block_group: None,
                    max_threads: None,
                },
            )
            .expect("build repair output for verify-only rebuild request")
        });

        assert!(
            output
                .limitations
                .iter()
                .any(|limitation| limitation.contains("ignored when --verify-only"))
        );
        assert!(matches!(
            output.action,
            super::RepairActionOutput::VerifyOnly
        ));
    }

    #[test]
    fn repair_coordination_allows_same_host_refresh() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let _guard = log_contract_guard();
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);

        with_temp_image_path(&image, |path| {
            let local_host = test_local_host_name();
            let first = coordinate_repair_write_access(
                "ffs::test",
                REPAIR_COORDINATION_SCENARIO_REPAIR,
                "repair",
                &path,
                true,
            );
            assert!(first.writes_allowed);
            assert!(matches!(
                first.output.status,
                RepairCoordinationStatus::Claimed
            ));

            let second = coordinate_repair_write_access(
                "ffs::test",
                REPAIR_COORDINATION_SCENARIO_REPAIR,
                "repair",
                &path,
                true,
            );
            assert!(second.writes_allowed);
            assert!(matches!(
                second.output.status,
                RepairCoordinationStatus::Claimed
            ));
            assert!(
                second.output.detail.contains("remains pinned to host"),
                "unexpected same-host refresh detail: {}",
                second.output.detail
            );

            let record_bytes = std::fs::read(repair_coordination_record_path(&path))
                .expect("read persisted coordination record");
            let record: RepairCoordinationRecord =
                serde_json::from_slice(&record_bytes).expect("parse persisted coordination record");
            assert_eq!(record.owner_host, local_host);
            assert_eq!(record.last_command, "repair");
        });
    }

    #[test]
    fn repair_coordination_blocks_foreign_host_owner() {
        const EXT4_VALID_FS: u16 = 0x0001;
        let _guard = log_contract_guard();
        let image = build_test_ext4_image_with_state(EXT4_VALID_FS);

        with_temp_image_path(&image, |path| {
            write_test_coordination_record(&path, "remote-host");
            let decision = coordinate_repair_write_access(
                "ffs::test",
                REPAIR_COORDINATION_SCENARIO_REPAIR,
                "repair",
                &path,
                true,
            );

            assert!(!decision.writes_allowed);
            assert!(matches!(
                decision.output.status,
                RepairCoordinationStatus::Blocked
            ));
            assert_eq!(decision.output.owner_host.as_deref(), Some("remote-host"));
            assert_eq!(
                decision.output.error_class.as_deref(),
                Some("multi_host_unsupported")
            );
        });
    }

    #[test]
    fn btrfs_super_mirror_offsets_follow_kernel_layout() {
        // Test with a 1 GiB image - should include mirrors at 64 KiB, 64 MiB, and 256 MiB.
        // (Note: BTRFS_SUPER_MIRROR_MAX is 3, so only first 3 mirrors are returned).
        let image_len = 1024 * 1024 * 1024;
        let offsets = btrfs_super_mirror_offsets(image_len);
        assert_eq!(
            offsets,
            vec![
                64 * 1024,         // Primary: 64 KiB
                64 * 1024 * 1024,  // Mirror 1: 64 MiB
                256 * 1024 * 1024, // Mirror 2: 256 MiB
            ]
        );
    }

    #[test]
    fn btrfs_superblock_normalization_retargets_primary_offset() {
        let mut region = build_test_btrfs_superblock(64 * 1024 * 1024, 3);
        normalize_btrfs_superblock_as_primary(&mut region)
            .expect("normalize mirror superblock for primary slot");
        let parsed = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(&region)
            .expect("normalized superblock should parse");
        assert_eq!(parsed.bytenr, super::BTRFS_SUPER_INFO_OFFSET as u64);
        ffs_ondisk::verify_btrfs_superblock_checksum(&region)
            .expect("normalized superblock checksum should be valid");
    }

    #[test]
    fn repair_restores_primary_btrfs_superblock_from_backup_mirror() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let backup_offset = 64 * 1024 * 1024_usize;
        let image_len = backup_offset + super::BTRFS_SUPER_INFO_SIZE + 4096;
        let mut image = vec![0_u8; image_len];

        let mut primary = build_test_btrfs_superblock(primary_offset as u64, 5);
        primary[0] ^= 0xA5; // Corrupt checksum but keep structure parseable.
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE]
            .copy_from_slice(&primary);

        let backup = build_test_btrfs_superblock(backup_offset as u64, 9);
        image[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&backup);

        let (output, parsed_primary) = with_temp_image_path(&image, |path| {
            build_repair_output(
                &path,
                RepairCommandOptions {
                    flags: RepairFlags::empty(),
                    block_group: None,
                    max_threads: Some(1),
                },
            )
            .map(|output| {
                let repaired = std::fs::read(&path).expect("read repaired image");
                let sb_region =
                    &repaired[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE];
                ffs_ondisk::verify_btrfs_superblock_checksum(sb_region)
                    .expect("repaired primary checksum should be valid");
                let parsed = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(sb_region)
                    .expect("repaired primary should parse");
                (output, parsed)
            })
            .expect("repair output for btrfs mirror recovery")
        });

        assert!(matches!(
            output.action,
            super::RepairActionOutput::RepairRequested
        ));
        assert_eq!(parsed_primary.bytenr, primary_offset as u64);
        assert!(
            output
                .limitations
                .iter()
                .any(|limitation| limitation.contains("restored primary btrfs superblock"))
        );
    }

    #[test]
    fn repair_blocked_preserves_corrupt_btrfs_backup_superblock() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let backup_offset = 64 * 1024 * 1024_usize;
        let image_len = backup_offset + super::BTRFS_SUPER_INFO_SIZE + 4096;
        let mut image = vec![0_u8; image_len];

        let primary = build_test_btrfs_superblock(primary_offset as u64, 21);
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE]
            .copy_from_slice(&primary);

        let mut backup = build_test_btrfs_superblock(backup_offset as u64, 17);
        backup[0] ^= 0x7E; // Corrupt checksum but keep structure parseable.
        image[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&backup);

        let (output, backup_still_corrupt) = with_temp_image_path(&image, |path| {
            write_test_coordination_record(&path, "remote-host");
            build_repair_output(
                &path,
                RepairCommandOptions {
                    flags: RepairFlags::empty(),
                    block_group: None,
                    max_threads: Some(1),
                },
            )
            .map(|output| {
                let repaired = std::fs::read(&path).expect("read image after blocked repair");
                let sb_region =
                    &repaired[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE];
                let backup_still_corrupt =
                    ffs_ondisk::verify_btrfs_superblock_checksum(sb_region).is_err();
                (output, backup_still_corrupt)
            })
            .expect("repair output for blocked multi-host repair")
        });

        assert!(matches!(
            output.action,
            super::RepairActionOutput::RepairBlocked
        ));
        assert!(matches!(
            output.repair_coordination.status,
            RepairCoordinationStatus::Blocked
        ));
        assert_eq!(
            output.repair_coordination.owner_host.as_deref(),
            Some("remote-host")
        );
        assert_eq!(output.exit_code, 2);
        assert!(backup_still_corrupt);
        assert!(
            output
                .limitations
                .iter()
                .any(|limitation| { limitation.contains("Multi-host repair is out of scope") })
        );
    }

    #[test]
    fn repair_restores_corrupt_btrfs_backup_superblock_from_primary() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let backup_offset = 64 * 1024 * 1024_usize;
        let image_len = backup_offset + super::BTRFS_SUPER_INFO_SIZE + 4096;
        let mut image = vec![0_u8; image_len];

        let primary = build_test_btrfs_superblock(primary_offset as u64, 21);
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE]
            .copy_from_slice(&primary);

        let mut backup = build_test_btrfs_superblock(backup_offset as u64, 17);
        backup[0] ^= 0x7E; // Corrupt checksum but keep structure parseable.
        image[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&backup);

        let (output, parsed_backup) = with_temp_image_path(&image, |path| {
            build_repair_output(
                &path,
                RepairCommandOptions {
                    flags: RepairFlags::empty(),
                    block_group: None,
                    max_threads: Some(1),
                },
            )
            .map(|output| {
                let repaired = std::fs::read(&path).expect("read repaired image");
                let sb_region =
                    &repaired[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE];
                ffs_ondisk::verify_btrfs_superblock_checksum(sb_region)
                    .expect("repaired backup checksum should be valid");
                let parsed = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(sb_region)
                    .expect("repaired backup should parse");
                (output, parsed)
            })
            .expect("repair output for btrfs backup mirror recovery")
        });

        assert!(matches!(
            output.action,
            super::RepairActionOutput::RepairRequested
        ));
        assert_eq!(parsed_backup.bytenr, backup_offset as u64);
        assert!(output.limitations.iter().any(|limitation| {
            limitation.contains("restored 1 btrfs superblock mirror(s) from primary superblock")
        }));
    }

    #[test]
    fn mirror_repair_skips_when_corrupt_backup_superblock_outside_scope() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let backup_offset = 64 * 1024 * 1024_usize;
        let image_len = backup_offset + super::BTRFS_SUPER_INFO_SIZE + 4096;
        let block_size = 4096_u32;
        let mut image = vec![0_u8; image_len];

        let primary = build_test_btrfs_superblock(primary_offset as u64, 53);
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE]
            .copy_from_slice(&primary);

        let mut backup = build_test_btrfs_superblock(backup_offset as u64, 51);
        backup[0] ^= 0x55; // Corrupt checksum but keep structure parseable.
        image[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&backup);

        let (outcome, limitations, backup_still_corrupt) = with_temp_image_path(&image, |path| {
            let mut limitations = Vec::new();
            let outcome = super::repair_corrupt_btrfs_superblock_mirrors_from_primary(
                &path,
                block_size,
                super::BlockNumber(0),
                8,
                &mut limitations,
            )
            .expect("run scoped mirror repair outside backup scope");
            let repaired = std::fs::read(&path).expect("read image after scoped mirror repair");
            let sb_region = &repaired[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE];
            let backup_still_corrupt =
                ffs_ondisk::verify_btrfs_superblock_checksum(sb_region).is_err();
            (outcome, limitations, backup_still_corrupt)
        });

        assert!(!outcome.attempted);
        assert_eq!(outcome.repaired, 0);
        assert!(backup_still_corrupt);
        assert!(!limitations.iter().any(|limitation| {
            limitation.contains("restored 1 btrfs superblock mirror(s) from primary superblock")
        }));
    }

    #[test]
    fn mirror_repair_restores_corrupt_backup_superblock_when_in_scope() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let backup_offset = 64 * 1024 * 1024_usize;
        let image_len = backup_offset + super::BTRFS_SUPER_INFO_SIZE + 4096;
        let block_size = 4096_u32;
        let mut image = vec![0_u8; image_len];

        let primary = build_test_btrfs_superblock(primary_offset as u64, 63);
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE]
            .copy_from_slice(&primary);

        let mut backup = build_test_btrfs_superblock(backup_offset as u64, 61);
        backup[0] ^= 0xAA; // Corrupt checksum but keep structure parseable.
        image[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&backup);

        let (outcome, limitations, parsed_backup) = with_temp_image_path(&image, |path| {
            let mut limitations = Vec::new();
            let backup_block = super::BlockNumber((backup_offset as u64) / u64::from(block_size));
            let outcome = super::repair_corrupt_btrfs_superblock_mirrors_from_primary(
                &path,
                block_size,
                backup_block,
                1,
                &mut limitations,
            )
            .expect("run scoped mirror repair for backup slot");
            let repaired = std::fs::read(&path).expect("read image after scoped mirror repair");
            let sb_region = &repaired[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE];
            ffs_ondisk::verify_btrfs_superblock_checksum(sb_region)
                .expect("repaired backup checksum should be valid");
            let parsed = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(sb_region)
                .expect("repaired backup should parse");
            (outcome, limitations, parsed)
        });

        assert!(outcome.attempted);
        assert_eq!(outcome.repaired, 1);
        assert_eq!(parsed_backup.bytenr, backup_offset as u64);
        assert!(limitations.iter().any(|limitation| {
            limitation.contains("restored 1 btrfs superblock mirror(s) from primary superblock")
        }));
    }

    #[test]
    fn fsck_repair_restores_primary_btrfs_superblock_from_backup_mirror() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let backup_offset = 64 * 1024 * 1024_usize;
        let image_len = backup_offset + super::BTRFS_SUPER_INFO_SIZE + 4096;
        let mut image = vec![0_u8; image_len];

        let mut primary = build_test_btrfs_superblock(primary_offset as u64, 11);
        primary[0] ^= 0x3C; // Corrupt checksum but keep structure parseable.
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE]
            .copy_from_slice(&primary);

        let backup = build_test_btrfs_superblock(backup_offset as u64, 13);
        image[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&backup);

        let (output, parsed_primary) = with_temp_image_path(&image, |path| {
            build_fsck_output(
                &path,
                FsckCommandOptions {
                    flags: FsckFlags::empty().with_repair(true),
                    block_group: None,
                },
            )
            .map(|output| {
                let repaired = std::fs::read(&path).expect("read repaired image");
                let sb_region =
                    &repaired[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE];
                ffs_ondisk::verify_btrfs_superblock_checksum(sb_region)
                    .expect("repaired primary checksum should be valid");
                let parsed = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(sb_region)
                    .expect("repaired primary should parse");
                (output, parsed)
            })
            .expect("fsck output for btrfs mirror recovery")
        });

        assert!(matches!(
            output.repair_status,
            super::FsckRepairStatus::RequestedPerformed
        ));
        let repair_phase = output
            .phases
            .iter()
            .find(|phase| phase.phase == "repair")
            .expect("repair phase should be present");
        assert_eq!(repair_phase.status, "ok");
        assert!(
            repair_phase
                .detail
                .contains("restored primary btrfs superblock")
        );
        assert_eq!(parsed_primary.bytenr, primary_offset as u64);
        assert!(output.scrub.scanned > 0);
    }

    #[test]
    fn fsck_repair_blocked_preserves_corrupt_btrfs_backup_superblock() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let backup_offset = 64 * 1024 * 1024_usize;
        let image_len = backup_offset + super::BTRFS_SUPER_INFO_SIZE + 4096;
        let mut image = vec![0_u8; image_len];

        let primary = build_test_btrfs_superblock(primary_offset as u64, 29);
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE]
            .copy_from_slice(&primary);

        let mut backup = build_test_btrfs_superblock(backup_offset as u64, 26);
        backup[0] ^= 0x19; // Corrupt checksum but keep structure parseable.
        image[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&backup);

        let (output, backup_still_corrupt) = with_temp_image_path(&image, |path| {
            write_test_coordination_record(&path, "remote-host");
            build_fsck_output(
                &path,
                FsckCommandOptions {
                    flags: FsckFlags::empty().with_repair(true),
                    block_group: None,
                },
            )
            .map(|output| {
                let repaired = std::fs::read(&path).expect("read image after blocked fsck repair");
                let sb_region =
                    &repaired[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE];
                let backup_still_corrupt =
                    ffs_ondisk::verify_btrfs_superblock_checksum(sb_region).is_err();
                (output, backup_still_corrupt)
            })
            .expect("fsck output for blocked multi-host repair")
        });

        assert!(matches!(
            output.repair_status,
            super::FsckRepairStatus::RequestedNotPerformed
        ));
        assert!(matches!(
            output
                .repair_coordination
                .as_ref()
                .expect("repair coordination should be reported")
                .status,
            RepairCoordinationStatus::Blocked
        ));
        let repair_phase = output
            .phases
            .iter()
            .find(|phase| phase.phase == "repair")
            .expect("repair phase should be present");
        assert_eq!(repair_phase.status, "error");
        assert!(
            repair_phase
                .detail
                .contains("Multi-host repair is out of scope"),
            "unexpected blocked repair detail: {}",
            repair_phase.detail
        );
        assert_eq!(output.exit_code, 2);
        assert!(backup_still_corrupt);
    }

    #[test]
    fn fsck_repair_restores_corrupt_btrfs_backup_superblock_from_primary() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let backup_offset = 64 * 1024 * 1024_usize;
        let image_len = backup_offset + super::BTRFS_SUPER_INFO_SIZE + 4096;
        let mut image = vec![0_u8; image_len];

        let primary = build_test_btrfs_superblock(primary_offset as u64, 29);
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE]
            .copy_from_slice(&primary);

        let mut backup = build_test_btrfs_superblock(backup_offset as u64, 26);
        backup[0] ^= 0x19; // Corrupt checksum but keep structure parseable.
        image[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&backup);

        let (output, parsed_backup) = with_temp_image_path(&image, |path| {
            build_fsck_output(
                &path,
                FsckCommandOptions {
                    flags: FsckFlags::empty().with_repair(true),
                    block_group: None,
                },
            )
            .map(|output| {
                let repaired = std::fs::read(&path).expect("read repaired image");
                let sb_region =
                    &repaired[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE];
                ffs_ondisk::verify_btrfs_superblock_checksum(sb_region)
                    .expect("repaired backup checksum should be valid");
                let parsed = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(sb_region)
                    .expect("repaired backup should parse");
                (output, parsed)
            })
            .expect("fsck output for btrfs backup mirror recovery")
        });

        assert!(matches!(
            output.repair_status,
            super::FsckRepairStatus::RequestedPerformed
        ));
        let repair_phase = output
            .phases
            .iter()
            .find(|phase| phase.phase == "repair")
            .expect("repair phase should be present");
        assert_eq!(repair_phase.status, "ok");
        assert!(
            repair_phase
                .detail
                .contains("restored 1 btrfs superblock mirror(s) from primary superblock")
        );
        assert_eq!(parsed_backup.bytenr, backup_offset as u64);
    }

    #[test]
    fn repair_bootstraps_btrfs_detection_from_backup_superblock() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let backup_offset = 64 * 1024 * 1024_usize;
        let image_len = backup_offset + super::BTRFS_SUPER_INFO_SIZE + 4096;
        let mut image = vec![0_u8; image_len];

        let mut primary = build_test_btrfs_superblock(primary_offset as u64, 31);
        primary[0x40..0x48].fill(0); // Break magic so initial filesystem detection fails.
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE]
            .copy_from_slice(&primary);

        let backup = build_test_btrfs_superblock(backup_offset as u64, 33);
        image[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&backup);

        let (output, parsed_primary) = with_temp_image_path(&image, |path| {
            build_repair_output(
                &path,
                RepairCommandOptions {
                    flags: RepairFlags::empty(),
                    block_group: None,
                    max_threads: Some(1),
                },
            )
            .map(|output| {
                let repaired = std::fs::read(&path).expect("read repaired image");
                let sb_region =
                    &repaired[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE];
                ffs_ondisk::verify_btrfs_superblock_checksum(sb_region)
                    .expect("repaired primary checksum should be valid");
                let parsed = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(sb_region)
                    .expect("repaired primary should parse");
                (output, parsed)
            })
            .expect("repair output for btrfs bootstrap recovery")
        });

        assert!(matches!(
            output.action,
            super::RepairActionOutput::RepairRequested
        ));
        assert_eq!(parsed_primary.bytenr, primary_offset as u64);
        assert!(
            output.limitations.iter().any(
                |limitation| limitation.contains("bootstrap restored primary btrfs superblock")
            )
        );
    }

    #[test]
    fn fsck_repair_bootstraps_btrfs_detection_from_backup_superblock() {
        let primary_offset = super::BTRFS_SUPER_INFO_OFFSET;
        let backup_offset = 64 * 1024 * 1024_usize;
        let image_len = backup_offset + super::BTRFS_SUPER_INFO_SIZE + 4096;
        let mut image = vec![0_u8; image_len];

        let mut primary = build_test_btrfs_superblock(primary_offset as u64, 41);
        primary[0x40..0x48].fill(0); // Break magic so initial filesystem detection fails.
        image[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE]
            .copy_from_slice(&primary);

        let backup = build_test_btrfs_superblock(backup_offset as u64, 44);
        image[backup_offset..backup_offset + super::BTRFS_SUPER_INFO_SIZE].copy_from_slice(&backup);

        let (output, parsed_primary) = with_temp_image_path(&image, |path| {
            build_fsck_output(
                &path,
                FsckCommandOptions {
                    flags: FsckFlags::empty().with_repair(true),
                    block_group: None,
                },
            )
            .map(|output| {
                let repaired = std::fs::read(&path).expect("read repaired image");
                let sb_region =
                    &repaired[primary_offset..primary_offset + super::BTRFS_SUPER_INFO_SIZE];
                ffs_ondisk::verify_btrfs_superblock_checksum(sb_region)
                    .expect("repaired primary checksum should be valid");
                let parsed = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(sb_region)
                    .expect("repaired primary should parse");
                (output, parsed)
            })
            .expect("fsck output for btrfs bootstrap recovery")
        });

        assert!(matches!(
            output.repair_status,
            super::FsckRepairStatus::RequestedPerformed
        ));
        let repair_phase = output
            .phases
            .iter()
            .find(|phase| phase.phase == "repair")
            .expect("repair phase should be present");
        assert_eq!(repair_phase.status, "ok");
        assert!(
            repair_phase
                .detail
                .contains("bootstrap restored primary btrfs superblock")
        );
        assert_eq!(parsed_primary.bytenr, primary_offset as u64);
        assert!(output.scrub.scanned > 0);
    }

    #[test]
    fn btrfs_repair_group_spec_maps_contiguous_single_chunk() {
        // Group must be large enough for the repair tail (>= 4 blocks):
        // REPAIR_DESC_SLOT_COUNT (2) + at least 1 repair block + source blocks.
        // Chunk covers [0x1000..0x20FFF], group occupies [0x2000..0x11FFF] (16 blocks).
        let chunks = vec![test_btrfs_chunk_entry(0x1000, 0x20000, 0x8000)];
        let spec = build_btrfs_repair_group_spec(2, 0x2000, 0x10000, 4096, &chunks)
            .expect("map contiguous btrfs group");
        assert_eq!(spec.group, 2);
        assert_eq!(spec.logical_start, 0x2000);
        assert_eq!(spec.logical_bytes, 0x10000);
        // physical_start = chunk_physical + (logical_start - chunk_logical) = 0x8000 + (0x2000 - 0x1000) = 0x9000
        // start_block = 0x9000 / 4096 = 9
        assert_eq!(spec.physical_start_block.0, 9);
        // block_count = 0x10000 / 4096 = 16
        assert_eq!(spec.physical_block_count, 16);
    }

    #[test]
    fn btrfs_repair_group_spec_rejects_unmapped_range() {
        let chunks = vec![test_btrfs_chunk_entry(0x1000, 0x1000, 0x8000)];
        let err = build_btrfs_repair_group_spec(0, 0x4000, 0x1000, 4096, &chunks)
            .expect_err("unmapped logical range should fail");
        let detail = format!("{err:#}");
        assert!(detail.contains("not covered by any chunk"));
    }

    #[test]
    fn btrfs_repair_group_spec_rejects_non_contiguous_chunk_mapping() {
        let chunks = vec![
            test_btrfs_chunk_entry(0x0, 0x1000, 0x10000),
            test_btrfs_chunk_entry(0x1000, 0x1000, 0x30000),
        ];
        let err = build_btrfs_repair_group_spec(1, 0x0, 0x2000, 4096, &chunks)
            .expect_err("discontiguous mapping should fail");
        let detail = format!("{err:#}");
        assert!(detail.contains("non-contiguous chunk mapping"));
    }

    // ── summarize_repair_staleness: additional edge cases ─────────────────

    #[test]
    fn summarize_repair_staleness_all_fresh() {
        let staleness = vec![
            (0, Ext4RepairStaleness::Fresh),
            (1, Ext4RepairStaleness::Fresh),
            (2, Ext4RepairStaleness::Fresh),
        ];
        let summary = summarize_repair_staleness(&staleness);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.fresh, 3);
        assert_eq!(summary.stale, 0);
        assert_eq!(summary.untracked, 0);
    }

    #[test]
    fn summarize_repair_staleness_all_stale() {
        let staleness = vec![
            (0, Ext4RepairStaleness::Stale),
            (1, Ext4RepairStaleness::Stale),
        ];
        let summary = summarize_repair_staleness(&staleness);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.fresh, 0);
        assert_eq!(summary.stale, 2);
        assert_eq!(summary.untracked, 0);
    }

    #[test]
    fn summarize_repair_staleness_all_untracked() {
        let staleness = vec![
            (0, Ext4RepairStaleness::Untracked),
            (1, Ext4RepairStaleness::Untracked),
            (2, Ext4RepairStaleness::Untracked),
            (3, Ext4RepairStaleness::Untracked),
        ];
        let summary = summarize_repair_staleness(&staleness);
        assert_eq!(summary.total, 4);
        assert_eq!(summary.fresh, 0);
        assert_eq!(summary.stale, 0);
        assert_eq!(summary.untracked, 4);
    }

    #[test]
    fn summarize_repair_staleness_single_entry() {
        let summary = summarize_repair_staleness(&[(42, Ext4RepairStaleness::Stale)]);
        assert_eq!(summary.total, 1);
        assert_eq!(summary.fresh, 0);
        assert_eq!(summary.stale, 1);
        assert_eq!(summary.untracked, 0);
    }

    // ── format_ratio_thousandths: metrics display helper ──────────────────

    #[test]
    fn format_ratio_thousandths_zero_denominator_returns_zero() {
        assert_eq!(format_ratio_thousandths(5, 0), "0.000");
    }

    #[test]
    fn format_ratio_thousandths_zero_numerator() {
        assert_eq!(format_ratio_thousandths(0, 100), "0.000");
    }

    #[test]
    fn format_ratio_thousandths_exact_ratio() {
        assert_eq!(format_ratio_thousandths(1, 1), "1.000");
        assert_eq!(format_ratio_thousandths(3, 1), "3.000");
    }

    #[test]
    fn format_ratio_thousandths_fractional() {
        assert_eq!(format_ratio_thousandths(1, 3), "0.333");
        assert_eq!(format_ratio_thousandths(2, 3), "0.666");
        assert_eq!(format_ratio_thousandths(7, 2), "3.500");
    }

    #[test]
    fn format_ratio_thousandths_large_values() {
        let result = format_ratio_thousandths(usize::MAX, 1);
        assert!(!result.is_empty());
        assert!(result.contains('.'));
    }

    // ── choose_btrfs_scrub_block_size: geometry validation ───────────────

    #[test]
    fn choose_btrfs_scrub_block_size_aligned_to_nodesize() {
        let block_size = choose_btrfs_scrub_block_size(16384 * 10, 16384, 4096)
            .expect("aligned image should succeed");
        assert_eq!(block_size, 16384);
    }

    #[test]
    fn choose_btrfs_scrub_block_size_falls_back_to_smaller_alignment() {
        // image length 40960 = 10 * 4096, not divisible by 16384
        let block_size = choose_btrfs_scrub_block_size(40960, 16384, 4096)
            .expect("should fall back to smaller aligned block size");
        assert!(block_size <= 16384);
        assert!(block_size >= 4096);
        assert_eq!(40960 % u64::from(block_size), 0);
    }

    #[test]
    fn choose_btrfs_scrub_block_size_rejects_zero_nodesize() {
        let err = choose_btrfs_scrub_block_size(65536, 0, 4096);
        assert!(err.is_err());
    }

    #[test]
    fn choose_btrfs_scrub_block_size_rejects_non_power_of_two_nodesize() {
        let err = choose_btrfs_scrub_block_size(65536, 12288, 4096);
        assert!(err.is_err());
    }

    #[test]
    fn choose_btrfs_scrub_block_size_rejects_unaligned_image() {
        let err = choose_btrfs_scrub_block_size(4097, 4096, 4096);
        assert!(err.is_err());
    }

    #[test]
    fn choose_btrfs_scrub_block_size_enforces_minimum_4096() {
        // sectorsize < 4096 should still enforce 4096 floor
        let block_size = choose_btrfs_scrub_block_size(4096 * 4, 4096, 512)
            .expect("should succeed with 4096 floor");
        assert!(block_size >= 4096);
    }

    // ── select_ext4_repair_groups: fresh-only path ───────────────────────

    #[test]
    fn repair_selection_returns_empty_when_all_fresh() {
        let all = vec![0, 1, 2];
        let staleness = vec![
            (0, Ext4RepairStaleness::Fresh),
            (1, Ext4RepairStaleness::Fresh),
            (2, Ext4RepairStaleness::Fresh),
        ];
        let selected = select_ext4_repair_groups(RepairFlags::empty(), false, &all, &staleness);
        assert!(selected.is_empty());
    }

    #[test]
    fn repair_selection_full_scrub_overrides_fresh_state() {
        let all = vec![0, 1, 2];
        let staleness = vec![
            (0, Ext4RepairStaleness::Fresh),
            (1, Ext4RepairStaleness::Fresh),
            (2, Ext4RepairStaleness::Fresh),
        ];
        let selected = select_ext4_repair_groups(
            RepairFlags::empty().with_full_scrub(true),
            true,
            &all,
            &staleness,
        );
        assert_eq!(selected, all);
    }

    #[test]
    fn repair_selection_empty_staleness_and_dirty_returns_all() {
        let all = vec![0, 1, 2];
        let staleness: Vec<(u32, Ext4RepairStaleness)> = vec![];
        let selected = select_ext4_repair_groups(RepairFlags::empty(), false, &all, &staleness);
        assert_eq!(selected, all);
    }

    #[test]
    fn repair_selection_empty_staleness_and_clean_skips_repair() {
        let all = vec![0, 1, 2];
        let staleness: Vec<(u32, Ext4RepairStaleness)> = vec![];
        let selected = select_ext4_repair_groups(RepairFlags::empty(), true, &all, &staleness);
        assert!(selected.is_empty());
    }

    // ── WAL replay telemetry tests ──────────────────────────────────────

    #[test]
    fn wal_replay_info_output_serializes_to_stable_json_schema() {
        use super::WalReplayInfoOutput;

        let info = WalReplayInfoOutput {
            outcome: "Clean".to_owned(),
            is_clean: true,
            commits_replayed: 5,
            versions_replayed: 12,
            records_discarded: 0,
            wal_valid_bytes: 2048,
            wal_total_bytes: 2048,
            used_checkpoint: false,
            checkpoint_commit_seq: None,
        };
        let json_str =
            serde_json::to_string_pretty(&info).expect("WalReplayInfoOutput should serialize");
        let parsed: Value = serde_json::from_str(&json_str).expect("should parse as JSON");

        assert_eq!(parsed["outcome"], "Clean");
        assert_eq!(parsed["is_clean"], true);
        assert_eq!(parsed["commits_replayed"], 5);
        assert_eq!(parsed["versions_replayed"], 12);
        assert_eq!(parsed["records_discarded"], 0);
        assert_eq!(parsed["wal_valid_bytes"], 2048);
        assert_eq!(parsed["wal_total_bytes"], 2048);
        assert_eq!(parsed["used_checkpoint"], false);
        // checkpoint_commit_seq should be omitted when None
        assert!(parsed.get("checkpoint_commit_seq").is_none());
    }

    #[test]
    fn wal_replay_info_output_includes_checkpoint_when_present() {
        use super::WalReplayInfoOutput;

        let info = WalReplayInfoOutput {
            outcome: "TruncatedTail".to_owned(),
            is_clean: false,
            commits_replayed: 3,
            versions_replayed: 7,
            records_discarded: 1,
            wal_valid_bytes: 1024,
            wal_total_bytes: 1500,
            used_checkpoint: true,
            checkpoint_commit_seq: Some(42),
        };
        let json_str =
            serde_json::to_string_pretty(&info).expect("WalReplayInfoOutput should serialize");
        let parsed: Value = serde_json::from_str(&json_str).expect("should parse as JSON");

        assert_eq!(parsed["is_clean"], false);
        assert_eq!(parsed["records_discarded"], 1);
        assert_eq!(parsed["used_checkpoint"], true);
        assert_eq!(parsed["checkpoint_commit_seq"], 42);
    }

    #[test]
    fn mvcc_stats_output_omits_wal_replay_when_none() {
        use super::{BlockVersionStatsOutput, EbrVersionStatsOutput, MvccStatsOutput};

        let output = MvccStatsOutput {
            block_versions: BlockVersionStatsOutput {
                tracked_blocks: 10,
                max_chain_length: 2,
                chains_over_cap: 0,
                chains_over_critical: 0,
                chain_cap: Some(8),
                critical_chain_length: Some(6),
            },
            ebr_versions: EbrVersionStatsOutput {
                retired: 5,
                reclaimed: 3,
                pending: 2,
            },
            wal_replay: None,
        };
        let json_str =
            serde_json::to_string_pretty(&output).expect("MvccStatsOutput should serialize");
        let parsed: Value = serde_json::from_str(&json_str).expect("should parse as JSON");

        assert!(
            parsed.get("wal_replay").is_none(),
            "wal_replay should be omitted from JSON when None"
        );
        assert_eq!(parsed["block_versions"]["tracked_blocks"], 10);
    }

    #[test]
    fn mvcc_stats_output_includes_wal_replay_when_present() {
        use super::{
            BlockVersionStatsOutput, EbrVersionStatsOutput, MvccStatsOutput, WalReplayInfoOutput,
        };

        let output = MvccStatsOutput {
            block_versions: BlockVersionStatsOutput {
                tracked_blocks: 5,
                max_chain_length: 1,
                chains_over_cap: 0,
                chains_over_critical: 0,
                chain_cap: None,
                critical_chain_length: None,
            },
            ebr_versions: EbrVersionStatsOutput {
                retired: 0,
                reclaimed: 0,
                pending: 0,
            },
            wal_replay: Some(WalReplayInfoOutput {
                outcome: "CorruptTail".to_owned(),
                is_clean: false,
                commits_replayed: 1,
                versions_replayed: 2,
                records_discarded: 3,
                wal_valid_bytes: 512,
                wal_total_bytes: 800,
                used_checkpoint: false,
                checkpoint_commit_seq: None,
            }),
        };
        let json_str =
            serde_json::to_string_pretty(&output).expect("MvccStatsOutput should serialize");
        let parsed: Value = serde_json::from_str(&json_str).expect("should parse as JSON");

        let wal = &parsed["wal_replay"];
        assert_eq!(wal["outcome"], "CorruptTail");
        assert_eq!(wal["is_clean"], false);
        assert_eq!(wal["commits_replayed"], 1);
        assert_eq!(wal["records_discarded"], 3);
    }

    #[test]
    fn mvcc_info_output_includes_wal_replay_when_present() {
        use super::{MvccInfoOutput, WalReplayInfoOutput};

        let output = MvccInfoOutput {
            current_commit_seq: 10,
            active_snapshot_count: 1,
            oldest_active_snapshot: Some(5),
            total_versioned_blocks: 20,
            max_chain_depth: 3,
            average_chain_depth: "1.500".to_owned(),
            blocks_pending_gc: 4,
            ssi_conflict_count: Some(0),
            abort_count: Some(0),
            wal_replay: Some(WalReplayInfoOutput {
                outcome: "EmptyLog".to_owned(),
                is_clean: true,
                commits_replayed: 0,
                versions_replayed: 0,
                records_discarded: 0,
                wal_valid_bytes: 16,
                wal_total_bytes: 16,
                used_checkpoint: false,
                checkpoint_commit_seq: None,
            }),
        };
        let json_str =
            serde_json::to_string_pretty(&output).expect("MvccInfoOutput should serialize");
        let parsed: Value = serde_json::from_str(&json_str).expect("should parse as JSON");

        assert_eq!(parsed["current_commit_seq"], 10);
        let wal = &parsed["wal_replay"];
        assert_eq!(wal["outcome"], "EmptyLog");
        assert_eq!(wal["is_clean"], true);
        assert_eq!(wal["wal_valid_bytes"], 16);
    }
}
