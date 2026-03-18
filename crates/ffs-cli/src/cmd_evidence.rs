use anyhow::{Context, Result, bail};
use ffs_repair::evidence::{EvidenceEventType, EvidenceRecord};
use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::Instant;
use tracing::{info, info_span, warn};

// ── Preset definitions ─────────────────────────────────────────────────────

/// Operator-oriented preset query names and their constituent event types.
pub const PRESET_REPLAY_ANOMALIES: &str = "replay-anomalies";
pub const PRESET_REPAIR_FAILURES: &str = "repair-failures";
pub const PRESET_PRESSURE_TRANSITIONS: &str = "pressure-transitions";
pub const PRESET_CONTENTION: &str = "contention";

/// Returns the event types included in a preset, or `None` if unknown.
pub fn preset_event_types(preset: &str) -> Option<&'static [EvidenceEventType]> {
    match preset {
        PRESET_REPLAY_ANOMALIES => Some(&[
            EvidenceEventType::WalRecovery,
            EvidenceEventType::TxnAborted,
            EvidenceEventType::SerializationConflict,
        ]),
        PRESET_REPAIR_FAILURES => Some(&[
            EvidenceEventType::CorruptionDetected,
            EvidenceEventType::RepairAttempted,
            EvidenceEventType::RepairSucceeded,
            EvidenceEventType::RepairFailed,
            EvidenceEventType::ScrubCycleComplete,
        ]),
        PRESET_PRESSURE_TRANSITIONS => Some(&[
            EvidenceEventType::BackpressureActivated,
            EvidenceEventType::FlushBatch,
            EvidenceEventType::DurabilityPolicyChanged,
            EvidenceEventType::RefreshPolicyChanged,
        ]),
        PRESET_CONTENTION => Some(&[
            EvidenceEventType::MergeProofChecked,
            EvidenceEventType::MergeApplied,
            EvidenceEventType::MergeRejected,
            EvidenceEventType::PolicySwitched,
            EvidenceEventType::ContentionSample,
        ]),
        _ => None,
    }
}

/// All known preset names.
pub const KNOWN_PRESETS: &[&str] = &[
    PRESET_REPLAY_ANOMALIES,
    PRESET_REPAIR_FAILURES,
    PRESET_PRESSURE_TRANSITIONS,
    PRESET_CONTENTION,
];

// ── Summary ────────────────────────────────────────────────────────────────

/// Aggregated summary of evidence records.
#[derive(Debug, serde::Serialize)]
pub struct EvidenceSummary {
    pub total_records: usize,
    pub event_type_counts: BTreeMap<String, usize>,
    pub time_span_ns: Option<(u64, u64)>,
    pub block_groups_seen: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay_summary: Option<ReplaySummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repair_summary: Option<RepairSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pressure_summary: Option<PressureSummary>,
}

#[derive(Debug, serde::Serialize)]
pub struct ReplaySummary {
    pub recovery_count: usize,
    pub total_commits_replayed: u64,
    pub total_records_discarded: u64,
    pub aborts: usize,
    pub conflicts: usize,
}

#[derive(Debug, serde::Serialize)]
pub struct RepairSummary {
    pub corruptions_detected: usize,
    pub repairs_attempted: usize,
    pub repairs_succeeded: usize,
    pub repairs_failed: usize,
    pub scrub_cycles: usize,
    pub total_blocks_corrupt: u64,
}

#[derive(Debug, serde::Serialize)]
pub struct PressureSummary {
    pub backpressure_events: usize,
    pub flush_batches: usize,
    pub total_blocks_flushed: u64,
    pub policy_changes: usize,
}

/// Mutable accumulators for building an evidence summary.
#[derive(Default)]
struct SummaryAccumulator {
    event_type_counts: BTreeMap<String, usize>,
    min_ts: Option<u64>,
    max_ts: Option<u64>,
    groups: Vec<u32>,
    // Replay
    recovery_count: usize,
    total_commits_replayed: u64,
    total_records_discarded: u64,
    aborts: usize,
    conflicts: usize,
    // Repair
    corruptions_detected: usize,
    repairs_attempted: usize,
    repairs_succeeded: usize,
    repairs_failed: usize,
    scrub_cycles: usize,
    total_blocks_corrupt: u64,
    // Pressure
    backpressure_events: usize,
    flush_batches: usize,
    total_blocks_flushed: u64,
    policy_changes: usize,
}

impl SummaryAccumulator {
    fn ingest(&mut self, record: &EvidenceRecord) {
        let name = evidence_event_type_name(record.event_type);
        *self.event_type_counts.entry(name.to_owned()).or_insert(0) += 1;

        let ts = record.timestamp_ns;
        self.min_ts = Some(self.min_ts.map_or(ts, |m: u64| m.min(ts)));
        self.max_ts = Some(self.max_ts.map_or(ts, |m: u64| m.max(ts)));

        if record.block_group != 0 && !self.groups.contains(&record.block_group) {
            self.groups.push(record.block_group);
        }

        match record.event_type {
            EvidenceEventType::WalRecovery => {
                self.recovery_count += 1;
                if let Some(w) = record.wal_recovery.as_ref() {
                    self.total_commits_replayed += w.commits_replayed;
                    self.total_records_discarded += w.records_discarded;
                }
            }
            EvidenceEventType::TxnAborted => self.aborts += 1,
            EvidenceEventType::SerializationConflict => self.conflicts += 1,
            EvidenceEventType::CorruptionDetected => {
                self.corruptions_detected += 1;
                if let Some(c) = record.corruption.as_ref() {
                    self.total_blocks_corrupt += u64::from(c.blocks_affected);
                }
            }
            EvidenceEventType::RepairAttempted => self.repairs_attempted += 1,
            EvidenceEventType::RepairSucceeded => self.repairs_succeeded += 1,
            EvidenceEventType::RepairFailed => self.repairs_failed += 1,
            EvidenceEventType::ScrubCycleComplete => self.scrub_cycles += 1,
            EvidenceEventType::BackpressureActivated => self.backpressure_events += 1,
            EvidenceEventType::FlushBatch => {
                self.flush_batches += 1;
                if let Some(f) = record.flush_batch.as_ref() {
                    self.total_blocks_flushed += f.blocks_flushed;
                }
            }
            EvidenceEventType::DurabilityPolicyChanged
            | EvidenceEventType::RefreshPolicyChanged => {
                self.policy_changes += 1;
            }
            _ => {}
        }
    }

    fn finalize(mut self, total: usize, preset: Option<&str>) -> EvidenceSummary {
        self.groups.sort_unstable();
        let has_replay = self.recovery_count > 0 || self.aborts > 0 || self.conflicts > 0;
        let has_repair = self.corruptions_detected > 0
            || self.repairs_attempted > 0
            || self.repairs_succeeded > 0
            || self.repairs_failed > 0
            || self.scrub_cycles > 0;
        let has_pressure =
            self.backpressure_events > 0 || self.flush_batches > 0 || self.policy_changes > 0;

        EvidenceSummary {
            total_records: total,
            event_type_counts: self.event_type_counts,
            time_span_ns: self.min_ts.zip(self.max_ts),
            block_groups_seen: self.groups,
            preset: preset.map(str::to_owned),
            replay_summary: if has_replay {
                Some(ReplaySummary {
                    recovery_count: self.recovery_count,
                    total_commits_replayed: self.total_commits_replayed,
                    total_records_discarded: self.total_records_discarded,
                    aborts: self.aborts,
                    conflicts: self.conflicts,
                })
            } else {
                None
            },
            repair_summary: if has_repair {
                Some(RepairSummary {
                    corruptions_detected: self.corruptions_detected,
                    repairs_attempted: self.repairs_attempted,
                    repairs_succeeded: self.repairs_succeeded,
                    repairs_failed: self.repairs_failed,
                    scrub_cycles: self.scrub_cycles,
                    total_blocks_corrupt: self.total_blocks_corrupt,
                })
            } else {
                None
            },
            pressure_summary: if has_pressure {
                Some(PressureSummary {
                    backpressure_events: self.backpressure_events,
                    flush_batches: self.flush_batches,
                    total_blocks_flushed: self.total_blocks_flushed,
                    policy_changes: self.policy_changes,
                })
            } else {
                None
            },
        }
    }
}

fn build_summary(records: &[EvidenceRecord], preset: Option<&str>) -> EvidenceSummary {
    let mut acc = SummaryAccumulator::default();
    for record in records {
        acc.ingest(record);
    }
    acc.finalize(records.len(), preset)
}

fn print_summary(summary: &EvidenceSummary) {
    println!("FrankenFS Evidence Summary");
    if let Some(preset) = summary.preset.as_ref() {
        println!("  Preset: {preset}");
    }
    println!("  Total records: {}", summary.total_records);
    if let Some((min_ts, max_ts)) = summary.time_span_ns {
        let min_s = min_ts / 1_000_000_000;
        let max_s = max_ts / 1_000_000_000;
        let span_s = max_s.saturating_sub(min_s);
        println!("  Time span: {span_s}s (earliest={min_s}, latest={max_s})");
    }
    if !summary.block_groups_seen.is_empty() {
        println!(
            "  Block groups: {} distinct",
            summary.block_groups_seen.len()
        );
    }

    println!();
    println!("  Event type breakdown:");
    for (name, count) in &summary.event_type_counts {
        println!("    {name:<32} {count}");
    }

    if let Some(replay) = summary.replay_summary.as_ref() {
        println!();
        println!("  Replay anomalies:");
        println!(
            "    WAL recoveries: {}  commits_replayed: {}  records_discarded: {}",
            replay.recovery_count, replay.total_commits_replayed, replay.total_records_discarded
        );
        println!(
            "    Aborts: {}  Serialization conflicts: {}",
            replay.aborts, replay.conflicts
        );
    }

    if let Some(repair) = summary.repair_summary.as_ref() {
        println!();
        println!("  Repair activity:");
        println!(
            "    Corruptions: {}  Blocks affected: {}",
            repair.corruptions_detected, repair.total_blocks_corrupt
        );
        println!(
            "    Repairs: {} attempted, {} succeeded, {} failed",
            repair.repairs_attempted, repair.repairs_succeeded, repair.repairs_failed
        );
        println!("    Scrub cycles: {}", repair.scrub_cycles);
    }

    if let Some(pressure) = summary.pressure_summary.as_ref() {
        println!();
        println!("  Pressure transitions:");
        println!(
            "    Backpressure activations: {}",
            pressure.backpressure_events
        );
        println!(
            "    Flush batches: {}  total blocks flushed: {}",
            pressure.flush_batches, pressure.total_blocks_flushed
        );
        println!("    Policy changes: {}", pressure.policy_changes);
    }
}

// ── Main command ───────────────────────────────────────────────────────────

pub fn evidence_cmd(
    path: &PathBuf,
    json: bool,
    event_type_filter: Option<&str>,
    tail: Option<usize>,
    preset: Option<&str>,
    summary: bool,
) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::evidence",
        "evidence",
        operation_id = %uuid_v4(),
        ledger = %path.display(),
        output_json = json,
        event_type_filter = event_type_filter.unwrap_or(""),
        tail = tail.unwrap_or(0),
        preset = preset.unwrap_or(""),
        summary = summary,
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::evidence", "evidence_start");

    // Validate preset name if provided.
    if let Some(preset_name) = preset {
        if preset_event_types(preset_name).is_none() {
            warn!(
                target: "ffs::cli::evidence",
                preset = preset_name,
                outcome = "rejected",
                error_class = "invalid_preset",
                "evidence_preset_rejected"
            );
            bail!(
                "unknown preset '{preset_name}'. Valid presets: {}",
                KNOWN_PRESETS.join(", ")
            );
        }
    }

    // Preset and event_type are mutually exclusive.
    if preset.is_some() && event_type_filter.is_some() {
        bail!("--preset and --event-type are mutually exclusive");
    }

    let records = load_evidence_records(path, event_type_filter, tail, preset)?;

    if summary {
        let s = build_summary(&records, preset);
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&s).context("serialize evidence summary")?
            );
        } else {
            print_summary(&s);
        }
    } else if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&records).context("serialize evidence records")?
        );
    } else if records.is_empty() {
        println!("No evidence records found.");
    } else {
        if let Some(preset_name) = preset {
            println!(
                "FrankenFS Evidence Ledger — preset: {preset_name} ({} records)",
                records.len()
            );
        } else {
            println!("FrankenFS Evidence Ledger ({} records)", records.len());
        }
        println!();
        for record in &records {
            print_evidence_record(record);
        }
    }

    info!(
        target: "ffs::cli::evidence",
        record_count = records.len(),
        preset = preset.unwrap_or(""),
        summary = summary,
        outcome = "success",
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "evidence_complete"
    );

    Ok(())
}

// ── Record loading ─────────────────────────────────────────────────────────

pub fn load_evidence_records(
    path: &PathBuf,
    event_type_filter: Option<&str>,
    tail: Option<usize>,
    preset: Option<&str>,
) -> Result<Vec<EvidenceRecord>> {
    let preset_types = preset.and_then(preset_event_types);

    let file = File::open(path)
        .with_context(|| format!("failed to open evidence ledger: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut records: Vec<EvidenceRecord> = Vec::new();
    let mut tail_records: VecDeque<EvidenceRecord> = VecDeque::new();
    let mut line_buf = Vec::new();

    loop {
        line_buf.clear();
        let bytes_read = reader
            .read_until(b'\n', &mut line_buf)
            .with_context(|| format!("failed reading evidence ledger line: {}", path.display()))?;
        if bytes_read == 0 {
            break;
        }
        let Ok(line) = std::str::from_utf8(&line_buf) else {
            // Preserve torn-write behavior: skip malformed byte sequences.
            continue;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(record) = serde_json::from_str::<EvidenceRecord>(line) else {
            // Preserve torn-write behavior: skip malformed lines.
            continue;
        };

        // Apply single event_type filter.
        if let Some(filter) = event_type_filter {
            if evidence_event_type_name(record.event_type) != filter {
                continue;
            }
        }

        // Apply preset multi-type filter.
        if let Some(types) = preset_types {
            if !types.contains(&record.event_type) {
                continue;
            }
        }

        if let Some(limit) = tail {
            if limit == 0 {
                continue;
            }
            if tail_records.len() == limit {
                tail_records.pop_front();
            }
            tail_records.push_back(record);
        } else {
            records.push(record);
        }
    }

    if tail.is_some() {
        Ok(tail_records.into_iter().collect())
    } else {
        Ok(records)
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn uuid_v4() -> String {
    // Minimal v4-like UUID for operation_id correlation.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut h);
    std::process::id().hash(&mut h);
    let bits = h.finish();
    format!("{bits:016x}")
}

pub const fn evidence_event_type_name(event_type: EvidenceEventType) -> &'static str {
    match event_type {
        EvidenceEventType::CorruptionDetected => "corruption_detected",
        EvidenceEventType::RepairAttempted => "repair_attempted",
        EvidenceEventType::RepairSucceeded => "repair_succeeded",
        EvidenceEventType::RepairFailed => "repair_failed",
        EvidenceEventType::ScrubCycleComplete => "scrub_cycle_complete",
        EvidenceEventType::PolicyDecision => "policy_decision",
        EvidenceEventType::SymbolRefresh => "symbol_refresh",
        EvidenceEventType::WalRecovery => "wal_recovery",
        EvidenceEventType::TransactionCommit => "transaction_commit",
        EvidenceEventType::TxnAborted => "txn_aborted",
        EvidenceEventType::SerializationConflict => "serialization_conflict",
        EvidenceEventType::VersionGc => "version_gc",
        EvidenceEventType::SnapshotAdvanced => "snapshot_advanced",
        EvidenceEventType::FlushBatch => "flush_batch",
        EvidenceEventType::BackpressureActivated => "backpressure_activated",
        EvidenceEventType::DirtyBlockDiscarded => "dirty_block_discarded",
        EvidenceEventType::DurabilityPolicyChanged => "durability_policy_changed",
        EvidenceEventType::RefreshPolicyChanged => "refresh_policy_changed",
        EvidenceEventType::MergeProofChecked => "merge_proof_checked",
        EvidenceEventType::MergeApplied => "merge_applied",
        EvidenceEventType::MergeRejected => "merge_rejected",
        EvidenceEventType::PolicySwitched => "policy_switched",
        EvidenceEventType::ContentionSample => "contention_sample",
    }
}

#[cfg(test)]
pub fn build_summary_for_test(records: &[EvidenceRecord], preset: Option<&str>) -> EvidenceSummary {
    build_summary(records, preset)
}

fn print_evidence_record(record: &EvidenceRecord) {
    let ts_secs = record.timestamp_ns / 1_000_000_000;
    let ts_nanos = record.timestamp_ns % 1_000_000_000;
    let event = evidence_event_type_name(record.event_type);

    print!(
        "  [{ts_secs}.{ts_nanos:09}] {event:<24} group={}",
        record.block_group
    );

    if let Some((start, end)) = record.block_range {
        print!(" blocks={start}..{end}");
    }

    print_evidence_record_event_payload(record);
    println!();
}

fn print_evidence_record_event_payload(record: &EvidenceRecord) {
    match record.event_type {
        EvidenceEventType::CorruptionDetected => print_corruption_payload(record),
        EvidenceEventType::RepairAttempted
        | EvidenceEventType::RepairSucceeded
        | EvidenceEventType::RepairFailed => print_repair_payload(record),
        EvidenceEventType::ScrubCycleComplete => print_scrub_cycle_payload(record),
        EvidenceEventType::PolicyDecision => print_policy_payload(record),
        EvidenceEventType::SymbolRefresh => print_symbol_refresh_payload(record),
        EvidenceEventType::WalRecovery => print_wal_recovery_payload(record),
        EvidenceEventType::TransactionCommit => print_transaction_commit_payload(record),
        EvidenceEventType::TxnAborted => print_txn_aborted_payload(record),
        EvidenceEventType::SerializationConflict => print_serialization_conflict_payload(record),
        EvidenceEventType::VersionGc => print_version_gc_payload(record),
        EvidenceEventType::SnapshotAdvanced => print_snapshot_advanced_payload(record),
        EvidenceEventType::FlushBatch => print_flush_batch_payload(record),
        EvidenceEventType::BackpressureActivated => print_backpressure_payload(record),
        EvidenceEventType::DirtyBlockDiscarded => print_dirty_block_discarded_payload(record),
        EvidenceEventType::DurabilityPolicyChanged => {
            print_durability_policy_changed_payload(record);
        }
        EvidenceEventType::RefreshPolicyChanged => print_refresh_policy_changed_payload(record),
        EvidenceEventType::MergeProofChecked => print_merge_proof_checked_payload(record),
        EvidenceEventType::MergeApplied => print_merge_applied_payload(record),
        EvidenceEventType::MergeRejected => print_merge_rejected_payload(record),
        EvidenceEventType::PolicySwitched => print_policy_switched_payload(record),
        EvidenceEventType::ContentionSample => print_contention_sample_payload(record),
    }
}

fn print_corruption_payload(record: &EvidenceRecord) {
    if let Some(c) = record.corruption.as_ref() {
        print!(
            " blocks_affected={} kind={} severity={}",
            c.blocks_affected, c.corruption_kind, c.severity
        );
    }
}

fn print_repair_payload(record: &EvidenceRecord) {
    if let Some(r) = record.repair.as_ref() {
        print!(
            " corrupt={} symbols={}/{} verify={}",
            r.corrupt_count, r.symbols_used, r.symbols_available, r.verify_pass
        );
        if let Some(reason) = r.reason.as_ref() {
            print!(" reason=\"{reason}\"");
        }
    }
}

fn print_scrub_cycle_payload(record: &EvidenceRecord) {
    if let Some(s) = record.scrub_cycle.as_ref() {
        print!(
            " scanned={} corrupt={} io_errors={} findings={}",
            s.blocks_scanned, s.blocks_corrupt, s.blocks_io_error, s.findings_count
        );
    }
}

fn print_policy_payload(record: &EvidenceRecord) {
    if let Some(p) = record.policy.as_ref() {
        print!(
            " posterior={:.4} overhead={:.3} risk_bound={:.1e} decision=\"{}\"",
            p.corruption_posterior, p.overhead_ratio, p.risk_bound, p.decision
        );
    }
}

fn print_symbol_refresh_payload(record: &EvidenceRecord) {
    if let Some(s) = record.symbol_refresh.as_ref() {
        print!(
            " gen={}→{} symbols={}",
            s.previous_generation, s.new_generation, s.symbols_generated
        );
    }
}

fn print_wal_recovery_payload(record: &EvidenceRecord) {
    if let Some(w) = record.wal_recovery.as_ref() {
        print!(
            " commits={} versions={} discarded={} valid={}/{}",
            w.commits_replayed,
            w.versions_replayed,
            w.records_discarded,
            w.wal_valid_bytes,
            w.wal_total_bytes
        );
        if w.used_checkpoint {
            if let Some(seq) = w.checkpoint_commit_seq {
                print!(" checkpoint_seq={seq}");
            }
        }
    }
}

fn print_transaction_commit_payload(record: &EvidenceRecord) {
    if let Some(t) = record.transaction_commit.as_ref() {
        print!(
            " txn_id={} commit_seq={} write_set_size={} duration_us={}",
            t.txn_id, t.commit_seq, t.write_set_size, t.duration_us
        );
    }
}

fn print_txn_aborted_payload(record: &EvidenceRecord) {
    if let Some(t) = record.txn_aborted.as_ref() {
        let reason = serde_json::to_value(t.reason)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("{:?}", t.reason));
        print!(
            " txn_id={} reason={reason} read_set_size={} write_set_size={}",
            t.txn_id, t.read_set_size, t.write_set_size
        );
        if let Some(detail) = t.detail.as_ref() {
            print!(" detail=\"{detail}\"");
        }
    }
}

fn print_serialization_conflict_payload(record: &EvidenceRecord) {
    if let Some(c) = record.serialization_conflict.as_ref() {
        print!(" txn_id={} conflict_type={}", c.txn_id, c.conflict_type);
        if let Some(conflicting_txn) = c.conflicting_txn {
            print!(" conflicting_txn={conflicting_txn}");
        }
    }
}

fn print_version_gc_payload(record: &EvidenceRecord) {
    if let Some(gc) = record.version_gc.as_ref() {
        print!(
            " block_id={} versions_freed={} oldest_retained_commit_seq={}",
            gc.block_id, gc.versions_freed, gc.oldest_retained_commit_seq
        );
    }
}

fn print_snapshot_advanced_payload(record: &EvidenceRecord) {
    if let Some(s) = record.snapshot_advanced.as_ref() {
        print!(
            " old_commit_seq={} new_commit_seq={} versions_eligible={}",
            s.old_commit_seq, s.new_commit_seq, s.versions_eligible
        );
    }
}

fn print_flush_batch_payload(record: &EvidenceRecord) {
    if let Some(f) = record.flush_batch.as_ref() {
        print!(
            " blocks_flushed={} bytes_written={} flush_duration_us={}",
            f.blocks_flushed, f.bytes_written, f.flush_duration_us
        );
    }
}

fn print_backpressure_payload(record: &EvidenceRecord) {
    if let Some(b) = record.backpressure_activated.as_ref() {
        print!(
            " dirty_ratio={:.4} threshold={:.4}",
            b.dirty_ratio, b.threshold
        );
    }
}

fn print_dirty_block_discarded_payload(record: &EvidenceRecord) {
    if let Some(d) = record.dirty_block_discarded.as_ref() {
        let reason = serde_json::to_value(d.reason)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("{:?}", d.reason));
        print!(
            " block_id={} txn_id={} reason={reason}",
            d.block_id, d.txn_id
        );
    }
}

fn print_durability_policy_changed_payload(record: &EvidenceRecord) {
    if let Some(d) = record.durability_policy_changed.as_ref() {
        print!(
            " old_overhead={:.4} new_overhead={:.4} posterior=({:.3},{:.3},{:.4})",
            d.old_overhead, d.new_overhead, d.posterior_alpha, d.posterior_beta, d.posterior_mean
        );
    }
}

fn print_refresh_policy_changed_payload(record: &EvidenceRecord) {
    if let Some(p) = record.refresh_policy_changed.as_ref() {
        print!(
            " policy=\"{}\"->\"{}\" policy_group={}",
            p.old_policy, p.new_policy, p.block_group
        );
    }
}

fn print_merge_proof_checked_payload(record: &EvidenceRecord) {
    if let Some(p) = record.merge_proof_checked.as_ref() {
        print!(
            " txn={} block={} proof={} valid={}",
            p.txn_id, p.block_id, p.proof_variant, p.valid
        );
        if let Some(reason) = p.rejection_reason.as_ref() {
            print!(" reason={reason}");
        }
    }
}

fn print_merge_applied_payload(record: &EvidenceRecord) {
    if let Some(p) = record.merge_applied.as_ref() {
        print!(
            " txn={} merged_blocks={} bytes={} proof={}",
            p.txn_id, p.merged_block_count, p.combined_write_set_bytes, p.proof_variant
        );
    }
}

fn print_merge_rejected_payload(record: &EvidenceRecord) {
    if let Some(p) = record.merge_rejected.as_ref() {
        print!(
            " txn={} block={} proof={} reason={}",
            p.txn_id, p.block_id, p.proof_variant, p.reason
        );
    }
}

fn print_policy_switched_payload(record: &EvidenceRecord) {
    if let Some(p) = record.policy_switched.as_ref() {
        print!(
            " from={} to={} delta={:.6} trigger={}",
            p.from_policy, p.to_policy, p.expected_loss_delta, p.trigger_reason
        );
    }
}

fn print_contention_sample_payload(record: &EvidenceRecord) {
    if let Some(p) = record.contention_sample.as_ref() {
        print!(
            " conflict_rate={:.4} merge_success={:.4} abort_rate={:.4} commits={} policy={}",
            p.conflict_rate,
            p.merge_success_rate,
            p.abort_rate,
            p.total_commits,
            p.effective_policy
        );
    }
}
