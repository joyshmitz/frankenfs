use anyhow::{Context, Result};
use ffs_repair::evidence::{EvidenceEventType, EvidenceRecord};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::Instant;
use tracing::{info, info_span};

pub fn evidence_cmd(
    path: &PathBuf,
    json: bool,
    event_type_filter: Option<&str>,
    tail: Option<usize>,
) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::evidence",
        "evidence",
        ledger = %path.display(),
        output_json = json,
        event_type_filter = event_type_filter.unwrap_or(""),
        tail = tail.unwrap_or(0)
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::evidence", "evidence_start");

    let records = load_evidence_records(path, event_type_filter, tail)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&records).context("serialize evidence records")?
        );
    } else {
        if records.is_empty() {
            println!("No evidence records found.");
            return Ok(());
        }
        println!("FrankenFS Evidence Ledger ({} records)", records.len());
        println!();
        for record in &records {
            print_evidence_record(record);
        }
    }

    info!(
        target: "ffs::cli::evidence",
        record_count = records.len(),
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "evidence_complete"
    );

    Ok(())
}

pub fn load_evidence_records(
    path: &PathBuf,
    event_type_filter: Option<&str>,
    tail: Option<usize>,
) -> Result<Vec<EvidenceRecord>> {
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
        if let Some(filter) = event_type_filter {
            if evidence_event_type_name(record.event_type) != filter {
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

const fn evidence_event_type_name(event_type: EvidenceEventType) -> &'static str {
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
    }
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
