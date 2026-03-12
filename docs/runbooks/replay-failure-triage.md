# Replay Failure Triage Runbook

Step-by-step procedure for diagnosing and recovering from WAL replay failures
during FrankenFS open/mount operations.

## Prerequisites

- Access to the repository with `cargo` and `rch` configured
- The ffs-cli binary built (`cargo build -p ffs-cli --release`)
- The filesystem image file accessible at a known path
- `RUST_LOG=info` or higher set for structured log output

## Quick Reference: Replay Failure Decision Tree

```
ffs open/mount fails with replay error
│
├─ Is the error "WAL file not found"?
│   └─ YES → Clean open. WAL was already consumed or never created.
│            Action: Open with --read-only to verify image integrity.
│
├─ Is the error "checksum mismatch" during replay?
│   └─ YES → WAL corruption detected.
│            Action: Go to Section 3 (Corruption Recovery).
│
├─ Is the error "truncated record" during replay?
│   └─ YES → Torn write from crash during commit.
│            Action: Replay engine should auto-skip truncated tail.
│            If persistent, go to Section 4 (Manual Recovery).
│
├─ Is the error "monotonicity violation"?
│   └─ YES → commit_seq went backward — WAL structural corruption.
│            Action: Go to Section 3 (Corruption Recovery).
│
└─ Unknown replay error
    └─ Collect structured logs and escalate. Go to Section 5.
```

## Section 1: Inspect Replay State

Run the info command to see WAL recovery telemetry:

```bash
ffs info --mvcc <image-path>
```

Expected output includes:

```
WAL Replay:
  Outcome: <Replayed|CleanOpen|CorruptionDetected>
  Commits replayed: N
  Versions replayed: N
  Records discarded: N
  WAL valid bytes: N
  WAL total bytes: N
  Used checkpoint: true/false
```

**Key indicators:**
- `Records discarded > 0` → torn writes were detected and skipped (normal after crash)
- `WAL valid bytes < WAL total bytes` → trailing corruption/truncation
- `Used checkpoint: true` → recovery started from checkpoint, not beginning

## Section 2: Check Structured Logs

Run with verbose logging to capture replay lifecycle:

```bash
RUST_LOG=debug ffs info --mvcc <image-path> 2>&1 | grep wal_replay
```

**Critical log markers to look for:**

| Marker | Meaning |
|--------|---------|
| `wal_replay_start` | Replay engine initialized |
| `wal_replay_apply` | Record successfully applied |
| `wal_replay_empty` | WAL was empty (clean open) |
| `wal_replay_truncated_tail` | Truncated record at end (expected after crash) |
| `wal_replay_corrupt_tail` | Corrupt record at end (recoverable) |
| `wal_replay_truncated_fail_fast` | Truncated record NOT at tail (structural damage) |
| `wal_replay_corrupt_fail_fast` | Corrupt record NOT at tail (structural damage) |
| `wal_replay_monotonicity_violation` | commit_seq regression detected |
| `wal_replay_done` | Replay completed with outcome summary |

## Section 3: Corruption Recovery

If the WAL has internal corruption (not just a truncated tail):

1. **Preserve the original image:**
   ```bash
   cp <image-path> <image-path>.backup
   ```

2. **Attempt read-only open** to check data integrity:
   ```bash
   ffs info <image-path>
   ```

3. **Run scrub** to detect filesystem-level corruption:
   ```bash
   ffs scrub <image-path>
   ```

4. **If scrub reports issues, run repair:**
   ```bash
   ffs repair <image-path>
   ```

5. **Verify the repaired image:**
   ```bash
   ffs info --mvcc <image-path>
   ```

## Section 4: Manual Recovery for Persistent Truncation

If the replay engine consistently fails on truncated records:

1. **Check the WAL size vs valid bytes** using `ffs info --mvcc`
2. **If `WAL valid bytes == 0`**, the WAL is entirely corrupt — recovery requires the last checkpoint
3. **Check if a checkpoint exists** in the structured logs (`Used checkpoint: true/false`)
4. **If checkpoint exists**, the version store should be recoverable to the checkpoint state

## Section 5: Escalation

If none of the above resolves the issue:

1. **Collect full structured logs:**
   ```bash
   RUST_LOG=trace ffs info --mvcc <image-path> 2> replay_debug.log
   ```

2. **Capture the crash matrix report** (if reproducible):
   ```bash
   cargo test -p ffs-mvcc -- crash_matrix --nocapture 2> crash_matrix.log
   ```

3. **Document:**
   - Image path and size
   - Last known operation before failure
   - Structured log output
   - Crash matrix results

## Stop Conditions

- **Stop recovery** if the image backup is lost and corruption persists after repair
- **Stop manual intervention** if `ffs scrub` reports zero corruption after replay skip
- **Escalate immediately** if `wal_replay_monotonicity_violation` appears (indicates WAL structural damage)
