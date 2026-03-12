# Corruption Detection and Repair Runbook

Step-by-step procedure for detecting, triaging, and recovering from filesystem
corruption in FrankenFS images.

## Prerequisites

- ffs-cli binary built (`cargo build -p ffs-cli --release`)
- The filesystem image accessible at a known path
- Sufficient disk space for a backup copy of the image
- `RUST_LOG=info` for structured log output

## Quick Reference: Corruption Decision Workflow

```
Suspicion of corruption (bad read, mount failure, etc.)
│
├─ Step 1: Run scrub
│   ffs scrub <image-path>
│   │
│   ├─ 0 corrupted blocks → Image clean. Monitor.
│   │
│   └─ N corrupted blocks detected
│       │
│       ├─ Step 2: Check evidence ledger
│       │   ffs evidence <image-path>
│       │
│       ├─ Step 3: Decide on repair
│       │   ├─ Corruption is in non-critical metadata?
│       │   │   └─ Repair: ffs repair <image-path>
│       │   │
│       │   ├─ Corruption is in critical superblock/journal?
│       │   │   └─ Escalate. Manual recovery required.
│       │   │
│       │   └─ Unknown extent?
│       │       └─ Run repair with evidence capture.
│       │
│       └─ Step 4: Verify repair
│           ffs scrub <image-path>
│           Expected: 0 corrupted blocks
```

## Section 1: Detection — Run Scrub

```bash
ffs scrub <image-path>
```

The scrub command validates all reachable metadata blocks against their checksums.

**Output interpretation:**

| Scrub Result | Meaning | Action |
|-------------|---------|--------|
| `corruption_count: 0` | Image clean | No action needed |
| `corruption_count: N, all in data blocks` | Data corruption | Repair if RaptorQ symbols available |
| `corruption_count: N, includes metadata` | Metadata corruption | Repair with caution, verify after |

**Structured log markers emitted during scrub:**

- `scrub_and_recover` — scrub engine start
- `scrub complete` — scrub finished with corruption count

## Section 2: Evidence — Check the Ledger

```bash
ffs evidence <image-path>
```

The evidence ledger records all repair and recovery events. Check for:

- Previous corruption detection events
- Previous repair attempts and outcomes
- Symbol refresh history

## Section 3: Repair Decision

### When to repair automatically

- Corruption is in data blocks with available RaptorQ parity symbols
- Evidence shows this is a first-time corruption (not recurring)
- Image has been backed up

### When to escalate

- Corruption is in the superblock
- Corruption recurs after repair (possible hardware issue)
- Journal/WAL corruption (use replay-failure-triage.md instead)

### Running repair

1. **Backup first:**
   ```bash
   cp <image-path> <image-path>.pre-repair
   ```

2. **Run repair:**
   ```bash
   ffs repair <image-path>
   ```

3. **Check structured logs for repair events:**
   ```bash
   RUST_LOG=info ffs repair <image-path> 2>&1 | grep -E "scrub|repair|symbol_refresh"
   ```

**Key structured log markers during repair:**

| Marker | Meaning |
|--------|---------|
| `scrub_and_recover` | Repair pipeline started |
| `scrub complete` | Scrub phase finished |
| `symbol_refresh_complete` | Fresh parity symbols generated |
| `refresh_staleness_timeout_triggered` | Symbols were stale, refreshed before repair |
| `refresh_group_marked_dirty` | Write churn invalidated a symbol group |

## Section 4: Post-Repair Verification

1. **Re-run scrub to confirm zero corruption:**
   ```bash
   ffs scrub <image-path>
   ```

2. **Check image opens cleanly:**
   ```bash
   ffs info <image-path>
   ```

3. **If using MVCC, check replay health:**
   ```bash
   ffs info --mvcc <image-path>
   ```

4. **Mount read-only to verify data accessibility:**
   ```bash
   ffs mount --read-only <image-path> /tmp/verify_mount
   ls /tmp/verify_mount/
   fusermount3 -u /tmp/verify_mount
   ```

## Section 5: Recurring Corruption

If corruption recurs after repair:

1. **Check for hardware issues:**
   - Run `smartctl` on the underlying device
   - Check kernel logs for I/O errors: `dmesg | grep -i error`

2. **Check for write churn invalidating symbols:**
   ```bash
   RUST_LOG=info ffs scrub <image-path> 2>&1 | grep dirty_groups
   ```
   High dirty_groups count indicates symbols need refresh before repair.

3. **Force symbol refresh before repair:**
   The repair pipeline automatically refreshes stale symbols (staleness timeout).
   If manual control is needed, check the `RefreshPolicy` (Eager/Lazy/Adaptive)
   configured for the image.

## Stop Conditions

- **Stop repair** if the backup was not created first
- **Stop and escalate** if corruption recurs more than twice in the same location
- **Stop and restore from backup** if repair makes corruption worse (more blocks affected)
