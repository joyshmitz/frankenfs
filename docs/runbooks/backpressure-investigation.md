# Backpressure and Degradation Investigation Runbook

Step-by-step procedure for investigating backpressure events, degraded-mode
transitions, and performance incidents in FrankenFS mounted filesystems.

## Prerequisites

- ffs-cli binary built with `--release`
- Active or recent FrankenFS mount session
- `RUST_LOG=info` or higher for structured log capture
- Access to the mount command's stderr (log output)

## Quick Reference: Pressure Investigation Tree

```
Performance degradation observed
│
├─ Is the mount in degraded mode?
│   Check logs for: degradation_level_changed
│   │
│   ├─ YES → Go to Section 2 (Degradation Analysis)
│   │
│   └─ NO → Go to Section 3 (Non-Degradation Bottleneck)
│
├─ Are backpressure events firing?
│   Check logs for: backpressure_decision
│   │
│   ├─ Throttle events → Transient pressure. Section 4.
│   ├─ Shed events → Overload. Section 5.
│   └─ No events → Not a backpressure issue. Check I/O.
│
└─ Is the mount runtime mode correct?
    Check logs for: mount_runtime_mode_selected
    └─ Section 1 (Verify Configuration)
```

## Section 1: Verify Mount Configuration

Filter the evidence ledger for pressure-related events:

```bash
ffs evidence --preset pressure-transitions <image-path>
```

This filters for backpressure, flush batch, and policy change events.

Check which runtime mode is active (use `ffs mount --runtime-mode` to select):

```bash
# In mount logs (stderr):
grep mount_runtime_mode_selected <mount-log>
```

**Expected fields in the log event:**
- `runtime_mode`: standard, managed, or per-core
- `allow_other`: FUSE allow_other flag
- `auto_unmount`: FUSE auto_unmount flag
- `read_write`: whether mount is read-write

**Common misconfigurations:**
- Using `standard` mode for high-concurrency workloads (should use `managed` or `per-core`)
- Using `--managed-unmount-timeout-secs` with `standard` mode (rejected at startup)

To verify runtime mode was correctly selected:
```bash
grep "mount_runtime_mode_selected\|mount_runtime_mode_rejected" <mount-log>
```

## Section 2: Degradation Analysis

FrankenFS uses a degradation state machine with levels:

| Level | Meaning | Effect |
|-------|---------|--------|
| Normal | System healthy | Full throughput |
| Elevated | Approaching limits | Monitoring increased |
| Degraded | Under pressure | Non-critical ops deprioritized |
| Emergency | Critical overload | Aggressive shedding active |

Check current degradation level transitions:

```bash
grep "degradation_level_changed\|degradation_fsm" <mount-log>
```

**If stuck in degraded/emergency:**
1. Check dirty page count and flush backlog
2. Check if the block cache is thrashing (high eviction rate)
3. Verify underlying device I/O latency is normal

## Section 3: Non-Degradation Bottleneck

If no degradation events are firing but performance is poor:

1. **Check per-core dispatch balance** (if using per-core mode):
   ```bash
   grep "per_core\|core_metrics\|work_steal" <mount-log>
   ```

2. **Check block cache hit rate:**
   ```bash
   grep "cache_hit\|cache_miss\|cache_evict" <mount-log>
   ```

3. **Check WAL writer throughput:**
   ```bash
   grep "wal_write\|group_commit\|sync_complete" <mount-log>
   ```

## Section 4: Throttle Events

Throttle means the system is applying backpressure by slowing requests:

```bash
grep "backpressure.*throttle\|backpressure_decision" <mount-log>
```

**Normal behavior:** Occasional throttle events during burst writes.

**Concerning patterns:**
- Sustained throttle events (> 10 per second)
- Throttle events with increasing delay values
- Throttle events correlating with client-visible latency spikes

**Resolution:**
1. Check if the underlying device is slow (`iostat`, `iotop`)
2. Increase the WAL buffer size if available
3. Consider switching to `per-core` runtime mode for better parallelism

## Section 5: Shed Events

Shed means the system is rejecting requests to prevent cascading failure:

```bash
grep "backpressure.*shed\|request_shed" <mount-log>
```

**Shed events are serious.** They mean clients receive EAGAIN/EBUSY errors.

**Immediate actions:**
1. **Reduce write pressure** — if possible, pause batch writes
2. **Check for runaway processes** — identify clients generating excessive I/O
3. **Check device health** — shed often indicates underlying device too slow

**If shed events persist after load reduction:**
1. Check degradation FSM — system may be stuck in Emergency level
2. Unmount cleanly and re-mount to reset state
3. Investigate device-level issues before re-mounting

## Section 6: Safe Escalation Checkpoints

Before escalating, gather:

1. **Structured logs from the mount session:**
   ```bash
   RUST_LOG=debug ffs mount <args> 2> mount_debug.log
   ```

2. **Image health check:**
   ```bash
   ffs info --mvcc <image-path>
   ffs scrub <image-path>
   ```

3. **System state:**
   ```bash
   iostat -x 1 5  # I/O statistics
   free -h         # Memory pressure
   nproc           # CPU count for per-core mode
   ```

## Safe Rollback Procedure

If the mount is in an unrecoverable degraded state:

1. **Graceful unmount:**
   ```bash
   fusermount3 -u <mount-point>
   ```

2. **If graceful unmount hangs (> 30s):**
   ```bash
   fusermount3 -z -u <mount-point>  # Lazy unmount
   ```

3. **Verify image integrity before re-mount:**
   ```bash
   ffs scrub <image-path>
   ffs info --mvcc <image-path>
   ```

4. **Re-mount with adjusted configuration** (e.g., different runtime mode).

## Stop Conditions

- **Stop investigation** if shed events stop after load reduction — transient overload
- **Escalate to hardware team** if device I/O latency is > 10x normal
- **Do not force-kill the mount process** — always use fusermount3 for clean shutdown
