# Performance Delta Closeout

- Closeout: `bd-rchk5.4-performance-delta-closeout-v1`
- Source bead: `bd-rchk5.4`
- Generated at: `2026-05-03T21:35:00Z`
- Valid: `true`
- Rows: `14`
- Rows requiring follow-up: `10`

## Classification Counts

- `improved`: 4
- `missing_reference`: 5
- `pending_capability`: 1
- `regression`: 3
- `unmeasured`: 1

## Follow-Up Beads

- `bd-9vzzk`
- `bd-rchk5.5`
- `bd-rchk5.6`
- `bd-rchk5.7`
- `bd-rchk5.8`
- `bd-t21em`

## Rows

| Operation | Class | p99 delta | Throughput delta | Follow-up | Rationale |
|---|---:|---:|---:|---|---|
| `block_cache_arc_sequential_scan` | `improved` | -99.861% | 76057.327% | `n/a` | same-operation comparison against benchmarks/baselines/history/20260406.json; classified as improved |
| `block_cache_arc_mixed_seq70_hot30` | `improved` | -99.864% | 76750.504% | `n/a` | same-operation comparison against benchmarks/baselines/history/20260406.json; classified as improved |
| `block_cache_sharded_arc_concurrent_hot_read_64threads` | `missing_reference` | n/a | n/a | `bd-rchk5.8` | measured in benchmarks/baselines/history/20260503-sharded-arc-hot64.json but no checked-in same-operation reference baseline exists |
| `block_cache_sharded_s3fifo_concurrent_hot_read_64threads` | `missing_reference` | n/a | n/a | `bd-rchk5.8` | measured in benchmarks/baselines/history/20260503-sharded-s3fifo-hot64.json but no checked-in same-operation reference baseline exists |
| `cli_metadata_parse_conformance` | `missing_reference` | n/a | n/a | `bd-rchk5.8` | measured in benchmarks/baselines/history/20260503-bd-rchk5-2-metadata-parse.json but no checked-in same-operation reference baseline exists |
| `mvcc_contention_4writers` | `improved` | -100.000% | 194326409.871% | `n/a` | same-operation comparison against benchmarks/baselines/history/20260406.json; classified as improved |
| `raptorq_encode_group_16blocks` | `improved` | -99.997% | 3783641.954% | `n/a` | same-operation comparison against benchmarks/baselines/history/20260406.json; classified as improved |
| `repair_symbol_refresh_staleness_latency` | `missing_reference` | n/a | n/a | `bd-rchk5.8` | measured in benchmarks/baselines/history/20260503-bd-rchk5-2-refresh-staleness.json but no checked-in same-operation reference baseline exists |
| `wal_commit_4k_sync` | `missing_reference` | n/a | n/a | `bd-rchk5.8` | measured in benchmarks/baselines/history/20260503-bd-rchk5-2-wal-commit.json but no checked-in same-operation reference baseline exists |
| `mount_warm` | `pending_capability` | n/a | n/a | `bd-9vzzk` | artifact benchmarks/baselines/history/20260503-bd-rchk5-3-mount-warm-pending.json is pending because required host capability was unavailable |
| `mount_cold` | `regression` | 374.884% | -77.863% | `bd-rchk5.5` | comparison artifact verdict=slower_than_reference; classified as regression |
| `mount_warm` | `regression` | 414.996% | -80.118% | `bd-rchk5.6` | comparison artifact verdict=slower_than_reference; classified as regression |
| `mount_recovery` | `regression` | 111.927% | -50.303% | `bd-rchk5.7` | comparison artifact verdict=slower_than_reference; classified as regression |
| `long_campaign_writeback_cache_smoke` | `unmeasured` | n/a | n/a | `bd-t21em` | Long-campaign writeback-cache performance remains deferred until soak stop conditions and flake root-cause classification are implemented. |
