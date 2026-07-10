# bd-ddryj — parked lever: bound the cold-read fan-out

Parked 2026-07-10 by BlackThrush (`cc_ffs`). **Not applied. Not compiled. Not perf-measured
in-tree.** Parked per the disk-constraint fallback ("design the lever, save the patch under
`tests/artifacts/perf/` and park it") because the in-tree proof is blocked — see *Blocker* below.

## What is actually the lever (corrected)

The cold-read cost is kernel page-cache `xa_lock` contention while inserting readahead folios
(`page_cache_ra_unbounded` / `page_cache_ra_order`). Two candidate fixes were measured. **Only one
of them moves wall time.**

| candidate | insertions | wall effect | verdict |
| --- | --- | --- | --- |
| **bound the read fan-out** (rayon default `nproc`=64 → 16) | 27,174 → 17,914 | **1.24x faster cold**, 7/7 paired reps, p=0.0156, on the *real* `ffs-cli` binary; warm also 1.48x | **THE LEVER** |
| per-reader `struct file` (kill `Arc<File>`) | 16,244 → 3,896 (**4.2x**) at production 128 KiB chunk | 1.02x median / 1.05x min, 7/9 paired reps, **p=0.18 — NOT significant** | CPU-only; not a latency fix |

### Self-correction (recorded so nobody re-derives the wrong number)

An earlier note claimed per-thread fd was worth **1.41x**. That was measured in the raw `pread`
harness at a **1 MiB** chunk, which `FileByteDevice` never uses. Re-measured at frankenfs's real
**128 KiB** default, the wall win collapses to noise (p=0.18) even though insertions still fall 4.2x.

This is the third independent confirmation that **folio insertions drive lock-wait (CPU), not
throughput (wall)** — consistent with `r(ins/MiB, MiB/s)` = +0.15 (T=16) / +0.25 (T=64), and with the
T=64 counter-example where 2.4x fewer insertions and 3.0x less lock wait ran 1% *slower*.

## The change

Bound the read fan-out instead of inheriting the global rayon pool. Fan-out sites, all on the global
pool:

* `crates/ffs-core/src/lib.rs:10108` — `jobs.into_par_iter().map(exec_job)`
* `crates/ffs-core/src/lib.rs:12677` — same
* `crates/ffs-core/src/lib.rs:12819` — `specs.into_par_iter().map(read_run)`

Sketch (do **not** apply blind — the pool must be process-wide and lazily built):

```rust
// A dedicated, bounded pool for read fan-out. The global rayon pool is nproc-wide
// (64 here), which over-parallelizes buffered reads: every worker preads the same
// inode, so they serialize inserting folios into one address_space xarray.
static READ_POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();

fn read_pool() -> &'static rayon::ThreadPool {
    READ_POOL.get_or_init(|| {
        let n = std::env::var("FFS_READ_PARALLELISM")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or_else(|| {
                let cpus = std::thread::available_parallelism().map_or(4, NonZero::get);
                (cpus / 4).clamp(4, 16)   // 16 is the measured optimum on a 64-core box
            });
        rayon::ThreadPoolBuilder::new().num_threads(n).build().expect("read pool")
    })
}

// at each fan-out site:
read_pool().install(|| jobs.into_par_iter().map(exec_job).collect())
```

### Why not a global `RAYON_NUM_THREADS`

Scrub, walk and repair share the global pool. Shrinking it globally would perturb lanes that are not
read-bound. A dedicated pool confines the change to the read path.

### Why `nproc/4` clamped to `[4,16]` rather than a hard 16

16 is the optimum **on this 64-core box**. The optimum is contention-dependent and will move with core
count and device speed. It must be re-measured on a second machine before any constant is hardcoded.

## Null control + provenance (2026-07-10, decision: TAKE IT)

**Null control** — the identical arm registered twice (`T=16` vs `T=16`), interleaved within each
rep, `drop_caches` between, 9 reps, per-rep startup subtracted:

| arm | median | cv |
| --- | --- | --- |
| A (T=16) | 35.20 ms | 3.8% |
| B (T=16, identical to A) | 34.40 ms | 10.4% |
| **null ratio A/B** | **1.0232x** (min-based 1.0132x) | — |

No order effect: A beats B in 4/9 reps, p=1.0000. (For reference, franken_whisper's null control read
**1.1163x at cv 29.0%**; `drop_caches` + within-rep interleaving + a quiet box tighten it to 1.02x.)

**The effect** — T=64 (shipped) vs T=16 (capped), same session, same interleave:

| arm | median | cv |
| --- | --- | --- |
| C (T=64, as shipped) | 42.57 ms | 4.6% |
| **effect ratio C/A** | **1.2095x** (min-based 1.1897x) | — |

Paired: A beats C in **9/9** reps, **p=0.0039**. **Effect exceeds the null-control deviation by ~8x**
(0.2095 vs 0.0232). Harness-corrected against the kernel: **1.40x → 1.13x**.

**Provenance:** binary `ffs-cli`
`sha256=03b7456d8cd6fa118bd214b2fdf8a03e56cac79e6768b7311613b039c8ae81eb` (`release-perf`,
55,453,584 B, built 2026-07-10 04:02:59); allocator `tikv_jemallocator`; self-time of the function
under test `native_queued_spin_lock_slowpath` **42.27%** at T=64 → **9.32%** at T=16 (the mechanism the
lever removes); worker = **local host** (`perf` + `drop_caches` require root, so no remote worker is
possible for this measurement); `rch` verification worker `ovh-a`; cv per arm 3.8 / 10.4 / 4.6%.

**Verdict: the lever is real and material.** It is the only remaining wall lever in the cold-read lane.

## Gates required before this may land

1. `sha256` byte-identity per fixture (extent / indirect / fragmented) against the kernel mount.
2. Cold A/B (`drop_caches=3` per rep, arms **interleaved within each rep**, paired sign test) — the
   effect is cold-path, so a criterion bench cannot express it.
3. Warm A/B — warm also prefers 16 (read ms: 8 → 9.0, **16 → 8.5**, 64 → 12.6), so no regression is
   expected, but it must be shown.
4. Conformance 100/0/2.
5. Self-time per arm recorded in the ledger entry (ledger-integrity rule, frankenmermaid `5feb977`).

## Blocker (why this is parked, not landed)

Proving it in-tree needs a modified `ffs-cli` binary run **locally** under `drop_caches` (root). Under
the active disk constraint local `cargo build` is forbidden, and remote build cannot return the binary:

* `env -u CARGO_TARGET_DIR rch exec -- cargo build --profile release-perf -p ffs-cli` still yields
  `ARTIFACT_MISSING`. `env -u` *does* unset the var in the child (verified), yet rch still logs
  *"Custom CARGO_TARGET_DIR artifacts retrieved: 5 files, 473 bytes"* and the 55 MB binary never lands
  in `./target/release-perf/`. So rch resolves that path independently of the caller's environment.
* Separately, `rch exec` fails **open**: without `RCH_REQUIRE_REMOTE=1` it silently runs the build
  locally when it cannot reserve a remote slot, which is what drained the disk.

A criterion bench cannot substitute: cold-path measurement needs `drop_caches` between reps, which a
remote worker cannot do.

**Unblock by either** (a) fixing rch artifact retrieval so a remote `cargo build` returns the binary
(with `RCH_REQUIRE_REMOTE=1` to fail closed), or (b) granting one local build.

Operational mitigation available today with zero code: **`RAYON_NUM_THREADS=16`**.
