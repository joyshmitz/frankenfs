# bd-xmh5g.9 rejected: sharded MVCC publication gate CAS fast path

Agent: PlumFern
Date: 2026-06-02
Crate: ffs-mvcc
Target: `crates/ffs-mvcc/src/sharded.rs` `CommitPublicationGate::publish`

## Profile-backed target

Baseline profile command:

```text
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary timeout 900 rch exec -- cargo bench --profile release-perf -p ffs-mvcc --bench wal_throughput -- --warm-up-time 1 --measurement-time 2 --sample-size 20 --noplot
```

Worker: `vmi1293453`

Top ranked rows:

| Rank | Benchmark | Mean | Interval |
| --- | --- | ---: | --- |
| 1 | `sharded_mvcc_disjoint_32writers` | 124.05 ms | [109.49, 139.00] ms |
| 2 | `sharded_mvcc_disjoint_16writers` | 27.005 ms | [23.704, 30.690] ms |
| 3 | `persistent_mvcc_checkpoint_256blocks_8versions` | 11.790 ms | [11.629, 11.955] ms |

Source symptom: every publication path took `wait_lock` even when
`completed_commit == commit_seq - 1`, serializing the apparently ordered
common case across otherwise disjoint writers.

## Alien primitive card

Primitive: ordered publication / RCU-style fast path, using one atomic
`compare_exchange(predecessor, commit_seq)` for the already-ready predecessor
case plus the existing condvar path for out-of-order commits.

Alien-graveyard match:

- `alien_cs_graveyard.md` section 14.8: RCU/QSBR for lock-free hot metadata reads.
- `alien_cs_graveyard.md` section 14.9: seqlock-style optimistic fast paths for infrequently updated coordination state.
- `alien_cs_graveyard.md` section 14.12: concurrency proof obligations for linearizability and progress.

Expected value before implementation: Impact 3, Confidence 2, Effort 1,
EV 6.0, fallback to original mutex/condvar publication if either proof or
benchmark failed.

## Candidate lever

One production lever was tried:

- Add an atomic CAS fast path to `CommitPublicationGate::publish`.
- Notify waiters only if `waiters > 0`.
- Keep the existing lock/condvar fallback for out-of-order publication.
- Add a second completed check after waiter registration to avoid sleeping
  after a predecessor had already published.

## Rebench result

Rebench command:

```text
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary timeout 900 rch exec -- cargo bench --profile release-perf -p ffs-mvcc --bench wal_throughput -- sharded_mvcc_disjoint_32writers --warm-up-time 1 --measurement-time 2 --sample-size 20 --noplot
```

Worker: `vmi1227854`

Candidate result:

```text
sharded_mvcc_disjoint_32writers time: [130.20 ms 149.03 ms 170.53 ms]
```

Decision: rejected. The candidate was slower than the profile baseline mean
of 124.05 ms and therefore scored 0.0 under the Score >= 2.0 rule. The
production code was restored to the original mutex/condvar implementation.

Likely cause: the extra atomic CAS path and waiter/lock interaction did not
reduce the dominant cost in this workload, and the notification race avoidance
added enough synchronization to lose.

## Isomorphism proof

The candidate was not shipped. During evaluation, the intended isomorphism was:

- Ordering preserved: the CAS could only advance from `commit_seq - 1` to
  `commit_seq`; out-of-order commits still waited for the predecessor.
- Tie-breaking: N/A, commit sequence allocation already defines total order.
- Floating point: N/A.
- RNG: N/A.
- Snapshot visibility: unchanged because installed versions remain hidden
  behind `completed_commit`; restored implementation is the original behavior.
- Golden outputs: verified from `conformance/golden` with
  `sha256sum -c checksums.sha256`; all 10 listed files were `OK`.

## Validation

Production code after rejection is byte-equivalent to the pre-candidate
publication gate in `crates/ffs-mvcc/src/sharded.rs`.

Gates:

```text
cargo fmt --package ffs-mvcc --check
```

Passed locally.

```text
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary timeout 600 rch exec -- cargo test -p ffs-mvcc commit_publication_gate -- --nocapture
```

Passed on `vmi1149989`: 2 tests passed.

```text
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary timeout 600 rch exec -- cargo check -p ffs-mvcc --all-targets
```

Passed on `vmi1153651`.

```text
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary timeout 600 rch exec -- cargo clippy -p ffs-mvcc --all-targets -- -D warnings
```

Passed on `vmi1153651`.
