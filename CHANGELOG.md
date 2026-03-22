# Changelog

All notable changes to [FrankenFS](https://github.com/Dicklesworthstone/frankenfs) are documented in this file.

FrankenFS is a memory-safe ext4 + btrfs implementation in Rust, running in userspace via FUSE. It features block-level MVCC, RaptorQ self-healing, adaptive conflict arbitration, and zero unsafe code.

> **Note:** This project is in early development. There are no tagged releases yet. The changelog is organized by development phase and capability milestone, derived from the git history (536 commits as of 2026-03-21).

---

## [Unreleased] — Active Development

### Phase 7: Write-Path Hardening & Checksum Infrastructure (2026-03-19 — 2026-03-21)

Focus: MVCC-safe write integration, checksum stamping, block allocator robustness, and scope-free API migration.

**Block/Inode Checksum Stamping**
- Parse and serialize block/inode bitmap checksums in group descriptors ([`b7a5cb8`](https://github.com/Dicklesworthstone/frankenfs/commit/b7a5cb835ec5a3d3f93c434c7fd39a2d0ae7b25b))
- Add checksum stamping functions and harden integer casts across ondisk, extent, and repair crates ([`481d08f`](https://github.com/Dicklesworthstone/frankenfs/commit/481d08fc3fa286134cbb7409d4ad4c67191e84b1))
- Add round-trip tests for checksum stamping ([`dfb02ac`](https://github.com/Dicklesworthstone/frankenfs/commit/dfb02ac163e6647bffe7aecc0ad589c608b510d5))

**MVCC-Safe Write Path**
- Add `TransactionBlockAdapter` for MVCC-safe writes and fix directory entry handling ([`cf39006`](https://github.com/Dicklesworthstone/frankenfs/commit/cf39006df0dfccf8c8e07cbe9aef7e698bd758b0))
- Plumb `RequestScope` through all `FsOps` methods for MVCC read/write scoping ([`58adb58`](https://github.com/Dicklesworthstone/frankenfs/commit/58adb580dc45d624a93e8b23ea6da1b79c23fe59))
- Migrate remaining call sites to scope-free `read_inode`, `read_group_desc`, `lookup_name` ([`efb7af1`](https://github.com/Dicklesworthstone/frankenfs/commit/efb7af18b2f7b11c5e8bbd687b4e53e6d3918d6a))
- Add scope-free convenience methods for core read operations ([`c6915f4`](https://github.com/Dicklesworthstone/frankenfs/commit/c6915f4a82cd2b623dc0094254859c3403d14bd9))

**Block Allocator & Bug Fixes**
- Block allocator improvements ([`ecffd3d`](https://github.com/Dicklesworthstone/frankenfs/commit/ecffd3d1a8de57849e59a58224c751959984bdbf))
- Eliminate panic in `bitmap_find_contiguous` for empty bitmaps ([`49d0dbb`](https://github.com/Dicklesworthstone/frankenfs/commit/49d0dbbc4cec65009ec64709bbb4e418b4754987))
- Fix TOCTOU race in `prune_safe` and harden RAID stripe arithmetic ([`020ac96`](https://github.com/Dicklesworthstone/frankenfs/commit/020ac96746847b5fb4059605a44a16b6d36f0d4b))
- Fix ARC cache dirty tracking, add scope propagation, expose link/symlink/setattr APIs ([`a16a009`](https://github.com/Dicklesworthstone/frankenfs/commit/a16a009f6c3ff9852b2b1ce53a4345babc73f0e9))
- Zero-division guard in `inode_index_in_group` ([`40619b0`](https://github.com/Dicklesworthstone/frankenfs/commit/40619b0b21ba653076cedf07d0072a5ba6e888fc))
- Bounds-check `resolve_data_with` index and prevent block address overflow ([`d8e561a`](https://github.com/Dicklesworthstone/frankenfs/commit/d8e561a88d00bd128bc700588d94d2efb806b3d0))
- Sequence-aware dirty tracking, VFS/FUSE formatting, and repair refactoring ([`e3b1cc5`](https://github.com/Dicklesworthstone/frankenfs/commit/e3b1cc59d71f38c8052121a0161f9079a9ac6f54))
- Add missing `FsGeometry` fields and clamp `encode_extra_timestamp` nsec ([`549aaad`](https://github.com/Dicklesworthstone/frankenfs/commit/549aaad4736eb62e02f59292603cb0c6b2ddf2b9))
- Replace unsafe as-casts in `trim_extents` with saturating clamp helpers ([`35610ff`](https://github.com/Dicklesworthstone/frankenfs/commit/35610ffd591b624640c8c8a8921fa7998c1808b0))
- Re-export `TxnAbortReason` as public for downstream crates ([`8126e90`](https://github.com/Dicklesworthstone/frankenfs/commit/8126e906b76a90d1bd6718d4ba598008de3838d5))
- Add `ExtentCache` namespace isolation tests ([`242c873`](https://github.com/Dicklesworthstone/frankenfs/commit/242c87378ea967fc6625877407d57b55584b16a6))

---

### Phase 6: Repair Pipeline, Fuzz Infrastructure & xfstests (2026-03-12 — 2026-03-19)

Focus: symbol exchange transport, adaptive refresh, batch allocation, fuzz corpus, xfstests harness, and evidence/observability CLI.

**Repair Symbol Exchange & Adaptive Refresh**
- Add symbol exchange transport and enhance repair pipeline ([`56a4b6d`](https://github.com/Dicklesworthstone/frankenfs/commit/56a4b6d788327e2733d78ec49371ec1b6552253a))
- Implement adaptive symbol refresh and expand xfstests conformance ([`14b1ec3`](https://github.com/Dicklesworthstone/frankenfs/commit/14b1ec33e2c3a42dcd8f508db12dbc7fc8b6a6df))
- Add evidence metrics presets and expand observability CLI ([`907d7a5`](https://github.com/Dicklesworthstone/frankenfs/commit/907d7a5f1b479a29e2c18d5040f06596755a26b0))
- Add evidence preset validation and refine repair exchange ([`5965c04`](https://github.com/Dicklesworthstone/frankenfs/commit/5965c048336c83f7e9286051df3d2e091073a09d))

**Batch Allocation & Extent Cache**
- Add batch block allocator and extent LRU cache ([`a51c901`](https://github.com/Dicklesworthstone/frankenfs/commit/a51c9017fad2be285e00a381a7c51b9fd87691aa))
- Rewrite `punch_hole` with per-extent deletion and add overflow tests ([`240e061`](https://github.com/Dicklesworthstone/frankenfs/commit/240e061c20bd746d12de5e72477934491379b466))

**Fuzz Infrastructure**
- Add 1281 fuzz corpus entries for btrfs metadata, ext4 xattr, and VFS operations ([`0ee5695`](https://github.com/Dicklesworthstone/frankenfs/commit/0ee5695ccea18561f40ff2e3220a47dbfcfe63a4))
- Add crash-to-regression-test promotion script ([`7225c09`](https://github.com/Dicklesworthstone/frankenfs/commit/7225c09731dcd7bcc24ed38664896b16ce077cea))
- Improve serialization, concurrency, and add fuzz infrastructure across crates ([`527980e`](https://github.com/Dicklesworthstone/frankenfs/commit/527980e57f1d18453ef47555f64a365b29a9ec66))

**xfstests Harness**
- Add xfstests test harness, result parsing, and CI regression gate ([`8417c93`](https://github.com/Dicklesworthstone/frankenfs/commit/8417c93a660eaaf1ff6a3736bcc3d235d5a967fc))
- Fix nightly fuzz dict flag placement and simplify `parse_check_output` ([`557f5fb`](https://github.com/Dicklesworthstone/frankenfs/commit/557f5fbf78a4f8bcfe42d0be30bb7ccc1b122905))

**Directory Checksum & MVCC Directory Handling**
- Implement ext4 directory metadata checksum support ([`875d735`](https://github.com/Dicklesworthstone/frankenfs/commit/875d73545214c82d8e465261ef91142f4133cf26))
- Expand MVCC logic and refactor directory listing ([`ed807e3`](https://github.com/Dicklesworthstone/frankenfs/commit/ed807e34fb650da2415ae11fbe3ef90715632e6f))

**V1.1 Verification Suite**
- Add 12 new E2E verification gate scripts for V1.1 validation suite ([`ca275b6`](https://github.com/Dicklesworthstone/frankenfs/commit/ca275b62f64c255513f230441ed3c023c5691304))
- Add 7 new ffs-harness validation modules ([`97501db`](https://github.com/Dicklesworthstone/frankenfs/commit/97501dbdf91730938f08051ba329477b0af8975b))
- Add verification gate E2E scripts for MVCC replay and mount runtime modes ([`f102e14`](https://github.com/Dicklesworthstone/frankenfs/commit/f102e1403cc732498a2508ea1d9432f4fcd61c0d))

---

### Phase 5: Safe-Merge Proofs, Adaptive Conflict Policy & Writeback-Cache (2026-03-14 — 2026-03-17)

Focus: MVCC merge-proof resolution, adaptive conflict arbitration, stale-window SLO, writeback-cache epoch barrier, and multi-host repair ownership.

**Merge-Proof Resolution**
- Add merge-proof resolution to allow non-conflicting concurrent writes to the same block ([`3ed57bc`](https://github.com/Dicklesworthstone/frankenfs/commit/3ed57bcd4268118caeb9b5a1b979886a42cf92c0))
- Add safe-merge taxonomy classifier with pairwise commutativity tests ([`c3c7c9c`](https://github.com/Dicklesworthstone/frankenfs/commit/c3c7c9c90943f84a38b653456594138fd542b162))
- Introduce `InodeMetadataMergeFootprint` and rename `classify_merge_pair` ([`1e415a3`](https://github.com/Dicklesworthstone/frankenfs/commit/1e415a360da3f147332db9fb23037301ff4ed186))
- Add 100-writer append-only merge proof stress test ([`b62f97d`](https://github.com/Dicklesworthstone/frankenfs/commit/b62f97df72c9ca3908fe785409de77c5c0ae7b76))
- Add verification gate stress test for safe-merge under 120 writers ([`0a704cb`](https://github.com/Dicklesworthstone/frankenfs/commit/0a704cbadf0ba24ef8dba6e7e2a0efdc636511c8))

**Adaptive Conflict Policy**
- Implement adaptive conflict policy with expected-loss selection ([`3d3d5cc`](https://github.com/Dicklesworthstone/frankenfs/commit/3d3d5ccd29d0b32e12d65fd7e508f6c452bfa665))
- Add contention evidence types, emit helpers, and CLI preset ([`522f441`](https://github.com/Dicklesworthstone/frankenfs/commit/522f441d8887f0a1f11990e3a1d48f97a0041a06))
- Correct policy-switch delta calculation and collect all merge variants ([`a13818d`](https://github.com/Dicklesworthstone/frankenfs/commit/a13818dc44b187ce882143609f3148d6d36bc017))

**Repair Refresh & SLO**
- Add expected-loss model for adaptive refresh trigger policies ([`8a3c614`](https://github.com/Dicklesworthstone/frankenfs/commit/8a3c614f0374dc5d6b15794418ac2366122e3f47))
- Implement hybrid refresh policy combining age-timeout and block-count triggers ([`6b383e6`](https://github.com/Dicklesworthstone/frankenfs/commit/6b383e63d26c9e3608895e84837b0422c6246d61))
- Add stale-window SLO instrumentation with percentile-based breach detection ([`f32ce08`](https://github.com/Dicklesworthstone/frankenfs/commit/f32ce0813c3b1fa81e5930f8e0ab93237dea875e))
- Harden `RefreshLossModel` edge cases for zero blocks, zero writes, and degenerate thresholds ([`46c0119`](https://github.com/Dicklesworthstone/frankenfs/commit/46c0119368d4bbc7e0e837c307775907c61412d1))

**Writeback-Cache Epoch Barrier**
- Add writeback-cache epoch barrier with per-inode epoch tracking ([`541e178`](https://github.com/Dicklesworthstone/frankenfs/commit/541e178fb0785220b70e6949ff479b7f9908d7e8))
- Make `commit_epoch` infallible and remove `EpochNotStaged` error ([`5e11da6`](https://github.com/Dicklesworthstone/frankenfs/commit/5e11da667cc750d9089004ab969a8e89a3dc37ef))
- Add crash consistency matrix for writeback epoch barrier ([`e8bd18d`](https://github.com/Dicklesworthstone/frankenfs/commit/e8bd18d5ec7fe17670d72f0183b8216a264c358f))
- Treat untracked inodes as visible in epoch barrier and improve recovery ([`389e17a`](https://github.com/Dicklesworthstone/frankenfs/commit/389e17a832acc88a63e31c792cf6bb9953eefaae))
- Add writeback-cache benchmark workload types and throughput comparison model ([`72391c7`](https://github.com/Dicklesworthstone/frankenfs/commit/72391c70d50e5c68f40cff9c7fddc66ddc858cac))
- Add writeback-cache MVCC barrier schedule invariant checker ([`f04d77c`](https://github.com/Dicklesworthstone/frankenfs/commit/f04d77cf6481c45f078702eecf86827abb53c305))

**Multi-Host Repair**
- Add multi-host repair ownership protocol and design ([`d5fde69`](https://github.com/Dicklesworthstone/frankenfs/commit/d5fde691e643b9ace8dbf9435bbae1a28375257c))

---

### Phase 4: Btrfs Read-Write, WAL Replay & E2E Expansion (2026-03-02 — 2026-03-13)

Focus: btrfs RW mount support, snapshot navigation, RAID stripe resolution, WAL replay engine, operator runbooks, and broad E2E test expansion.

**Btrfs Snapshot Navigation & Subvolumes**
- Add snapshot navigation, subvolume CLI, and snapshot diff ([`0258ba2`](https://github.com/Dicklesworthstone/frankenfs/commit/0258ba2b07a76d3d55c3c97ae2a89f8de9dbfc45))
- Add btrfs subvolume enumeration and multi-device RAID stripe resolution ([`bc67946`](https://github.com/Dicklesworthstone/frankenfs/commit/bc67946e9b829f4d8f3d040115fdb9448911ce9f))
- Correct RAID5/6 parity rotation for data stripe mapping ([`18bc6b0`](https://github.com/Dicklesworthstone/frankenfs/commit/18bc6b01b219c611f0b35e117adc3e70e0c77092))
- Add comprehensive tests for subvolume/snapshot enumeration and RAID stripe resolution ([`1fa72b3`](https://github.com/Dicklesworthstone/frankenfs/commit/1fa72b35503729726038f7f918610cb40a771c93))

**WAL Replay Engine**
- Extract WAL replay engine and harden recovery pipeline ([`112ad62`](https://github.com/Dicklesworthstone/frankenfs/commit/112ad62393ee1645b5564f99b781d0ab0f56fc50))
- Resolve OQ1 native-mode boundary and OQ7 version-store format ([`7fab707`](https://github.com/Dicklesworthstone/frankenfs/commit/7fab7079290c24f701eb682b5e06453599416d50))
- Add WAL replay telemetry, crash matrix, verification runner ([`d949529`](https://github.com/Dicklesworthstone/frankenfs/commit/d94952931e690f42ec17d28b3a819173a6ac7b56))

**Runtime Mode & CLI Expansion**
- Add runtime-mode CLI contract with structured observability ([`9d4a46e`](https://github.com/Dicklesworthstone/frankenfs/commit/9d4a46e0677212a3337284163c1e408c1ac3d59b))
- Wire real MVCC transaction counters and extend dump group for btrfs ([`82b87f3`](https://github.com/Dicklesworthstone/frankenfs/commit/82b87f310e8cc5fd92eb0c194dde1ef6e16e9004))
- Add btrfs chunk-group reporting to `ffs info --groups` ([`a53de18`](https://github.com/Dicklesworthstone/frankenfs/commit/a53de18333d3bd3748a362716f3bb45f73fd07d5))
- Add btrfs stale-only repair scoping and btrfs inode dump support ([`162510f`](https://github.com/Dicklesworthstone/frankenfs/commit/162510fea6f376bc85d8207f5a1f33d22a89eab6))
- Expand repair command, CLI surface, artifact manifest, and E2E test infrastructure ([`c47b7df`](https://github.com/Dicklesworthstone/frankenfs/commit/c47b7df5bd0d8f67f7e8b4186181bc3b9f4b49ed))

**Btrfs RW & Fallocate**
- Add machine-checkable fallocate RW capability contract and E2E coverage ([`6fc1e5c`](https://github.com/Dicklesworthstone/frankenfs/commit/6fc1e5cfc78fbbc4cca2ff89eca039c00313f6ae))
- Add structured fallocate tracing and comprehensive test coverage ([`9d3e88b`](https://github.com/Dicklesworthstone/frankenfs/commit/9d3e88b7d116134f2e8a8255cfa2d4475a53cff1))
- Harden unsupported rw guardrails and contracts ([`5699270`](https://github.com/Dicklesworthstone/frankenfs/commit/569927052d65a6d21fece54d99a1d9993b2b678e))
- Add btrfs RW fallocate capability contract and E2E smoke harness ([`c7e9630`](https://github.com/Dicklesworthstone/frankenfs/commit/c7e963014e806f0fc7f80c8599f00aafb24c2f5c))

**Operator Runbooks & Observability**
- Add operator runbooks for replay failure triage, corruption recovery, and backpressure investigation ([`b9caa45`](https://github.com/Dicklesworthstone/frankenfs/commit/b9caa45cadba75df5af3964be1475ce3777ecc80))
- Add preset queries and summary aggregation to the evidence command ([`77f6c56`](https://github.com/Dicklesworthstone/frankenfs/commit/77f6c56566e08690f4592537479958d8a562f354))
- Add extent resolve benchmarks, metrics module, and profiling scripts ([`137299f`](https://github.com/Dicklesworthstone/frankenfs/commit/137299f05e82a742405c040b14ed6b42f4bbf31d))
- Add performance regression triage module with runbook and E2E coverage ([`4e8e37e`](https://github.com/Dicklesworthstone/frankenfs/commit/4e8e37e1a2663f9a044ee384d9cb0da01a07a970))

**E2E & Integration Tests**
- Add cross-crate integration tests for ffs-core ([`a82cefe`](https://github.com/Dicklesworthstone/frankenfs/commit/a82cefe7b0ef4feff163483a6ac78744bc81f2ed))
- Add comprehensive TUI dashboard test coverage ([`0a019dc`](https://github.com/Dicklesworthstone/frankenfs/commit/0a019dcc70f4b4208276a9d9248d90c3fb263894))
- Add benchmark taxonomy, log contracts, perf comparison, and E2E scenarios ([`9bb2db6`](https://github.com/Dicklesworthstone/frankenfs/commit/9bb2db6f4f1c195f6def9a34dcf1e59e2f068b22))
- Resolve OQ2 conflict policy and add MVCC stress test suite ([`13ace26`](https://github.com/Dicklesworthstone/frankenfs/commit/13ace266eecb915c4abaf427a9b43fc99913fed8))

---

### Phase 3: Massive Test Expansion, Correctness Hardening & FUSE E2E (2026-02-22 — 2026-03-02)

Focus: hundreds of edge-case and property-based tests, integer cast hardening, JBD2 correctness, FUSE backpressure, MVCC compression, and btrfs RW mount.

**Property-Based Testing Blitz (~300+ proptests added)**
- Add proptest coverage across types, inode, alloc, fuse, ondisk, repair, extent, xattr, mvcc, dir, journal, block crates ([`179beea`](https://github.com/Dicklesworthstone/frankenfs/commit/179beeaeeb340c54db40419f87c38b86a1069975)...[`c104a48`](https://github.com/Dicklesworthstone/frankenfs/commit/c104a4875586f408631a037980357eff24b68aa7))
- Add adversarial dir block fuzzing and image-level fuzzing for `Ext4ImageReader` ([`566f377`](https://github.com/Dicklesworthstone/frankenfs/commit/566f37736cd11e4f7bcb57b6ec7d30bb21089b64), [`5ec7a9e`](https://github.com/Dicklesworthstone/frankenfs/commit/5ec7a9e8941ed0d9b34f912e89190ffd08d2c3d0))

**Edge-Case Test Expansion (~350+ tests added)**
- Add ~57 edge-case tests across block, mvcc, and repair ([`ad9f258`](https://github.com/Dicklesworthstone/frankenfs/commit/ad9f2586d1bd34dd7bb0cb3fbb42a7b1cc5887ad))
- Add ~49 edge-case tests for repair symbol, scrub, lrc, and evidence modules ([`3742c29`](https://github.com/Dicklesworthstone/frankenfs/commit/3742c2964f20818816dfebb178a65aa5c4574123))
- Add ~48 edge-case tests across fuse, ondisk-ext4, and types ([`c256f40`](https://github.com/Dicklesworthstone/frankenfs/commit/c256f40873954e95b660b3205a6bf9ae0d9662ba))
- Add ~48 edge-case tests across extent, xattr, and inode ([`0a6425b`](https://github.com/Dicklesworthstone/frankenfs/commit/0a6425b2093491b514897b8ae08acb00e02b68d8))
- Add ~45 edge-case tests across btree, core, extent, and inode ([`c8197bb`](https://github.com/Dicklesworthstone/frankenfs/commit/c8197bb3b9e2fd5b3dfd5e483a2df0cca8e46480))
- Add ~44 edge-case tests across dir, alloc, and journal ([`092e0ee`](https://github.com/Dicklesworthstone/frankenfs/commit/092e0eebcd877f84a661a15ec0a788608c11a647))
- Add ~42 edge-case tests across btree and core ([`0a3d02c`](https://github.com/Dicklesworthstone/frankenfs/commit/0a3d02cb49ab10f4174c1894e1050b1cf9fb0c8a))

**Integer Safety Hardening**
- Replace lossy as-casts with checked `try_from` conversions across core, alloc, ondisk ([`0181976`](https://github.com/Dicklesworthstone/frankenfs/commit/0181976cfc860238d4e737ed80e455e05e744113))
- Add overflow-cap edge-case tests for `try_from` conversions ([`a791ae7`](https://github.com/Dicklesworthstone/frankenfs/commit/a791ae70319da886a626318e2a2faf6b8f2ecb1c))
- Replace as-casts with `try_from`, inline format args, simplify raw strings ([`73ce8c8`](https://github.com/Dicklesworthstone/frankenfs/commit/73ce8c88f1a26d7ccd22d4ba88f6d59d12b1f593))

**JBD2 & Journal Correctness**
- Correct JBD2 revoke-across-transactions semantics ([`4cf620a`](https://github.com/Dicklesworthstone/frankenfs/commit/4cf620a7422380d45cdb91df4e612ff0ec4c7636))
- Respect `r_count` length limit when parsing JBD2 revoke blocks ([`d2e1be5`](https://github.com/Dicklesworthstone/frankenfs/commit/d2e1be5006d99b421c7222f520701cbe2dbae127))
- Stabilize flaky `throughput_scales_with_thread_count` test ([`e4dee25`](https://github.com/Dicklesworthstone/frankenfs/commit/e4dee25e1013143c9c5083b8a9ce3c4af0e361b0))

**FUSE Hardening**
- Add backpressure throttle tier, FUSE queue tuning, and mount timeout ([`21c8652`](https://github.com/Dicklesworthstone/frankenfs/commit/21c8652c73774014d5c8d57cbbf49233cce7d0d0))
- Split FCW commit into preflight+apply phases; fix RCU write-lock gaps ([`7a17036`](https://github.com/Dicklesworthstone/frankenfs/commit/7a1703654bcd5228f95f0142bae4d071fbcce767))
- Add backpressure shedding for fsync/fsyncdir and extract `preflight_fcw` ([`457613a`](https://github.com/Dicklesworthstone/frankenfs/commit/457613ab4ece4a00860392ad232c3685662b2a8f))
- Harden mount validation and fix stale readahead after writes ([`8938b01`](https://github.com/Dicklesworthstone/frankenfs/commit/8938b0126555130a2206a1e6ff78525f4f50ee50))

**MVCC Compression**
- Add zstd/brotli transparent compression for MVCC version chains ([`ce6cb61`](https://github.com/Dicklesworthstone/frankenfs/commit/ce6cb6121d6afa1e4816ca736405770f497178c8))

**Btrfs Read-Write**
- Implement btrfs read-write mount support with COW tree and extent allocator ([`c9c7388`](https://github.com/Dicklesworthstone/frankenfs/commit/c9c7388a3b8333d764a0760d7042149984b16667))
- Preserve data during fallocate overlap and inline-to-regular extent transition ([`b57e7aa`](https://github.com/Dicklesworthstone/frankenfs/commit/b57e7aaf010f3840490b0a6c85ad4cca9d14fb19))
- Report accurate free space from extent allocator in statfs ([`cda44ce`](https://github.com/Dicklesworthstone/frankenfs/commit/cda44cee826f4dbb73bf9fcf42a59b0ec3b776b2))

**B-Tree Correctness**
- Repair insert separator-key maintenance and add proptests ([`47ef0f9`](https://github.com/Dicklesworthstone/frankenfs/commit/47ef0f99c028bfc1f6e41ac12b16e299acc16056))
- Reorder split writes and defer child frees for crash safety ([`15769c7`](https://github.com/Dicklesworthstone/frankenfs/commit/15769c70107823dbdb314e9f75c49b19c107bb90))

**Write-Path Fixes**
- Journaled commit atomicity, btrfs extent/fallocate correctness, ext4 unwritten extents ([`b9772d0`](https://github.com/Dicklesworthstone/frankenfs/commit/b9772d080f059901b3944a4cad7fcdecfe6a6a25))
- Correct ext4 DX directory parser layout ([`ae4c1be`](https://github.com/Dicklesworthstone/frankenfs/commit/ae4c1beac5cb4deee9fcfec3d809e6c30433f47f))
- Harden ext4 fsck group descriptor verification, cap btrfs symlink reads ([`52af491`](https://github.com/Dicklesworthstone/frankenfs/commit/52af491134150cc4d39838d94c742b4825e15ca8))
- Harden allocator locality, WAL replay integrity, and ext4 fsck safety ([`d19be9b`](https://github.com/Dicklesworthstone/frankenfs/commit/d19be9b3b25df58c827390ca7ad68530b01e5d40))

**Block Cache**
- Replace S3-FIFO cache panics with self-healing invariant recovery ([`8967c05`](https://github.com/Dicklesworthstone/frankenfs/commit/8967c05195d8b9bc3027baab96f7e8f4beec64e3))
- Replace dirty-block eviction panics with graceful skip-and-requeue ([`d68552a`](https://github.com/Dicklesworthstone/frankenfs/commit/d68552a5608e47a38638a136392d4e036bc75082))

**Code Quality**
- Remove genuinely dead code from cli, core, and journal ([`2a5f85b`](https://github.com/Dicklesworthstone/frankenfs/commit/2a5f85bf16b8efd240755ee0a1241911f5891e45))
- Extract repair and evidence commands into dedicated modules ([`6d16739`](https://github.com/Dicklesworthstone/frankenfs/commit/6d16739151972aacb1c935f53fe55f8f3bd014df))
- Extract degradation FSM and VFS semantics into dedicated submodules ([`e657cee`](https://github.com/Dicklesworthstone/frankenfs/commit/e657cee78b14983c985bfd5d70ce1f659397542c))

---

### Phase 2: Write Path, MVCC Integration & Repair Infrastructure (2026-02-11 — 2026-02-21)

Focus: full ext4 write path, FUSE write ops, journaling, MVCC persistence, btrfs parsing expansion, repair pipeline, and advanced concurrency primitives.

**Write-Path Epic (bd-zge)**
- Implement ext4 extent B+tree operations ([`092a48a`](https://github.com/Dicklesworthstone/frankenfs/commit/092a48aebdd7596170f5ebfc7467493489ef3f1c))
- Implement block/inode allocation ([`5d99bd7`](https://github.com/Dicklesworthstone/frankenfs/commit/5d99bd72096335dded82b76fca8849e9edc70c57))
- Implement extent write operations ([`0e8a9d6`](https://github.com/Dicklesworthstone/frankenfs/commit/0e8a9d6690fb81cd91ca26dee994a8ddeec4b76b))
- Implement inode lifecycle operations ([`20e4a7f`](https://github.com/Dicklesworthstone/frankenfs/commit/20e4a7f539fe543cb31bba1eb808ed2de49c5c32))
- Implement directory write operations ([`90baa90`](https://github.com/Dicklesworthstone/frankenfs/commit/90baa906db425777dee4d84aaeccbb7f10f3c48f))
- Implement JBD2 replay + native COW journal ([`03925fb`](https://github.com/Dicklesworthstone/frankenfs/commit/03925fb7d9c3f63063921ad8cc0d481ae5350724))
- Implement extended attribute write operations ([`3bde39c`](https://github.com/Dicklesworthstone/frankenfs/commit/3bde39ce0d5d4b68e9855f94a44f735f26eb3c7a))
- Integrate journal replay into ext4 mount path ([`db9d1d0`](https://github.com/Dicklesworthstone/frankenfs/commit/db9d1d0ef5fb838aa1e184e7dd8e87164b2a600e))

**MVCC Engine**
- Implement Serializable Snapshot Isolation (SSI) with rw-antidependency detection ([`3211b35`](https://github.com/Dicklesworthstone/frankenfs/commit/3211b35321d1e3c93cc6cf09c6f3f0a2db4b3a5f))
- Add watermark API + active snapshot tracking for version GC ([`9252739`](https://github.com/Dicklesworthstone/frankenfs/commit/9252739bce6ae7bbccde524c06ac93b1f51c6572))
- Integrate MVCC store into OpenFs with full transaction API ([`f0dc595`](https://github.com/Dicklesworthstone/frankenfs/commit/f0dc595dd8c2b739e76fdfb7b7f78dd0f11def2a))
- Add COW tree mutation API, tracing diagnostics, and snapshot registry ([`45c401c`](https://github.com/Dicklesworthstone/frankenfs/commit/45c401c61771237fc08f5f3aed4bf294066a2774))
- Add sharded MVCC store and expanded btrfs parsing ([`d9c2568`](https://github.com/Dicklesworthstone/frankenfs/commit/d9c25689cdba7c2ae2b2d4513e712dd4e7b72784))
- Add RCU primitives for lock-free metadata reads ([`9de8036`](https://github.com/Dicklesworthstone/frankenfs/commit/9de80367844ef82b6345671c5a84c255cab65263))
- Version chain backpressure, JBD2 writer, persist layer, FUSE write ops ([`d51a0c1`](https://github.com/Dicklesworthstone/frankenfs/commit/d51a0c1593f852b1938cbd677f7e651e8dc195c2))
- Add persistence layer with WAL support ([`c4a3764`](https://github.com/Dicklesworthstone/frankenfs/commit/c4a37647e277898a98d8945ababd13e433a50e4e))

**FUSE Write Operations**
- Wire up flush, fsync, and fsyncdir FUSE handlers ([`892691e`](https://github.com/Dicklesworthstone/frankenfs/commit/892691e4d185db00cfa3ca7288cc7adbfee07cee))
- Wire read-only xattr operations through FUSE adapter ([`b61dc73`](https://github.com/Dicklesworthstone/frankenfs/commit/b61dc7311f2df34f55e95576636659217e9f3777))
- FUSE multi-threading with thread-per-core dispatch routing ([`b2e24e7`](https://github.com/Dicklesworthstone/frankenfs/commit/b2e24e78c3faa9af1640d5b177155f71b9768497))

**Repair Pipeline**
- Implement RaptorQ encode/decode workflow ([`ce955c3`](https://github.com/Dicklesworthstone/frankenfs/commit/ce955c3fc1976bc1f195ab4ee78881fc82021276))
- Add `RepairPolicy` + comprehensive `DurabilityAutopilot` tests ([`f4c3073`](https://github.com/Dicklesworthstone/frankenfs/commit/f4c3073b0f9be7d12283c5a03342ecfd7f276a59))
- Implement scrub pipeline for corruption detection ([`a743f6a`](https://github.com/Dicklesworthstone/frankenfs/commit/a743f6a914224e2b436959351e5eca8ba30027aa))
- Add background scrub daemon with backpressure-aware scheduling ([`65296a3`](https://github.com/Dicklesworthstone/frankenfs/commit/65296a3c5bf76e639f53285fd2fa4198d1b5b6c4))
- Add evidence ledger viewer command and expand repair evidence tracking ([`7f5ed30`](https://github.com/Dicklesworthstone/frankenfs/commit/7f5ed3034397597998ea7672c273673a960715cb))
- Add self-healing demo module with adoption-wedge example ([`e101bd9`](https://github.com/Dicklesworthstone/frankenfs/commit/e101bd96d6cb54836e438c740e1be53ab228fd49))
- Add Local Reconstruction Codes for distributed repair ([`6a64689`](https://github.com/Dicklesworthstone/frankenfs/commit/6a64689e477cb6ebd48fa73e3f5ce41c4b4b9037))
- Add Proof of Retrievability for cryptographic durability audit ([`020da2c`](https://github.com/Dicklesworthstone/frankenfs/commit/020da2cdd86205eee12033d4288f869647d80237))
- Adaptive symbol-refresh protocol and Bayesian overhead autopilot ([`62d688d`](https://github.com/Dicklesworthstone/frankenfs/commit/62d688d8023efd35de9d04e6d4654354a8dd1451))
- Btrfs backup superblock mirror repair from primary ([`025c3ec`](https://github.com/Dicklesworthstone/frankenfs/commit/025c3ec385ddbd14a3269cbf74a4b1edaa2513fa))
- Wire RaptorQ block-level recovery into btrfs fsck --repair path ([`ef72e83`](https://github.com/Dicklesworthstone/frankenfs/commit/ef72e83e1276ed7d272f130be0a250d1b48c36e0))

**Block Cache & I/O**
- Add S3-FIFO cache eviction with btrfs transaction model ([`b3c6af2`](https://github.com/Dicklesworthstone/frankenfs/commit/b3c6af2802150f90ca5965297dc7442080aded94))
- Degradation FSM with hysteresis and FUSE backpressure shedding ([`b7704fc`](https://github.com/Dicklesworthstone/frankenfs/commit/b7704fc506944446ab1a6aec296a513cb1295845))
- Lock-free `AtomicU8` cache for `DegradationFsm` level reads ([`a1996f0`](https://github.com/Dicklesworthstone/frankenfs/commit/a1996f06fcd9175a4d329c439493e1a3904f7c1a))
- ARC cache memory pressure hooks for graceful degradation ([`ff1663c`](https://github.com/Dicklesworthstone/frankenfs/commit/ff1663c40e95c4d0491f10652df8b4f09faf4d90))
- MVCC-aware transactional dirty tracking and flush lifecycle in ARC cache ([`6d5d95e`](https://github.com/Dicklesworthstone/frankenfs/commit/6d5d95e4a011b26938ab2cb1c662b4b75a2e08c9))
- Add pluggable `IoEngine` trait for kernel-bypass I/O ([`696ef28`](https://github.com/Dicklesworthstone/frankenfs/commit/696ef28004584a80dcc50307624208f499455dcd))

**Btrfs Expansion**
- Implement delayed-ref queue with bounded flush and parity bookkeeping ([`f446e3f`](https://github.com/Dicklesworthstone/frankenfs/commit/f446e3fb1a3f16ce6da36097bc4c722976719c98))
- Add btrfs cycle and duplicate-node detection to tree walker ([`da090fe`](https://github.com/Dicklesworthstone/frankenfs/commit/da090feab3923042d051ef05a5a96ad2d9477bfd))
- Add comprehensive btrfs structure parsing support ([`a3a9606`](https://github.com/Dicklesworthstone/frankenfs/commit/a3a960689f0c8a5a05e17aee436dcdd6482563d1))

**Advanced Features**
- Major refactor: crash recovery, journaled writes, compute budget, write-path VFS ops ([`117b530`](https://github.com/Dicklesworthstone/frankenfs/commit/117b530ca52e97ba428e38c8b0d1887bad7d5df4))
- Add succinct rank/select bitmap for O(1) free-space queries ([`21de74b`](https://github.com/Dicklesworthstone/frankenfs/commit/21de74b375d81d49b3d9eab3812c8001431437d8))
- Widen ext4 timestamp pipeline to 64-bit seconds for year-2106+ support ([`53c697b`](https://github.com/Dicklesworthstone/frankenfs/commit/53c697b0d598062eb35968a2e20492c6ece3f734))
- Support non-contiguous ext4 journal extents ([`fdd192b`](https://github.com/Dicklesworthstone/frankenfs/commit/fdd192b4da525f6a41f67edd9975243f401db25b))

**Benchmarks & Conformance**
- Add ARC/S3-FIFO cache workload benchmarks, Bw-Tree vs locked B-tree bench ([`19ea92c`](https://github.com/Dicklesworthstone/frankenfs/commit/19ea92cbd77a08318241ad4da00ba1097c8e6efb))
- Add Bw-Tree, per-core WAL buffers, I/O throttle injection, and full conformance gate ([`b98c3ba`](https://github.com/Dicklesworthstone/frankenfs/commit/b98c3ba6453d110edcfa94e23924dcccd6e62328))
- Add xfstests subset infrastructure for FUSE E2E validation ([`a23e89b`](https://github.com/Dicklesworthstone/frankenfs/commit/a23e89b73c59db44ec8966eacc2d93b9b706da0b))

**TUI Dashboard**
- Implement minimal TUI dashboard via ftui ([`1defb2d`](https://github.com/Dicklesworthstone/frankenfs/commit/1defb2d043bb44b5c7ff6bfe40b712e67c326558))

**Licensing**
- Adopt MIT + OpenAI/Anthropic rider metadata across workspace ([`9cb3ba5`](https://github.com/Dicklesworthstone/frankenfs/commit/9cb3ba58f90cb867be567db80180282d229a1217))

---

### Phase 1: Foundation, Read Path & FUSE Mount (2026-02-09 — 2026-02-10)

Focus: initial workspace, ext4/btrfs on-disk parsing, read-only FUSE mount, VFS abstraction, ARC block cache, MVCC block device wrapper, conformance harness, and CLI.

**Initial Workspace**
- Initial commit: 21-crate Cargo workspace with `#![forbid(unsafe_code)]` at every crate root ([`01bc389`](https://github.com/Dicklesworthstone/frankenfs/commit/01bc38985fb499db3598734e29ec9b7adcbc7253))
- Reconcile spec/arch/plan/README for 21-crate workspace ([`48858ce`](https://github.com/Dicklesworthstone/frankenfs/commit/48858ce3f02bd27844496d99e283763512343ed6))

**Type System & Error Handling**
- Add checked arithmetic + alignment helpers (ffs-types) ([`6e91588`](https://github.com/Dicklesworthstone/frankenfs/commit/6e915881f7d7fd32c4f7012057c8cc08422be9fa))
- Define canonical error taxonomy + mapping boundaries (ffs-error) ([`74fce48`](https://github.com/Dicklesworthstone/frankenfs/commit/74fce48a2beb5d5267b71c95e52caa5d0fbbee4a))
- Add mount-validation error variants ([`0c24f84`](https://github.com/Dicklesworthstone/frankenfs/commit/0c24f84fb9466c3536cb08ce4f89a95222579d67))
- Replace u32 feature flag constants with typed structs; add `Ext4InodeNumber`/`BtrfsObjectId` wrappers ([`5b284ac`](https://github.com/Dicklesworthstone/frankenfs/commit/5b284acdeb11cd8100f87956ca704b62cb3ba046))
- Add `ByteOffset`/`DeviceId` newtypes, directory parsing, metadata checksums ([`f96eb7a`](https://github.com/Dicklesworthstone/frankenfs/commit/f96eb7ad7433e595ca5040a0a441d3c6df8a163a))

**ext4 On-Disk Parsing**
- Expand ext4 on-disk parsing with group descriptors, inode reading, and directory traversal ([`3d334bf`](https://github.com/Dicklesworthstone/frankenfs/commit/3d334bfbe7a8012569582ab8292457c1f6d78412))
- Add extent mapping, file reads, directory ops, and path resolution to `Ext4ImageReader` ([`098b4c5`](https://github.com/Dicklesworthstone/frankenfs/commit/098b4c50777375a6b5478ebd4a8ac3e52a406ff4))
- Add zero-allocation `DirBlockIter` for ext4 directory parsing ([`2aae5c7`](https://github.com/Dicklesworthstone/frankenfs/commit/2aae5c7d7a583c08abdda7204dbb74ad384d085a))
- Add `SystemTime` helpers + inode edge-case tests ([`29627fa`](https://github.com/Dicklesworthstone/frankenfs/commit/29627fa159334a17fb079684b726f9101785193a))
- Add feature flag decode helpers + diagnostics ([`d959f65`](https://github.com/Dicklesworthstone/frankenfs/commit/d959f65c45926e8b3d306a10bea11aef36779b8e))
- Comprehensive superblock geometry validation ([`aaae453`](https://github.com/Dicklesworthstone/frankenfs/commit/aaae453d64052cee4f792a42cbcbc81d88b07376))
- Add validated inode location helpers ([`5ebb344`](https://github.com/Dicklesworthstone/frankenfs/commit/5ebb3447f95957384eee8505f2ce61e922cd5e08))

**btrfs On-Disk Parsing**
- Btrfs logical-to-physical mapping via `sys_chunk_array` ([`6ed1bf0`](https://github.com/Dicklesworthstone/frankenfs/commit/6ed1bf0e47155890e8da3b0453f3dededabdaea8))
- Expand btrfs superblock with `sys_chunk_array` + validation ([`e6fa78e`](https://github.com/Dicklesworthstone/frankenfs/commit/e6fa78eda92c2696d3ac9daf187e0f25e8344380))
- Btrfs internal node parsing + header validation ([`1ae63e0`](https://github.com/Dicklesworthstone/frankenfs/commit/1ae63e0a144461fef443284635ae1e6f94933cc1))
- Implement read-only tree-walk with I/O-agnostic callback ([`35598fe`](https://github.com/Dicklesworthstone/frankenfs/commit/35598fee2d2be09bd33e367eceb65124aa75b4ac))
- Btrfs open/validate pipeline with tree-walk ([`7d2c475`](https://github.com/Dicklesworthstone/frankenfs/commit/7d2c475981651b5504e47ff036efd3689be79da3))
- Add btrfs CRC32C checksum verification ([`c24a2b7`](https://github.com/Dicklesworthstone/frankenfs/commit/c24a2b75eea31c1b10b4ce43bb469fc94f761a5f))

**VFS & Core**
- Define `FsOps` VFS trait with `InodeAttr`/`DirEntry`/`FileType` ([`535d019`](https://github.com/Dicklesworthstone/frankenfs/commit/535d0192b9b78951832bc2ac2c91adc80ba0e14a))
- Implement `OpenFs` API with detect-parse-validate pipeline ([`0f368b7`](https://github.com/Dicklesworthstone/frankenfs/commit/0f368b7ce9ad7abd823b192d7eb575230106520d))
- Device-based inode read, extent mapping, readdir, name lookup, path resolution ([`b1bfd2a`](https://github.com/Dicklesworthstone/frankenfs/commit/b1bfd2aca27f732ba2f76a0a74d846aceaad21e8)...[`0269d26`](https://github.com/Dicklesworthstone/frankenfs/commit/0269d26fedff201a69036b5ac5290b2af8d9bac2))
- High-level `read_file` by inode number ([`f7a6e42`](https://github.com/Dicklesworthstone/frankenfs/commit/f7a6e42ac167770f7c77294ee985026236b44d84))
- `FsOps` impl for `OpenFs` + symlink reading ([`8025164`](https://github.com/Dicklesworthstone/frankenfs/commit/8025164fcee105c7df3cdfdd53d8fa0e08284e3c))
- Add `listxattr`/`getxattr` to `FsOps` VFS trait ([`010dd43`](https://github.com/Dicklesworthstone/frankenfs/commit/010dd4393a72cbef1f45f130a7ab9a04c143280e))
- Extract device numbers for block/char inodes ([`8074e16`](https://github.com/Dicklesworthstone/frankenfs/commit/8074e16dc3263719b24f1eacaadad56feb4b09ce))

**FUSE Adapter**
- Implement real FUSE adapter via fuser crate ([`f6b2ca8`](https://github.com/Dicklesworthstone/frankenfs/commit/f6b2ca8af0edcf672d58f2db5cfadbb4e354a45e))
- Add readlink FUSE callback + complete read-only ops ([`decc239`](https://github.com/Dicklesworthstone/frankenfs/commit/decc239e05cdd7fd2df37677d0eb2e3162ac4dc3))
- Add mount subcommand for read-only ext4 FUSE mount ([`de66b4b`](https://github.com/Dicklesworthstone/frankenfs/commit/de66b4b58c0c1a0c8dab3a2cfe6a971ce2f2770a))

**Block Cache**
- Fix ARC eviction logic + add tests ([`e52aa8b`](https://github.com/Dicklesworthstone/frankenfs/commit/e52aa8b60de1c30159edc085a5c43aa9e2215493))
- Add `CacheMetrics` instrumentation surface ([`8fead6b`](https://github.com/Dicklesworthstone/frankenfs/commit/8fead6b4364e34cc57cdaf8f42f00377e11f3a01))
- Cache concurrency design + TOCTOU race fix ([`8b91122`](https://github.com/Dicklesworthstone/frankenfs/commit/8b91122f47dc7381ce92f938a548a3ebe16a5c76))
- Add criterion benchmarks for ARC cache hot paths ([`3fb2fc7`](https://github.com/Dicklesworthstone/frankenfs/commit/3fb2fc7268e66bfcfa10a98d46f1eef2880aa835))

**MVCC Foundation**
- Implement MVCC-aware block device wrapper ([`ddcb0ea`](https://github.com/Dicklesworthstone/frankenfs/commit/ddcb0ea2dc8be2cf324b37646e4dcc876290a095))
- Add deterministic MVCC concurrency invariant tests ([`ee24769`](https://github.com/Dicklesworthstone/frankenfs/commit/ee247698148de9409eb032a9d3901fa5386c441e))

**Repair Foundation**
- Define repair symbol format and storage strategy ([`1a8605b`](https://github.com/Dicklesworthstone/frankenfs/commit/1a8605b02f1cf97a778a63a3c8743b2e80aa83bd))
- Add scrub subcommand for read-only integrity scanning ([`3210ca5`](https://github.com/Dicklesworthstone/frankenfs/commit/3210ca536e7d963cef705df5c69802bab507c444))

**CLI**
- Switch to clap-based structured CLI ([`f0aebe8`](https://github.com/Dicklesworthstone/frankenfs/commit/f0aebe8c11b0eb583893cf6378f64c30a6114ae6))
- Add free-space subcommand for ext4 analysis ([`aa2ec8d`](https://github.com/Dicklesworthstone/frankenfs/commit/aa2ec8d233fd7e524867ae1ca855607db21d35f1))
- Add production `Cx` acquisition helpers for CLI commands ([`1fe3b8c`](https://github.com/Dicklesworthstone/frankenfs/commit/1fe3b8cc17b4f43262953fa2dfb6474b23939f09))

**Conformance Harness**
- Add golden output verification + isomorphism proof protocol ([`a09518d`](https://github.com/Dicklesworthstone/frankenfs/commit/a09518dfd1877564f9e8d04255ba98b6203ff1ed))
- Add Linux-kernel reference capture pipeline + E2E conformance tests ([`220c92a`](https://github.com/Dicklesworthstone/frankenfs/commit/220c92ae9993ca8de951ac16d9b506b1a7bf7e93))
- Enforce parity accounting invariant ([`032613f`](https://github.com/Dicklesworthstone/frankenfs/commit/032613fabd9ffc92caedf7e4b5629d7223f0b332))
- Add ondisk_parse benchmarks + CLI baselines ([`db56b56`](https://github.com/Dicklesworthstone/frankenfs/commit/db56b56c024dca15f31d5159eb1a23d310cee241))
- Add fixture generation workflow + `SparseFixture::from_bytes` ([`c25115e`](https://github.com/Dicklesworthstone/frankenfs/commit/c25115ed8738735bff5c4c49394345fa883ad1d0))
- Add ext4 fixtures for group desc, inode, dir block ([`de3bcef`](https://github.com/Dicklesworthstone/frankenfs/commit/de3bcef8b4731a48d80007dcdb5daa9e29414085))
- Add btrfs fixtures for sys_chunk mapping + leaf nodes ([`6a6d5de`](https://github.com/Dicklesworthstone/frankenfs/commit/6a6d5de85bab7445483b2e5298b7d280ce42b59c))
- Add ext4 superblock fixture for mkfs 4096-byte block size ([`85f5fc6`](https://github.com/Dicklesworthstone/frankenfs/commit/85f5fc600f9edf92ec2dfcee4ed0b572742cf348))

---

## Project Metadata

| Field | Value |
|-------|-------|
| **Repository** | <https://github.com/Dicklesworthstone/frankenfs> |
| **License** | MIT + OpenAI/Anthropic Rider |
| **Language** | Rust (Edition 2024, MSRV 1.85) |
| **Workspace** | 21 crates (`ffs-types`, `ffs-error`, `ffs-ondisk`, `ffs-block`, `ffs-journal`, `ffs-mvcc`, `ffs-btree`, `ffs-alloc`, `ffs-inode`, `ffs-dir`, `ffs-extent`, `ffs-xattr`, `ffs-fuse`, `ffs-repair`, `ffs-core`, `ffs`, `ffs-cli`, `ffs-tui`, `ffs-harness`, `ffs-ext4`, `ffs-btrfs`) |
| **Safety** | `#![forbid(unsafe_code)]` at every crate root |
| **Total Commits** | 536 (as of 2026-03-21) |
| **Tags / Releases** | None yet (early development) |
| **First Commit** | 2026-02-09 |
| **Author** | Jeffrey Emanuel |

---

*This changelog was built from exhaustive git history research. All commit links point to the canonical repository.*
