# Changelog

All notable changes to FrankenFS are documented in this file, organized by capability area rather than chronological diff order. This project has no formal releases or tags; development has been continuous since inception. Commit links point to the canonical GitHub repository.

> **Repository:** <https://github.com/Dicklesworthstone/frankenfs>
> **Period covered:** 2026-02-09 through 2026-04-06
> **Total commits:** 670

---

## Table of Contents

- [On-Disk Parsing (ext4)](#on-disk-parsing-ext4)
- [On-Disk Parsing (btrfs)](#on-disk-parsing-btrfs)
- [FUSE Mount and VFS Layer](#fuse-mount-and-vfs-layer)
- [Block I/O and ARC Cache](#block-io-and-arc-cache)
- [MVCC Concurrency Engine](#mvcc-concurrency-engine)
- [Safe-Merge Conflict Resolution](#safe-merge-conflict-resolution)
- [Self-Healing Repair Pipeline](#self-healing-repair-pipeline)
- [Writeback-Cache Epoch Barriers](#writeback-cache-epoch-barriers)
- [Write Path (Allocation, Extents, Inodes, Directories, Xattrs)](#write-path)
- [Journal and WAL Recovery](#journal-and-wal-recovery)
- [CLI and Observability](#cli-and-observability)
- [TUI Dashboard](#tui-dashboard)
- [Conformance Harness and Testing](#conformance-harness-and-testing)
- [Fuzz Infrastructure](#fuzz-infrastructure)
- [Performance and Benchmarking](#performance-and-benchmarking)
- [Foundation Types and Error Handling](#foundation-types-and-error-handling)
- [Documentation and Architecture](#documentation-and-architecture)
- [Build, Dependencies, and Licensing](#build-dependencies-and-licensing)

---

## On-Disk Parsing (ext4)

Pure, I/O-free parsing of ext4 on-disk structures in `ffs-ondisk`. All parsers take `&[u8]` and return typed structures.

- **Initial ext4 superblock and structure parsing** -- superblock (106 fields), group descriptors (32-bit and 64-bit), inodes, extent header/entries, feature flag decoding
  [`01bc389`](https://github.com/Dicklesworthstone/frankenfs/commit/01bc38985fb499db3598734e29ec9b7adcbc7253),
  [`3d334bf`](https://github.com/Dicklesworthstone/frankenfs/commit/3d334bfbe7a8012569582ab8292457c1f6d78412)

- **Group descriptor, inode, and directory traversal** -- expand parsing with directory ops, path resolution, extent mapping, file reads via `Ext4ImageReader`
  [`098b4c5`](https://github.com/Dicklesworthstone/frankenfs/commit/098b4c50777375a6b5478ebd4a8ac3e52a406ff4),
  [`f96eb7a`](https://github.com/Dicklesworthstone/frankenfs/commit/f96eb7ad7433e595ca5040a0a441d3c6df8a163a)

- **Feature flag decode helpers** with typed structs replacing raw `u32` constants; `Ext4InodeNumber` and `BtrfsObjectId` wrapper types
  [`5b284ac`](https://github.com/Dicklesworthstone/frankenfs/commit/5b284acdeb11cd8100f87956ca704b62cb3ba046),
  [`d959f65`](https://github.com/Dicklesworthstone/frankenfs/commit/d959f65c45926e8b3d306a10bea11aef36779b8e)

- **SystemTime helpers and inode edge-case tests**
  [`29627fa`](https://github.com/Dicklesworthstone/frankenfs/commit/29627fa159334a17fb079684b726f9101785193a)

- **Comprehensive superblock geometry validation**
  [`aaae453`](https://github.com/Dicklesworthstone/frankenfs/commit/aaae453d64052cee4f792a42cbcbc81d88b07376)

- **Validated inode location helpers** for computing group/block/offset from inode number
  [`5ebb344`](https://github.com/Dicklesworthstone/frankenfs/commit/5ebb3447f95957384eee8505f2ce61e922cd5e08)

- **Zero-allocation `DirBlockIter`** for ext4 directory parsing without heap allocation
  [`2aae5c7`](https://github.com/Dicklesworthstone/frankenfs/commit/2aae5c7d7a583c08abdda7204dbb74ad384d085a)

- **Metadata checksum fixes** -- correct dir + extent block checksum coverage areas
  [`2a1fda2`](https://github.com/Dicklesworthstone/frankenfs/commit/2a1fda2344794d085f0345513d8b106259c59c48)

- **CRC32C convention mismatch fix** in ext4 checksum verification
  [`004fbc0`](https://github.com/Dicklesworthstone/frankenfs/commit/004fbc0f471cd05c90f7f13cfa3556f5dcc7701d)

- **DX hash multi-chunk iteration fix**, TEA transform, and directory size corrections
  [`3958521`](https://github.com/Dicklesworthstone/frankenfs/commit/3958521a88a2bf36a4d6330af44f4bd86687728a)

- **Off-by-one fix** in ext4 inode extended field parsing
  [`93fb9ca`](https://github.com/Dicklesworthstone/frankenfs/commit/93fb9ca7ee0614272ed24417dea12939cdf3161a)

- **ext4 on-disk format enhancements** -- block cache traits, persistent allocator structures
  [`66b3acd`](https://github.com/Dicklesworthstone/frankenfs/commit/66b3acd138268b5aca32bcddcdd7d77e0c1afd52)

- **Block/inode bitmap checksum parsing and serialization** in group descriptors
  [`b7a5cb8`](https://github.com/Dicklesworthstone/frankenfs/commit/b7a5cb835ec5a3d3f93c434c7fd39a2d0ae7b25b)

- **Checksum stamping functions** with hardened integer casts and round-trip tests
  [`481d08f`](https://github.com/Dicklesworthstone/frankenfs/commit/481d08fc3fa286134cbb7409d4ad4c67191e84b1),
  [`dfb02ac`](https://github.com/Dicklesworthstone/frankenfs/commit/dfb02ac163e6647bffe7aecc0ad589c608b510d5)

- **Ext4 metadata surface expansion** -- superblock metadata, JBD2 superblock, flex BG, and MMP parsing landed alongside indirect-block addressing support for the ext4 read/write path
  [`c3b1f26`](https://github.com/Dicklesworthstone/frankenfs/commit/c3b1f26d8ca7c7bd1ed0aef78d5563fa6d698b4c),
  [`ad2280e`](https://github.com/Dicklesworthstone/frankenfs/commit/ad2280e0ad74d8f89cce1c64f9672d31eb9cc4ea),
  [`a19f7d6`](https://github.com/Dicklesworthstone/frankenfs/commit/a19f7d6f9f17b4838c8274c9973d4f478d2ca211)

- **Feature-compatibility and metadata-layout corrections** -- casefold lookup, relaxed incompat acceptance, external-journal UUID pairing, kernel-compatible bitmap CRC32C handling, and ext4 xattr field layout fixes all tightened ext4 compatibility
  [`9e8acdd`](https://github.com/Dicklesworthstone/frankenfs/commit/9e8acdd1c84eb29a35b44990ac4d73fd748b52f2),
  [`23c47de`](https://github.com/Dicklesworthstone/frankenfs/commit/23c47de9e96dcb6e7cce2e7e977bb31969a0c65a),
  [`20d65f4`](https://github.com/Dicklesworthstone/frankenfs/commit/20d65f477ba6e020d573033951f9db6dcf43dcba),
  [`7f4d6eb`](https://github.com/Dicklesworthstone/frankenfs/commit/7f4d6eb767b457b9edda06be4fb74c612996c4d6),
  [`1b08f04`](https://github.com/Dicklesworthstone/frankenfs/commit/1b08f04d9ea9bfd273e640af75385d1111cd9281)

---

## On-Disk Parsing (btrfs)

Pure parsing of btrfs on-disk structures, also in `ffs-ondisk` and the `ffs-btrfs` crate.

- **btrfs superblock parsing** with `sys_chunk_array` and validation
  [`e6fa78e`](https://github.com/Dicklesworthstone/frankenfs/commit/e6fa78eda92c2696d3ac9daf187e0f25e8344380)

- **Logical-to-physical mapping** via `sys_chunk_array` for single-device images
  [`6ed1bf0`](https://github.com/Dicklesworthstone/frankenfs/commit/6ed1bf0e47155890e8da3b0453f3dededabdaea8)

- **Internal node parsing + header validation** for btrfs B-tree traversal
  [`1ae63e0`](https://github.com/Dicklesworthstone/frankenfs/commit/1ae63e0a144461fef443284635ae1e6f94933cc1)

- **Read-only tree-walk** with I/O-agnostic callback, cycle detection, depth bounds, and visit deduplication
  [`35598fe`](https://github.com/Dicklesworthstone/frankenfs/commit/35598fee2d2be09bd33e367eceb65124aa75b4ac)

- **btrfs open/validate pipeline** with tree-walk integration in `ffs-core`
  [`7d2c475`](https://github.com/Dicklesworthstone/frankenfs/commit/7d2c475981651b5504e47ff036efd3689be79da3)

- **CRC32C checksum verification** for btrfs metadata
  [`c24a2b7`](https://github.com/Dicklesworthstone/frankenfs/commit/c24a2b75eea31c1b10b4ce43bb469fc94f761a5f)

- **Comprehensive btrfs structure parsing** -- leaf items, chunk items, root items, device items
  [`a3a9606`](https://github.com/Dicklesworthstone/frankenfs/commit/a3a960689f0c8a5a05e17aee436dcdd6482563d1)

- **Cycle and duplicate-node detection** in btrfs tree walker
  [`da090fe`](https://github.com/Dicklesworthstone/frankenfs/commit/da090feab3923042d051ef05a5a96ad2d9477bfd)

- **Subvolume enumeration and multi-device RAID stripe resolution**
  [`bc67946`](https://github.com/Dicklesworthstone/frankenfs/commit/bc67946e9b829f4d8f3d040115fdb9448911ce9f)

- **Snapshot navigation, subvolume CLI, and snapshot diff**
  [`0258ba2`](https://github.com/Dicklesworthstone/frankenfs/commit/0258ba2b07a76d3d55c3c97ae2a89f8de9dbfc45)

- **RAID5/6 parity rotation fix** for data stripe mapping
  [`18bc6b0`](https://github.com/Dicklesworthstone/frankenfs/commit/18bc6b01b219c611f0b35e117adc3e70e0c77092)

- **COW tree mutation API** with tracing diagnostics and snapshot registry
  [`45c401c`](https://github.com/Dicklesworthstone/frankenfs/commit/45c401c61771237fc08f5f3aed4bf294066a2774)

- **Transaction model with MVCC integration** and S3-FIFO cache eviction
  [`b3c6af2`](https://github.com/Dicklesworthstone/frankenfs/commit/b3c6af2802150f90ca5965297dc7442080aded94)

- **Delayed-ref queue** with bounded flush and parity bookkeeping
  [`f446e3f`](https://github.com/Dicklesworthstone/frankenfs/commit/f446e3fb1a3f16ce6da36097bc4c722976719c98)

- **Read-write mount support** with COW tree and extent allocator
  [`c9c7388`](https://github.com/Dicklesworthstone/frankenfs/commit/c9c7388a3b8333d764a0760d7042149984b16667)

- **Backup superblock mirror repair** from primary
  [`025c3ec`](https://github.com/Dicklesworthstone/frankenfs/commit/025c3ec385ddbd14a3269cbf74a4b1edaa2513fa)

- **btrfs statfs free space** -- report accurate free space from extent allocator
  [`cda44ce`](https://github.com/Dicklesworthstone/frankenfs/commit/cda44cee826f4dbb73bf9fcf42a59b0ec3b776b2)

- **Fallocate data preservation** during overlap and inline-to-regular extent transition
  [`b57e7aa`](https://github.com/Dicklesworthstone/frankenfs/commit/b57e7aaf010f3840490b0a6c85ad4cca9d14fb19)

- **Structured fallocate tracing** and comprehensive test coverage for btrfs
  [`9d3e88b`](https://github.com/Dicklesworthstone/frankenfs/commit/9d3e88b7d116134f2e8a8255cfa2d4475a53cff1),
  [`6fc1e5c`](https://github.com/Dicklesworthstone/frankenfs/commit/6fc1e5cfc78fbbc4cca2ff89eca039c00313f6ae)

- **btrfs metadata coverage expansion** -- subvolume object IDs, chunk/device tree walking, `ram_bytes` on extent items, and multi-device RAID stripe resolution all became first-class in the parser + adapter stack
  [`ad2280e`](https://github.com/Dicklesworthstone/frankenfs/commit/ad2280e0ad74d8f89cce1c64f9672d31eb9cc4ea),
  [`083f790`](https://github.com/Dicklesworthstone/frankenfs/commit/083f790ebc1ca50efaa8ea9b4ba09ad915d3a60a),
  [`3b3b5e8`](https://github.com/Dicklesworthstone/frankenfs/commit/3b3b5e8530b0f131431a958670d59d41cc7a1287),
  [`af1dfed`](https://github.com/Dicklesworthstone/frankenfs/commit/af1dfede9cf9597b4bb84b751d2f0a0579bec2e6)

---

## FUSE Mount and VFS Layer

The `ffs-fuse` adapter translates kernel FUSE protocol into `FsOps` calls on `ffs-core::OpenFs`. The `ffs-core` crate orchestrates format detection, validation, and all subsystem integration.

- **FsOps VFS trait** with `InodeAttr`, `DirEntry`, `FileType` -- the abstract interface all FUSE operations dispatch through
  [`535d019`](https://github.com/Dicklesworthstone/frankenfs/commit/535d0192b9b78951832bc2ac2c91adc80ba0e14a)

- **OpenFs API** with detect-parse-validate pipeline for both ext4 and btrfs
  [`d40f0fa`](https://github.com/Dicklesworthstone/frankenfs/commit/d40f0fa8bf8904bada753b47bb60c3b61513e000),
  [`0f368b7`](https://github.com/Dicklesworthstone/frankenfs/commit/0f368b7ce9ad7abd823b192d7eb575230106520d)

- **Device-based inode read pipeline**, extent mapping, readdir, name lookup, path resolution, file read, and symlink reading
  [`b1bfd2a`](https://github.com/Dicklesworthstone/frankenfs/commit/b1bfd2aca27f732ba2f76a0a74d846aceaad21e8),
  [`b3343f8`](https://github.com/Dicklesworthstone/frankenfs/commit/b3343f8c1af04a0f0b389aee4e0715e52e0e3b16),
  [`be49b64`](https://github.com/Dicklesworthstone/frankenfs/commit/be49b64365d390a0a4ef7c5d96eb502425095b95),
  [`f7a6e42`](https://github.com/Dicklesworthstone/frankenfs/commit/f7a6e42ac167770f7c77294ee985026236b44d84),
  [`0269d26`](https://github.com/Dicklesworthstone/frankenfs/commit/0269d26fedff201a69036b5ac5290b2af8d9bac2),
  [`8025164`](https://github.com/Dicklesworthstone/frankenfs/commit/8025164fcee105c7df3cdfdd53d8fa0e08284e3c)

- **Real FUSE adapter** via the `fuser` crate with read-only ops (lookup, getattr, read, readdir, readlink)
  [`f6b2ca8`](https://github.com/Dicklesworthstone/frankenfs/commit/f6b2ca8af0edcf672d58f2db5cfadbb4e354a45e),
  [`decc239`](https://github.com/Dicklesworthstone/frankenfs/commit/decc239e05cdd7fd2df37677d0eb2e3162ac4dc3)

- **Xattr VFS integration** -- `listxattr`/`getxattr` in FsOps and FUSE read-only xattr operations
  [`010dd43`](https://github.com/Dicklesworthstone/frankenfs/commit/010dd4393a72cbef1f45f130a7ab9a04c143280e),
  [`b61dc73`](https://github.com/Dicklesworthstone/frankenfs/commit/b61dc7311f2df34f55e95576636659217e9f3777)

- **Device numbers for block/char inodes**
  [`8074e16`](https://github.com/Dicklesworthstone/frankenfs/commit/8074e16dc3263719b24f1eacaadad56feb4b09ce)

- **Flush, fsync, fsyncdir FUSE handlers**
  [`892691e`](https://github.com/Dicklesworthstone/frankenfs/commit/892691e4d185db00cfa3ca7288cc7adbfee07cee)

- **FUSE write operations** -- create, mkdir, unlink, rmdir, rename, write, setattr, link, symlink
  [`d51a0c1`](https://github.com/Dicklesworthstone/frankenfs/commit/d51a0c1593f852b1938cbd677f7e651e8dc195c2),
  [`117b530`](https://github.com/Dicklesworthstone/frankenfs/commit/117b530ca52e97ba428e38c8b0d1887bad7d5df4)

- **Degradation FSM** with hysteresis and FUSE backpressure shedding; lock-free `AtomicU8` cache for FSM level reads
  [`b7704fc`](https://github.com/Dicklesworthstone/frankenfs/commit/b7704fc506944446ab1a6aec296a513cb1295845),
  [`a1996f0`](https://github.com/Dicklesworthstone/frankenfs/commit/a1996f06fcd9175a4d329c439493e1a3904f7c1a)

- **Thread-per-core dispatch routing** and FUSE metrics
  [`b2e24e7`](https://github.com/Dicklesworthstone/frankenfs/commit/b2e24e78c3faa9af1640d5b177155f71b9768497)

- **Backpressure throttle tier**, FUSE queue tuning, and mount timeout
  [`21c8652`](https://github.com/Dicklesworthstone/frankenfs/commit/21c8652c73774014d5c8d57cbbf49233cce7d0d0)

- **Backpressure shedding for fsync/fsyncdir** and preflight FCW extraction
  [`457613a`](https://github.com/Dicklesworthstone/frankenfs/commit/457613ab4ece4a00860392ad232c3685662b2a8f)

- **VFS link/symlink/fallocate/statfs** and readahead predictor
  [`9e58f4e`](https://github.com/Dicklesworthstone/frankenfs/commit/9e58f4eadf81ca11f7ba1564de0857001b02a4ed)

- **RequestScope plumbing** through all FsOps methods for MVCC read/write scoping
  [`58adb58`](https://github.com/Dicklesworthstone/frankenfs/commit/58adb580dc45d624a93e8b23ea6da1b79c23fe59)

- **Scope-free convenience methods** for `read_group_desc`, `read_inode`, `read_inode_attr`, `read_dir`, and `lookup_name`
  [`c6915f4`](https://github.com/Dicklesworthstone/frankenfs/commit/c6915f4a82cd2b623dc0094254859c3403d14bd9),
  [`efb7af1`](https://github.com/Dicklesworthstone/frankenfs/commit/efb7af18b2f7b11c5e8bbd687b4e53e6d3918d6a)

- **TransactionBlockAdapter** for MVCC-safe writes and directory entry handling
  [`cf39006`](https://github.com/Dicklesworthstone/frankenfs/commit/cf39006df0dfccf8c8e07cbe9aef7e698bd758b0)

- **Mount validation hardening** and stale readahead fix after writes
  [`8938b01`](https://github.com/Dicklesworthstone/frankenfs/commit/8938b0126555130a2206a1e6ff78525f4f50ee50)

- **Link/symlink/setattr API exposure** and ARC cache dirty tracking fix
  [`a16a009`](https://github.com/Dicklesworthstone/frankenfs/commit/a16a009f6c3ff9852b2b1ce53a4345babc73f0e9)

- **Ioctl and inspection-surface expansion** -- FIEMAP support, `EXT4_IOC_GETFLAGS/SETFLAGS`, btrfs FIEMAP, btrfs `DIR_ITEM` inspection, and stricter ioctl/path validation all landed in the same wave
  [`0f3bfa5`](https://github.com/Dicklesworthstone/frankenfs/commit/0f3bfa5cb7d410eb2845869c4b83f1e0660a2744),
  [`fafa0fa`](https://github.com/Dicklesworthstone/frankenfs/commit/fafa0fa4e0fdfbd59396280da84c0e16076fa436),
  [`d546f57`](https://github.com/Dicklesworthstone/frankenfs/commit/d546f570cbd7c814f8f2ac842db40b9d8f938ff9),
  [`9bd4eb0`](https://github.com/Dicklesworthstone/frankenfs/commit/9bd4eb0d6f917de24dd3c078fa0d538e57a96fc1),
  [`4bcc449`](https://github.com/Dicklesworthstone/frankenfs/commit/4bcc44920f514fd0f2f2f6155a2cbf2f32ab8506),
  [`284797e`](https://github.com/Dicklesworthstone/frankenfs/commit/284797e924c670d523077f6bf81d71540bc0414e)

- **RequestScope and runtime hardening** -- ext4 mutators now run under active request scopes, scope-commit ordering was fixed after create, `fuser` ABI 7-31 was enabled, `forget` landed, and per-core/scope-failure metrics became more trustworthy
  [`16a309b`](https://github.com/Dicklesworthstone/frankenfs/commit/16a309b8dd42fb01fb20e4e0564fb641e84547f7),
  [`f729ea8`](https://github.com/Dicklesworthstone/frankenfs/commit/f729ea8567037b1d4ffc90def0d127dc5bca2a03),
  [`e9e89c0`](https://github.com/Dicklesworthstone/frankenfs/commit/e9e89c052191b93ff8a185d48e7406d6e2db95ad),
  [`27a3207`](https://github.com/Dicklesworthstone/frankenfs/commit/27a32074076e7193aa9f5fbdbbc65b4b92efc0bc),
  [`954ee2a`](https://github.com/Dicklesworthstone/frankenfs/commit/954ee2a7a8c74ab99f9ca514ea7867df69d326f0)

---

## Block I/O and ARC Cache

The `ffs-block` crate provides the `BlockDevice` trait, Adaptive Replacement Cache (ARC), aligned buffers, and write-back coordination.

- **ARC eviction logic fix** and initial tests
  [`e52aa8b`](https://github.com/Dicklesworthstone/frankenfs/commit/e52aa8b60de1c30159edc085a5c43aa9e2215493)

- **CacheMetrics instrumentation surface** for observability
  [`8fead6b`](https://github.com/Dicklesworthstone/frankenfs/commit/8fead6b4364e34cc57cdaf8f42f00377e11f3a01)

- **Cache concurrency design** and TOCTOU race fix
  [`8b91122`](https://github.com/Dicklesworthstone/frankenfs/commit/8b91122f47dc7381ce92f938a548a3ebe16a5c76)

- **Criterion benchmarks** for ARC cache hot paths
  [`3fb2fc7`](https://github.com/Dicklesworthstone/frankenfs/commit/3fb2fc7268e66bfcfa10a98d46f1eef2880aa835)

- **Dirty block tracking and flush accounting** for write-back mode
  [`9ec9dab`](https://github.com/Dicklesworthstone/frankenfs/commit/9ec9dabce3d3c2986aff6d7f9370a973411a77fa)

- **MVCC-aware transactional dirty tracking** and flush lifecycle
  [`6d5d95e`](https://github.com/Dicklesworthstone/frankenfs/commit/6d5d95e4a011b26938ab2cb1c662b4b75a2e08c9)

- **ARC cache memory pressure hooks** for graceful degradation
  [`ff1663c`](https://github.com/Dicklesworthstone/frankenfs/commit/ff1663c40e95c4d0491f10652df8b4f09faf4d90)

- **Aligned I/O and vectored block ops** (`VectoredBlockDevice` trait) for O_DIRECT support
  [`9e58f4e`](https://github.com/Dicklesworthstone/frankenfs/commit/9e58f4eadf81ca11f7ba1564de0857001b02a4ed)

- **Pluggable IoEngine trait** for kernel-bypass I/O (io_uring future support)
  [`696ef28`](https://github.com/Dicklesworthstone/frankenfs/commit/696ef28004584a80dcc50307624208f499455dcd)

- **S3-FIFO cache panics replaced** with self-healing invariant recovery
  [`8967c05`](https://github.com/Dicklesworthstone/frankenfs/commit/8967c05195d8b9bc3027baab96f7e8f4beec64e3)

- **Dirty-block eviction panics replaced** with graceful skip-and-requeue
  [`d68552a`](https://github.com/Dicklesworthstone/frankenfs/commit/d68552a5608e47a38638a136392d4e036bc75082)

- **Dirty block eviction protection** during cache pressure
  [`1e759e9`](https://github.com/Dicklesworthstone/frankenfs/commit/1e759e9c1596c39244254543629c825d955d04c3)

- **Sequence-aware dirty tracking** and repair refactoring
  [`e3b1cc5`](https://github.com/Dicklesworthstone/frankenfs/commit/e3b1cc59d71f38c8052121a0161f9079a9ac6f54)

- **Don't restore dirty state** when repair notification fails after successful flush
  [`2fb7834`](https://github.com/Dicklesworthstone/frankenfs/commit/2fb78340ce693b75b4b54895ace3de9761b6ef33)

- **I/O metric semantics alignment** -- `IoEngine` submission counters now reflect real submission behavior rather than optimistic dispatch intent, improving block-layer observability
  [`3f67e30`](https://github.com/Dicklesworthstone/frankenfs/commit/3f67e3074127030e7cdef861fbe40165f426e531)

---

## MVCC Concurrency Engine

The `ffs-mvcc` crate provides block-level Multi-Version Concurrency Control with snapshot isolation, version chains, sharded stores, and WAL persistence.

- **MVCC-aware block device wrapper** with staged writes and snapshot isolation
  [`ddcb0ea`](https://github.com/Dicklesworthstone/frankenfs/commit/ddcb0ea2dc8be2cf324b37646e4dcc876290a095)

- **Deterministic MVCC concurrency invariant tests** using `LabRuntime`
  [`ee24769`](https://github.com/Dicklesworthstone/frankenfs/commit/ee247698148de9409eb032a9d3901fa5386c441e)

- **Watermark API + active snapshot tracking** for version GC
  [`9252739`](https://github.com/Dicklesworthstone/frankenfs/commit/9252739bce6ae7bbccde524c06ac93b1f51c6572)

- **Serializable Snapshot Isolation (SSI)** with rw-antidependency detection
  [`3211b35`](https://github.com/Dicklesworthstone/frankenfs/commit/3211b35321d1e3c93cc6cf09c6f3f0a2db4b3a5f),
  [`66e28b1`](https://github.com/Dicklesworthstone/frankenfs/commit/66e28b1cb2f6b26db631d3bb33ddf07b958b06f6)

- **WAL persistence layer** with crash recovery and replay
  [`c4a3764`](https://github.com/Dicklesworthstone/frankenfs/commit/c4a37647e277898a98d8945ababd13e433a50e4e)

- **Sharded concurrent MVCC store** (`ShardedMvccStore`) with sorted lock acquisition for deadlock prevention
  [`d9c2568`](https://github.com/Dicklesworthstone/frankenfs/commit/d9c25689cdba7c2ae2b2d4513e712dd4e7b72784)

- **MVCC store integration** into `OpenFs` with full transaction API
  [`f0dc595`](https://github.com/Dicklesworthstone/frankenfs/commit/f0dc595dd8c2b739e76fdfb7b7f78dd0f11def2a)

- **Version chain backpressure** with chain-cap enforcement
  [`d51a0c1`](https://github.com/Dicklesworthstone/frankenfs/commit/d51a0c1593f852b1938cbd677f7e651e8dc195c2),
  [`1a6f2ce`](https://github.com/Dicklesworthstone/frankenfs/commit/1a6f2cef817df9ae4b39742e1a59cea44a0effb0)

- **Zstd/Brotli transparent compression** for version chain entries
  [`ce6cb61`](https://github.com/Dicklesworthstone/frankenfs/commit/ce6cb6121d6afa1e4816ca736405770f497178c8)

- **RCU primitives** for lock-free metadata reads
  [`9de8036`](https://github.com/Dicklesworthstone/frankenfs/commit/9de80367844ef82b6345671c5a84c255cab65263)

- **Evidence ledger integration** and budget-aware GC
  [`2a9c863`](https://github.com/Dicklesworthstone/frankenfs/commit/2a9c8636ba15ad6f34d3459cbe51eaa88e00cc0d)

- **FCW commit split** into preflight+apply phases; RCU write-lock gap fix
  [`7a17036`](https://github.com/Dicklesworthstone/frankenfs/commit/7a1703654bcd5228f95f0142bae4d071fbcce767)

- **Snapshot backpressure semantics** restoration and clippy cleanup
  [`1a1e129`](https://github.com/Dicklesworthstone/frankenfs/commit/1a1e129637d10e0dabddf11aea3c43c5c86eb55f)

- **Epoch advancement consolidation** under single lock; field privacy and WAL rollback on write failure
  [`9132ceb`](https://github.com/Dicklesworthstone/frankenfs/commit/9132ceb27c29f775c80bd3e6d90fc8fad9c780df),
  [`9a34f35`](https://github.com/Dicklesworthstone/frankenfs/commit/9a34f355e030456bed4eb8df5306480d66c03117)

- **TOCTOU race fix** in `prune_safe` and RAID stripe arithmetic hardening
  [`020ac96`](https://github.com/Dicklesworthstone/frankenfs/commit/020ac96746847b5fb4059605a44a16b6d36f0d4b)

- **Contention metrics on chain-backpressure abort**
  [`f9386d7`](https://github.com/Dicklesworthstone/frankenfs/commit/f9386d79213435b62d90a8f04bcd283996ec6c63)

- **Zero-division guard** in `inode_index_in_group`
  [`40619b0`](https://github.com/Dicklesworthstone/frankenfs/commit/40619b0b21ba653076cedf07d0072a5ba6e888fc)

- **Bounds-check** on `resolve_data_with` index and block address overflow prevention
  [`d8e561a`](https://github.com/Dicklesworthstone/frankenfs/commit/d8e561a88d00bd128bc700588d94d2efb806b3d0)

- **`TxnAbortReason` re-export** as public for downstream crates
  [`8126e90`](https://github.com/Dicklesworthstone/frankenfs/commit/8126e906b76a90d1bd6718d4ba598008de3838d5)

- **MVCC durability tightening** -- sharding continued to expand, committed block versions now flush on `fsync`/destroy, snapshot capture was fixed, and `ext4_fallocate` no longer bypasses MVCC bookkeeping
  [`81ae68b`](https://github.com/Dicklesworthstone/frankenfs/commit/81ae68b29a6c1f3fdd8921d7d73962c0caef3d68),
  [`11c75dd`](https://github.com/Dicklesworthstone/frankenfs/commit/11c75ddca479747a95c167de0365a65edecdf1d5),
  [`ff6edef`](https://github.com/Dicklesworthstone/frankenfs/commit/ff6edef13d4a96380a69691ccbbd7e7707765e57),
  [`27a3207`](https://github.com/Dicklesworthstone/frankenfs/commit/27a32074076e7193aa9f5fbdbbc65b4b92efc0bc)

---

## Safe-Merge Conflict Resolution

Merge-proof system allowing non-conflicting concurrent writes to the same block, with adaptive policy selection.

- **Safe-merge taxonomy classifier** with pairwise commutativity tests
  [`c3c7c9c`](https://github.com/Dicklesworthstone/frankenfs/commit/c3c7c9c90943f84a38b653456594138fd542b162)

- **Merge-proof resolution** for non-conflicting concurrent writes (AppendOnly, IndependentKeys, NonOverlappingExtents, TimestampOnlyInode, DisjointBlocks)
  [`3ed57bc`](https://github.com/Dicklesworthstone/frankenfs/commit/3ed57bcd4268118caeb9b5a1b979886a42cf92c0)

- **100-writer append-only merge proof stress test** with structured progress
  [`b62f97d`](https://github.com/Dicklesworthstone/frankenfs/commit/b62f97df72c9ca3908fe785409de77c5c0ae7b76)

- **Adaptive conflict policy** with expected-loss selection between Strict FCW and SafeMerge
  [`3d3d5cc`](https://github.com/Dicklesworthstone/frankenfs/commit/3d3d5ccd29d0b32e12d65fd7e508f6c452bfa665)

- **Contention evidence types**, emit helpers, and CLI preset
  [`522f441`](https://github.com/Dicklesworthstone/frankenfs/commit/522f441d8887f0a1f11990e3a1d48f97a0041a06)

- **120-writer verification gate** stress test proving safe-merge under high contention (SafeMerge 9.5x lower expected loss than Strict, zero corruption)
  [`0a704cb`](https://github.com/Dicklesworthstone/frankenfs/commit/0a704cbadf0ba24ef8dba6e7e2a0efdc636511c8)

- **Policy-switch delta calculation fix** and collection of all merge variants
  [`a13818d`](https://github.com/Dicklesworthstone/frankenfs/commit/a13818dc44b187ce882143609f3148d6d36bc017)

- **`InodeMetadataMergeFootprint`** introduction and merge-classifier extraction
  [`1e415a3`](https://github.com/Dicklesworthstone/frankenfs/commit/1e415a360da3f147332db9fb23037301ff4ed186),
  [`e719cc4`](https://github.com/Dicklesworthstone/frankenfs/commit/e719cc47fdacc6660161ce715ebc2ddf8faeae40)

- **Merge preflight hardening** -- staged block-range validation now rejects malformed merge/write-set combinations before they can become visible
  [`4301dfa`](https://github.com/Dicklesworthstone/frankenfs/commit/4301dfa7c33ca4e682a6c83f81b4738ab8fffc62)

---

## Self-Healing Repair Pipeline

RaptorQ fountain-coded repair with Bayesian overhead optimization, scrub pipeline, adaptive refresh, and multi-host coordination in `ffs-repair`.

- **FrankenSQLite RaptorQ approach** extracted for filesystem repair design
  [`fdd193e`](https://github.com/Dicklesworthstone/frankenfs/commit/fdd193e5a2f379dc920d7339d8903e9548d37e39)

- **Scrub pipeline** for corruption detection
  [`a743f6a`](https://github.com/Dicklesworthstone/frankenfs/commit/a743f6a914224e2b436959351e5eca8ba30027aa)

- **Repair symbol format** and storage strategy
  [`1a8605b`](https://github.com/Dicklesworthstone/frankenfs/commit/1a8605b02f1cf97a778a63a3c8743b2e80aa83bd)

- **RaptorQ encode/decode workflow** (RFC 6330 fountain codes)
  [`ce955c3`](https://github.com/Dicklesworthstone/frankenfs/commit/ce955c3fc1976bc1f195ab4ee78881fc82021276)

- **`RepairPolicy` + `DurabilityAutopilot`** with Bayesian Beta posterior for overhead optimization
  [`f4c3073`](https://github.com/Dicklesworthstone/frankenfs/commit/f4c3073b0f9be7d12283c5a03342ecfd7f276a59)

- **Format-aware scrub validators** and error taxonomy refinement
  [`47d6e29`](https://github.com/Dicklesworthstone/frankenfs/commit/47d6e29cc89e32b5b8a7e8643d9bc20fada1b73d)

- **Background scrub daemon** with backpressure-aware scheduling
  [`65296a3`](https://github.com/Dicklesworthstone/frankenfs/commit/65296a3c5bf76e639f53285fd2fa4198d1b5b6c4),
  [`b0c9349`](https://github.com/Dicklesworthstone/frankenfs/commit/b0c9349dfe1eae491a72100de81ab42da872f3e7)

- **Adaptive symbol-refresh protocol** and Bayesian overhead autopilot
  [`62d688d`](https://github.com/Dicklesworthstone/frankenfs/commit/62d688d8023efd35de9d04e6d4654354a8dd1451)

- **Recovery and storage repair infrastructure**
  [`7a0d1fd`](https://github.com/Dicklesworthstone/frankenfs/commit/7a0d1fd5ff78cc578946448cd4f41d005bfefbc4),
  [`5bd3446`](https://github.com/Dicklesworthstone/frankenfs/commit/5bd344615fdc65ee1c6ff49579150053e1d99ad3)

- **Repair flush lifecycle** and budget-aware flush daemon
  [`fd195b8`](https://github.com/Dicklesworthstone/frankenfs/commit/fd195b852ed8161ce0650d6bc642cdd5e2966598)

- **Self-healing demo module** with adoption-wedge example
  [`e101bd9`](https://github.com/Dicklesworthstone/frankenfs/commit/e101bd96d6cb54836e438c740e1be53ab228fd49),
  [`00ea3f7`](https://github.com/Dicklesworthstone/frankenfs/commit/00ea3f750d401ed5ce4305d523ec5189d13cf3bb)

- **Local Reconstruction Codes (LRC)** for distributed repair
  [`6a64689`](https://github.com/Dicklesworthstone/frankenfs/commit/6a64689e477cb6ebd48fa73e3f5ce41c4b4b9037)

- **Proof of Retrievability (PoR)** for cryptographic durability audit
  [`020da2c`](https://github.com/Dicklesworthstone/frankenfs/commit/020da2cdd86205eee12033d4288f869647d80237)

- **Expected-loss model** for adaptive refresh trigger policies (age-only vs block-count vs hybrid)
  [`8a3c614`](https://github.com/Dicklesworthstone/frankenfs/commit/8a3c614f0374dc5d6b15794418ac2366122e3f47)

- **`RefreshLossModel` edge case hardening** for zero blocks, zero writes, degenerate thresholds
  [`46c0119`](https://github.com/Dicklesworthstone/frankenfs/commit/46c0119368d4bbc7e0e837c307775907c61412d1)

- **Hybrid refresh policy** combining age-timeout and block-count triggers
  [`6b383e6`](https://github.com/Dicklesworthstone/frankenfs/commit/6b383e63d26c9e3608895e84837b0422c6246d61)

- **Stale-window SLO instrumentation** with percentile-based breach detection (p95 83.3% reduction under heavy writes)
  [`f32ce08`](https://github.com/Dicklesworthstone/frankenfs/commit/f32ce0813c3b1fa81e5930f8e0ab93237dea875e)

- **Multi-host repair ownership protocol** with optimistic lease-based coordination
  [`d5fde69`](https://github.com/Dicklesworthstone/frankenfs/commit/d5fde691e643b9ace8dbf9435bbae1a28375257c)

- **Symbol exchange transport** and repair pipeline enhancement
  [`56a4b6d`](https://github.com/Dicklesworthstone/frankenfs/commit/56a4b6d788327e2733d78ec49371ec1b6552253a)

- **Adaptive symbol refresh** and xfstests conformance expansion
  [`14b1ec3`](https://github.com/Dicklesworthstone/frankenfs/commit/14b1ec33e2c3a42dcd8f508db12dbc7fc8b6a6df)

- **RaptorQ block-level recovery** wired into btrfs `fsck --repair` path
  [`ef72e83`](https://github.com/Dicklesworthstone/frankenfs/commit/ef72e83e1276ed7d272f130be0a250d1b48c36e0)

- **Evidence preset validation** and repair exchange refinement
  [`5965c04`](https://github.com/Dicklesworthstone/frankenfs/commit/5965c048336c83f7e9286051df3d2e091073a09d)

- **Repair robustness improvements** -- decode paths now fail explicitly instead of silently falling back, exchange completion shuts down TCP streams cleanly, and PoR challenge generation is cheaper for full-block cases
  [`5306287`](https://github.com/Dicklesworthstone/frankenfs/commit/530628751b38d49eb8b5f2c90412f716ef0d0c75),
  [`77229d4`](https://github.com/Dicklesworthstone/frankenfs/commit/77229d4129d75c9f4d09b83cf0b58c0c22fd9c4a),
  [`ffb921b`](https://github.com/Dicklesworthstone/frankenfs/commit/ffb921b12d5fb6cd490ef8bb8a9e55ed1aa63181)

---

## Writeback-Cache Epoch Barriers

Per-inode epoch state machine (`staged >= visible >= durable`) for future FUSE writeback-cache enablement, with crash consistency proofs in `ffs-core`.

- **Writeback-cache epoch barrier** with per-inode epoch tracking (staged/visible/durable counters)
  [`541e178`](https://github.com/Dicklesworthstone/frankenfs/commit/541e178fb0785220b70e6949ff479b7f9908d7e8)

- **Infallible `commit_epoch`** -- removed `EpochNotStaged` error
  [`5e11da6`](https://github.com/Dicklesworthstone/frankenfs/commit/5e11da667cc750d9089004ab969a8e89a3dc37ef)

- **12-scenario crash consistency matrix** for writeback epoch barrier
  [`e8bd18d`](https://github.com/Dicklesworthstone/frankenfs/commit/e8bd18d5ec7fe17670d72f0183b8216a264c358f)

- **Untracked inodes treated as visible** in epoch barrier; recovery hardening
  [`389e17a`](https://github.com/Dicklesworthstone/frankenfs/commit/389e17a832acc88a63e31c792cf6bb9953eefaae)

- **Writeback-cache benchmark workload types** and throughput comparison model
  [`72391c7`](https://github.com/Dicklesworthstone/frankenfs/commit/72391c70d50e5c68f40cff9c7fddc66ddc858cac)

- **Writeback-cache MVCC barrier schedule invariant checker** (6 formal invariants: I1-I6)
  [`f04d77c`](https://github.com/Dicklesworthstone/frankenfs/commit/f04d77cf6481c45f078702eecf86827abb53c305)

- **Barrier invariant types gated** behind `#[cfg(test)]`
  [`64e81db`](https://github.com/Dicklesworthstone/frankenfs/commit/64e81db1f4853a5480ab38d27f19a4edae174178)

---

## Write Path

Block/inode allocation (`ffs-alloc`), extent B+tree (`ffs-btree`), extent mapping (`ffs-extent`), inode lifecycle (`ffs-inode`), directory operations (`ffs-dir`), and extended attributes (`ffs-xattr`).

- **ext4 extent B+tree operations** -- search, insert, split, merge
  [`092a48a`](https://github.com/Dicklesworthstone/frankenfs/commit/092a48aebdd7596170f5ebfc7467493489ef3f1c)

- **Block/inode allocation** -- mballoc-style bitmap allocator with buddy system, goal-directed placement, Orlov directory spreading
  [`5d99bd7`](https://github.com/Dicklesworthstone/frankenfs/commit/5d99bd72096335dded82b76fca8849e9edc70c57)

- **Extent write operations** -- insert, truncate, mark-written, punch-hole
  [`0e8a9d6`](https://github.com/Dicklesworthstone/frankenfs/commit/0e8a9d6690fb81cd91ca26dee994a8ddeec4b76b)

- **Inode lifecycle operations** -- create, read, write, delete with checksum validation
  [`20e4a7f`](https://github.com/Dicklesworthstone/frankenfs/commit/20e4a7f539fe543cb31bba1eb808ed2de49c5c32)

- **Directory write operations** -- add_entry, remove_entry, init_dir_block
  [`90baa90`](https://github.com/Dicklesworthstone/frankenfs/commit/90baa906db425777dee4d84aaeccbb7f10f3c48f)

- **Extended attribute write operations** with Create/Replace mode semantics
  [`3bde39c`](https://github.com/Dicklesworthstone/frankenfs/commit/3bde39ce0d5d4b68e9855f94a44f735f26eb3c7a)

- **Succinct rank/select bitmap** for O(1) free-space queries
  [`21de74b`](https://github.com/Dicklesworthstone/frankenfs/commit/21de74b375d81d49b3d9eab3812c8001431437d8)

- **Batch block allocator** and extent LRU cache
  [`a51c901`](https://github.com/Dicklesworthstone/frankenfs/commit/a51c9017fad2be285e00a381a7c51b9fd87691aa)

- **Punch-hole rewrite** with per-extent deletion and overflow tests
  [`240e061`](https://github.com/Dicklesworthstone/frankenfs/commit/240e061c20bd746d12de5e72477934491379b466)

- **Btree insert separator-key maintenance fix** with proptests
  [`47ef0f9`](https://github.com/Dicklesworthstone/frankenfs/commit/47ef0f99c028bfc1f6e41ac12b16e299acc16056)

- **Split write reordering** and deferred child frees for crash safety
  [`15769c7`](https://github.com/Dicklesworthstone/frankenfs/commit/15769c70107823dbdb314e9f75c49b19c107bb90)

- **Double-free detection** in inode bitmap allocator
  [`b6eb23c`](https://github.com/Dicklesworthstone/frankenfs/commit/b6eb23c297100f5f3eda34a8b2d0a248d0514a46)

- **Cross-group extent rejection** in `free_blocks`
  [`657ddc6`](https://github.com/Dicklesworthstone/frankenfs/commit/657ddc64879e331a3763f756626f09b600b6a35b)

- **Block allocator improvements** including empty bitmap panic elimination
  [`ecffd3d`](https://github.com/Dicklesworthstone/frankenfs/commit/ecffd3d1a8de57849e59a58224c751959984bdbf),
  [`49d0dbb`](https://github.com/Dicklesworthstone/frankenfs/commit/49d0dbbc4cec65009ec64709bbb4e418b4754987)

- **64-bit timestamp pipeline** for year-2106+ support
  [`53c697b`](https://github.com/Dicklesworthstone/frankenfs/commit/53c697b0d598062eb35968a2e20492c6ece3f734)

- **Checked/saturating arithmetic** for block numbers and counters
  [`4ef909f`](https://github.com/Dicklesworthstone/frankenfs/commit/4ef909fff1ac6d50460bd8166e1168cde3a1e365)

- **Saturating clamp helpers** replacing unsafe as-casts in `trim_extents`
  [`35610ff`](https://github.com/Dicklesworthstone/frankenfs/commit/35610ffd591b624640c8c8a8921fa7998c1808b0)

- **Missing FsGeometry fields** fix and `encode_extra_timestamp` nsec clamping
  [`549aaad`](https://github.com/Dicklesworthstone/frankenfs/commit/549aaad4736eb62e02f59292603cb0c6b2ddf2b9)

- **`huge_file` flag respect** in block accounting; COW for shared xattr blocks
  [`507f826`](https://github.com/Dicklesworthstone/frankenfs/commit/507f826fcf05e0846a0847296a5731ea7b0d73cc)

- **Directory nlink handling** correction, xattr block freeing on delete
  [`2791388`](https://github.com/Dicklesworthstone/frankenfs/commit/279138864e47004aa5988992f7b5dbab90a2d4ed)

- **ext4 directory metadata checksum support**
  [`875d735`](https://github.com/Dicklesworthstone/frankenfs/commit/875d73545214c82d8e465261ef91142f4133cf26)

- **ExtentCache namespace isolation tests**
  [`242c873`](https://github.com/Dicklesworthstone/frankenfs/commit/242c87378ea967fc6625877407d57b55584b16a6)

- **ext4 `e2compr` write support** -- the path moved from read-only decompression to bidirectional read/write, including single/double/triple indirect block pointers, cluster accounting, and compressed-indirect truncate coverage
  [`008da90`](https://github.com/Dicklesworthstone/frankenfs/commit/008da90a6a8becbb6569c4aa50b3c0550aa9c3f8),
  [`ca8ed79`](https://github.com/Dicklesworthstone/frankenfs/commit/ca8ed791418341953440c19b66ced33360aad8a9),
  [`18cd3d7`](https://github.com/Dicklesworthstone/frankenfs/commit/18cd3d75734f264b9f85c9599cf74db9628b4993),
  [`06a4288`](https://github.com/Dicklesworthstone/frankenfs/commit/06a42887617df6103a5fe72ed0bcf4bd0d7e5e02),
  [`a57561d`](https://github.com/Dicklesworthstone/frankenfs/commit/a57561dbbc3fcfffe695d4781bf8582667c11e39),
  [`220ea22`](https://github.com/Dicklesworthstone/frankenfs/commit/220ea22fcf5c9d194601b779bc98ce03326ef233)

- **btrfs fallocate and extent mutation expansion** -- punch-hole and zero-range support landed with overlapping-extent removal helpers, compressed-extent guard rails, and additional extent-management logic
  [`5731ae3`](https://github.com/Dicklesworthstone/frankenfs/commit/5731ae35d725f5ebced7f7966f665ce6a2a35342),
  [`bcf92b2`](https://github.com/Dicklesworthstone/frankenfs/commit/bcf92b2ccc18c4e24d8707e6e55ec839c9524068),
  [`ea9f019`](https://github.com/Dicklesworthstone/frankenfs/commit/ea9f01900fb9c7f3fdb74b8cbb93ce98b93ae8d9),
  [`10a90ff`](https://github.com/Dicklesworthstone/frankenfs/commit/10a90ffbd4c30f19dd938e6b45f28289c3b0f512),
  [`f674445`](https://github.com/Dicklesworthstone/frankenfs/commit/f67444506d397bef7db9b1620d5b0fb857a1c23a)

- **Namespace and metadata correctness hardening** -- directory block allocation became transactional, POSIX rename semantics were enforced, inode `i_version` now bumps on mutation, xattr collision handling improved, and new/preflight dir blocks now initialize checksum tails correctly
  [`6b01343`](https://github.com/Dicklesworthstone/frankenfs/commit/6b013433c012652cfe318078c2485e479863c4aa),
  [`75e1888`](https://github.com/Dicklesworthstone/frankenfs/commit/75e1888b7398df6ab3dc0b0fba15aa4816af9842),
  [`f3c69f2`](https://github.com/Dicklesworthstone/frankenfs/commit/f3c69f2390d79a7fd30986e9f15194249f64578f),
  [`24afc31`](https://github.com/Dicklesworthstone/frankenfs/commit/24afc3168f2c255d86f05015ca64e3a52865de4b),
  [`872ce8d`](https://github.com/Dicklesworthstone/frankenfs/commit/872ce8deac41e9a7f6d47b19fca8fd2cdcd8dfde),
  [`28ab2b4`](https://github.com/Dicklesworthstone/frankenfs/commit/28ab2b4d2523f8b3b2f0a98b764d56099379a734)

---

## Journal and WAL Recovery

JBD2 replay for ext4 compatibility and native MVCC WAL for crash recovery, in `ffs-journal` and `ffs-mvcc`.

- **JBD2 replay + native COW journal** implementation
  [`03925fb`](https://github.com/Dicklesworthstone/frankenfs/commit/03925fb7d9c3f63063921ad8cc0d481ae5350724)

- **Journal replay integration** into ext4 mount path
  [`db9d1d0`](https://github.com/Dicklesworthstone/frankenfs/commit/db9d1d0ef5fb838aa1e184e7dd8e87164b2a600e)

- **JBD2 revoke-across-transactions** semantics fix and `r_count` length limit enforcement
  [`4cf620a`](https://github.com/Dicklesworthstone/frankenfs/commit/4cf620a7422380d45cdb91df4e612ff0ec4c7636),
  [`d2e1be5`](https://github.com/Dicklesworthstone/frankenfs/commit/d2e1be5006d99b421c7222f520701cbe2dbae127)

- **Non-contiguous ext4 journal extents** support
  [`fdd192b`](https://github.com/Dicklesworthstone/frankenfs/commit/fdd192b4da525f6a41f67edd9975243f401db25b)

- **WAL replay engine extraction** and recovery pipeline hardening
  [`112ad62`](https://github.com/Dicklesworthstone/frankenfs/commit/112ad62393ee1645b5564f99b781d0ab0f56fc50)

- **Native-mode boundary resolution** and version-store format
  [`7fab707`](https://github.com/Dicklesworthstone/frankenfs/commit/7fab7079290c24f701eb682b5e06453599416d50)

- **WAL replay telemetry**, crash matrix, and verification runner
  [`d949529`](https://github.com/Dicklesworthstone/frankenfs/commit/d94952931e690f42ec17d28b3a819173a6ac7b56)

- **Journaled commit atomicity** fix; btrfs extent/fallocate correctness; ext4 unwritten extents
  [`b9772d0`](https://github.com/Dicklesworthstone/frankenfs/commit/b9772d080f059901b3944a4cad7fcdecfe6a6a25)

- **Superblock checksum write ordering** fix
  [`8400820`](https://github.com/Dicklesworthstone/frankenfs/commit/8400820e9317ee98b769dcb2bc920d20c31da623)

- **Recovery surface expansion** -- ext4 fast-commit, btrfs tree-log replay, mount-time fast-commit application, 64-bit JBD2 support, and external-journal pairing/replay helpers all landed in this window
  [`64098b5`](https://github.com/Dicklesworthstone/frankenfs/commit/64098b58af122cbc97c92ebd53191787a742c0b8),
  [`6a4dd9c`](https://github.com/Dicklesworthstone/frankenfs/commit/6a4dd9c146cce2024d95110dac331d42a579faf8),
  [`a19f7d6`](https://github.com/Dicklesworthstone/frankenfs/commit/a19f7d6f9f17b4838c8274c9973d4f478d2ca211),
  [`23c47de`](https://github.com/Dicklesworthstone/frankenfs/commit/23c47de9e96dcb6e7cce2e7e977bb31969a0c65a),
  [`7a8ede4`](https://github.com/Dicklesworthstone/frankenfs/commit/7a8ede42527c95b3b006e3ef16eabdaf4efdc9c4),
  [`81ae68b`](https://github.com/Dicklesworthstone/frankenfs/commit/81ae68b29a6c1f3fdd8921d7d73962c0caef3d68)

- **Journal and WAL hardening** -- malformed descriptors/revokes and duplicate sequence reuse are now rejected, duplicate/post-commit COW records are blocked, replay logic moved to event-ordered helpers, and WAL-writer logging/evidence paths were strengthened
  [`136231d`](https://github.com/Dicklesworthstone/frankenfs/commit/136231d4c96d7c0f7e479a35f1e2f9d521ecfd8f),
  [`0441102`](https://github.com/Dicklesworthstone/frankenfs/commit/04411027aebef1c2a2729bc8ff08a311f75cf840),
  [`c2faa7a`](https://github.com/Dicklesworthstone/frankenfs/commit/c2faa7ac8ca34ca2513478d0cf2726ae42a5828d),
  [`d20a990`](https://github.com/Dicklesworthstone/frankenfs/commit/d20a9908bc2460f0055794c18e4441f18ee8d345),
  [`b341e26`](https://github.com/Dicklesworthstone/frankenfs/commit/b341e26c06518bece53f7a7a0f10aaef1162a4dc),
  [`b2aa26f`](https://github.com/Dicklesworthstone/frankenfs/commit/b2aa26f3fdafeb0641a2b71e8580df3f45fb60a8),
  [`890ac99`](https://github.com/Dicklesworthstone/frankenfs/commit/890ac99bbf3542d0b28b8dbd5f43a72bc4496627),
  [`cba534c`](https://github.com/Dicklesworthstone/frankenfs/commit/cba534c3a9d8af2bd607f48a2499e17a4a6ffb1e)

---

## CLI and Observability

The `ffs-cli` crate provides the command-line interface (`inspect`, `info`, `dump`, `fsck`, `repair`, `mount`, `scrub`, `parity`, `evidence`, `mkfs`, `mvcc-stats`).

- **Clap-based structured CLI** replacing ad-hoc argument parsing
  [`f0aebe8`](https://github.com/Dicklesworthstone/frankenfs/commit/f0aebe8c11b0eb583893cf6378f64c30a6114ae6)

- **Mount subcommand** for read-only ext4 FUSE mount; later expanded to btrfs and experimental `--rw`
  [`de66b4b`](https://github.com/Dicklesworthstone/frankenfs/commit/de66b4b58c0c1a0c8dab3a2cfe6a971ce2f2770a),
  [`436c257`](https://github.com/Dicklesworthstone/frankenfs/commit/436c2576a38302cc7850978882feb5770aaf8f0d)

- **Scrub subcommand** for read-only integrity scanning
  [`3210ca5`](https://github.com/Dicklesworthstone/frankenfs/commit/3210ca536e7d963cef705df5c69802bab507c444)

- **Free-space subcommand** for ext4 analysis
  [`aa2ec8d`](https://github.com/Dicklesworthstone/frankenfs/commit/aa2ec8d233fd7e524867ae1ca855607db21d35f1)

- **Evidence ledger viewer** command with preset queries (replay-anomalies, repair-failures, pressure-transitions, contention) and summary aggregation
  [`7f5ed30`](https://github.com/Dicklesworthstone/frankenfs/commit/7f5ed3034397597998ea7672c273673a960715cb),
  [`77f6c56`](https://github.com/Dicklesworthstone/frankenfs/commit/77f6c56566e08690f4592537479958d8a562f354)

- **Evidence metrics presets** and expanded observability CLI
  [`907d7a5`](https://github.com/Dicklesworthstone/frankenfs/commit/907d7a5f1b479a29e2c18d5040f06596755a26b0)

- **`mvcc-stats` command** for version-chain statistics
  [`4b0c21d`](https://github.com/Dicklesworthstone/frankenfs/commit/4b0c21db419d360a393a03b2cf150477e1959a4d)

- **`fsck --force` semantics** with clean-state skip logic
  [`0e73ba8`](https://github.com/Dicklesworthstone/frankenfs/commit/0e73ba8b8d3413a3037127f702587316255deb78)

- **Major CLI expansion** -- dump superblock/inode/extents/dir, info with groups/mvcc/repair/journal, mkfs
  [`6290318`](https://github.com/Dicklesworthstone/frankenfs/commit/6290318e4d5fb7c8e60246ce88bd8637a0dada57),
  [`11202d4`](https://github.com/Dicklesworthstone/frankenfs/commit/11202d40f8d930f9d6c0e798f80a2c71c2cd0466)

- **Repair command expansion** and artifact manifest
  [`c47b7df`](https://github.com/Dicklesworthstone/frankenfs/commit/c47b7df5bd0d8f67f7e8b4186181bc3b9f4b49ed)

- **btrfs CLI integration** -- chunk-group reporting, btrfs inode dump, btrfs stale-only repair scoping, subvolume CLI
  [`a53de18`](https://github.com/Dicklesworthstone/frankenfs/commit/a53de18333d3bd3748a362716f3bb45f73fd07d5),
  [`162510f`](https://github.com/Dicklesworthstone/frankenfs/commit/162510fea6f376bc85d8207f5a1f33d22a89eab6),
  [`dbb5ed2`](https://github.com/Dicklesworthstone/frankenfs/commit/dbb5ed2410323d3af0f4718c18e6e22a76e6f512)

- **Runtime-mode CLI contract** with structured observability and E2E coverage
  [`9d4a46e`](https://github.com/Dicklesworthstone/frankenfs/commit/9d4a46e0677212a3337284163c1e408c1ac3d59b)

- **Seeked file-region I/O** replacing full-image reads in CLI
  [`47e0f11`](https://github.com/Dicklesworthstone/frankenfs/commit/47e0f11d593c4844be259451f3702254138eefac)

- **Operator runbooks** for replay failure triage, corruption recovery, and backpressure investigation
  [`b9caa45`](https://github.com/Dicklesworthstone/frankenfs/commit/b9caa45cadba75df5af3964be1475ce3777ecc80)

- **CLI inspection depth expansion** -- btrfs ZLIB/ZSTD/LZ4 decoding, DIR_INDEX-aware dumps, and dynamic superblock-derived constants improved the fidelity of `inspect`, `dump`, and `info`
  [`1b47dde`](https://github.com/Dicklesworthstone/frankenfs/commit/1b47dde441dfdb3cbe49ce268a8e35d2252ff53d),
  [`a7c0761`](https://github.com/Dicklesworthstone/frankenfs/commit/a7c0761c11495de3f9ef5044bcba59cbc3835c4a),
  [`3f67e30`](https://github.com/Dicklesworthstone/frankenfs/commit/3f67e3074127030e7cdef861fbe40165f426e531),
  [`3231f01`](https://github.com/Dicklesworthstone/frankenfs/commit/3231f016a9227ebd6e74d6d4e5c8d7c53c770b30)

- **Evidence and error-reporting hardening** -- evidence collection expanded, JSON escaping moved to `serde_json`, and scope-failure metrics made mount/runtime failures easier to diagnose
  [`5672f65`](https://github.com/Dicklesworthstone/frankenfs/commit/5672f6504497c24497917019f34a26c2aa970650),
  [`890ac99`](https://github.com/Dicklesworthstone/frankenfs/commit/890ac99bbf3542d0b28b8dbd5f43a72bc4496627),
  [`cba534c`](https://github.com/Dicklesworthstone/frankenfs/commit/cba534c3a9d8af2bd607f48a2499e17a4a6ffb1e),
  [`954ee2a`](https://github.com/Dicklesworthstone/frankenfs/commit/954ee2a7a8c74ab99f9ca514ea7867df69d326f0)

---

## TUI Dashboard

The `ffs-tui` crate provides a terminal-based live monitoring dashboard via `ftui`.

- **Minimal TUI dashboard** implementation
  [`1defb2d`](https://github.com/Dicklesworthstone/frankenfs/commit/1defb2d043bb44b5c7ff6bfe40b712e67c326558)

- **Expanded TUI rendering** capabilities and comprehensive test coverage
  [`2d72e2d`](https://github.com/Dicklesworthstone/frankenfs/commit/2d72e2d10367aee354c6b0cbf6ea1bf1938dbce8),
  [`0a019dc`](https://github.com/Dicklesworthstone/frankenfs/commit/0a019dcc70f4b4208276a9d9248d90c3fb263894)

---

## Conformance Harness and Testing

The `ffs-harness` crate provides sparse fixtures, golden-file conformance, parity tracking, E2E tests, and verification gates.

- **Fixture generation workflow** and `SparseFixture::from_bytes`
  [`c25115e`](https://github.com/Dicklesworthstone/frankenfs/commit/c25115ed8738735bff5c4c49394345fa883ad1d0)

- **Parity accounting invariant enforcement**
  [`032613f`](https://github.com/Dicklesworthstone/frankenfs/commit/032613fabd9ffc92caedf7e4b5629d7223f0b332)

- **ext4 fixtures** for group desc, inode, dir block, superblock
  [`de3bcef`](https://github.com/Dicklesworthstone/frankenfs/commit/de3bcef8b4731a48d80007dcdb5daa9e29414085),
  [`85f5fc6`](https://github.com/Dicklesworthstone/frankenfs/commit/85f5fc600f9edf92ec2dfcee4ed0b572742cf348)

- **btrfs fixtures** for sys_chunk mapping, leaf nodes, fs-tree, root-tree
  [`6a6d5de`](https://github.com/Dicklesworthstone/frankenfs/commit/6a6d5de85bab7445483b2e5298b7d280ce42b59c),
  [`882082b`](https://github.com/Dicklesworthstone/frankenfs/commit/882082b396d63d809bff1b1b47d456b0a902e95a)

- **Golden output verification** and isomorphism proof protocol
  [`a09518d`](https://github.com/Dicklesworthstone/frankenfs/commit/a09518dfd1877564f9e8d04255ba98b6203ff1ed)

- **Linux-kernel reference capture pipeline** and E2E conformance tests
  [`220c92a`](https://github.com/Dicklesworthstone/frankenfs/commit/220c92ae9993ca8de951ac16d9b506b1a7bf7e93)

- **End-to-end test infrastructure** and fixture generation
  [`4cdc823`](https://github.com/Dicklesworthstone/frankenfs/commit/4cdc823a4aef428199e89b48d0b2f8e584b09160)

- **xfstests harness** with result parsing and CI regression gate
  [`8417c93`](https://github.com/Dicklesworthstone/frankenfs/commit/8417c93a660eaaf1ff6a3736bcc3d235d5a967fc),
  [`a23e89b`](https://github.com/Dicklesworthstone/frankenfs/commit/a23e89b73c59db44ec8966eacc2d93b9b706da0b)

- **EMLINK limit test** for hard link rejection
  [`39d05e5`](https://github.com/Dicklesworthstone/frankenfs/commit/39d05e5780a3ffb50cafc71afcd4eedf3f10a2b5)

- **Deterministic SIGKILL recovery harness** replacing best-effort crash phase
  [`baeaca0`](https://github.com/Dicklesworthstone/frankenfs/commit/baeaca0dea4cefe3d55ae97f3163e88bbbea07de)

- **Massive edge-case test expansion** -- approximately 400+ new tests across all crates in a single push
  [`c256f40`](https://github.com/Dicklesworthstone/frankenfs/commit/c256f40873954e95b660b3205a6bf9ae0d9662ba),
  [`8023b64`](https://github.com/Dicklesworthstone/frankenfs/commit/8023b646a766be6b1b4045a502ed834c1860df84),
  [`0a3d02c`](https://github.com/Dicklesworthstone/frankenfs/commit/0a3d02cb49ab10f4174c1894e1050b1cf9fb0c8a),
  [`3742c29`](https://github.com/Dicklesworthstone/frankenfs/commit/3742c2964f20818816dfebb178a65aa5c4574123),
  [`9ae2809`](https://github.com/Dicklesworthstone/frankenfs/commit/9ae2809d296ae660c5c24c36cfc8f56071675f29),
  [`0a6425b`](https://github.com/Dicklesworthstone/frankenfs/commit/0a6425b2093491b514897b8ae08acb00e02b68d8),
  [`092e0ee`](https://github.com/Dicklesworthstone/frankenfs/commit/092e0eebcd877f84a661a15ec0a788608c11a647),
  [`c8197bb`](https://github.com/Dicklesworthstone/frankenfs/commit/c8197bb3b9e2fd5b3dfd5e483a2df0cca8e46480),
  [`ad9f258`](https://github.com/Dicklesworthstone/frankenfs/commit/ad9f2586d1bd34dd7bb0cb3fbb42a7b1cc5887ad),
  [`e58660b`](https://github.com/Dicklesworthstone/frankenfs/commit/e58660b0a1426c9396134f2476be13512c07aa84),
  [`d05069e`](https://github.com/Dicklesworthstone/frankenfs/commit/d05069ece5cc974522d27d936c95f6327e051842),
  [`d72ae01`](https://github.com/Dicklesworthstone/frankenfs/commit/d72ae01675dbbc7c2687f5b971c0ce6c686d788b)

- **Property-based tests (proptest)** -- ARC cache invariants, MVCC concurrency, ext4 checksums/parsing, RaptorQ codec, inode operations, types, xattr, extent, allocator, journal, directory
  [`f54f58f`](https://github.com/Dicklesworthstone/frankenfs/commit/f54f58f7bb5bc79689f3d9a220744f4b5ee83748),
  [`c104a48`](https://github.com/Dicklesworthstone/frankenfs/commit/c104a4875586f408631a037980357eff24b68aa7),
  [`869259f`](https://github.com/Dicklesworthstone/frankenfs/commit/869259f2fb2192372552b295b53fd7ce9fe3311c),
  [`09d0d70`](https://github.com/Dicklesworthstone/frankenfs/commit/09d0d704a3575ec06a1741030a4c1d7a4303762b),
  [`87b7f73`](https://github.com/Dicklesworthstone/frankenfs/commit/87b7f73b5aad0b3e490f8274ce80c05a31b4faf3),
  [`179beea`](https://github.com/Dicklesworthstone/frankenfs/commit/179beeaeeb340c54db40419f87c38b86a1069975),
  [`088584d`](https://github.com/Dicklesworthstone/frankenfs/commit/088584df72d3c5e0e9a80781332400285ba6146b),
  [`84b23c6`](https://github.com/Dicklesworthstone/frankenfs/commit/84b23c628a1932819243b0f34602406cad026109),
  [`5ec7a9e`](https://github.com/Dicklesworthstone/frankenfs/commit/5ec7a9e8941ed0d9b34f912e89190ffd08d2c3d0),
  [`09d8d62`](https://github.com/Dicklesworthstone/frankenfs/commit/09d8d6215e9ec60663fb8f9d39f9e10a4e47c22b)

- **Verification gate scripts** for MVCC replay, mount runtime modes, and V1.1 validation suite
  [`f102e14`](https://github.com/Dicklesworthstone/frankenfs/commit/f102e1403cc732498a2508ea1d9432f4fcd61c0d),
  [`ca275b6`](https://github.com/Dicklesworthstone/frankenfs/commit/ca275b62f64c255513f230441ed3c023c5691304),
  [`97501db`](https://github.com/Dicklesworthstone/frankenfs/commit/97501dbdf91730938f08051ba329477b0af8975b)

- **Cross-crate integration tests** for ffs-core
  [`a82cefe`](https://github.com/Dicklesworthstone/frankenfs/commit/a82cefe7b0ef4feff163483a6ac78744bc81f2ed)

- **Real-image FUSE regression coverage** -- FIEMAP moved to real ext images, ABI 7-31 was exercised under E2E, and truncate/fallocate/ioctl coverage expanded across ext4 and btrfs
  [`e9e89c0`](https://github.com/Dicklesworthstone/frankenfs/commit/e9e89c052191b93ff8a185d48e7406d6e2db95ad),
  [`f273f30`](https://github.com/Dicklesworthstone/frankenfs/commit/f273f30b24ff57f192f190707f33f021933888c4),
  [`0f3bfa5`](https://github.com/Dicklesworthstone/frankenfs/commit/0f3bfa5cb7d410eb2845869c4b83f1e0660a2744),
  [`fafa0fa`](https://github.com/Dicklesworthstone/frankenfs/commit/fafa0fa4e0fdfbd59396280da84c0e16076fa436),
  [`4fdf096`](https://github.com/Dicklesworthstone/frankenfs/commit/4fdf09633d62d0c7f779b38f7587eaf7e5572e83)

- **`e2compr` and namespace hardening tests** -- adversarial decompression, new proptests, bulk create/lookup coverage, external-journal cases, and broader cross-crate integration suites landed with the write-path work
  [`17ca2ee`](https://github.com/Dicklesworthstone/frankenfs/commit/17ca2ee112f611f1af5b8fb03a955067d2f56235),
  [`60a85a7`](https://github.com/Dicklesworthstone/frankenfs/commit/60a85a7e0f81b1a40163ca5b87dfd18adf8cdbaf),
  [`73dd17a`](https://github.com/Dicklesworthstone/frankenfs/commit/73dd17ac99ba09dff0e34c3ef7e7d7366a0d3df4),
  [`9864864`](https://github.com/Dicklesworthstone/frankenfs/commit/98648647f0ec25944c35db338f6ab8e4d99d96d1),
  [`5672f65`](https://github.com/Dicklesworthstone/frankenfs/commit/5672f6504497c24497917019f34a26c2aa970650)

- **Canonical golden gate documentation** -- `verify_golden.sh` became the single documented entrypoint for golden/conformance verification, with the older script retained as a shim
  [`162aa59`](https://github.com/Dicklesworthstone/frankenfs/commit/162aa5942ee48d4769c4c046f885f28561d1c1fe),
  [`bd91c3d`](https://github.com/Dicklesworthstone/frankenfs/commit/bd91c3d662cfa47387e3b37805d350827e8db719)

---

## Fuzz Infrastructure

Fuzzing corpus, crash-to-regression promotion, and nightly fuzz dictionaries.

- **1281 fuzz corpus entries** for btrfs metadata, ext4 xattr, and VFS operations
  [`0ee5695`](https://github.com/Dicklesworthstone/frankenfs/commit/0ee5695ccea18561f40ff2e3220a47dbfcfe63a4)

- **Crash-to-regression-test promotion script**
  [`7225c09`](https://github.com/Dicklesworthstone/frankenfs/commit/7225c09731dcd7bcc24ed38664896b16ce077cea)

- **Fuzz infrastructure and serialization improvements** across crates
  [`527980e`](https://github.com/Dicklesworthstone/frankenfs/commit/527980e57f1d18453ef47555f64a365b29a9ec66)

- **Nightly fuzz dict flag placement fix**
  [`557f5fb`](https://github.com/Dicklesworthstone/frankenfs/commit/557f5fbf78a4f8bcfe42d0be30bb7ccc1b122905)

---

## Performance and Benchmarking

Criterion benchmarks, perf regression harness, baseline recording, and profiling infrastructure.

- **ondisk_parse benchmarks** and CLI baselines
  [`db56b56`](https://github.com/Dicklesworthstone/frankenfs/commit/db56b56c024dca15f31d5159eb1a23d310cee241)

- **ARC/S3-FIFO cache workload benchmarks** and Bw-Tree vs locked B-tree bench
  [`19ea92c`](https://github.com/Dicklesworthstone/frankenfs/commit/19ea92cbd77a08318241ad4da00ba1097c8e6efb)

- **Perf regression harness** with benchmark thresholds and CI workflow
  [`83cf153`](https://github.com/Dicklesworthstone/frankenfs/commit/83cf153f8f15da41ba093d1ba4a432a51c87ca9f),
  [`38921a6`](https://github.com/Dicklesworthstone/frankenfs/commit/38921a6b3368dca51eb91346a416603909670810)

- **Benchmark taxonomy**, log contracts, perf comparison, and E2E scenarios
  [`9bb2db6`](https://github.com/Dicklesworthstone/frankenfs/commit/9bb2db6f4f1c195f6def9a34dcf1e59e2f068b22)

- **Performance regression triage module** with runbook and E2E coverage
  [`4e8e37e`](https://github.com/Dicklesworthstone/frankenfs/commit/4e8e37e1a2663f9a044ee384d9cb0da01a07a970)

- **Extent resolve benchmarks**, metrics module, and profiling scripts
  [`137299f`](https://github.com/Dicklesworthstone/frankenfs/commit/137299f05e82a742405c040b14ed6b42f4bbf31d)

- **Benchmark governance** with comparison context and triage followup commands
  [`9bd8ced`](https://github.com/Dicklesworthstone/frankenfs/commit/9bd8cedc33e9c30e3b9428125bb06838309f3c0e)

- **Benchmark baseline refresh** and recording pipeline hardening
  [`4007dfa`](https://github.com/Dicklesworthstone/frankenfs/commit/4007dfa6416dfb649b96c2c1040c88ce36455c82)

- **Benchmark harness sanity fixes** -- benchmark RNG seeding was corrected and EBR benchmark artifacts were refreshed during recovery-path hardening
  [`096024e`](https://github.com/Dicklesworthstone/frankenfs/commit/096024efc36d9f5e9e8cc16d2b6809f1bc7db5ec),
  [`90bbc5d`](https://github.com/Dicklesworthstone/frankenfs/commit/90bbc5d87f0b60221531f6172c4ca70aa32f3fef)

---

## Foundation Types and Error Handling

`ffs-types` (newtypes, checked arithmetic) and `ffs-error` (14-variant error enum with errno mappings).

- **Canonical error taxonomy** with 14-variant `FfsError` and POSIX errno mappings
  [`74fce48`](https://github.com/Dicklesworthstone/frankenfs/commit/74fce48a2beb5d5267b71c95e52caa5d0fbbee4a)

- **Mount-validation error variants**
  [`0c24f84`](https://github.com/Dicklesworthstone/frankenfs/commit/0c24f84fb9466c3536cb08ce4f89a95222579d67)

- **Checked arithmetic and alignment helpers** in `ffs-types`
  [`6e91588`](https://github.com/Dicklesworthstone/frankenfs/commit/6e915881f7d7fd32c4f7012057c8cc08422be9fa)

- **Typed `BlockNumber`, `InodeNumber`, `TxnId`, `CommitSeq`** newtypes; `ByteOffset`/`DeviceId` wrappers
  [`f96eb7a`](https://github.com/Dicklesworthstone/frankenfs/commit/f96eb7ad7433e595ca5040a0a441d3c6df8a163a)

- **`InvalidMagic` typed error** replacing string-based `InvalidField` variant
  [`5a62422`](https://github.com/Dicklesworthstone/frankenfs/commit/5a62422df08d5d6b6dc2d95f3723a03f6733bfd8)

- **Lossy as-cast elimination** -- replaced with checked `try_from` conversions across core, alloc, and ondisk
  [`0181976`](https://github.com/Dicklesworthstone/frankenfs/commit/0181976cfc860238d4e737ed80e455e05e744113),
  [`73ce8c8`](https://github.com/Dicklesworthstone/frankenfs/commit/73ce8c88f1a26d7ccd22d4ba88f6d59d12b1f593)

- **Error taxonomy variant-class mismatch** fix for FFS-RPL-001
  [`9ed7fb2`](https://github.com/Dicklesworthstone/frankenfs/commit/9ed7fb2a85fd18c033a16fee4cfbf43ea071154f)

- **`SymbolEquationArityMismatch`** error handling and dependency graph update
  [`fb714f4`](https://github.com/Dicklesworthstone/frankenfs/commit/fb714f41da075d3dacc46f3595d481f36c1e5f11)

- **Broader checked-conversion and panic-removal sweep** -- more silent truncations, panicking integer casts, and ad hoc literals were replaced with fallible conversions and explicit error paths across `core`, `extent`, `alloc`, `types`, and `cli`
  [`efbebc3`](https://github.com/Dicklesworthstone/frankenfs/commit/efbebc32f3be1cf34d80ba8ec31a2b73c0f9d95a),
  [`01c3439`](https://github.com/Dicklesworthstone/frankenfs/commit/01c34398361256a8cebaf07f3a5e850a534749b2),
  [`797b6de`](https://github.com/Dicklesworthstone/frankenfs/commit/797b6de9274f47f7e27e1b0ff1a11cbf2e3f6c96),
  [`5408144`](https://github.com/Dicklesworthstone/frankenfs/commit/540814425999d6d89f27fa623efef312d8b801ef),
  [`54b0857`](https://github.com/Dicklesworthstone/frankenfs/commit/54b0857d803af1f89f36ef3e219f7f1fe0493248)

- **Type and error-surface expansion** -- additional filesystem kinds, directory/error variants, and xattr-adjacent APIs were added while pedantic cleanup reduced diagnostic noise
  [`edd50bd`](https://github.com/Dicklesworthstone/frankenfs/commit/edd50bd4d20ddf615c5435c0d73d388f55852fe3),
  [`754907b`](https://github.com/Dicklesworthstone/frankenfs/commit/754907b68b53bc5d59a0289920ec2a2ca2040e52)

---

## Documentation and Architecture

README, specification documents, architecture alignment, and design documents.

- **21-crate workspace architecture** reconciliation with spec, errata tracking, and Bayesian autopilot spec
  [`48858ce`](https://github.com/Dicklesworthstone/frankenfs/commit/48858ce3f02bd27844496d99e283763512343ed6)

- **Crate layering contract** alignment -- dependency graph matched to code
  [`f970460`](https://github.com/Dicklesworthstone/frankenfs/commit/f970460583b3bc0b270165dbcbb4f19a10f949be),
  [`3debcee`](https://github.com/Dicklesworthstone/frankenfs/commit/3debcee47cde14dfcb857fc7bce76240c8019ab9)

- **Canonical type definitions** with cross-links in spec
  [`1e06ab5`](https://github.com/Dicklesworthstone/frankenfs/commit/1e06ab56f36ee3c36e03b3bf0fb0c4fbf3fff1ff)

- **V1 filesystem scope section** and FAQ updates
  [`8ac730e`](https://github.com/Dicklesworthstone/frankenfs/commit/8ac730e70e45a54cd78c1bbbe929855b14c1f9c1)

- **Safe-merge taxonomy design** document with proof obligation sketches
  [`30d6fa3`](https://github.com/Dicklesworthstone/frankenfs/commit/30d6fa35d247dcc5120b8aec026e55270a9ac7d8)

- **Write-back cache + dirty tracking design** document
  [`29c17a9`](https://github.com/Dicklesworthstone/frankenfs/commit/29c17a97702d67e15c3fd454873c08e91c674ce9)

- **README rewrite** with MVCC merge proofs, adaptive policies, and benchmark model
  [`4a9b0d3`](https://github.com/Dicklesworthstone/frankenfs/commit/4a9b0d342e2ce4eb20a465396cd27263c4394a40)

- **README expansion** with writeback-cache design, repair pipeline, and evidence system
  [`2f8b5b1`](https://github.com/Dicklesworthstone/frankenfs/commit/2f8b5b1b06255c285dbcb805ee265e63a39e4931)

- **Comprehensive rustdoc** and property-based tests across core, extent, and MVCC crates
  [`1c6fe66`](https://github.com/Dicklesworthstone/frankenfs/commit/1c6fe66598cb5489c9b97001c63b11497f3ee247)

- **README and parity-document refresh** -- tracked V1 parity semantics, feature scope, test-count claims, and the canonical golden-verification workflow were all updated to match the implementation that landed after 2026-03-21
  [`3aff3af`](https://github.com/Dicklesworthstone/frankenfs/commit/3aff3af0952d929e68d99ca2fa2d413c66b89af6),
  [`5537150`](https://github.com/Dicklesworthstone/frankenfs/commit/55371502f8d954999d2b090e587644652bcdf7b2),
  [`dce710b`](https://github.com/Dicklesworthstone/frankenfs/commit/dce710b252d88c7f5908f8f52a9b25ac9d5d6cb5),
  [`7587971`](https://github.com/Dicklesworthstone/frankenfs/commit/7587971422135d52948087a9a3247324109052b0),
  [`bd91c3d`](https://github.com/Dicklesworthstone/frankenfs/commit/bd91c3d662cfa47387e3b37805d350827e8db719)

---

## Build, Dependencies, and Licensing

Workspace configuration, dependency management, CI, and license.

- **Initial commit** -- 21-crate Cargo workspace with `#![forbid(unsafe_code)]` at every crate root
  [`01bc389`](https://github.com/Dicklesworthstone/frankenfs/commit/01bc38985fb499db3598734e29ec9b7adcbc7253)

- **MIT + OpenAI/Anthropic rider license** adoption across workspace
  [`9cb3ba5`](https://github.com/Dicklesworthstone/frankenfs/commit/9cb3ba58f90cb867be567db80180282d229a1217)

- **asupersync/ftui bumped** to crates.io releases (0.2.0+)
  [`e98f3dc`](https://github.com/Dicklesworthstone/frankenfs/commit/e98f3dc9256ad7fc63a3b7e7668d75c3e3264aeb),
  [`cd7a9f8`](https://github.com/Dicklesworthstone/frankenfs/commit/cd7a9f8f77be5adb413e30b6b07606a8bd9d6c67)

- **CI pipeline hardening** with `cargo fmt --check`, `cargo clippy -- -D warnings`, and full workspace test gate
  [`436c257`](https://github.com/Dicklesworthstone/frankenfs/commit/436c2576a38302cc7850978882feb5770aaf8f0d)

- **Rustfmt formatting** applied across all crates
  [`0603f71`](https://github.com/Dicklesworthstone/frankenfs/commit/0603f714e72b2856c843a1926dec5904906f7333)

- **Dead code cleanup** -- genuinely dead code removed from cli, core, and journal
  [`2a5f85b`](https://github.com/Dicklesworthstone/frankenfs/commit/2a5f85bf16b8efd240755ee0a1241911f5891e45)

- **Stale `#[allow(dead_code)]` removal** on actively-used items
  [`d5d118a`](https://github.com/Dicklesworthstone/frankenfs/commit/d5d118a310411e0007966cda1f36c67e8a1da3f6)

- **GitHub social preview image** (1280x640)
  [`042df32`](https://github.com/Dicklesworthstone/frankenfs/commit/042df327e04d8d505d187aa3684541d75541a0fe)

- **WebP illustration** added to README header
  [`a72cf4f`](https://github.com/Dicklesworthstone/frankenfs/commit/a72cf4f759db9773100dab0fd199749e8af7900d)

- **Verification entrypoint normalization** -- the legacy `verify-goldens.sh` path now shims to canonical `verify_golden.sh`, keeping CI and operator workflows on one supported script
  [`162aa59`](https://github.com/Dicklesworthstone/frankenfs/commit/162aa5942ee48d4769c4c046f885f28561d1c1fe)
