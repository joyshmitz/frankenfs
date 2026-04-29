#![no_main]
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use asupersync::Cx;
use ffs_alloc::{AllocHint, FsGeometry, GroupStats, PersistCtx};
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_extent::{
    allocate_extent, allocate_unwritten_extent, collapse_range, insert_range,
    map_logical_to_physical, mark_written, punch_hole, ExtentMapping,
};
use ffs_types::{BlockNumber, GroupNumber};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 2048;
const MAX_OPS: usize = 96;
const LOW_LOGICAL_DOMAIN: u32 = 512;
const MAX_OP_COUNT: u32 = 16;

fuzz_target!(|data: &[u8]| {
    // Fuzz extent tree parsing with malformed nodes.
    let _ = ffs_ondisk::parse_extent_tree(data);

    // Fuzz inode extent tree parsing — requires a parsed inode first.
    if let Ok(inode) = ffs_ondisk::Ext4Inode::parse_from_bytes(data) {
        let _ = ffs_ondisk::parse_inode_extent_tree(&inode);
    }

    // Fuzz dx_root (htree directory root) parsing.
    if data.len() >= 32 {
        let _ = ffs_ondisk::parse_dx_root(data);
    }

    fuzz_stateful_extent_edits(data);
});

struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        b
    }

    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }
}

struct MemBlockDevice {
    block_size: u32,
    block_count: u64,
    blocks: Mutex<HashMap<u64, Vec<u8>>>,
}

impl MemBlockDevice {
    fn new(block_size: u32, block_count: u64) -> Self {
        Self {
            block_size,
            block_count,
            blocks: Mutex::new(HashMap::new()),
        }
    }

    fn lock_blocks(&self) -> MutexGuard<'_, HashMap<u64, Vec<u8>>> {
        match self.blocks.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn block_len(&self) -> Result<usize> {
        usize::try_from(self.block_size)
            .map_err(|_| FfsError::InvalidGeometry("block size does not fit usize".to_owned()))
    }
}

impl BlockDevice for MemBlockDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        if block.0 >= self.block_count {
            return Err(FfsError::InvalidGeometry(format!(
                "read block {} beyond device block count {}",
                block.0, self.block_count
            )));
        }
        let blocks = self.lock_blocks();
        blocks.get(&block.0).map_or_else(
            || Ok(BlockBuf::new(vec![0u8; self.block_len()?])),
            |data| Ok(BlockBuf::new(data.clone())),
        )
    }

    fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        if block.0 >= self.block_count {
            return Err(FfsError::InvalidGeometry(format!(
                "write block {} beyond device block count {}",
                block.0, self.block_count
            )));
        }
        let block_len = self.block_len()?;
        if data.len() != block_len {
            return Err(FfsError::Format(format!(
                "write_block length mismatch: got {}, expected {block_len}",
                data.len()
            )));
        }
        self.lock_blocks().insert(block.0, data.to_vec());
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        self.block_count
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

fn fuzz_stateful_extent_edits(data: &[u8]) {
    if data.len() < 8 || data.len() > MAX_INPUT_BYTES {
        return;
    }

    let cx = Cx::for_testing();
    let dev = MemBlockDevice::new(4096, 1_000_000);
    let geo = make_geometry();
    let mut groups = make_groups(&geo);
    let pctx = make_pctx(&geo);
    let mut root = empty_root();
    let mut cursor = ByteCursor::new(data);
    let mut interesting_ranges = Vec::new();

    assert_failed_insert_preserves_boundary_tail(&cx, &dev, &geo, &mut groups, &pctx);

    let op_limit = usize::from(cursor.next_u8() % (MAX_OPS as u8));
    for _ in 0..op_limit {
        let op = cursor.next_u8() % 7;
        let count = next_count(&mut cursor);
        let logical_start = next_logical_start(&mut cursor, count);

        match op {
            0 => {
                if range_is_sparse(&cx, &dev, &root, logical_start, count) {
                    let _ = allocate_extent(
                        &cx,
                        &dev,
                        &mut root,
                        &geo,
                        &mut groups,
                        logical_start,
                        count,
                        &AllocHint::default(),
                        &pctx,
                    );
                    interesting_ranges.push((logical_start, count));
                }
            }
            1 => {
                if range_is_sparse(&cx, &dev, &root, logical_start, count) {
                    let _ = allocate_unwritten_extent(
                        &cx,
                        &dev,
                        &mut root,
                        &geo,
                        &mut groups,
                        logical_start,
                        count,
                        &AllocHint::default(),
                        &pctx,
                    );
                    interesting_ranges.push((logical_start, count));
                }
            }
            2 => {
                let _ = punch_hole(
                    &cx,
                    &dev,
                    &mut root,
                    &geo,
                    &mut groups,
                    logical_start,
                    u64::from(count),
                    &pctx,
                );
            }
            3 => {
                let _ = collapse_range(
                    &cx,
                    &dev,
                    &mut root,
                    &geo,
                    &mut groups,
                    logical_start,
                    count,
                    &pctx,
                );
            }
            4 => {
                let _ = insert_range(
                    &cx,
                    &dev,
                    &mut root,
                    &geo,
                    &mut groups,
                    logical_start,
                    count,
                    &pctx,
                );
            }
            5 => {
                let _ = mark_written(
                    &cx,
                    &dev,
                    &mut root,
                    &geo,
                    &mut groups,
                    logical_start,
                    count,
                    &pctx,
                );
            }
            _ => assert_covering_mappings(&cx, &dev, &root, logical_start, u64::from(count)),
        }

        assert_covering_mappings(&cx, &dev, &root, logical_start, u64::from(count));
        if let Some(&(probe_start, probe_count)) = interesting_ranges.last() {
            assert_covering_mappings(&cx, &dev, &root, probe_start, u64::from(probe_count));
        }
        if interesting_ranges.len() > 32 {
            interesting_ranges.remove(0);
        }
    }
}

fn assert_failed_insert_preserves_boundary_tail(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    pctx: &PersistCtx,
) {
    let mut root = empty_root();
    let logical_start = u32::MAX;
    let mapping = allocate_extent(
        cx,
        dev,
        &mut root,
        geo,
        groups,
        logical_start,
        1,
        &AllocHint::default(),
        pctx,
    );
    if mapping.is_err() {
        return;
    }

    let before = match map_logical_to_physical(cx, dev, &root, logical_start, 1) {
        Ok(mappings) => mappings,
        Err(err) => invariant_failure(format!(
            "boundary tail mapping must be readable before insert_range: {err}"
        )),
    };
    assert_physical_mapping(&before, logical_start, 1);

    let result = insert_range(cx, dev, &mut root, geo, groups, 0, 1, pctx);
    if result.is_ok() {
        invariant_failure(
            "insert_range must reject shifting the final logical block beyond ext4 space"
                .to_owned(),
        );
    }

    let after = match map_logical_to_physical(cx, dev, &root, logical_start, 1) {
        Ok(mappings) => mappings,
        Err(err) => invariant_failure(format!(
            "failed insert_range must leave boundary tail readable: {err}"
        )),
    };
    if before != after {
        invariant_failure(
            "failed insert_range must not mutate the boundary tail mapping".to_owned(),
        );
    }
}

fn range_is_sparse(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root: &[u8; 60],
    logical_start: u32,
    count: u32,
) -> bool {
    map_logical_to_physical(cx, dev, root, logical_start, u64::from(count))
        .map(|mappings| mappings.iter().all(|mapping| mapping.physical_start == 0))
        .unwrap_or(false)
}

fn assert_covering_mappings(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root: &[u8; 60],
    logical_start: u32,
    count: u64,
) {
    let mappings = match map_logical_to_physical(cx, dev, root, logical_start, count) {
        Ok(mappings) => mappings,
        Err(err) => invariant_failure(format!(
            "extent tree must remain mappable after stateful op: {err}"
        )),
    };
    let mut expected_start = u64::from(logical_start);
    let expected_end = expected_start + count;
    for mapping in mappings {
        if u64::from(mapping.logical_start) != expected_start {
            invariant_failure("mappings must be contiguous and ordered".to_owned());
        }
        if mapping.count == 0 {
            invariant_failure("mapping count must be positive".to_owned());
        }
        let mapping_end = u64::from(mapping.logical_start) + u64::from(mapping.count);
        if mapping_end > expected_end {
            invariant_failure(format!(
                "mapping end {mapping_end} must not exceed requested end {expected_end}"
            ));
        }
        if mapping.physical_start != 0 {
            assert_physical_mapping(&[mapping], mapping.logical_start, mapping.count);
        }
        expected_start = mapping_end;
    }
    if expected_start != expected_end {
        invariant_failure("mappings must cover the full requested range".to_owned());
    }
}

fn assert_physical_mapping(mappings: &[ExtentMapping], logical_start: u32, count: u32) {
    if !mappings.iter().any(|mapping| {
        mapping.logical_start == logical_start
            && mapping.count == count
            && mapping.physical_start != 0
    }) {
        invariant_failure(format!(
            "expected physical mapping at logical range [{logical_start}, {})",
            u64::from(logical_start) + u64::from(count)
        ));
    }
}

fn next_count(cursor: &mut ByteCursor<'_>) -> u32 {
    u32::from(cursor.next_u8() % (MAX_OP_COUNT as u8)).saturating_add(1)
}

fn next_logical_start(cursor: &mut ByteCursor<'_>, count: u32) -> u32 {
    let raw = cursor.next_u32();
    let max_start = u64::from(u32::MAX) + 1 - u64::from(count);
    let candidate = match cursor.next_u8() % 4 {
        0 => u64::from(raw % LOW_LOGICAL_DOMAIN),
        1 => max_start.saturating_sub(u64::from(raw % 64)),
        2 => u64::from(LOW_LOGICAL_DOMAIN) + u64::from(raw % 4096),
        _ => u64::from(raw).min(max_start),
    };
    u32::try_from(candidate.min(max_start)).unwrap_or(u32::MAX)
}

fn invariant_failure(message: String) -> ! {
    std::panic::panic_any(message);
}

fn empty_root() -> [u8; 60] {
    let mut root = [0u8; 60];
    root[0] = 0x0A;
    root[1] = 0xF3;
    root[4] = 4;
    root
}

fn make_geometry() -> FsGeometry {
    FsGeometry {
        blocks_per_group: 8192,
        inodes_per_group: 2048,
        block_size: 4096,
        total_blocks: 32768,
        total_inodes: 8192,
        first_data_block: 0,
        group_count: 4,
        inode_size: 256,
        desc_size: 32,
        reserved_gdt_blocks: 0,
        first_meta_bg: 0,
        feature_compat: ffs_ondisk::Ext4CompatFeatures(0),
        feature_incompat: ffs_ondisk::Ext4IncompatFeatures(0),
        feature_ro_compat: ffs_ondisk::Ext4RoCompatFeatures(0),
        log_groups_per_flex: 0,
        backup_bgs: [0, 0],
        first_inode: 11,
        cluster_ratio: 1,
    }
}

fn make_groups(geo: &FsGeometry) -> Vec<GroupStats> {
    (0..geo.group_count)
        .map(|g| GroupStats {
            group: GroupNumber(g),
            free_blocks: geo.blocks_per_group,
            free_inodes: geo.inodes_per_group,
            used_dirs: 0,
            block_bitmap_block: BlockNumber(u64::from(g) * 100 + 1),
            inode_bitmap_block: BlockNumber(u64::from(g) * 100 + 2),
            inode_table_block: BlockNumber(u64::from(g) * 100 + 3),
            flags: 0,
            block_bitmap_csum: 0,
            inode_bitmap_csum: 0,
        })
        .collect()
}

fn make_pctx(geo: &FsGeometry) -> PersistCtx {
    PersistCtx {
        gdt_block: BlockNumber(50),
        desc_size: geo.desc_size,
        has_metadata_csum: false,
        csum_seed: 0,
        uuid: [0; 16],
        group_desc_checksum_kind: ffs_ondisk::ext4::Ext4GroupDescChecksumKind::None,
        blocks_per_group: geo.blocks_per_group,
        inodes_per_group: geo.inodes_per_group,
    }
}
