#![no_main]

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_btrfs::{
    BTRFS_FILE_EXTENT_REG, BTRFS_FS_TREE_OBJECTID, BTRFS_FT_REG_FILE, BTRFS_ITEM_DIR_INDEX,
    BTRFS_ITEM_EXTENT_DATA, BTRFS_ITEM_INODE_ITEM, BTRFS_ITEM_ROOT_ITEM,
};
use ffs_core::{DirEntry, FileType, InodeAttr, OpenFs, OpenOptions};
use ffs_error::{FfsError, Result};
use ffs_types::{crc32c, ByteOffset, InodeNumber, BTRFS_MAGIC, BTRFS_SUPER_INFO_OFFSET};
use libfuzzer_sys::fuzz_target;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

const MAX_INPUT_BYTES: usize = 1024;
const MAX_NAME_BYTES: usize = 320;
const MAX_TARGET_BYTES: usize = 512;
const ROOT_INO: InodeNumber = InodeNumber(1);

const ROOT_TREE_LOGICAL: u64 = 0x4_000;
const FS_TREE_LOGICAL: u64 = 0x8_000;
const FILE_DATA_LOGICAL: u64 = 0x12_000;
const NODESIZE: usize = 4096;
const LEAF_HEADER_SIZE: usize = 101;
const LEAF_ITEM_SIZE: usize = 25;

const SEED_LINK_SRC: &[u8] = b".path-link-src";
const SEED_RENAME_SRC: &[u8] = b".path-rename-src";
const RENAME_FIXED_DEST: &[u8] = b".path-rename-fixed";

#[derive(Debug)]
struct MemByteDevice {
    data: Arc<Mutex<Vec<u8>>>,
}

impl MemByteDevice {
    fn from_vec(data: Vec<u8>) -> Self {
        Self {
            data: Arc::new(Mutex::new(data)),
        }
    }
}

impl ByteDevice for MemByteDevice {
    fn len_bytes(&self) -> u64 {
        let data = self
            .data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        u64::try_from(data.len()).unwrap_or(u64::MAX)
    }

    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        let off = usize::try_from(offset.0)
            .map_err(|_| FfsError::Format("offset does not fit usize".to_owned()))?;
        let data = self
            .data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let end = off
            .checked_add(buf.len())
            .ok_or_else(|| FfsError::Format("read offset overflow".to_owned()))?;
        if end > data.len() {
            return Err(FfsError::Format(format!(
                "read out of bounds: {off}..{end} > {}",
                data.len()
            )));
        }
        buf.copy_from_slice(&data[off..end]);
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        let off = usize::try_from(offset.0)
            .map_err(|_| FfsError::Format("offset does not fit usize".to_owned()))?;
        let mut data = self
            .data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let end = off
            .checked_add(buf.len())
            .ok_or_else(|| FfsError::Format("write offset overflow".to_owned()))?;
        if end > data.len() {
            return Err(FfsError::Format(format!(
                "write out of bounds: {off}..{end} > {}",
                data.len()
            )));
        }
        data[off..end].copy_from_slice(buf);
        Ok(())
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct Inputs {
    create_name: Vec<u8>,
    mkdir_name: Vec<u8>,
    link_name: Vec<u8>,
    rename_new_name: Vec<u8>,
    rename_old_name: Vec<u8>,
    symlink_name: Vec<u8>,
    symlink_target: Vec<u8>,
}

impl Inputs {
    fn decode(data: &[u8]) -> Self {
        let capped = &data[..data.len().min(MAX_INPUT_BYTES)];
        let mut segments = capped.splitn(7, |byte| *byte == b'\n');

        Self {
            create_name: take_segment(segments.next(), MAX_NAME_BYTES),
            mkdir_name: take_segment(segments.next(), MAX_NAME_BYTES),
            link_name: take_segment(segments.next(), MAX_NAME_BYTES),
            rename_new_name: take_segment(segments.next(), MAX_NAME_BYTES),
            rename_old_name: take_segment(segments.next(), MAX_NAME_BYTES),
            symlink_name: take_segment(segments.next(), MAX_NAME_BYTES),
            symlink_target: take_segment(segments.next(), MAX_TARGET_BYTES),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameValidity {
    Valid,
    Empty,
    ContainsSlash,
    TooLong,
}

impl NameValidity {
    fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            Self::Empty
        } else if bytes.contains(&b'/') {
            Self::ContainsSlash
        } else if bytes.len() > usize::from(u8::MAX) {
            Self::TooLong
        } else {
            Self::Valid
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OpOutcome {
    Attr { ino: u64, kind: u8, nlink: u32 },
    Entries { count: usize, crc32c: u32 },
    Bytes { len: usize, crc32c: u32 },
    Unit,
    Err(i32),
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidationOutcome {
    create: OpOutcome,
    mkdir: OpOutcome,
    link: OpOutcome,
    rename_dst: OpOutcome,
    rename_src: OpOutcome,
    symlink: OpOutcome,
    symlink_readback: OpOutcome,
    root_dir: OpOutcome,
}

fn take_segment(segment: Option<&[u8]>, limit: usize) -> Vec<u8> {
    segment
        .unwrap_or_default()
        .iter()
        .copied()
        .take(limit)
        .collect()
}

fn kind_code(kind: FileType) -> u8 {
    match kind {
        FileType::RegularFile => 1,
        FileType::Directory => 2,
        FileType::Symlink => 3,
        FileType::BlockDevice => 4,
        FileType::CharDevice => 5,
        FileType::Fifo => 6,
        FileType::Socket => 7,
    }
}

fn attr_outcome(attr: InodeAttr) -> OpOutcome {
    OpOutcome::Attr {
        ino: attr.ino.0,
        kind: kind_code(attr.kind),
        nlink: attr.nlink,
    }
}

fn attr_result(result: Result<InodeAttr>) -> OpOutcome {
    match result {
        Ok(attr) => attr_outcome(attr),
        Err(err) => OpOutcome::Err(err.to_errno()),
    }
}

fn unit_result(result: Result<()>) -> OpOutcome {
    match result {
        Ok(()) => OpOutcome::Unit,
        Err(err) => OpOutcome::Err(err.to_errno()),
    }
}

fn bytes_result(result: Result<Vec<u8>>) -> OpOutcome {
    match result {
        Ok(bytes) => OpOutcome::Bytes {
            len: bytes.len(),
            crc32c: crc32c(&bytes),
        },
        Err(err) => OpOutcome::Err(err.to_errno()),
    }
}

fn entries_result(result: Result<Vec<DirEntry>>) -> OpOutcome {
    match result {
        Ok(entries) => {
            let mut digest_bytes = Vec::new();
            for entry in &entries {
                digest_bytes.extend_from_slice(&entry.ino.0.to_le_bytes());
                digest_bytes.push(kind_code(entry.kind));
                digest_bytes.extend_from_slice(&entry.name);
                digest_bytes.push(0xFF);
            }
            OpOutcome::Entries {
                count: entries.len(),
                crc32c: crc32c(&digest_bytes),
            }
        }
        Err(err) => OpOutcome::Err(err.to_errno()),
    }
}

fn assert_rejected_if_invalid(name: &[u8], outcome: &OpOutcome) {
    if !matches!(NameValidity::from_bytes(name), NameValidity::Valid) {
        assert!(
            matches!(outcome, OpOutcome::Err(_)),
            "invalid name unexpectedly accepted: {name:?} -> {outcome:?}"
        );
    }
}

fn seed_write_ops(fs: &OpenFs, cx: &Cx) -> Result<InodeNumber> {
    fs.create(
        cx,
        ROOT_INO,
        OsStr::from_bytes(SEED_RENAME_SRC),
        0o644,
        0,
        0,
    )?;
    let link_src = fs
        .create(cx, ROOT_INO, OsStr::from_bytes(SEED_LINK_SRC), 0o644, 0, 0)?
        .ino;
    Ok(link_src)
}

fn classify_case(inputs: &Inputs) -> ValidationOutcome {
    let cx = Cx::for_testing();
    let dev = MemByteDevice::from_vec(build_btrfs_fsops_image());
    let mut fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default())
        .expect("synthetic btrfs image should open");
    fs.enable_writes(&cx)
        .expect("synthetic btrfs image should become writable");
    let link_src = seed_write_ops(&fs, &cx).expect("seed write ops");

    let create = attr_result(fs.create(
        &cx,
        ROOT_INO,
        OsStr::from_bytes(&inputs.create_name),
        0o644,
        0,
        0,
    ));
    assert_rejected_if_invalid(&inputs.create_name, &create);

    let mkdir = attr_result(fs.mkdir(
        &cx,
        ROOT_INO,
        OsStr::from_bytes(&inputs.mkdir_name),
        0o755,
        0,
        0,
    ));
    assert_rejected_if_invalid(&inputs.mkdir_name, &mkdir);

    let link = attr_result(fs.link(
        &cx,
        link_src,
        ROOT_INO,
        OsStr::from_bytes(&inputs.link_name),
    ));
    assert_rejected_if_invalid(&inputs.link_name, &link);

    let symlink = attr_result(fs.symlink(
        &cx,
        ROOT_INO,
        OsStr::from_bytes(&inputs.symlink_name),
        Path::new(OsStr::from_bytes(&inputs.symlink_target)),
        0,
        0,
    ));
    assert_rejected_if_invalid(&inputs.symlink_name, &symlink);

    let symlink_readback = match &symlink {
        OpOutcome::Attr { ino, .. } => bytes_result(fs.readlink(&cx, InodeNumber(*ino))),
        _ => OpOutcome::Skipped,
    };

    let rename_dst = unit_result(fs.rename(
        &cx,
        ROOT_INO,
        OsStr::from_bytes(SEED_RENAME_SRC),
        ROOT_INO,
        OsStr::from_bytes(&inputs.rename_new_name),
    ));
    assert_rejected_if_invalid(&inputs.rename_new_name, &rename_dst);

    let rename_src = unit_result(fs.rename(
        &cx,
        ROOT_INO,
        OsStr::from_bytes(&inputs.rename_old_name),
        ROOT_INO,
        OsStr::from_bytes(RENAME_FIXED_DEST),
    ));
    assert_rejected_if_invalid(&inputs.rename_old_name, &rename_src);

    let root_dir = entries_result(fs.readdir(&cx, ROOT_INO, 0));

    ValidationOutcome {
        create,
        mkdir,
        link,
        rename_dst,
        rename_src,
        symlink,
        symlink_readback,
        root_dir,
    }
}

fuzz_target!(|data: &[u8]| {
    let inputs = Inputs::decode(data);
    let first = classify_case(&inputs);
    let second = classify_case(&inputs);
    assert_eq!(first, second, "identical input must classify identically");
});

struct LeafItemSpec {
    idx: usize,
    objectid: u64,
    item_type: u8,
    key_offset: u64,
    data_offset: u32,
    data_size: u32,
}

fn write_btrfs_leaf_item(image: &mut [u8], leaf_off: usize, spec: LeafItemSpec) {
    let item_off = leaf_off + LEAF_HEADER_SIZE + spec.idx * LEAF_ITEM_SIZE;
    let data_offset_rel = spec
        .data_offset
        .checked_sub(u32::try_from(LEAF_HEADER_SIZE).unwrap_or(0))
        .expect("test payload must live after the leaf header");
    image[item_off..item_off + 8].copy_from_slice(&spec.objectid.to_le_bytes());
    image[item_off + 8] = spec.item_type;
    image[item_off + 9..item_off + 17].copy_from_slice(&spec.key_offset.to_le_bytes());
    image[item_off + 17..item_off + 21].copy_from_slice(&data_offset_rel.to_le_bytes());
    image[item_off + 21..item_off + 25].copy_from_slice(&spec.data_size.to_le_bytes());
}

fn encode_btrfs_inode_item(mode: u32, size: u64, nbytes: u64, nlink: u32) -> [u8; 160] {
    let mut inode = [0_u8; 160];
    inode[0..8].copy_from_slice(&1_u64.to_le_bytes());
    inode[8..16].copy_from_slice(&1_u64.to_le_bytes());
    inode[16..24].copy_from_slice(&size.to_le_bytes());
    inode[24..32].copy_from_slice(&nbytes.to_le_bytes());
    inode[40..44].copy_from_slice(&nlink.to_le_bytes());
    inode[44..48].copy_from_slice(&1000_u32.to_le_bytes());
    inode[48..52].copy_from_slice(&1000_u32.to_le_bytes());
    inode[52..56].copy_from_slice(&mode.to_le_bytes());
    inode[112..120].copy_from_slice(&10_u64.to_le_bytes());
    inode[124..132].copy_from_slice(&10_u64.to_le_bytes());
    inode[136..144].copy_from_slice(&10_u64.to_le_bytes());
    inode[148..156].copy_from_slice(&10_u64.to_le_bytes());
    inode
}

fn encode_btrfs_dir_index_entry(name: &[u8], child_objectid: u64, file_type: u8) -> Vec<u8> {
    let mut entry = vec![0_u8; 30 + name.len()];
    entry[0..8].copy_from_slice(&child_objectid.to_le_bytes());
    entry[8] = BTRFS_ITEM_INODE_ITEM;
    entry[9..17].copy_from_slice(&0_u64.to_le_bytes());
    entry[17..25].copy_from_slice(&1_u64.to_le_bytes());
    entry[25..27].copy_from_slice(&0_u16.to_le_bytes());
    let name_len = u16::try_from(name.len()).expect("test name should fit in u16");
    entry[27..29].copy_from_slice(&name_len.to_le_bytes());
    entry[29] = file_type;
    entry[30..30 + name.len()].copy_from_slice(name);
    entry
}

fn encode_btrfs_extent_regular(disk_bytenr: u64, num_bytes: u64) -> [u8; 53] {
    let mut extent = [0_u8; 53];
    extent[0..8].copy_from_slice(&1_u64.to_le_bytes());
    extent[8..16].copy_from_slice(&num_bytes.to_le_bytes());
    extent[20] = BTRFS_FILE_EXTENT_REG;
    extent[21..29].copy_from_slice(&disk_bytenr.to_le_bytes());
    extent[29..37].copy_from_slice(&num_bytes.to_le_bytes());
    extent[37..45].copy_from_slice(&0_u64.to_le_bytes());
    extent[45..53].copy_from_slice(&num_bytes.to_le_bytes());
    extent
}

fn stamp_tree_block_crc32c(image: &mut [u8], logical: usize) {
    let block = &mut image[logical..logical + NODESIZE];
    let csum = crc32c(&block[0x20..]);
    block[0..4].copy_from_slice(&csum.to_le_bytes());
}

fn write_superblock(image: &mut [u8]) {
    let image_size = u64::try_from(image.len()).unwrap_or(u64::MAX);
    let sb_off = BTRFS_SUPER_INFO_OFFSET;

    image[sb_off + 0x40..sb_off + 0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
    image[sb_off + 0x48..sb_off + 0x50].copy_from_slice(&1_u64.to_le_bytes());
    image[sb_off + 0x50..sb_off + 0x58].copy_from_slice(&ROOT_TREE_LOGICAL.to_le_bytes());
    image[sb_off + 0x58..sb_off + 0x60].copy_from_slice(&0_u64.to_le_bytes());
    image[sb_off + 0x70..sb_off + 0x78].copy_from_slice(&image_size.to_le_bytes());
    image[sb_off + 0x80..sb_off + 0x88].copy_from_slice(&256_u64.to_le_bytes());
    image[sb_off + 0x88..sb_off + 0x90].copy_from_slice(&1_u64.to_le_bytes());
    image[sb_off + 0x90..sb_off + 0x94].copy_from_slice(&4096_u32.to_le_bytes());
    image[sb_off + 0x94..sb_off + 0x98].copy_from_slice(&4096_u32.to_le_bytes());
    image[sb_off + 0x9C..sb_off + 0xA0].copy_from_slice(&4096_u32.to_le_bytes());
    image[sb_off + 0xC6] = 0;

    write_sys_chunk_array(image);
}

fn write_sys_chunk_array(image: &mut [u8]) {
    let image_size = u64::try_from(image.len()).unwrap_or(u64::MAX);
    let sb_off = BTRFS_SUPER_INFO_OFFSET;

    let mut chunk_array = Vec::new();
    chunk_array.extend_from_slice(&256_u64.to_le_bytes());
    chunk_array.push(228_u8);
    chunk_array.extend_from_slice(&0_u64.to_le_bytes());
    chunk_array.extend_from_slice(&image_size.to_le_bytes());
    chunk_array.extend_from_slice(&2_u64.to_le_bytes());
    chunk_array.extend_from_slice(&0x1_0000_u64.to_le_bytes());
    chunk_array.extend_from_slice(&1_u64.to_le_bytes());
    chunk_array.extend_from_slice(&4096_u32.to_le_bytes());
    chunk_array.extend_from_slice(&4096_u32.to_le_bytes());
    chunk_array.extend_from_slice(&4096_u32.to_le_bytes());
    chunk_array.extend_from_slice(&1_u16.to_le_bytes());
    chunk_array.extend_from_slice(&0_u16.to_le_bytes());
    chunk_array.extend_from_slice(&1_u64.to_le_bytes());
    chunk_array.extend_from_slice(&0_u64.to_le_bytes());
    chunk_array.extend_from_slice(&[0_u8; 16]);

    image[sb_off + 0xA0..sb_off + 0xA4]
        .copy_from_slice(&(u32::try_from(chunk_array.len()).unwrap_or(u32::MAX)).to_le_bytes());
    let array_start = sb_off + 0x32B;
    image[array_start..array_start + chunk_array.len()].copy_from_slice(&chunk_array);
}

fn write_root_tree_leaf(image: &mut [u8]) {
    let root_leaf = usize::try_from(ROOT_TREE_LOGICAL).unwrap_or(0);
    image[root_leaf + 0x30..root_leaf + 0x38].copy_from_slice(&ROOT_TREE_LOGICAL.to_le_bytes());
    image[root_leaf + 0x50..root_leaf + 0x58].copy_from_slice(&1_u64.to_le_bytes());
    image[root_leaf + 0x58..root_leaf + 0x60].copy_from_slice(&1_u64.to_le_bytes());
    image[root_leaf + 0x60..root_leaf + 0x64].copy_from_slice(&1_u32.to_le_bytes());
    image[root_leaf + 0x64] = 0;

    let root_item_offset = 3000_u32;
    let root_item_size = 239_u32;
    write_btrfs_leaf_item(
        image,
        root_leaf,
        LeafItemSpec {
            idx: 0,
            objectid: BTRFS_FS_TREE_OBJECTID,
            item_type: BTRFS_ITEM_ROOT_ITEM,
            key_offset: 0,
            data_offset: root_item_offset,
            data_size: root_item_size,
        },
    );

    let mut root_item = vec![0_u8; usize::try_from(root_item_size).unwrap_or(0)];
    root_item[168..176].copy_from_slice(&256_u64.to_le_bytes());
    root_item[176..184].copy_from_slice(&FS_TREE_LOGICAL.to_le_bytes());
    if let Some(last) = root_item.last_mut() {
        *last = 0;
    }

    let root_data_off = root_leaf + usize::try_from(root_item_offset).unwrap_or(0);
    image[root_data_off..root_data_off + root_item.len()].copy_from_slice(&root_item);
    stamp_tree_block_crc32c(image, root_leaf);
}

fn write_fs_tree_leaf(image: &mut [u8]) {
    let fs_leaf = usize::try_from(FS_TREE_LOGICAL).unwrap_or(0);
    let file_data_logical = FILE_DATA_LOGICAL;
    let file_bytes = b"hello from btrfs fsops";

    image[fs_leaf + 0x30..fs_leaf + 0x38].copy_from_slice(&FS_TREE_LOGICAL.to_le_bytes());
    image[fs_leaf + 0x50..fs_leaf + 0x58].copy_from_slice(&1_u64.to_le_bytes());
    image[fs_leaf + 0x58..fs_leaf + 0x60].copy_from_slice(&5_u64.to_le_bytes());
    image[fs_leaf + 0x60..fs_leaf + 0x64].copy_from_slice(&4_u32.to_le_bytes());
    image[fs_leaf + 0x64] = 0;

    let root_inode = encode_btrfs_inode_item(0o040_755, 4096, 4096, 2);
    let file_inode = encode_btrfs_inode_item(
        0o100_644,
        u64::try_from(file_bytes.len()).unwrap_or(0),
        u64::try_from(file_bytes.len()).unwrap_or(0),
        1,
    );
    let dir_index = encode_btrfs_dir_index_entry(b"hello.txt", 257, BTRFS_FT_REG_FILE);
    let extent = encode_btrfs_extent_regular(
        file_data_logical,
        u64::try_from(file_bytes.len()).unwrap_or(0),
    );

    let root_inode_off = 3200_u32;
    let dir_index_off = 3060_u32;
    let file_inode_off = 2860_u32;
    let extent_off = 2780_u32;

    write_btrfs_leaf_item(
        image,
        fs_leaf,
        LeafItemSpec {
            idx: 0,
            objectid: 256,
            item_type: BTRFS_ITEM_INODE_ITEM,
            key_offset: 0,
            data_offset: root_inode_off,
            data_size: u32::try_from(root_inode.len()).unwrap_or(u32::MAX),
        },
    );
    write_btrfs_leaf_item(
        image,
        fs_leaf,
        LeafItemSpec {
            idx: 1,
            objectid: 256,
            item_type: BTRFS_ITEM_DIR_INDEX,
            key_offset: 2,
            data_offset: dir_index_off,
            data_size: u32::try_from(dir_index.len()).unwrap_or(u32::MAX),
        },
    );
    write_btrfs_leaf_item(
        image,
        fs_leaf,
        LeafItemSpec {
            idx: 2,
            objectid: 257,
            item_type: BTRFS_ITEM_INODE_ITEM,
            key_offset: 0,
            data_offset: file_inode_off,
            data_size: u32::try_from(file_inode.len()).unwrap_or(u32::MAX),
        },
    );
    write_btrfs_leaf_item(
        image,
        fs_leaf,
        LeafItemSpec {
            idx: 3,
            objectid: 257,
            item_type: BTRFS_ITEM_EXTENT_DATA,
            key_offset: 0,
            data_offset: extent_off,
            data_size: u32::try_from(extent.len()).unwrap_or(u32::MAX),
        },
    );

    copy_payload(image, fs_leaf, root_inode_off, &root_inode);
    copy_payload(image, fs_leaf, dir_index_off, &dir_index);
    copy_payload(image, fs_leaf, file_inode_off, &file_inode);
    copy_payload(image, fs_leaf, extent_off, &extent);

    let file_data_off = usize::try_from(FILE_DATA_LOGICAL).unwrap_or(0);
    image[file_data_off..file_data_off + file_bytes.len()].copy_from_slice(file_bytes);
    stamp_tree_block_crc32c(image, fs_leaf);
}

fn copy_payload(image: &mut [u8], leaf_off: usize, payload_off: u32, payload: &[u8]) {
    let payload_off = leaf_off + usize::try_from(payload_off).unwrap_or(0);
    image[payload_off..payload_off + payload.len()].copy_from_slice(payload);
}

fn build_btrfs_fsops_image() -> Vec<u8> {
    let mut image = vec![0_u8; 512 * 1024];
    write_superblock(&mut image);
    write_root_tree_leaf(&mut image);
    write_fs_tree_leaf(&mut image);
    image
}
