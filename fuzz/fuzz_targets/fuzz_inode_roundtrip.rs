#![no_main]

use ffs_inode::{encode_extra_timestamp, file_type, fuzz_serialize_inode};
use ffs_ondisk::Ext4Inode;
use libfuzzer_sys::fuzz_target;

const MAX_RAW_BYTES: usize = 512;
const MAX_EXTENT_BYTES: usize = 60;
const MAX_EXTRA_ISIZE: usize = 64;
const EXTRA_ISIZE_CHOICES: [u16; 4] = [0, 28, 32, 64];

struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        let byte = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        byte
    }

    fn next_u16(&mut self) -> u16 {
        u16::from_le_bytes([self.next_u8(), self.next_u8()])
    }

    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    fn next_index(&mut self, len: usize) -> usize {
        if len == 0 {
            0
        } else {
            usize::from(self.next_u16()) % len
        }
    }

    fn take_vec(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.next_index(max_len.saturating_add(1));
        (0..len).map(|_| self.next_u8()).collect()
    }

    fn remainder(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or(&[])
    }
}

#[derive(Clone, Copy)]
enum SeedMode {
    Raw,
    SyntheticRegular,
    SyntheticDirectory,
    Truncated,
}

impl SeedMode {
    fn from_selector(selector: u8) -> Self {
        match selector % 4 {
            0 => Self::Raw,
            1 => Self::SyntheticRegular,
            2 => Self::SyntheticDirectory,
            _ => Self::Truncated,
        }
    }
}

fn expected_encode_extra_timestamp(secs: u64, nsec: u32) -> u32 {
    ((secs >> 32) as u32 & 0x3) | (nsec.min(999_999_999) << 2)
}

fn choose_inode_size(cursor: &mut ByteCursor<'_>) -> usize {
    if cursor.next_u8() & 1 == 0 {
        128
    } else {
        256
    }
}

fn choose_extra_isize(cursor: &mut ByteCursor<'_>, inode_size: usize) -> u16 {
    if inode_size <= 128 {
        return 0;
    }

    let max_extra = inode_size.saturating_sub(128).min(MAX_EXTRA_ISIZE);
    EXTRA_ISIZE_CHOICES[cursor.next_index(EXTRA_ISIZE_CHOICES.len())]
        .min(u16::try_from(max_extra).unwrap_or(u16::MAX))
}

fn build_synthetic_inode(
    cursor: &mut ByteCursor<'_>,
    mode_bits: u16,
    inode_size: usize,
) -> Ext4Inode {
    let extra_isize = choose_extra_isize(cursor, inode_size);
    let xattr_capacity = inode_size.saturating_sub(128 + usize::from(extra_isize));

    let atime = cursor.next_u32();
    let ctime = cursor.next_u32();
    let mtime = cursor.next_u32();
    let dtime = cursor.next_u32();
    let crtime = if inode_size >= 0x98 {
        cursor.next_u32()
    } else {
        0
    };

    Ext4Inode {
        mode: mode_bits | (u16::from(cursor.next_u8()) & 0o777),
        uid: cursor.next_u32(),
        gid: cursor.next_u32(),
        size: cursor.next_u64(),
        links_count: cursor.next_u16(),
        blocks: cursor.next_u64(),
        flags: cursor.next_u32(),
        version: cursor.next_u32(),
        generation: cursor.next_u32(),
        file_acl: cursor.next_u64(),
        atime,
        ctime,
        mtime,
        dtime,
        atime_extra: if inode_size >= 0x90 {
            expected_encode_extra_timestamp(cursor.next_u64(), cursor.next_u32())
        } else {
            0
        },
        ctime_extra: if inode_size >= 0x88 {
            expected_encode_extra_timestamp(cursor.next_u64(), cursor.next_u32())
        } else {
            0
        },
        mtime_extra: if inode_size >= 0x8C {
            expected_encode_extra_timestamp(cursor.next_u64(), cursor.next_u32())
        } else {
            0
        },
        crtime,
        crtime_extra: if inode_size >= 0x98 {
            expected_encode_extra_timestamp(cursor.next_u64(), cursor.next_u32())
        } else {
            0
        },
        extra_isize,
        checksum: cursor.next_u32(),
        version_hi: if inode_size >= 0x9C {
            cursor.next_u32()
        } else {
            0
        },
        projid: if inode_size >= 0xA0 {
            cursor.next_u32()
        } else {
            0
        },
        extent_bytes: cursor.take_vec(MAX_EXTENT_BYTES),
        xattr_ibody: cursor.take_vec(xattr_capacity),
    }
}

fn verify_roundtrip(inode: &Ext4Inode, inode_size: usize) {
    let raw = fuzz_serialize_inode(inode, inode_size);
    let parsed = match Ext4Inode::parse_from_bytes(&raw) {
        Ok(parsed) => parsed,
        Err(_) => std::process::abort(),
    };
    if &parsed != inode {
        std::process::abort();
    }
    let raw_again = fuzz_serialize_inode(&parsed, inode_size);
    if raw_again != raw {
        std::process::abort();
    }
}

fn verify_raw_bytes(raw: &[u8]) {
    if let Ok(parsed) = Ext4Inode::parse_from_bytes(raw) {
        let inode_size = if raw.len() >= 256 { 256 } else { 128 };
        verify_roundtrip(&parsed, inode_size);
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = ByteCursor::new(data);
    let secs = cursor.next_u64();
    let nsec = cursor.next_u32();
    let encoded = encode_extra_timestamp(secs, nsec);
    if encoded != expected_encode_extra_timestamp(secs, nsec) {
        std::process::abort();
    }

    match SeedMode::from_selector(cursor.next_u8()) {
        SeedMode::Raw => {
            let raw: Vec<u8> = cursor
                .remainder()
                .iter()
                .copied()
                .take(MAX_RAW_BYTES)
                .collect();
            verify_raw_bytes(&raw);
        }
        SeedMode::SyntheticRegular => {
            let inode_size = choose_inode_size(&mut cursor);
            let inode = build_synthetic_inode(&mut cursor, file_type::S_IFREG, inode_size);
            verify_roundtrip(&inode, inode_size);
        }
        SeedMode::SyntheticDirectory => {
            let inode_size = choose_inode_size(&mut cursor);
            let inode = build_synthetic_inode(&mut cursor, file_type::S_IFDIR, inode_size);
            verify_roundtrip(&inode, inode_size);
        }
        SeedMode::Truncated => {
            let mut raw: Vec<u8> = cursor
                .remainder()
                .iter()
                .copied()
                .take(MAX_RAW_BYTES)
                .collect();
            raw.truncate(cursor.next_index(raw.len().saturating_add(1)));
            verify_raw_bytes(&raw);
        }
    }
});
