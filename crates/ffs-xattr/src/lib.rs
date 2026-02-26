#![forbid(unsafe_code)]
//! Extended attributes (xattr).
//!
//! Inline xattr storage (after inode extra fields within the inode table
//! entry) and external xattr block storage. Namespace routing for user,
//! system, security, and trusted attribute namespaces.

use ffs_error::{FfsError, Result};
use ffs_ondisk::{Ext4Inode, Ext4Xattr, parse_ibody_xattrs, parse_xattr_block};
use ffs_types::{
    EXT4_XATTR_INDEX_POSIX_ACL_ACCESS, EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT,
    EXT4_XATTR_INDEX_SECURITY, EXT4_XATTR_INDEX_SYSTEM, EXT4_XATTR_INDEX_TRUSTED,
    EXT4_XATTR_INDEX_USER, EXT4_XATTR_MAGIC, ParseError,
};

const INLINE_HEADER_LEN: usize = 4;
const EXTERNAL_HEADER_LEN: usize = 32;
const XATTR_ENTRY_HEADER_LEN: usize = 16;
const XATTR_NAME_MAX: usize = u8::MAX as usize;
const XATTR_VALUE_MAX: usize = 65_536;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn parse_to_ffs(err: &ParseError) -> FfsError {
    FfsError::Format(err.to_string())
}

fn parse_external_magic(block: &[u8]) -> Result<u32> {
    let Some(bytes) = block.get(0..4) else {
        return Err(FfsError::Format(
            "external xattr block shorter than 4-byte magic".to_owned(),
        ));
    };
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn parse_inline_entries(inode: &Ext4Inode) -> Result<Vec<Ext4Xattr>> {
    parse_ibody_xattrs(inode).map_err(|err| parse_to_ffs(&err))
}

fn parse_external_entries(block: &[u8], allow_zero_initialized: bool) -> Result<Vec<Ext4Xattr>> {
    if block.len() < EXTERNAL_HEADER_LEN {
        return Err(FfsError::Format(
            "external xattr block shorter than 32-byte header".to_owned(),
        ));
    }
    let magic = parse_external_magic(block)?;
    if magic != EXT4_XATTR_MAGIC {
        if allow_zero_initialized && block.iter().all(|b| *b == 0) {
            return Ok(Vec::new());
        }
        return Err(FfsError::Format(
            "external xattr block has invalid magic".to_owned(),
        ));
    }
    parse_xattr_block(block).map_err(|err| parse_to_ffs(&err))
}

fn entry_index(entries: &[Ext4Xattr], name_index: u8, name: &[u8]) -> Option<usize> {
    entries
        .iter()
        .position(|e| e.name_index == name_index && e.name == name)
}

fn encode_entries_region(region_capacity: usize, entries: &[Ext4Xattr]) -> Result<Vec<u8>> {
    let mut data = vec![0_u8; region_capacity];
    let mut next_entry = 0_usize;
    let mut value_tail = region_capacity;

    for entry in entries {
        if entry.name.len() > XATTR_NAME_MAX {
            return Err(FfsError::NameTooLong);
        }
        if entry.value.len() > XATTR_VALUE_MAX {
            return Err(FfsError::Format(
                "xattr value exceeds 65536-byte limit".to_owned(),
            ));
        }

        let entry_len = align4(
            XATTR_ENTRY_HEADER_LEN
                .checked_add(entry.name.len())
                .ok_or_else(|| FfsError::Format("xattr entry length overflow".to_owned()))?,
        );
        let value_start = value_tail
            .checked_sub(entry.value.len())
            .ok_or(FfsError::NoSpace)?;

        let entry_end = next_entry
            .checked_add(entry_len)
            .ok_or_else(|| FfsError::Format("xattr entry offset overflow".to_owned()))?;
        let entry_end_with_term = entry_end
            .checked_add(4)
            .ok_or_else(|| FfsError::Format("xattr terminator offset overflow".to_owned()))?;
        if entry_end_with_term > value_start {
            return Err(FfsError::NoSpace);
        }

        data[value_start..value_tail].copy_from_slice(&entry.value);
        value_tail = value_start;

        data[next_entry] = u8::try_from(entry.name.len()).map_err(|_| FfsError::NameTooLong)?;
        data[next_entry + 1] = entry.name_index;
        data[next_entry + 2..next_entry + 4].copy_from_slice(
            &u16::try_from(value_start)
                .map_err(|_| FfsError::Format("xattr value offset exceeds u16".to_owned()))?
                .to_le_bytes(),
        );
        data[next_entry + 4..next_entry + 8].copy_from_slice(
            &u32::try_from(entry.value.len())
                .map_err(|_| FfsError::Format("xattr value size exceeds u32".to_owned()))?
                .to_le_bytes(),
        );
        data[next_entry + XATTR_ENTRY_HEADER_LEN
            ..next_entry + XATTR_ENTRY_HEADER_LEN + entry.name.len()]
            .copy_from_slice(&entry.name);

        next_entry = entry_end;
    }

    Ok(data)
}

fn build_inline_ibody(ibody_len: usize, entries: &[Ext4Xattr]) -> Result<Vec<u8>> {
    if ibody_len == 0 {
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        return Err(FfsError::NoSpace);
    }
    if ibody_len < INLINE_HEADER_LEN {
        return Err(FfsError::Format(
            "inline xattr region shorter than 4-byte header".to_owned(),
        ));
    }

    let mut out = vec![0_u8; ibody_len];
    if entries.is_empty() {
        return Ok(out);
    }

    out[0..4].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());
    let encoded = encode_entries_region(ibody_len - INLINE_HEADER_LEN, entries)?;
    out[INLINE_HEADER_LEN..].copy_from_slice(&encoded);
    Ok(out)
}

fn build_external_block(block_len: usize, entries: &[Ext4Xattr]) -> Result<Vec<u8>> {
    if block_len < EXTERNAL_HEADER_LEN {
        return Err(FfsError::Format(
            "external xattr block shorter than 32-byte header".to_owned(),
        ));
    }

    let mut out = vec![0_u8; block_len];
    if entries.is_empty() {
        return Ok(out);
    }

    out[0..4].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());
    out[4..8].copy_from_slice(&1_u32.to_le_bytes()); // h_refcount
    out[8..12].copy_from_slice(&1_u32.to_le_bytes()); // h_blocks

    let encoded = encode_entries_region(block_len - EXTERNAL_HEADER_LEN, entries)?;
    out[EXTERNAL_HEADER_LEN..].copy_from_slice(&encoded);
    Ok(out)
}

fn ext4_name_index_from_full_name(full_name: &str) -> Result<(u8, Vec<u8>)> {
    if let Some(name) = full_name.strip_prefix("user.") {
        if name.is_empty() {
            return Err(FfsError::Format(
                "xattr name after user. cannot be empty".to_owned(),
            ));
        }
        return Ok((EXT4_XATTR_INDEX_USER, name.as_bytes().to_vec()));
    }

    if let Some(name) = full_name.strip_prefix("trusted.") {
        if name.is_empty() {
            return Err(FfsError::Format(
                "xattr name after trusted. cannot be empty".to_owned(),
            ));
        }
        return Ok((EXT4_XATTR_INDEX_TRUSTED, name.as_bytes().to_vec()));
    }

    if let Some(name) = full_name.strip_prefix("security.") {
        if name.is_empty() {
            return Err(FfsError::Format(
                "xattr name after security. cannot be empty".to_owned(),
            ));
        }
        return Ok((EXT4_XATTR_INDEX_SECURITY, name.as_bytes().to_vec()));
    }

    if full_name == "system.posix_acl_access" {
        return Ok((EXT4_XATTR_INDEX_POSIX_ACL_ACCESS, Vec::new()));
    }
    if full_name == "system.posix_acl_default" {
        return Ok((EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT, Vec::new()));
    }

    if let Some(name) = full_name.strip_prefix("system.") {
        if name.is_empty() {
            return Err(FfsError::Format(
                "xattr name after system. cannot be empty".to_owned(),
            ));
        }
        return Ok((EXT4_XATTR_INDEX_SYSTEM, name.as_bytes().to_vec()));
    }

    Err(FfsError::Format(format!(
        "unsupported xattr namespace in '{full_name}'"
    )))
}

/// Permission context used for namespace write checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XattrWriteAccess {
    pub is_owner: bool,
    pub has_cap_fowner: bool,
    pub has_cap_sys_admin: bool,
}

fn check_write_permissions(name_index: u8, access: XattrWriteAccess) -> Result<()> {
    let user_allowed = access.is_owner || access.has_cap_fowner || access.has_cap_sys_admin;
    match name_index {
        EXT4_XATTR_INDEX_USER => {
            if user_allowed {
                Ok(())
            } else {
                Err(FfsError::PermissionDenied)
            }
        }
        EXT4_XATTR_INDEX_TRUSTED
        | EXT4_XATTR_INDEX_SECURITY
        | EXT4_XATTR_INDEX_SYSTEM
        | EXT4_XATTR_INDEX_POSIX_ACL_ACCESS
        | EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT => {
            if access.has_cap_sys_admin {
                Ok(())
            } else {
                Err(FfsError::PermissionDenied)
            }
        }
        _ => Err(FfsError::UnsupportedFeature(format!(
            "unsupported xattr name index: {name_index}"
        ))),
    }
}

/// Where a successful xattr mutation was stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrStorage {
    Inline,
    External,
}

/// Parse a full xattr name (`user.foo`, `security.selinux`, ...) into ext4 components.
pub fn parse_xattr_name(full_name: &str) -> Result<(u8, Vec<u8>)> {
    let (name_index, name) = ext4_name_index_from_full_name(full_name)?;
    if name.len() > XATTR_NAME_MAX {
        return Err(FfsError::NameTooLong);
    }
    Ok((name_index, name))
}

/// Set or replace one extended attribute.
///
/// Behavior:
/// - Enforces namespace write permissions.
/// - Updates existing entries in-place in their current storage location.
/// - For new entries, tries inline storage first, then external block.
/// - If an inline update no longer fits, spills that entry to external storage.
pub fn set_xattr(
    inode: &mut Ext4Inode,
    mut external_block: Option<&mut [u8]>,
    full_name: &str,
    value: &[u8],
    access: XattrWriteAccess,
) -> Result<XattrStorage> {
    if value.len() > XATTR_VALUE_MAX {
        return Err(FfsError::Format(
            "xattr value exceeds 65536-byte limit".to_owned(),
        ));
    }

    let (name_index, name) = parse_xattr_name(full_name)?;
    check_write_permissions(name_index, access)?;

    let mut inline_entries = parse_inline_entries(inode)?;
    let mut external_entries = if let Some(block) = external_block.as_deref() {
        parse_external_entries(block, true)?
    } else {
        Vec::new()
    };

    if let Some(pos) = entry_index(&external_entries, name_index, &name) {
        external_entries[pos].value = value.to_vec();
        let Some(block) = external_block.as_mut() else {
            return Err(FfsError::Format(
                "external xattr entries exist but no external block was provided".to_owned(),
            ));
        };
        let block = &mut **block;
        let new_block = build_external_block(block.len(), &external_entries)?;
        block.copy_from_slice(&new_block);
        return Ok(XattrStorage::External);
    }

    if let Some(pos) = entry_index(&inline_entries, name_index, &name) {
        inline_entries[pos].value = value.to_vec();
        if let Ok(new_ibody) = build_inline_ibody(inode.xattr_ibody.len(), &inline_entries) {
            inode.xattr_ibody = new_ibody;
            return Ok(XattrStorage::Inline);
        }

        let mut inline_without_target = inline_entries;
        inline_without_target.remove(pos);
        let new_ibody = build_inline_ibody(inode.xattr_ibody.len(), &inline_without_target)?;

        let Some(block) = external_block.as_mut() else {
            return Err(FfsError::NoSpace);
        };
        let block = &mut **block;
        external_entries.push(Ext4Xattr {
            name_index,
            name,
            value: value.to_vec(),
        });
        let new_block = build_external_block(block.len(), &external_entries)?;

        inode.xattr_ibody = new_ibody;
        block.copy_from_slice(&new_block);
        return Ok(XattrStorage::External);
    }

    let mut inline_candidate = inline_entries;
    inline_candidate.push(Ext4Xattr {
        name_index,
        name: name.clone(),
        value: value.to_vec(),
    });
    if let Ok(new_ibody) = build_inline_ibody(inode.xattr_ibody.len(), &inline_candidate) {
        inode.xattr_ibody = new_ibody;
        return Ok(XattrStorage::Inline);
    }

    let Some(block) = external_block.as_mut() else {
        return Err(FfsError::NoSpace);
    };
    let block = &mut **block;
    external_entries.push(Ext4Xattr {
        name_index,
        name,
        value: value.to_vec(),
    });
    let new_block = build_external_block(block.len(), &external_entries)?;
    block.copy_from_slice(&new_block);
    Ok(XattrStorage::External)
}

/// Remove one extended attribute by full name.
///
/// Returns `true` when an entry was removed.
pub fn remove_xattr(
    inode: &mut Ext4Inode,
    mut external_block: Option<&mut [u8]>,
    full_name: &str,
    access: XattrWriteAccess,
) -> Result<bool> {
    let (name_index, name) = parse_xattr_name(full_name)?;
    check_write_permissions(name_index, access)?;

    let mut inline_entries = parse_inline_entries(inode)?;
    if let Some(pos) = entry_index(&inline_entries, name_index, &name) {
        inline_entries.remove(pos);
        inode.xattr_ibody = build_inline_ibody(inode.xattr_ibody.len(), &inline_entries)?;
        return Ok(true);
    }

    let Some(block) = external_block.as_mut() else {
        if inode.file_acl != 0 {
            return Err(FfsError::Format(
                "inode references external xattr block but none was provided".to_owned(),
            ));
        }
        return Ok(false);
    };
    let block = &mut **block;

    let mut external_entries = parse_external_entries(block, true)?;
    let Some(pos) = entry_index(&external_entries, name_index, &name) else {
        return Ok(false);
    };
    external_entries.remove(pos);

    let new_block = build_external_block(block.len(), &external_entries)?;
    block.copy_from_slice(&new_block);
    if external_entries.is_empty() {
        inode.file_acl = 0;
    }
    Ok(true)
}

/// List all xattr names (`user.foo`, `security.selinux`, ...).
pub fn list_xattrs(inode: &Ext4Inode, external_block: Option<&[u8]>) -> Result<Vec<String>> {
    let mut names = Vec::new();

    let inline_entries = parse_inline_entries(inode)?;
    names.extend(inline_entries.into_iter().map(|e| e.full_name()));

    if inode.file_acl != 0 && external_block.is_none() {
        return Err(FfsError::Format(
            "inode references external xattr block but none was provided".to_owned(),
        ));
    }

    if let Some(block) = external_block {
        let ext_entries = parse_external_entries(block, true)?;
        names.extend(ext_entries.into_iter().map(|e| e.full_name()));
    }

    Ok(names)
}

/// Get one xattr value by full name.
pub fn get_xattr(
    inode: &Ext4Inode,
    external_block: Option<&[u8]>,
    full_name: &str,
) -> Result<Option<Vec<u8>>> {
    let (name_index, name) = parse_xattr_name(full_name)?;

    let inline_entries = parse_inline_entries(inode)?;
    if let Some(entry) = inline_entries
        .iter()
        .find(|e| e.name_index == name_index && e.name == name)
    {
        return Ok(Some(entry.value.clone()));
    }

    if inode.file_acl != 0 && external_block.is_none() {
        return Err(FfsError::Format(
            "inode references external xattr block but none was provided".to_owned(),
        ));
    }

    if let Some(block) = external_block {
        let external_entries = parse_external_entries(block, true)?;
        if let Some(entry) = external_entries
            .iter()
            .find(|e| e.name_index == name_index && e.name == name)
        {
            return Ok(Some(entry.value.clone()));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_inode(ibody_len: usize) -> Ext4Inode {
        Ext4Inode {
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 0,
            blocks: 0,
            flags: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,
            projid: 0,
            extent_bytes: vec![0; 60],
            xattr_ibody: vec![0; ibody_len],
        }
    }

    #[test]
    fn parse_xattr_name_maps_namespaces() {
        let (idx_user, name_user) = parse_xattr_name("user.mime").unwrap();
        assert_eq!(idx_user, EXT4_XATTR_INDEX_USER);
        assert_eq!(name_user, b"mime".to_vec());

        let (idx_trusted, name_trusted) = parse_xattr_name("trusted.hash").unwrap();
        assert_eq!(idx_trusted, EXT4_XATTR_INDEX_TRUSTED);
        assert_eq!(name_trusted, b"hash".to_vec());

        let (idx_security, name_security) = parse_xattr_name("security.selinux").unwrap();
        assert_eq!(idx_security, EXT4_XATTR_INDEX_SECURITY);
        assert_eq!(name_security, b"selinux".to_vec());

        let (idx_acl, name_acl) = parse_xattr_name("system.posix_acl_access").unwrap();
        assert_eq!(idx_acl, EXT4_XATTR_INDEX_POSIX_ACL_ACCESS);
        assert!(name_acl.is_empty());

        let (idx_acl_default, name_acl_default) =
            parse_xattr_name("system.posix_acl_default").unwrap();
        assert_eq!(idx_acl_default, EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT);
        assert!(name_acl_default.is_empty());
    }

    #[test]
    fn parse_xattr_name_rejects_suffix_over_u8_limit() {
        let too_long = format!("user.{}", "a".repeat(XATTR_NAME_MAX + 1));
        let err = parse_xattr_name(&too_long).unwrap_err();
        assert!(matches!(err, FfsError::NameTooLong));
    }

    #[test]
    fn user_namespace_requires_owner_or_capability() {
        let mut inode = make_inode(96);
        let err = set_xattr(
            &mut inode,
            None,
            "user.test",
            b"v",
            XattrWriteAccess {
                is_owner: false,
                has_cap_fowner: false,
                has_cap_sys_admin: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::PermissionDenied));
    }

    #[test]
    fn set_get_list_remove_inline_xattr() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        let stored = set_xattr(&mut inode, None, "user.mime", b"image", access).unwrap();
        assert_eq!(stored, XattrStorage::Inline);

        let value = get_xattr(&inode, None, "user.mime").unwrap();
        assert_eq!(value, Some(b"image".to_vec()));

        let names = list_xattrs(&inode, None).unwrap();
        assert_eq!(names, vec!["user.mime".to_owned()]);

        let removed = remove_xattr(&mut inode, None, "user.mime", access).unwrap();
        assert!(removed);
        assert_eq!(get_xattr(&inode, None, "user.mime").unwrap(), None);
    }

    #[test]
    fn set_xattr_falls_back_to_external_when_inline_full() {
        let mut inode = make_inode(20);
        let mut external = vec![0_u8; 1024];
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        let stored = set_xattr(
            &mut inode,
            Some(&mut external),
            "user.payload",
            b"value",
            access,
        )
        .unwrap();
        assert_eq!(stored, XattrStorage::External);
        assert_eq!(
            u32::from_le_bytes([external[0], external[1], external[2], external[3]]),
            EXT4_XATTR_MAGIC
        );
        assert_eq!(
            get_xattr(&inode, Some(&external), "user.payload").unwrap(),
            Some(b"value".to_vec())
        );
    }

    #[test]
    fn remove_xattr_from_external_clears_block_and_pointer() {
        let mut inode = make_inode(20);
        inode.file_acl = 123;
        let mut external = vec![0_u8; 1024];
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        set_xattr(
            &mut inode,
            Some(&mut external),
            "user.payload",
            b"value",
            access,
        )
        .unwrap();
        assert!(remove_xattr(&mut inode, Some(&mut external), "user.payload", access).unwrap());
        assert_eq!(inode.file_acl, 0);
        assert!(external.iter().all(|b| *b == 0));
    }

    #[test]
    fn trusted_namespace_requires_sys_admin() {
        let mut inode = make_inode(128);
        let err = set_xattr(
            &mut inode,
            None,
            "trusted.fsmeta",
            b"v",
            XattrWriteAccess {
                is_owner: true,
                has_cap_fowner: false,
                has_cap_sys_admin: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::PermissionDenied));
    }

    #[test]
    fn system_acl_write_allowed_for_sys_admin() {
        let mut inode = make_inode(128);
        let stored = set_xattr(
            &mut inode,
            None,
            "system.posix_acl_access",
            b"acl",
            XattrWriteAccess {
                is_owner: false,
                has_cap_fowner: false,
                has_cap_sys_admin: true,
            },
        )
        .unwrap();
        assert_eq!(stored, XattrStorage::Inline);
    }

    #[test]
    fn value_size_limit_enforced() {
        let mut inode = make_inode(128);
        let too_large = vec![0_u8; XATTR_VALUE_MAX + 1];
        let err = set_xattr(
            &mut inode,
            None,
            "user.too_large",
            &too_large,
            XattrWriteAccess {
                is_owner: true,
                has_cap_fowner: false,
                has_cap_sys_admin: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn set_xattr_rejects_external_block_shorter_than_header() {
        let mut inode = make_inode(128);
        let mut short_external = vec![0_u8; EXTERNAL_HEADER_LEN - 1];
        let err = set_xattr(
            &mut inode,
            Some(&mut short_external),
            "user.key",
            b"value",
            XattrWriteAccess {
                is_owner: true,
                has_cap_fowner: false,
                has_cap_sys_admin: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn list_xattrs_rejects_corrupt_external_magic() {
        let inode = make_inode(128);
        let mut external = vec![0_u8; 1024];
        external[0] = 0x7f; // Non-zero garbage magic, not all-zero initialized.
        let err = list_xattrs(&inode, Some(&external)).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn updating_inline_xattr_spills_to_external_and_preserves_others() {
        let mut inode = make_inode(80);
        let mut external = vec![0_u8; 1024];
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        set_xattr(&mut inode, None, "user.keep", b"k", access).unwrap();
        set_xattr(&mut inode, None, "user.move", b"small", access).unwrap();

        let big_value = vec![b'Z'; 80];
        let stored = set_xattr(
            &mut inode,
            Some(&mut external),
            "user.move",
            &big_value,
            access,
        )
        .unwrap();
        assert_eq!(stored, XattrStorage::External);
        assert_eq!(
            get_xattr(&inode, Some(&external), "user.keep").unwrap(),
            Some(b"k".to_vec())
        );
        assert_eq!(
            get_xattr(&inode, Some(&external), "user.move").unwrap(),
            Some(big_value)
        );
    }

    #[test]
    fn spillover_failure_keeps_existing_inline_value_intact() {
        let mut inode = make_inode(80);
        let mut external = vec![0_u8; EXTERNAL_HEADER_LEN];
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        set_xattr(&mut inode, None, "user.move", b"old", access).unwrap();
        let err = set_xattr(
            &mut inode,
            Some(&mut external),
            "user.move",
            &[b'X'; 64],
            access,
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::NoSpace));
        assert_eq!(
            get_xattr(&inode, None, "user.move").unwrap(),
            Some(b"old".to_vec())
        );
        assert!(external.iter().all(|b| *b == 0));
    }

    #[test]
    fn remove_xattr_requires_external_block_when_file_acl_is_set() {
        let mut inode = make_inode(128);
        inode.file_acl = 42;
        let err = remove_xattr(
            &mut inode,
            None,
            "user.any",
            XattrWriteAccess {
                is_owner: true,
                has_cap_fowner: false,
                has_cap_sys_admin: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn list_xattrs_requires_external_block_when_file_acl_is_set() {
        let mut inode = make_inode(128);
        inode.file_acl = 7;

        let err = list_xattrs(&inode, None).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn get_xattr_requires_external_block_when_file_acl_is_set() {
        let mut inode = make_inode(128);
        inode.file_acl = 7;

        let err = get_xattr(&inode, None, "user.any").unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn remove_xattr_denies_user_namespace_without_privileges() {
        let mut inode = make_inode(128);
        let err = remove_xattr(
            &mut inode,
            None,
            "user.any",
            XattrWriteAccess {
                is_owner: false,
                has_cap_fowner: false,
                has_cap_sys_admin: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::PermissionDenied));
    }

    #[test]
    fn parse_external_magic_rejects_short_block() {
        let err = parse_external_magic(&[]).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn build_inline_ibody_rejects_too_short_header_region() {
        let err = build_inline_ibody(INLINE_HEADER_LEN - 1, &[]).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    // ── Additional edge-case tests ───────────────────────────────────

    #[test]
    fn parse_xattr_name_rejects_unknown_namespace() {
        let err = parse_xattr_name("unknown.key").unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn parse_xattr_name_rejects_empty_after_prefix() {
        assert!(parse_xattr_name("user.").is_err());
        assert!(parse_xattr_name("trusted.").is_err());
        assert!(parse_xattr_name("security.").is_err());
        assert!(parse_xattr_name("system.").is_err());
    }

    #[test]
    fn get_xattr_returns_none_for_missing() {
        let inode = make_inode(128);
        let result = get_xattr(&inode, None, "user.nonexistent").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn remove_nonexistent_xattr_returns_false() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };
        let removed = remove_xattr(&mut inode, None, "user.nope", access).unwrap();
        assert!(!removed);
    }

    #[test]
    fn list_xattrs_empty_returns_empty() {
        let inode = make_inode(128);
        let names = list_xattrs(&inode, None).unwrap();
        assert!(names.is_empty());
    }

    #[test]
    fn set_multiple_inline_xattrs() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        set_xattr(&mut inode, None, "user.a", b"v1", access).unwrap();
        set_xattr(&mut inode, None, "user.b", b"v2", access).unwrap();

        assert_eq!(
            get_xattr(&inode, None, "user.a").unwrap(),
            Some(b"v1".to_vec())
        );
        assert_eq!(
            get_xattr(&inode, None, "user.b").unwrap(),
            Some(b"v2".to_vec())
        );

        let mut names = list_xattrs(&inode, None).unwrap();
        names.sort();
        assert_eq!(names, vec!["user.a", "user.b"]);
    }

    #[test]
    fn set_xattr_updates_existing_value() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        set_xattr(&mut inode, None, "user.key", b"old", access).unwrap();
        set_xattr(&mut inode, None, "user.key", b"new", access).unwrap();

        assert_eq!(
            get_xattr(&inode, None, "user.key").unwrap(),
            Some(b"new".to_vec())
        );

        // Should still be just one entry.
        let names = list_xattrs(&inode, None).unwrap();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn cap_fowner_allows_user_xattr_write() {
        let mut inode = make_inode(128);
        let stored = set_xattr(
            &mut inode,
            None,
            "user.test",
            b"v",
            XattrWriteAccess {
                is_owner: false,
                has_cap_fowner: true,
                has_cap_sys_admin: false,
            },
        )
        .unwrap();
        assert_eq!(stored, XattrStorage::Inline);
    }

    #[test]
    fn security_namespace_requires_sys_admin() {
        let mut inode = make_inode(128);
        let err = set_xattr(
            &mut inode,
            None,
            "security.selinux",
            b"context",
            XattrWriteAccess {
                is_owner: true,
                has_cap_fowner: true,
                has_cap_sys_admin: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::PermissionDenied));
    }

    #[test]
    fn no_inline_space_no_external_returns_error() {
        let mut inode = make_inode(0); // zero ibody space
        let err = set_xattr(
            &mut inode,
            None,
            "user.key",
            b"value",
            XattrWriteAccess {
                is_owner: true,
                has_cap_fowner: false,
                has_cap_sys_admin: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::NoSpace));
    }

    #[test]
    fn xattr_write_access_default_denies_all() {
        let access = XattrWriteAccess::default();
        assert!(!access.is_owner);
        assert!(!access.has_cap_fowner);
        assert!(!access.has_cap_sys_admin);
    }

    // ── Hardening edge-case tests ────────────────────────────────────

    #[test]
    fn constants_match_ext4_spec() {
        assert_eq!(INLINE_HEADER_LEN, 4);
        assert_eq!(EXTERNAL_HEADER_LEN, 32);
        assert_eq!(XATTR_ENTRY_HEADER_LEN, 16);
        assert_eq!(XATTR_NAME_MAX, 255);
        assert_eq!(XATTR_VALUE_MAX, 65_536);
    }

    #[test]
    fn align4_boundaries() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(2), 4);
        assert_eq!(align4(3), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
        assert_eq!(align4(16), 16);
        assert_eq!(align4(17), 20);
    }

    #[test]
    fn xattr_write_access_debug_clone_copy_eq() {
        let a = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: true,
        };
        let b = a; // Copy
        assert_eq!(a, b);
        let c = a; // Copy (same as clone for Copy types)
        assert_eq!(a, c);
        let _ = format!("{a:?}");

        let d = XattrWriteAccess {
            is_owner: false,
            ..a
        };
        assert_ne!(a, d);
    }

    #[test]
    fn xattr_storage_debug_clone_copy_eq() {
        let s = XattrStorage::Inline;
        let t = s; // Copy
        assert_eq!(s, t);
        assert_ne!(XattrStorage::Inline, XattrStorage::External);
        let _ = format!("{s:?}");
    }

    #[test]
    fn check_write_permissions_unknown_index_returns_unsupported() {
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: true,
            has_cap_sys_admin: true,
        };
        let err = check_write_permissions(255, access).unwrap_err();
        assert!(matches!(err, FfsError::UnsupportedFeature(_)));
    }

    #[test]
    fn check_write_permissions_sys_admin_allows_all_known_indexes() {
        let access = XattrWriteAccess {
            is_owner: false,
            has_cap_fowner: false,
            has_cap_sys_admin: true,
        };
        for idx in [
            EXT4_XATTR_INDEX_USER,
            EXT4_XATTR_INDEX_TRUSTED,
            EXT4_XATTR_INDEX_SECURITY,
            EXT4_XATTR_INDEX_SYSTEM,
            EXT4_XATTR_INDEX_POSIX_ACL_ACCESS,
            EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT,
        ] {
            assert!(
                check_write_permissions(idx, access).is_ok(),
                "index {idx} should be allowed"
            );
        }
    }

    #[test]
    fn build_inline_ibody_zero_len_empty_entries_returns_empty() {
        let data = build_inline_ibody(0, &[]).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn build_inline_ibody_zero_len_with_entries_returns_no_space() {
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: b"k".to_vec(),
            value: b"v".to_vec(),
        };
        let err = build_inline_ibody(0, &[entry]).unwrap_err();
        assert!(matches!(err, FfsError::NoSpace));
    }

    #[test]
    fn build_external_block_rejects_short_block() {
        let err = build_external_block(EXTERNAL_HEADER_LEN - 1, &[]).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn parse_external_entries_all_zeros_allowed() {
        let block = vec![0_u8; 1024];
        let entries = parse_external_entries(&block, true).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_external_entries_all_zeros_rejected_without_flag() {
        let block = vec![0_u8; 1024];
        let err = parse_external_entries(&block, false).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn entry_index_finds_correct_position() {
        let entries = vec![
            Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_USER,
                name: b"alpha".to_vec(),
                value: b"a".to_vec(),
            },
            Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_USER,
                name: b"beta".to_vec(),
                value: b"b".to_vec(),
            },
            Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_TRUSTED,
                name: b"gamma".to_vec(),
                value: b"c".to_vec(),
            },
        ];
        assert_eq!(
            entry_index(&entries, EXT4_XATTR_INDEX_USER, b"alpha"),
            Some(0)
        );
        assert_eq!(
            entry_index(&entries, EXT4_XATTR_INDEX_USER, b"beta"),
            Some(1)
        );
        assert_eq!(
            entry_index(&entries, EXT4_XATTR_INDEX_TRUSTED, b"gamma"),
            Some(2)
        );
        assert_eq!(entry_index(&entries, EXT4_XATTR_INDEX_USER, b"gamma"), None);
        assert_eq!(
            entry_index(&entries, EXT4_XATTR_INDEX_TRUSTED, b"alpha"),
            None
        );
    }

    #[test]
    fn update_existing_external_entry_stays_external() {
        let mut inode = make_inode(20);
        let mut external = vec![0_u8; 1024];
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        // First set goes to external (inline too small).
        let stored = set_xattr(
            &mut inode,
            Some(&mut external),
            "user.key",
            b"value1",
            access,
        )
        .unwrap();
        assert_eq!(stored, XattrStorage::External);

        // Update the same key — should stay external.
        let stored = set_xattr(
            &mut inode,
            Some(&mut external),
            "user.key",
            b"value2",
            access,
        )
        .unwrap();
        assert_eq!(stored, XattrStorage::External);

        assert_eq!(
            get_xattr(&inode, Some(&external), "user.key").unwrap(),
            Some(b"value2".to_vec())
        );
    }

    #[test]
    fn list_xattrs_combines_inline_and_external() {
        let mut inode = make_inode(80);
        let mut external = vec![0_u8; 1024];
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        // First xattr fits inline.
        set_xattr(&mut inode, Some(&mut external), "user.a", b"v", access).unwrap();
        // Fill up inline, force next to external.
        let big = vec![b'X'; 60];
        set_xattr(&mut inode, Some(&mut external), "user.big", &big, access).unwrap();

        let mut names = list_xattrs(&inode, Some(&external)).unwrap();
        names.sort();
        assert!(names.contains(&"user.a".to_owned()));
        assert!(names.contains(&"user.big".to_owned()));
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn remove_external_xattr_does_not_affect_inline() {
        let mut inode = make_inode(80);
        let mut external = vec![0_u8; 1024];
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        // Put one inline.
        set_xattr(&mut inode, Some(&mut external), "user.inline", b"i", access).unwrap();
        // Put one that spills to external.
        let big = vec![b'Y'; 60];
        set_xattr(&mut inode, Some(&mut external), "user.ext", &big, access).unwrap();

        // Remove external entry.
        let removed = remove_xattr(&mut inode, Some(&mut external), "user.ext", access).unwrap();
        assert!(removed);

        // Inline entry should still be present.
        assert_eq!(
            get_xattr(&inode, Some(&external), "user.inline").unwrap(),
            Some(b"i".to_vec())
        );
    }

    #[test]
    fn set_xattr_empty_value_allowed() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        let stored = set_xattr(&mut inode, None, "user.empty", b"", access).unwrap();
        assert_eq!(stored, XattrStorage::Inline);
        assert_eq!(
            get_xattr(&inode, None, "user.empty").unwrap(),
            Some(b"".to_vec())
        );
    }

    #[test]
    fn parse_xattr_name_system_generic() {
        let (idx, name) = parse_xattr_name("system.data").unwrap();
        assert_eq!(idx, EXT4_XATTR_INDEX_SYSTEM);
        assert_eq!(name, b"data".to_vec());
    }

    #[test]
    fn encode_entries_region_rejects_oversized_name() {
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: vec![b'a'; XATTR_NAME_MAX + 1],
            value: b"v".to_vec(),
        };
        let err = encode_entries_region(4096, &[entry]).unwrap_err();
        assert!(matches!(err, FfsError::NameTooLong));
    }

    #[test]
    fn encode_entries_region_rejects_oversized_value() {
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: b"k".to_vec(),
            value: vec![0_u8; XATTR_VALUE_MAX + 1],
        };
        let err = encode_entries_region(XATTR_VALUE_MAX + 100, &[entry]).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn encode_entries_region_no_space_when_too_small() {
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: b"key".to_vec(),
            value: b"value".to_vec(),
        };
        // Region too small to hold even one entry + value.
        let err = encode_entries_region(10, &[entry]).unwrap_err();
        assert!(matches!(err, FfsError::NoSpace));
    }

    // ── Proptest property-based tests ──────────────────────────────────

    use proptest::prelude::*;

    /// Generate a valid xattr suffix name (1..20 alphanumeric bytes).
    fn xattr_suffix_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop::sample::select(
                (b'a'..=b'z')
                    .chain(b'A'..=b'Z')
                    .chain(b'0'..=b'9')
                    .collect::<Vec<u8>>(),
            ),
            1..20,
        )
        .prop_map(|bytes| String::from_utf8(bytes).unwrap())
    }

    /// Generate a small xattr value (0..64 bytes).
    fn xattr_value_strategy() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..64)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// set_xattr followed by get_xattr always returns the set value.
        #[test]
        fn proptest_set_get_roundtrip(
            name in xattr_suffix_strategy(),
            value in xattr_value_strategy(),
        ) {
            let mut inode = make_inode(256);
            let mut external = vec![0_u8; 1024];
            let access = XattrWriteAccess { is_owner: true, ..Default::default() };
            let full_name = format!("user.{name}");

            set_xattr(&mut inode, Some(&mut external), &full_name, &value, access)
                .unwrap();
            let got = get_xattr(&inode, Some(&external), &full_name).unwrap();
            prop_assert_eq!(got, Some(value));
        }

        /// set then remove ⟹ get returns None.
        #[test]
        fn proptest_set_remove_get_none(
            name in xattr_suffix_strategy(),
            value in xattr_value_strategy(),
        ) {
            let mut inode = make_inode(256);
            let mut external = vec![0_u8; 1024];
            let access = XattrWriteAccess { is_owner: true, ..Default::default() };
            let full_name = format!("user.{name}");

            set_xattr(&mut inode, Some(&mut external), &full_name, &value, access)
                .unwrap();
            remove_xattr(&mut inode, Some(&mut external), &full_name, access).unwrap();
            let got = get_xattr(&inode, Some(&external), &full_name).unwrap();
            prop_assert_eq!(got, None);
        }

        /// Overwriting a value preserves other xattrs.
        #[test]
        fn proptest_overwrite_preserves_others(
            suffix_a in xattr_suffix_strategy(),
            suffix_b in xattr_suffix_strategy(),
            val_a in xattr_value_strategy(),
            val_b1 in xattr_value_strategy(),
        ) {
            // Ensure distinct names.
            prop_assume!(suffix_a != suffix_b);

            let mut inode = make_inode(256);
            let mut external = vec![0_u8; 1024];
            let access = XattrWriteAccess { is_owner: true, ..Default::default() };
            let name_a = format!("user.{suffix_a}");
            let name_b = format!("user.{suffix_b}");

            set_xattr(&mut inode, Some(&mut external), &name_a, &val_a, access).unwrap();
            set_xattr(&mut inode, Some(&mut external), &name_b, &val_b1, access).unwrap();

            // Overwrite B with new value.
            let new_b = b"replaced";
            set_xattr(&mut inode, Some(&mut external), &name_b, new_b, access).unwrap();

            // A should be unchanged.
            let got_a = get_xattr(&inode, Some(&external), &name_a).unwrap();
            prop_assert_eq!(got_a, Some(val_a));
            // B should be the new value.
            let got_b = get_xattr(&inode, Some(&external), &name_b).unwrap();
            prop_assert_eq!(got_b, Some(new_b.to_vec()));
        }

        /// Setting N unique xattrs ⟹ list returns exactly those N names.
        #[test]
        fn proptest_set_multiple_list_complete(
            suffixes in prop::collection::hash_set(xattr_suffix_strategy(), 1..8),
        ) {
            let mut inode = make_inode(256);
            let mut external = vec![0_u8; 4096];
            let access = XattrWriteAccess { is_owner: true, ..Default::default() };

            let mut expected: Vec<String> = Vec::new();
            for suffix in &suffixes {
                let full_name = format!("user.{suffix}");
                set_xattr(&mut inode, Some(&mut external), &full_name, b"v", access)
                    .unwrap();
                expected.push(full_name);
            }

            let mut listed = list_xattrs(&inode, Some(&external)).unwrap();
            listed.sort();
            expected.sort();
            prop_assert_eq!(listed, expected);
        }

        /// encode_entries_region → parse roundtrip: encoded entries parse back identically.
        #[test]
        fn proptest_encode_parse_external_roundtrip(
            suffixes in prop::collection::hash_set(xattr_suffix_strategy(), 1..5),
            values in prop::collection::vec(xattr_value_strategy(), 1..5),
        ) {
            let entries: Vec<Ext4Xattr> = suffixes.iter().zip(values.iter()).map(|(s, v)| {
                Ext4Xattr {
                    name_index: EXT4_XATTR_INDEX_USER,
                    name: s.as_bytes().to_vec(),
                    value: v.clone(),
                }
            }).collect();

            // Build an external block and parse it back.
            let block_len = 4096;
            let block = build_external_block(block_len, &entries).unwrap();
            let parsed = parse_external_entries(&block, false).unwrap();

            prop_assert_eq!(parsed.len(), entries.len());
            for (orig, parsed_e) in entries.iter().zip(parsed.iter()) {
                prop_assert_eq!(orig.name_index, parsed_e.name_index);
                prop_assert_eq!(&orig.name, &parsed_e.name);
                prop_assert_eq!(&orig.value, &parsed_e.value);
            }
        }

        /// Removing all xattrs one-by-one leaves list empty.
        #[test]
        fn proptest_remove_all_leaves_empty(
            suffixes in prop::collection::hash_set(xattr_suffix_strategy(), 1..6),
        ) {
            let mut inode = make_inode(256);
            let mut external = vec![0_u8; 4096];
            let access = XattrWriteAccess { is_owner: true, ..Default::default() };

            let names: Vec<String> = suffixes.iter().map(|s| format!("user.{s}")).collect();
            for name in &names {
                set_xattr(&mut inode, Some(&mut external), name, b"val", access).unwrap();
            }

            for name in &names {
                remove_xattr(&mut inode, Some(&mut external), name, access).unwrap();
            }

            let listed = list_xattrs(&inode, Some(&external)).unwrap();
            prop_assert!(listed.is_empty(), "expected empty list, got: {:?}", listed);
        }
    }

    // ── Additional edge-case and boundary tests ─────────────────────────

    #[test]
    fn align4_values() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(2), 4);
        assert_eq!(align4(3), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
        assert_eq!(align4(16), 16);
        assert_eq!(align4(17), 20);
    }

    #[test]
    fn build_external_block_too_short_errors() {
        let err = build_external_block(EXTERNAL_HEADER_LEN - 1, &[]).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn build_external_block_empty_entries_returns_zeroed() {
        let block = build_external_block(1024, &[]).unwrap();
        assert!(block.iter().all(|b| *b == 0));
    }

    #[test]
    fn build_inline_ibody_zero_length_empty_entries() {
        let out = build_inline_ibody(0, &[]).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn build_inline_ibody_zero_length_nonempty_entries_errors() {
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: b"k".to_vec(),
            value: b"v".to_vec(),
        };
        let err = build_inline_ibody(0, &[entry]).unwrap_err();
        assert!(matches!(err, FfsError::NoSpace));
    }

    #[test]
    fn build_inline_ibody_with_entry_writes_magic() {
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: b"k".to_vec(),
            value: b"v".to_vec(),
        };
        let out = build_inline_ibody(128, &[entry]).unwrap();
        let magic = u32::from_le_bytes([out[0], out[1], out[2], out[3]]);
        assert_eq!(magic, EXT4_XATTR_MAGIC);
    }

    #[test]
    fn check_write_permissions_unsupported_index() {
        let err = check_write_permissions(
            255, // unsupported
            XattrWriteAccess {
                is_owner: true,
                has_cap_fowner: true,
                has_cap_sys_admin: true,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::UnsupportedFeature(_)));
    }

    #[test]
    fn parse_external_entries_accepts_zero_initialized() {
        let block = vec![0_u8; 1024];
        let entries = parse_external_entries(&block, true).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_external_entries_rejects_zero_initialized_when_not_allowed() {
        let block = vec![0_u8; 1024];
        let err = parse_external_entries(&block, false).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn entry_index_finds_correct_entry() {
        let entries = vec![
            Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_USER,
                name: b"foo".to_vec(),
                value: b"v1".to_vec(),
            },
            Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_USER,
                name: b"bar".to_vec(),
                value: b"v2".to_vec(),
            },
            Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_TRUSTED,
                name: b"foo".to_vec(),
                value: b"v3".to_vec(),
            },
        ];
        assert_eq!(
            entry_index(&entries, EXT4_XATTR_INDEX_USER, b"foo"),
            Some(0)
        );
        assert_eq!(
            entry_index(&entries, EXT4_XATTR_INDEX_USER, b"bar"),
            Some(1)
        );
        assert_eq!(
            entry_index(&entries, EXT4_XATTR_INDEX_TRUSTED, b"foo"),
            Some(2)
        );
        // Same name, different index → not found.
        assert_eq!(
            entry_index(&entries, EXT4_XATTR_INDEX_SECURITY, b"foo"),
            None
        );
        // Missing name entirely.
        assert_eq!(
            entry_index(&entries, EXT4_XATTR_INDEX_USER, b"missing"),
            None
        );
    }

    #[test]
    fn set_xattr_update_existing_external_entry() {
        let mut inode = make_inode(20); // small inline
        let mut external = vec![0_u8; 1024];
        let access = XattrWriteAccess {
            is_owner: true,
            ..Default::default()
        };

        // First set goes to external (inline too small).
        set_xattr(
            &mut inode,
            Some(&mut external),
            "user.key",
            b"original",
            access,
        )
        .unwrap();

        // Update the existing external entry.
        let stored = set_xattr(
            &mut inode,
            Some(&mut external),
            "user.key",
            b"updated",
            access,
        )
        .unwrap();
        assert_eq!(stored, XattrStorage::External);

        let val = get_xattr(&inode, Some(&external), "user.key").unwrap();
        assert_eq!(val, Some(b"updated".to_vec()));
    }

    #[test]
    fn remove_one_of_multiple_external_xattrs() {
        let mut inode = make_inode(20);
        let mut external = vec![0_u8; 4096];
        let access = XattrWriteAccess {
            is_owner: true,
            ..Default::default()
        };

        set_xattr(&mut inode, Some(&mut external), "user.keep", b"v1", access).unwrap();
        set_xattr(
            &mut inode,
            Some(&mut external),
            "user.remove_me",
            b"v2",
            access,
        )
        .unwrap();

        let removed =
            remove_xattr(&mut inode, Some(&mut external), "user.remove_me", access).unwrap();
        assert!(removed);

        // "keep" should still be there.
        let val = get_xattr(&inode, Some(&external), "user.keep").unwrap();
        assert_eq!(val, Some(b"v1".to_vec()));

        // "remove_me" should be gone.
        let val = get_xattr(&inode, Some(&external), "user.remove_me").unwrap();
        assert_eq!(val, None);

        // file_acl should still be set because there are remaining entries.
        let names = list_xattrs(&inode, Some(&external)).unwrap();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn mixed_namespace_xattrs() {
        let mut inode = make_inode(256);
        let mut external = vec![0_u8; 4096];
        let admin = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: true,
            has_cap_sys_admin: true,
        };

        set_xattr(&mut inode, Some(&mut external), "user.tag", b"u", admin).unwrap();
        set_xattr(
            &mut inode,
            Some(&mut external),
            "security.selinux",
            b"context",
            admin,
        )
        .unwrap();
        set_xattr(&mut inode, Some(&mut external), "trusted.meta", b"t", admin).unwrap();

        let mut names = list_xattrs(&inode, Some(&external)).unwrap();
        names.sort();
        assert_eq!(names, vec!["security.selinux", "trusted.meta", "user.tag"]);

        assert_eq!(
            get_xattr(&inode, Some(&external), "user.tag").unwrap(),
            Some(b"u".to_vec())
        );
        assert_eq!(
            get_xattr(&inode, Some(&external), "security.selinux").unwrap(),
            Some(b"context".to_vec())
        );
        assert_eq!(
            get_xattr(&inode, Some(&external), "trusted.meta").unwrap(),
            Some(b"t".to_vec())
        );
    }

    #[test]
    fn system_generic_xattr_allowed_for_sys_admin() {
        let mut inode = make_inode(128);
        let admin = XattrWriteAccess {
            is_owner: false,
            has_cap_fowner: false,
            has_cap_sys_admin: true,
        };

        let stored = set_xattr(&mut inode, None, "system.custom_attr", b"val", admin).unwrap();
        assert_eq!(stored, XattrStorage::Inline);

        let val = get_xattr(&inode, None, "system.custom_attr").unwrap();
        assert_eq!(val, Some(b"val".to_vec()));
    }

    #[test]
    fn encode_entries_region_name_too_long_errors() {
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: vec![b'x'; 256], // exceeds u8::MAX
            value: b"v".to_vec(),
        };
        let err = encode_entries_region(4096, &[entry]).unwrap_err();
        assert!(matches!(err, FfsError::NameTooLong));
    }

    #[test]
    fn encode_entries_region_value_too_large_errors() {
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: b"k".to_vec(),
            value: vec![0u8; XATTR_VALUE_MAX + 1],
        };
        let err = encode_entries_region(65600, &[entry]).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn encode_entries_region_nospace_when_too_small() {
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: b"key".to_vec(),
            value: vec![b'v'; 100],
        };
        // Region too small to hold entry header + name + value.
        let err = encode_entries_region(32, &[entry]).unwrap_err();
        assert!(matches!(err, FfsError::NoSpace));
    }

    #[test]
    fn parse_xattr_name_system_posix_acl_default() {
        let (idx, name) = parse_xattr_name("system.posix_acl_default").unwrap();
        assert_eq!(idx, EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT);
        assert!(name.is_empty());
    }

    #[test]
    fn xattr_storage_variants() {
        // Ensure XattrStorage derives work correctly.
        let inline = XattrStorage::Inline;
        let external = XattrStorage::External;
        assert_ne!(inline, external);
        assert_eq!(inline, XattrStorage::Inline);
        assert_eq!(external, XattrStorage::External);
        let _ = format!("{inline:?}");
        let _ = format!("{external:?}");
    }

    #[test]
    fn xattr_write_access_debug_and_clone() {
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: true,
        };
        let cloned = access;
        assert_eq!(access, cloned);
        let _ = format!("{access:?}");
    }

    #[test]
    fn set_xattr_empty_value() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            ..Default::default()
        };

        // Empty value is valid.
        set_xattr(&mut inode, None, "user.empty", b"", access).unwrap();
        let val = get_xattr(&inode, None, "user.empty").unwrap();
        assert_eq!(val, Some(Vec::new()));
    }

    #[test]
    fn set_xattr_replaces_with_empty_value() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            ..Default::default()
        };

        set_xattr(&mut inode, None, "user.key", b"nonempty", access).unwrap();
        set_xattr(&mut inode, None, "user.key", b"", access).unwrap();
        let val = get_xattr(&inode, None, "user.key").unwrap();
        assert_eq!(val, Some(Vec::new()));
    }
}
