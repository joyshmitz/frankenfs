import os

with open('crates/ffs-core/src/lib.rs', 'r') as f:
    lib_rs = f.read()

with open('crates/ffs-core/src/vfs.rs', 'r') as f:
    vfs_rs = f.read()

# Fix vfs.rs
vfs_rs = vfs_rs.replace(
    "_scope: &mut RequestScope,\n        parent: InodeNumber,",
    "scope: &mut RequestScope,\n        parent: InodeNumber,"
)
vfs_rs = vfs_rs.replace(
    "_scope: &mut RequestScope,\n        ino: InodeNumber,\n        offset:",
    "scope: &mut RequestScope,\n        ino: InodeNumber,\n        offset:"
)

# Fix lib.rs ext4 signatures
lib_rs = lib_rs.replace(
    "fn ext4_create(\n        &self,\n        cx: &Cx,\n        parent: InodeNumber,\n        name: &[u8],\n        mode: u16,\n        uid: u32,\n        gid: u32,\n    ) -> ffs_error::Result<InodeAttr> {",
    "fn ext4_create(\n        &self,\n        cx: &Cx,\n        scope: &mut RequestScope,\n        parent: InodeNumber,\n        name: &[u8],\n        mode: u16,\n        uid: u32,\n        gid: u32,\n    ) -> ffs_error::Result<InodeAttr> {"
)

lib_rs = lib_rs.replace(
    "fn ext4_mkdir(\n        &self,\n        cx: &Cx,\n        parent: InodeNumber,\n        name: &[u8],\n        mode: u16,\n        uid: u32,\n        gid: u32,\n    ) -> ffs_error::Result<InodeAttr> {",
    "fn ext4_mkdir(\n        &self,\n        cx: &Cx,\n        scope: &mut RequestScope,\n        parent: InodeNumber,\n        name: &[u8],\n        mode: u16,\n        uid: u32,\n        gid: u32,\n    ) -> ffs_error::Result<InodeAttr> {"
)

lib_rs = lib_rs.replace(
    "fn ext4_symlink(\n        &self,\n        cx: &Cx,\n        parent: InodeNumber,\n        name: &[u8],\n        target: &Path,\n        uid: u32,\n        gid: u32,\n    ) -> ffs_error::Result<InodeAttr> {",
    "fn ext4_symlink(\n        &self,\n        cx: &Cx,\n        scope: &mut RequestScope,\n        parent: InodeNumber,\n        name: &[u8],\n        target: &Path,\n        uid: u32,\n        gid: u32,\n    ) -> ffs_error::Result<InodeAttr> {"
)

lib_rs = lib_rs.replace(
    "fn ext4_link(\n        &self,\n        cx: &Cx,\n        ino: InodeNumber,\n        new_parent: InodeNumber,\n        new_name: &[u8],\n    ) -> ffs_error::Result<InodeAttr> {",
    "fn ext4_link(\n        &self,\n        cx: &Cx,\n        scope: &mut RequestScope,\n        ino: InodeNumber,\n        new_parent: InodeNumber,\n        new_name: &[u8],\n    ) -> ffs_error::Result<InodeAttr> {"
)

lib_rs = lib_rs.replace(
    "fn ext4_rename(\n        &self,\n        cx: &Cx,\n        parent: InodeNumber,\n        name: &[u8],\n        new_parent: InodeNumber,\n        new_name: &[u8],\n    ) -> ffs_error::Result<()> {",
    "fn ext4_rename(\n        &self,\n        cx: &Cx,\n        scope: &mut RequestScope,\n        parent: InodeNumber,\n        name: &[u8],\n        new_parent: InodeNumber,\n        new_name: &[u8],\n    ) -> ffs_error::Result<()> {"
)

lib_rs = lib_rs.replace(
    "fn ext4_unlink(\n        &self,\n        cx: &Cx,\n        parent: InodeNumber,\n        name: &[u8],\n    ) -> ffs_error::Result<()> {",
    "fn ext4_unlink(\n        &self,\n        cx: &Cx,\n        scope: &mut RequestScope,\n        parent: InodeNumber,\n        name: &[u8],\n    ) -> ffs_error::Result<()> {"
)

lib_rs = lib_rs.replace(
    "fn ext4_rmdir(\n        &self,\n        cx: &Cx,\n        parent: InodeNumber,\n        name: &[u8],\n    ) -> ffs_error::Result<()> {",
    "fn ext4_rmdir(\n        &self,\n        cx: &Cx,\n        scope: &mut RequestScope,\n        parent: InodeNumber,\n        name: &[u8],\n    ) -> ffs_error::Result<()> {"
)

lib_rs = lib_rs.replace(
    "fn ext4_fallocate(\n        &self,\n        cx: &Cx,\n        ino: InodeNumber,\n        offset: u64,\n        length: u64,\n        mode: i32,\n    ) -> ffs_error::Result<()> {",
    "fn ext4_fallocate(\n        &self,\n        cx: &Cx,\n        scope: &mut RequestScope,\n        ino: InodeNumber,\n        offset: u64,\n        length: u64,\n        mode: i32,\n    ) -> ffs_error::Result<()> {"
)

lib_rs = lib_rs.replace(
    "fn ext4_add_dir_entry(\n        &self,\n        cx: &Cx,\n        block_dev: &dyn BlockDevice,\n        alloc: &mut Ext4AllocState,\n        parent: InodeNumber,",
    "fn ext4_add_dir_entry(\n        &self,\n        cx: &Cx,\n        scope: &mut RequestScope,\n        block_dev: &dyn BlockDevice,\n        alloc: &mut Ext4AllocState,\n        parent: InodeNumber,"
)

lib_rs = lib_rs.replace(
    "fn ext4_remove_dir_entry(\n        &self,\n        cx: &Cx,\n        block_dev: &dyn BlockDevice,\n        parent: InodeNumber,",
    "fn ext4_remove_dir_entry(\n        &self,\n        cx: &Cx,\n        scope: &mut RequestScope,\n        block_dev: &dyn BlockDevice,\n        parent: InodeNumber,"
)

# Fix lib.rs FsOps implementations
lib_rs = lib_rs.replace(
    "fn create(\n        &self,\n        cx: &Cx,\n        _scope: &mut RequestScope,",
    "fn create(\n        &self,\n        cx: &Cx,\n        scope: &mut RequestScope,"
)
lib_rs = lib_rs.replace(
    "self.ext4_create(\n                    cx,\n                    Self::ext4_canonical_inode(parent),\n                    name.as_encoded_bytes(),\n                    mode,\n                    uid,\n                    gid,\n                )",
    "self.ext4_create(\n                    cx,\n                    scope,\n                    Self::ext4_canonical_inode(parent),\n                    name.as_encoded_bytes(),\n                    mode,\n                    uid,\n                    gid,\n                )"
)

lib_rs = lib_rs.replace(
    "fn mkdir(\n        &self,\n        cx: &Cx,\n        _scope: &mut RequestScope,",
    "fn mkdir(\n        &self,\n        cx: &Cx,\n        scope: &mut RequestScope,"
)
lib_rs = lib_rs.replace(
    "self.ext4_mkdir(\n                    cx,\n                    Self::ext4_canonical_inode(parent),\n                    name.as_encoded_bytes(),\n                    mode,\n                    uid,\n                    gid,\n                )",
    "self.ext4_mkdir(\n                    cx,\n                    scope,\n                    Self::ext4_canonical_inode(parent),\n                    name.as_encoded_bytes(),\n                    mode,\n                    uid,\n                    gid,\n                )"
)

lib_rs = lib_rs.replace(
    "fn symlink(\n        &self,\n        cx: &Cx,\n        _scope: &mut RequestScope,",
    "fn symlink(\n        &self,\n        cx: &Cx,\n        scope: &mut RequestScope,"
)
lib_rs = lib_rs.replace(
    "self.ext4_symlink(\n                    cx,\n                    Self::ext4_canonical_inode(parent),\n                    name.as_encoded_bytes(),\n                    target,\n                    uid,\n                    gid,\n                )",
    "self.ext4_symlink(\n                    cx,\n                    scope,\n                    Self::ext4_canonical_inode(parent),\n                    name.as_encoded_bytes(),\n                    target,\n                    uid,\n                    gid,\n                )"
)

lib_rs = lib_rs.replace(
    "fn link(\n        &self,\n        cx: &Cx,\n        _scope: &mut RequestScope,",
    "fn link(\n        &self,\n        cx: &Cx,\n        scope: &mut RequestScope,"
)
lib_rs = lib_rs.replace(
    "self.ext4_link(\n                    cx,\n                    Self::ext4_canonical_inode(ino),\n                    Self::ext4_canonical_inode(new_parent),\n                    new_name.as_encoded_bytes(),\n                )",
    "self.ext4_link(\n                    cx,\n                    scope,\n                    Self::ext4_canonical_inode(ino),\n                    Self::ext4_canonical_inode(new_parent),\n                    new_name.as_encoded_bytes(),\n                )"
)

lib_rs = lib_rs.replace(
    "fn rename(\n        &self,\n        cx: &Cx,\n        _scope: &mut RequestScope,",
    "fn rename(\n        &self,\n        cx: &Cx,\n        scope: &mut RequestScope,"
)
lib_rs = lib_rs.replace(
    "self.ext4_rename(\n                    cx,\n                    Self::ext4_canonical_inode(parent),\n                    name.as_encoded_bytes(),\n                    Self::ext4_canonical_inode(new_parent),\n                    new_name.as_encoded_bytes(),\n                )",
    "self.ext4_rename(\n                    cx,\n                    scope,\n                    Self::ext4_canonical_inode(parent),\n                    name.as_encoded_bytes(),\n                    Self::ext4_canonical_inode(new_parent),\n                    new_name.as_encoded_bytes(),\n                )"
)

lib_rs = lib_rs.replace(
    "fn unlink(\n        &self,\n        cx: &Cx,\n        _scope: &mut RequestScope,",
    "fn unlink(\n        &self,\n        cx: &Cx,\n        scope: &mut RequestScope,"
)
lib_rs = lib_rs.replace(
    "self.ext4_unlink(cx, Self::ext4_canonical_inode(parent), name.as_encoded_bytes())",
    "self.ext4_unlink(cx, scope, Self::ext4_canonical_inode(parent), name.as_encoded_bytes())"
)

lib_rs = lib_rs.replace(
    "fn rmdir(\n        &self,\n        cx: &Cx,\n        _scope: &mut RequestScope,",
    "fn rmdir(\n        &self,\n        cx: &Cx,\n        scope: &mut RequestScope,"
)
lib_rs = lib_rs.replace(
    "self.ext4_rmdir(cx, Self::ext4_canonical_inode(parent), name.as_encoded_bytes())",
    "self.ext4_rmdir(cx, scope, Self::ext4_canonical_inode(parent), name.as_encoded_bytes())"
)

lib_rs = lib_rs.replace(
    "fn fallocate(\n        &self,\n        cx: &Cx,\n        _scope: &mut RequestScope,",
    "fn fallocate(\n        &self,\n        cx: &Cx,\n        scope: &mut RequestScope,"
)
lib_rs = lib_rs.replace(
    "self.ext4_fallocate(cx, Self::ext4_canonical_inode(ino), offset, length, mode)",
    "self.ext4_fallocate(cx, scope, Self::ext4_canonical_inode(ino), offset, length, mode)"
)

with open('crates/ffs-core/src/vfs.rs', 'w') as f:
    f.write(vfs_rs)
with open('crates/ffs-core/src/lib.rs', 'w') as f:
    f.write(lib_rs)

print("Applied replacements")
