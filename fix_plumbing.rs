use std::fs;

fn main() {
    let mut vfs = fs::read_to_string("crates/ffs-core/src/vfs.rs").unwrap();
    vfs = vfs.replace(
        "_scope: &mut RequestScope,\n        parent: InodeNumber,",
        "scope: &mut RequestScope,\n        parent: InodeNumber,",
    );
    vfs = vfs.replace(
        "_scope: &mut RequestScope,\n        ino: InodeNumber,\n        offset:",
        "scope: &mut RequestScope,\n        ino: InodeNumber,\n        offset:",
    );
    
    // Fix create
    vfs = vfs.replace(
        "self.ext4_create(\n                    cx,\n                    Self::ext4_canonical_inode(parent),\n                    name.as_encoded_bytes(),\n                    mode,\n                    uid,\n                    gid,\n                )",
        "self.ext4_create(\n                    cx,\n                    scope,\n                    Self::ext4_canonical_inode(parent),\n                    name.as_encoded_bytes(),\n                    mode,\n                    uid,\n                    gid,\n                )"
    );
    
    // Fix mkdir
    vfs = vfs.replace(
        "self.ext4_mkdir(\n                    cx,\n                    Self::ext4_canonical_inode(parent),\n                    name.as_encoded_bytes(),\n                    mode,\n                    uid,\n                    gid,\n                )",
        "self.ext4_mkdir(\n                    cx,\n                    scope,\n                    Self::ext4_canonical_inode(parent),\n                    name.as_encoded_bytes(),\n                    mode,\n                    uid,\n                    gid,\n                )"
    );

    // Fix symlink
    vfs = vfs.replace(
        "self.ext4_symlink(\n                    cx,\n                    Self::ext4_canonical_inode(parent),\n                    name.as_encoded_bytes(),\n                    target,\n                    uid,\n                    gid,\n                )",
        "self.ext4_symlink(\n                    cx,\n                    scope,\n                    Self::ext4_canonical_inode(parent),\n                    name.as_encoded_bytes(),\n                    target,\n                    uid,\n                    gid,\n                )"
    );

    // Fix link
    vfs = vfs.replace(
        "self.ext4_link(\n                    cx,\n                    Self::ext4_canonical_inode(ino),\n                    Self::ext4_canonical_inode(new_parent),\n                    new_name.as_encoded_bytes(),\n                )",
        "self.ext4_link(\n                    cx,\n                    scope,\n                    Self::ext4_canonical_inode(ino),\n                    Self::ext4_canonical_inode(new_parent),\n                    new_name.as_encoded_bytes(),\n                )"
    );

    // Fix rename
    vfs = vfs.replace(
        "self.ext4_rename(\n                    cx,\n                    Self::ext4_canonical_inode(parent),\n                    name.as_encoded_bytes(),\n                    Self::ext4_canonical_inode(new_parent),\n                    new_name.as_encoded_bytes(),\n                )",
        "self.ext4_rename(\n                    cx,\n                    scope,\n                    Self::ext4_canonical_inode(parent),\n                    name.as_encoded_bytes(),\n                    Self::ext4_canonical_inode(new_parent),\n                    new_name.as_encoded_bytes(),\n                )"
    );

    // Fix unlink
    vfs = vfs.replace(
        "self.ext4_unlink(cx, Self::ext4_canonical_inode(parent), name.as_encoded_bytes())",
        "self.ext4_unlink(cx, scope, Self::ext4_canonical_inode(parent), name.as_encoded_bytes())"
    );

    // Fix rmdir
    vfs = vfs.replace(
        "self.ext4_rmdir(cx, Self::ext4_canonical_inode(parent), name.as_encoded_bytes())",
        "self.ext4_rmdir(cx, scope, Self::ext4_canonical_inode(parent), name.as_encoded_bytes())"
    );

    // Fix fallocate
    vfs = vfs.replace(
        "self.ext4_fallocate(cx, Self::ext4_canonical_inode(ino), offset, length, mode)",
        "self.ext4_fallocate(cx, scope, Self::ext4_canonical_inode(ino), offset, length, mode)"
    );

    fs::write("crates/ffs-core/src/vfs.rs", vfs).unwrap();
    println!("Updated vfs.rs");
}
