use std::fs;
use std::path::Path;

fn main() {
    let lib_rs = "crates/ffs-core/src/lib.rs";
    let mut content = fs::read_to_string(lib_rs).unwrap();

    // Fix ext4_create
    content = content.replace(
        "fn ext4_create(\n        &self,\n        cx: &Cx,\n        parent: InodeNumber,\n        name: &[u8],\n        mode: u16,\n        uid: u32,\n        gid: u32,\n    ) -> ffs_error::Result<InodeAttr> {",
        "fn ext4_create(\n        &self,\n        cx: &Cx,\n        scope: &mut RequestScope,\n        parent: InodeNumber,\n        name: &[u8],\n        mode: u16,\n        uid: u32,\n        gid: u32,\n    ) -> ffs_error::Result<InodeAttr> {"
    );

    // Fix ext4_add_dir_entry signature
    content = content.replace(
        "fn ext4_add_dir_entry(\n        &self,\n        cx: &Cx,\n        block_dev: &dyn BlockDevice,\n        alloc: &mut Ext4AllocState,\n        parent: InodeNumber,",
        "fn ext4_add_dir_entry(\n        &self,\n        cx: &Cx,\n        scope: &mut RequestScope,\n        block_dev: &dyn BlockDevice,\n        alloc: &mut Ext4AllocState,\n        parent: InodeNumber,"
    );

    // Fix ext4_remove_dir_entry signature
    content = content.replace(
        "fn ext4_remove_dir_entry(\n        &self,\n        cx: &Cx,\n        block_dev: &dyn BlockDevice,\n        parent: InodeNumber,",
        "fn ext4_remove_dir_entry(\n        &self,\n        cx: &Cx,\n        scope: &mut RequestScope,\n        block_dev: &dyn BlockDevice,\n        parent: InodeNumber,"
    );

    // Write back
    fs::write(lib_rs, content).unwrap();
    println!("Done");
}
