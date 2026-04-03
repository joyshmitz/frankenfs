fn main() {
    let img_path = "tests/fixtures/images/ext4_small.img";
    let dev = std::sync::Arc::new(ffs_block::FileIoEngine::open(img_path).unwrap());
    let geo = ffs_core::ext4::read_ext4_superblock(&ffs_core::Cx::for_testing(), &*dev).unwrap();
    println!("Inode size: {}", geo.inode_size);
}