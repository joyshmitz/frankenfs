use asupersync::Cx;
use ffs_core::{Ext4DataErrPolicy, Ext4JournalReplayMode, OpenFs, OpenOptions};
use ffs_error::FfsError;
use ffs_types::{ByteOffset, InodeNumber};
use std::ffi::OsStr;
use std::fs::File;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
struct FaultyByteDevice {
    data: Arc<Mutex<Vec<u8>>>,
    fail_writes: Arc<AtomicBool>,
}

impl FaultyByteDevice {
    fn from_vec(bytes: Vec<u8>) -> Self {
        Self {
            data: Arc::new(Mutex::new(bytes)),
            fail_writes: Arc::new(AtomicBool::new(false)),
        }
    }

    fn set_fail_writes(&self, fail: bool) {
        self.fail_writes.store(fail, Ordering::SeqCst);
    }
}

impl ffs_block::ByteDevice for FaultyByteDevice {
    fn len_bytes(&self) -> u64 {
        self.data.lock().expect("device lock poisoned").len() as u64
    }

    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> ffs_error::Result<()> {
        let off = usize::try_from(offset.0).expect("offset fits usize");
        let data = self.data.lock().expect("device lock poisoned");
        let end = off + buf.len();
        if end > data.len() {
            return Err(FfsError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "read past end",
            )));
        }
        buf.copy_from_slice(&data[off..end]);
        drop(data);
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, offset: ByteOffset, buf: &[u8]) -> ffs_error::Result<()> {
        if self.fail_writes.load(Ordering::SeqCst) {
            return Err(FfsError::Io(std::io::Error::other(
                "injected write failure",
            )));
        }
        let off = usize::try_from(offset.0).expect("offset fits usize");
        let mut data = self.data.lock().expect("device lock poisoned");
        let end = off + buf.len();
        if end > data.len() {
            return Err(FfsError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "write past end",
            )));
        }
        data[off..end].copy_from_slice(buf);
        drop(data);
        Ok(())
    }

    fn sync(&self, _cx: &Cx) -> ffs_error::Result<()> {
        Ok(())
    }
}

fn open_writable_ext4_with_policy(
    policy: Ext4DataErrPolicy,
) -> Option<(OpenFs, FaultyByteDevice, tempfile::TempDir)> {
    let tmp = tempfile::TempDir::new().expect("tmpdir");
    let image = tmp.path().join("mount-options.ext4");
    let file = File::create(&image).expect("create image");
    file.set_len(64 * 1024 * 1024).expect("size image");
    drop(file);

    let mkfs = Command::new("mkfs.ext4")
        .args(["-F", "-b", "4096", image.to_str().expect("utf8 path")])
        .output();
    match mkfs {
        Ok(output) if output.status.success() => {}
        _ => return None,
    }

    let _ = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            "set_inode_field / mode 040777",
            image.to_str().expect("utf8 path"),
        ])
        .output();

    let cx = Cx::for_testing();
    let dev = FaultyByteDevice::from_vec(std::fs::read(&image).expect("read image"));
    let snapshot = dev.clone();
    let opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::Apply,
        ext4_data_err_policy: policy,
        ..OpenOptions::default()
    };
    let mut fs = OpenFs::from_device(&cx, Box::new(dev), &opts).expect("open ext4");
    fs.enable_writes(&cx).expect("enable writes");
    Some((fs, snapshot, tmp))
}

fn create_test_file(fs: &OpenFs, cx: &Cx, name: &str) -> InodeNumber {
    fs.create(cx, InodeNumber(2), OsStr::new(name), 0o644, 0, 0)
        .expect("create file")
        .ino
}

fn assert_non_abort_policy_keeps_fs_writable(policy: Ext4DataErrPolicy) {
    let Some((fs, dev, _tmp)) = open_writable_ext4_with_policy(policy) else {
        return;
    };
    let cx = Cx::for_testing();
    let ino = create_test_file(&fs, &cx, "keep-writable.txt");
    fs.write(&cx, ino, 0, b"payload")
        .expect("initial write should stage data");

    dev.set_fail_writes(true);
    let err = fs
        .flush_mvcc_to_device(&cx)
        .expect_err("ordered writeback should see injected I/O failure");
    assert!(matches!(err, FfsError::Io(_)));
    assert!(fs.is_writable(), "{policy:?} must not force read-only");

    dev.set_fail_writes(false);
    let written = fs
        .write(&cx, ino, 0, b"retry")
        .expect("filesystem should stay writable after non-abort policy");
    assert_eq!(
        usize::try_from(written).expect("small write"),
        b"retry".len()
    );
}

#[test]
fn data_err_abort_forces_read_only_after_write_io_error() {
    let Some((fs, dev, _tmp)) = open_writable_ext4_with_policy(Ext4DataErrPolicy::Abort) else {
        return;
    };
    let cx = Cx::for_testing();
    let ino = create_test_file(&fs, &cx, "abort-policy.txt");
    fs.write(&cx, ino, 0, b"payload")
        .expect("initial write should stage data");

    dev.set_fail_writes(true);
    let err = fs
        .flush_mvcc_to_device(&cx)
        .expect_err("abort policy should surface the injected writeback failure");
    assert!(matches!(err, FfsError::Io(_)));
    assert!(!fs.is_writable(), "abort policy must remount read-only");

    dev.set_fail_writes(false);
    let retry = fs
        .write(&cx, ino, 0, b"retry")
        .expect_err("subsequent writes must be rejected after abort policy trips");
    assert!(matches!(retry, FfsError::ReadOnly));
}

#[test]
fn data_err_ignore_keeps_filesystem_writable_after_write_io_error() {
    assert_non_abort_policy_keeps_fs_writable(Ext4DataErrPolicy::Ignore);
}

#[test]
fn data_err_continue_keeps_filesystem_writable_after_write_io_error() {
    assert_non_abort_policy_keeps_fs_writable(Ext4DataErrPolicy::Continue);
}
