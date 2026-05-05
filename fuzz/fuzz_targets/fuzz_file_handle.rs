#![no_main]

use ffs_core::file_handle::{self, HandleError};
use ffs_types::InodeNumber;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 256;

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let Some(chunk) = bytes.get(offset..offset + 4) else {
        return 0;
    };
    let mut out = [0_u8; 4];
    out.copy_from_slice(chunk);
    u32::from_le_bytes(out)
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let Some(chunk) = bytes.get(offset..offset + 8) else {
        return 0;
    };
    let mut out = [0_u8; 8];
    out.copy_from_slice(chunk);
    u64::from_le_bytes(out)
}

fn assert_bad_length(data: &[u8]) {
    let result = file_handle::decode(data);
    assert_eq!(
        result,
        Err(HandleError::BadLength {
            actual: data.len(),
            expected: file_handle::FILE_HANDLE_LEN,
        }),
        "wrong-length handles must fail deterministically"
    );

    let Err(err) = result else {
        std::process::abort();
    };
    assert_eq!(err.to_errno(), libc::EINVAL);
    let ffs_error: ffs_error::FfsError = err.into();
    assert_eq!(ffs_error.to_errno(), libc::EINVAL);
}

fn assert_exact_length_decode(data: &[u8]) {
    let Ok(decoded) = file_handle::decode(data) else {
        std::process::abort();
    };
    let expected_ino = InodeNumber(read_u64(data, 0));
    let expected_generation = read_u32(data, 8);
    assert_eq!(decoded, (expected_ino, expected_generation));

    let encoded = file_handle::encode(decoded.0, decoded.1);
    assert_eq!(encoded.as_slice(), data);
    assert_eq!(
        file_handle::decode(&encoded),
        Ok(decoded),
        "encode/decode must round-trip arbitrary exact-length handles"
    );

    if file_handle::verify(decoded.0, decoded.1, decoded.1).is_err() {
        std::process::abort();
    }
    let observed = decoded.1.wrapping_add(1);
    let Err(stale) = file_handle::verify(decoded.0, decoded.1, observed) else {
        std::process::abort();
    };
    assert_eq!(stale.to_errno(), libc::ESTALE);
    assert_eq!(
        stale,
        HandleError::Stale {
            ino: decoded.0,
            expected_generation: decoded.1,
            observed_generation: observed,
        }
    );
    let ffs_error: ffs_error::FfsError = stale.into();
    assert_eq!(ffs_error.to_errno(), libc::ESTALE);
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if data.len() == file_handle::FILE_HANDLE_LEN {
        assert_exact_length_decode(data);
    } else {
        assert_bad_length(data);
    }
});
