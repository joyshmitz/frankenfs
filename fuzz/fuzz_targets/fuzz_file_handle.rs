#![no_main]

use ffs_core::file_handle::{self, decode as parse_file_handle, HandleError};
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

fn assert_contract_failure(message: String) {
    assert!(message.is_empty(), "{message}");
}

fn assert_bad_length(data: &[u8]) {
    let err = match parse_file_handle(data) {
        Err(err) => err,
        Ok(decoded) => {
            assert_contract_failure(format!("wrong-length handle decoded as {decoded:?}"));
            return;
        }
    };
    assert_eq!(
        err,
        HandleError::BadLength {
            actual: data.len(),
            expected: file_handle::FILE_HANDLE_LEN,
        },
        "wrong-length handles must fail deterministically"
    );
    assert_eq!(err.to_errno(), libc::EINVAL);
    let ffs_error: ffs_error::FfsError = err.into();
    assert_eq!(ffs_error.to_errno(), libc::EINVAL);
}

fn assert_exact_length_parse(data: &[u8]) {
    let decoded = match parse_file_handle(data) {
        Ok(decoded) => decoded,
        Err(err) => {
            assert_contract_failure(format!("exact-length handle failed to parse: {err:?}"));
            return;
        }
    };
    let expected_ino = InodeNumber(read_u64(data, 0));
    let expected_generation = read_u32(data, 8);
    assert_eq!(decoded, (expected_ino, expected_generation));

    let encoded = file_handle::encode(decoded.0, decoded.1);
    assert_eq!(encoded.as_slice(), data);
    assert_eq!(
        parse_file_handle(&encoded),
        Ok(decoded),
        "handle serialization must round-trip arbitrary exact-length handles"
    );

    if let Err(err) = file_handle::verify(decoded.0, decoded.1, decoded.1) {
        assert_contract_failure(format!(
            "matching file-handle generation failed verification: {err:?}"
        ));
        return;
    }
    let observed = decoded.1.wrapping_add(1);
    let stale = match file_handle::verify(decoded.0, decoded.1, observed) {
        Err(stale) => stale,
        Ok(()) => {
            assert_contract_failure(format!(
                "mismatched file-handle generation verified: ino={:?} expected={} observed={}",
                decoded.0, decoded.1, observed
            ));
            return;
        }
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
        assert_exact_length_parse(data);
    } else {
        assert_bad_length(data);
    }
});
