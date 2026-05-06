#![no_main]

use ffs_btrfs::{
    parse_send_stream, SendAttr, SendCommand, BTRFS_SEND_STREAM_MAGIC, BTRFS_SEND_STREAM_VERSION,
};
use libfuzzer_sys::fuzz_target;

const BTRFS_SEND_CRC32C_POLY: u32 = 0x82F6_3B78;

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParseOutcome {
    Stream(StreamSig),
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StreamSig {
    version: u32,
    commands: Vec<CommandSig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandSig {
    cmd: SendCommand,
    attrs: Vec<(u16, Vec<u8>)>,
}

fn normalize_parse(data: &[u8]) -> ParseOutcome {
    match parse_send_stream(data) {
        Ok(result) => ParseOutcome::Stream(StreamSig {
            version: result.version,
            commands: result
                .commands
                .into_iter()
                .map(|command| CommandSig {
                    cmd: command.cmd,
                    attrs: command.attrs,
                })
                .collect(),
        }),
        Err(err) => ParseOutcome::Error(err.to_string()),
    }
}

fn btrfs_send_crc32c(seed: u32, data: &[u8]) -> u32 {
    let mut crc = seed;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ BTRFS_SEND_CRC32C_POLY
            };
        }
    }
    crc
}

fn append_send_attr(payload: &mut Vec<u8>, attr: SendAttr, value: &[u8]) {
    payload.extend_from_slice(&(attr as u16).to_le_bytes());
    payload.extend_from_slice(&u16::try_from(value.len()).unwrap_or(0).to_le_bytes());
    payload.extend_from_slice(value);
}

fn append_send_command(stream: &mut Vec<u8>, cmd: u16, payload: &[u8]) {
    let command_start = stream.len();
    stream.extend_from_slice(&u32::try_from(payload.len()).unwrap_or(0).to_le_bytes());
    stream.extend_from_slice(&cmd.to_le_bytes());
    stream.extend_from_slice(&0_u32.to_le_bytes());
    stream.extend_from_slice(payload);
    let crc = btrfs_send_crc32c(0, &stream[command_start..]);
    stream[command_start + 6..command_start + 10].copy_from_slice(&crc.to_le_bytes());
}

fn stream_header() -> Vec<u8> {
    let mut stream = Vec::new();
    stream.extend_from_slice(BTRFS_SEND_STREAM_MAGIC);
    stream.extend_from_slice(&BTRFS_SEND_STREAM_VERSION.to_le_bytes());
    stream
}

fn bounded_bytes(data: &[u8], offset: usize, len: usize, fallback_seed: u8) -> Vec<u8> {
    (0..len)
        .map(|idx| {
            data.get(offset.saturating_add(idx))
                .copied()
                .unwrap_or(fallback_seed.wrapping_add(u8::try_from(idx).unwrap_or(0)))
        })
        .collect()
}

fn synthetic_path(data: &[u8], offset: usize, default_suffix: &[u8]) -> Vec<u8> {
    let suffix_len = usize::from(data.get(offset).copied().unwrap_or(4) % 16);
    let mut path = Vec::from(&b"/fuzz"[..]);
    path.extend_from_slice(default_suffix);
    path.extend_from_slice(&bounded_bytes(
        data,
        offset.saturating_add(1),
        suffix_len,
        b'a',
    ));
    path
}

fn synthetic_valid_stream(data: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mkdir_path = synthetic_path(data, 0, b"/dir");
    let write_path = synthetic_path(data, 24, b"/file");
    let write_data_len = usize::from(data.get(48).copied().unwrap_or(5) % 32);
    let write_data = bounded_bytes(data, 49, write_data_len, b'w');

    let mut stream = stream_header();

    let mut mkdir_payload = Vec::new();
    append_send_attr(&mut mkdir_payload, SendAttr::Path, &mkdir_path);
    append_send_command(&mut stream, SendCommand::Mkdir as u16, &mkdir_payload);

    let mut write_payload = Vec::new();
    append_send_attr(&mut write_payload, SendAttr::Path, &write_path);
    append_send_attr(
        &mut write_payload,
        SendAttr::FileOffset,
        &0_u64.to_le_bytes(),
    );
    append_send_attr(&mut write_payload, SendAttr::Data, &write_data);
    append_send_command(&mut stream, SendCommand::Write as u16, &write_payload);

    append_send_command(&mut stream, SendCommand::End as u16, &[]);
    (stream, mkdir_path, write_path, write_data)
}

fn synthetic_unknown_stream(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let path = synthetic_path(data, 80, b"/unknown");
    let mut stream = stream_header();
    let mut payload = Vec::new();
    append_send_attr(&mut payload, SendAttr::Path, &path);
    append_send_command(&mut stream, 0xFFFE, &payload);
    append_send_command(&mut stream, SendCommand::End as u16, &[]);
    (stream, path)
}

fn synthetic_malformed_attr_len_stream(data: &[u8]) -> Vec<u8> {
    let path = synthetic_path(data, 128, b"/bad_attr_len");
    let declared_len = u16::try_from(path.len().saturating_add(1)).unwrap_or(u16::MAX);
    let mut stream = stream_header();
    let mut payload = Vec::new();
    payload.extend_from_slice(&(SendAttr::Path as u16).to_le_bytes());
    payload.extend_from_slice(&declared_len.to_le_bytes());
    payload.extend_from_slice(&path);
    append_send_command(&mut stream, SendCommand::Mkdir as u16, &payload);
    append_send_command(&mut stream, SendCommand::End as u16, &[]);
    stream
}

fn assert_success_shape(sig: &StreamSig) {
    assert_eq!(
        sig.version, BTRFS_SEND_STREAM_VERSION,
        "successful parse must expose the supported stream version"
    );
    assert!(
        !sig.commands.is_empty(),
        "successful send stream parse must include at least END"
    );

    let end_positions = sig
        .commands
        .iter()
        .enumerate()
        .filter_map(|(idx, command)| (command.cmd == SendCommand::End).then_some(idx))
        .collect::<Vec<_>>();
    assert_eq!(
        end_positions.len(),
        1,
        "successful send stream parse must contain exactly one END command"
    );
    assert_eq!(
        end_positions[0] + 1,
        sig.commands.len(),
        "END must terminate the parsed command stream"
    );

    for command in &sig.commands {
        for (_, value) in &command.attrs {
            assert!(
                value.len() <= u16::MAX as usize,
                "send attrs are length-prefixed by u16"
            );
        }
    }
}

fn assert_arbitrary_stream(data: &[u8]) {
    let parsed = normalize_parse(data);
    assert_eq!(
        parsed,
        normalize_parse(data),
        "send-stream parsing must be deterministic"
    );

    match &parsed {
        ParseOutcome::Stream(sig) => assert_success_shape(sig),
        ParseOutcome::Error(_) => {}
    }
}

fn assert_synthetic_valid_stream(data: &[u8]) {
    let (stream, mkdir_path, write_path, write_data) = synthetic_valid_stream(data);
    let parsed = parse_send_stream(&stream);
    assert!(parsed.is_ok(), "synthetic valid send stream must parse");
    let Ok(parsed) = parsed else {
        return;
    };

    assert_eq!(parsed.version, BTRFS_SEND_STREAM_VERSION);
    assert_eq!(parsed.commands.len(), 3);
    assert_eq!(parsed.commands[0].cmd, SendCommand::Mkdir);
    assert_eq!(
        parsed.commands[0].attrs,
        vec![(SendAttr::Path as u16, mkdir_path)]
    );
    assert_eq!(parsed.commands[1].cmd, SendCommand::Write);
    assert_eq!(
        parsed.commands[1].attrs,
        vec![
            (SendAttr::Path as u16, write_path),
            (SendAttr::FileOffset as u16, 0_u64.to_le_bytes().to_vec()),
            (SendAttr::Data as u16, write_data),
        ]
    );
    assert_eq!(parsed.commands[2].cmd, SendCommand::End);
    assert!(parsed.commands[2].attrs.is_empty());
}

fn assert_synthetic_unknown_command(data: &[u8]) {
    let (stream, path) = synthetic_unknown_stream(data);
    let parsed = parse_send_stream(&stream);
    assert!(
        parsed.is_ok(),
        "synthetic unknown-command send stream must parse"
    );
    let Ok(parsed) = parsed else {
        return;
    };

    assert_eq!(parsed.commands.len(), 2);
    assert_eq!(parsed.commands[0].cmd, SendCommand::Unspec);
    assert_eq!(
        parsed.commands[0].attrs,
        vec![(SendAttr::Path as u16, path)]
    );
    assert_eq!(parsed.commands[1].cmd, SendCommand::End);
}

fn assert_synthetic_prefix_rejections(data: &[u8]) {
    let (valid_stream, _, _, _) = synthetic_valid_stream(data);
    let cut = usize::from(data.get(127).copied().unwrap_or(0)) % valid_stream.len();
    assert!(
        matches!(
            normalize_parse(&valid_stream[..cut]),
            ParseOutcome::Error(_)
        ),
        "every proper prefix of a synthetic valid send stream must reject"
    );
}

fn assert_synthetic_rejections(data: &[u8]) {
    let (valid_stream, _, _, _) = synthetic_valid_stream(data);

    let mut crc_mismatch = valid_stream.clone();
    crc_mismatch[23] ^= 0x01;
    assert!(
        matches!(normalize_parse(&crc_mismatch), ParseOutcome::Error(_)),
        "send stream command CRC mismatch must reject"
    );

    let mut unsupported_version = valid_stream.clone();
    unsupported_version[13..17]
        .copy_from_slice(&BTRFS_SEND_STREAM_VERSION.saturating_add(1).to_le_bytes());
    assert!(
        matches!(
            normalize_parse(&unsupported_version),
            ParseOutcome::Error(_)
        ),
        "unsupported send stream version must reject before command decode"
    );

    let mut trailing_after_end = valid_stream;
    trailing_after_end.extend_from_slice(&bounded_bytes(data, 96, 3, b't'));
    assert!(
        matches!(normalize_parse(&trailing_after_end), ParseOutcome::Error(_)),
        "bytes after END must reject instead of being ignored"
    );

    let mut missing_end = stream_header();
    let mut payload = Vec::new();
    let path = synthetic_path(data, 112, b"/unterminated");
    append_send_attr(&mut payload, SendAttr::Path, &path);
    append_send_command(&mut missing_end, SendCommand::Mkdir as u16, &payload);
    assert!(
        matches!(normalize_parse(&missing_end), ParseOutcome::Error(_)),
        "streams without END must reject"
    );

    assert!(
        matches!(
            normalize_parse(&synthetic_malformed_attr_len_stream(data)),
            ParseOutcome::Error(_)
        ),
        "attribute payload length mismatches must reject even with a valid command CRC"
    );
}

fuzz_target!(|data: &[u8]| {
    assert_arbitrary_stream(data);
    assert_synthetic_valid_stream(data);
    assert_synthetic_unknown_command(data);
    assert_synthetic_prefix_rejections(data);
    assert_synthetic_rejections(data);
});
