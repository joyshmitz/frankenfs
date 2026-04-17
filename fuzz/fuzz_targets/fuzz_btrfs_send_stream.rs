#![no_main]

use ffs_btrfs::{parse_send_stream, SendCommand, BTRFS_SEND_STREAM_MAGIC};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let parsed = parse_send_stream(data);

    if data.len() >= 17 && &data[..13] == BTRFS_SEND_STREAM_MAGIC {
        let version = u32::from_le_bytes([data[13], data[14], data[15], data[16]]);
        if let Ok(result) = &parsed {
            assert_eq!(result.version, version, "parsed version should match header");

            let end_positions = result
                .commands
                .iter()
                .enumerate()
                .filter_map(|(idx, command)| (command.cmd == SendCommand::End).then_some(idx))
                .collect::<Vec<_>>();
            if let Some(end_idx) = end_positions.first().copied() {
                assert_eq!(
                    end_positions.len(),
                    1,
                    "parser should stop at the first END command"
                );
                assert_eq!(
                    end_idx + 1,
                    result.commands.len(),
                    "END command must terminate the parsed command stream"
                );
            }
        }
    }
});
