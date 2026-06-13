use bytes::Bytes;
use ebpf_abi::{
    EBPF_TLS_DIRECTION_INBOUND, EBPF_TLS_DIRECTION_OUTBOUND, EBPF_TLS_PLAINTEXT_FD_VALID,
    EBPF_TLS_PLAINTEXT_READ_FAILED, EBPF_TLS_PLAINTEXT_SAMPLE_BYTES, EBPF_TLS_PLAINTEXT_TRUNCATED,
    EbpfTlsPlaintextEvent,
};
use probe_core::Direction;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::tls::plaintext) struct LibsslUprobePlaintextSample {
    pub(super) pid: u32,
    pub(super) tgid: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) command: [u8; 16],
    pub(super) ssl_pointer: u64,
    pub(super) fd: Option<i32>,
    pub(super) direction: Direction,
    pub(super) stream_offset: u64,
    pub(super) original_len: u32,
    pub(super) captured_bytes: Bytes,
    pub(super) truncated: bool,
    pub(super) read_failed: bool,
}

impl LibsslUprobePlaintextSample {
    pub(in crate::tls::plaintext) fn from_ebpf_event(
        event: &EbpfTlsPlaintextEvent,
    ) -> Result<Self, LibsslUprobePlaintextSampleError> {
        let observation = event.observation();
        let captured_len = usize::from(observation.captured_len);
        if captured_len > EBPF_TLS_PLAINTEXT_SAMPLE_BYTES {
            return Err(
                LibsslUprobePlaintextSampleError::CapturedLengthExceedsCapacity {
                    captured: observation.captured_len,
                    capacity: EBPF_TLS_PLAINTEXT_SAMPLE_BYTES,
                },
            );
        }
        if u32::from(observation.captured_len) > observation.original_len {
            return Err(
                LibsslUprobePlaintextSampleError::CapturedLengthExceedsOriginal {
                    captured: observation.captured_len,
                    original: observation.original_len,
                },
            );
        }
        if event.flags() & EBPF_TLS_PLAINTEXT_READ_FAILED != 0 && observation.captured_len > 0 {
            return Err(
                LibsslUprobePlaintextSampleError::ReadFailedWithCapturedBytes {
                    captured: observation.captured_len,
                },
            );
        }
        let direction = direction_from_wire(observation.direction)?;
        let header = event.header();
        Ok(Self {
            pid: header.pid,
            tgid: header.tgid,
            uid: header.uid,
            gid: header.gid,
            command: event.command(),
            ssl_pointer: observation.ssl_pointer,
            fd: fd_from_event(event),
            direction,
            stream_offset: observation.stream_offset,
            original_len: observation.original_len,
            captured_bytes: Bytes::copy_from_slice(&observation.payload[..captured_len]),
            truncated: event.flags() & EBPF_TLS_PLAINTEXT_TRUNCATED != 0,
            read_failed: event.flags() & EBPF_TLS_PLAINTEXT_READ_FAILED != 0,
        })
    }

    pub(super) fn command_lossy(&self) -> String {
        let len = self
            .command
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(self.command.len());
        String::from_utf8_lossy(&self.command[..len]).into_owned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(in crate::tls::plaintext) enum LibsslUprobePlaintextSampleError {
    #[error("invalid libssl plaintext direction {value}")]
    InvalidDirection { value: u8 },
    #[error("captured TLS plaintext length {captured} exceeds record capacity {capacity}")]
    CapturedLengthExceedsCapacity { captured: u16, capacity: usize },
    #[error("captured TLS plaintext length {captured} exceeds original length {original}")]
    CapturedLengthExceedsOriginal { captured: u16, original: u32 },
    #[error("read-failed TLS plaintext record carries {captured} captured byte(s)")]
    ReadFailedWithCapturedBytes { captured: u16 },
}

fn direction_from_wire(value: u8) -> Result<Direction, LibsslUprobePlaintextSampleError> {
    match value {
        EBPF_TLS_DIRECTION_INBOUND => Ok(Direction::Inbound),
        EBPF_TLS_DIRECTION_OUTBOUND => Ok(Direction::Outbound),
        value => Err(LibsslUprobePlaintextSampleError::InvalidDirection { value }),
    }
}

fn fd_from_event(event: &EbpfTlsPlaintextEvent) -> Option<i32> {
    (event.flags() & EBPF_TLS_PLAINTEXT_FD_VALID != 0).then_some(event.observation().fd)
}

#[cfg(test)]
mod tests {
    use ebpf_abi::{
        EBPF_TLS_DIRECTION_OUTBOUND, EBPF_TLS_PLAINTEXT_EVENT_BYTES, EbpfTlsPlaintextObservation,
        encode_tls_plaintext_event,
    };

    use super::*;

    #[test]
    fn sample_decodes_from_valid_ebpf_plaintext_event() -> Result<(), Box<dyn std::error::Error>> {
        let event = sample_event(5, 5, EBPF_TLS_PLAINTEXT_FD_VALID);

        let sample = LibsslUprobePlaintextSample::from_ebpf_event(&event)?;

        assert_eq!(sample.pid, 11);
        assert_eq!(sample.tgid, 22);
        assert_eq!(sample.uid, 33);
        assert_eq!(sample.gid, 44);
        assert_eq!(sample.command_lossy(), "curl");
        assert_eq!(sample.ssl_pointer, 0xfeed);
        assert_eq!(sample.fd, Some(7));
        assert_eq!(sample.direction, Direction::Outbound);
        assert_eq!(sample.stream_offset, 100);
        assert_eq!(sample.original_len, 5);
        assert_eq!(sample.captured_bytes.as_ref(), b"GET /");
        assert!(!sample.truncated);
        assert!(!sample.read_failed);
        assert_eq!(
            encode_tls_plaintext_event(&event).len(),
            EBPF_TLS_PLAINTEXT_EVENT_BYTES
        );
        Ok(())
    }

    #[test]
    fn sample_rejects_read_failed_event_with_payload() {
        let error = LibsslUprobePlaintextSample::from_ebpf_event(&sample_event(
            5,
            5,
            EBPF_TLS_PLAINTEXT_READ_FAILED,
        ))
        .expect_err("read-failed sample must not carry plaintext bytes");

        assert_eq!(
            error,
            LibsslUprobePlaintextSampleError::ReadFailedWithCapturedBytes { captured: 5 }
        );
    }

    fn sample_event(captured_len: u16, original_len: u32, flags: u16) -> EbpfTlsPlaintextEvent {
        let mut payload = [0; EBPF_TLS_PLAINTEXT_SAMPLE_BYTES];
        payload[..5].copy_from_slice(b"GET /");
        EbpfTlsPlaintextEvent::libssl_plaintext_sampled(
            11,
            22,
            33,
            44,
            nul_padded_command("curl"),
            EbpfTlsPlaintextObservation::new(
                0xfeed,
                7,
                EBPF_TLS_DIRECTION_OUTBOUND,
                100,
                original_len,
                captured_len,
                payload,
            ),
            flags,
        )
    }

    fn nul_padded_command(command: &str) -> [u8; 16] {
        let mut bytes = [0; 16];
        for (target, source) in bytes.iter_mut().zip(command.as_bytes()) {
            *target = *source;
        }
        bytes
    }
}
