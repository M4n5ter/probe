use super::common::{EBPF_EVENTS_MAP_NAME, EbpfMapKind, EbpfMapSpec};
use crate::event::{
    EBPF_RING_BUFFER_BYTES, EBPF_TLS_DIRECTION_INBOUND, EBPF_TLS_DIRECTION_OUTBOUND,
    EbpfTlsPlaintextEvent,
};

pub const EBPF_TLS_CALLS_MAP_NAME: &str = "SSSA_TLS_CALLS";
pub const EBPF_TLS_FDS_MAP_NAME: &str = "SSSA_TLS_FDS";
pub const EBPF_TLS_OFFSETS_MAP_NAME: &str = "SSSA_TLS_OFFSETS";
pub const EBPF_TLS_STATE_EPOCHS_MAP_NAME: &str = "SSSA_TLS_STATE_EPOCHS";
pub const EBPF_TLS_STATE_EPOCH_KEY: u32 = 0;
pub const EBPF_TLS_EVENT_SCRATCH_MAP_NAME: &str = "SSSA_TLS_EVENT_SCRATCH";
pub const EBPF_TLS_OUTPUT_LOSSES_MAP_NAME: &str = "SSSA_TLS_OUTPUT_LOSSES";
pub const EBPF_TLS_CALLS_MAX_ENTRIES: u32 = 16_384;
pub const EBPF_TLS_FDS_MAX_ENTRIES: u32 = 65_536;
pub const EBPF_TLS_OFFSETS_MAX_ENTRIES: u32 = 131_072;
pub const EBPF_TLS_STATE_EPOCHS_MAX_ENTRIES: u32 = 1;
pub const EBPF_TLS_EVENT_SCRATCH_MAX_ENTRIES: u32 = 1;
pub const EBPF_TLS_OUTPUT_LOSSES_MAX_ENTRIES: u32 = 1;
pub const EBPF_TLS_SSL_SET_FD_PROGRAM_NAME: &str = "sssa_ssl_set_fd";
pub const EBPF_TLS_SSL_SET_FD_EXIT_PROGRAM_NAME: &str = "sssa_ssl_set_fd_exit";
pub const EBPF_TLS_SSL_CLEAR_PROGRAM_NAME: &str = "sssa_ssl_clear";
pub const EBPF_TLS_SSL_CLEAR_EXIT_PROGRAM_NAME: &str = "sssa_ssl_clear_exit";
pub const EBPF_TLS_SSL_FREE_PROGRAM_NAME: &str = "sssa_ssl_free";
pub const EBPF_TLS_SSL_READ_ENTER_PROGRAM_NAME: &str = "sssa_ssl_read_enter";
pub const EBPF_TLS_SSL_READ_EXIT_PROGRAM_NAME: &str = "sssa_ssl_read_exit";
pub const EBPF_TLS_SSL_WRITE_ENTER_PROGRAM_NAME: &str = "sssa_ssl_write_enter";
pub const EBPF_TLS_SSL_WRITE_EXIT_PROGRAM_NAME: &str = "sssa_ssl_write_exit";
pub const EBPF_TLS_SSL_READ_EX_ENTER_PROGRAM_NAME: &str = "sssa_ssl_read_ex_enter";
pub const EBPF_TLS_SSL_READ_EX_EXIT_PROGRAM_NAME: &str = "sssa_ssl_read_ex_exit";
pub const EBPF_TLS_SSL_WRITE_EX_ENTER_PROGRAM_NAME: &str = "sssa_ssl_write_ex_enter";
pub const EBPF_TLS_SSL_WRITE_EX_EXIT_PROGRAM_NAME: &str = "sssa_ssl_write_ex_exit";
pub const EBPF_TLS_CALL_KIND_LEN_RETURN: u8 = 1;
pub const EBPF_TLS_CALL_KIND_SIZE_POINTER: u8 = 2;
pub const EBPF_TLS_CALL_KIND_SET_FD: u8 = 3;
pub const EBPF_TLS_CALL_KIND_CLEAR: u8 = 4;

pub const EBPF_TLS_LIBSSL_UPROBE_SPECS: [EbpfTlsUprobeSpec; 7] = [
    EbpfTlsUprobeSpec {
        symbol: EbpfTlsLibsslSymbol::SslSetFd,
        role: EbpfTlsUprobeRole::FdAssociation,
        entry_program_name: EBPF_TLS_SSL_SET_FD_PROGRAM_NAME,
        return_program_name: Some(EBPF_TLS_SSL_SET_FD_EXIT_PROGRAM_NAME),
    },
    EbpfTlsUprobeSpec {
        symbol: EbpfTlsLibsslSymbol::SslClear,
        role: EbpfTlsUprobeRole::StateReset,
        entry_program_name: EBPF_TLS_SSL_CLEAR_PROGRAM_NAME,
        return_program_name: Some(EBPF_TLS_SSL_CLEAR_EXIT_PROGRAM_NAME),
    },
    EbpfTlsUprobeSpec {
        symbol: EbpfTlsLibsslSymbol::SslFree,
        role: EbpfTlsUprobeRole::StateCleanup,
        entry_program_name: EBPF_TLS_SSL_FREE_PROGRAM_NAME,
        return_program_name: None,
    },
    EbpfTlsUprobeSpec {
        symbol: EbpfTlsLibsslSymbol::SslRead,
        role: EbpfTlsUprobeRole::Plaintext {
            direction: EbpfTlsDirection::Inbound,
        },
        entry_program_name: EBPF_TLS_SSL_READ_ENTER_PROGRAM_NAME,
        return_program_name: Some(EBPF_TLS_SSL_READ_EXIT_PROGRAM_NAME),
    },
    EbpfTlsUprobeSpec {
        symbol: EbpfTlsLibsslSymbol::SslWrite,
        role: EbpfTlsUprobeRole::Plaintext {
            direction: EbpfTlsDirection::Outbound,
        },
        entry_program_name: EBPF_TLS_SSL_WRITE_ENTER_PROGRAM_NAME,
        return_program_name: Some(EBPF_TLS_SSL_WRITE_EXIT_PROGRAM_NAME),
    },
    EbpfTlsUprobeSpec {
        symbol: EbpfTlsLibsslSymbol::SslReadEx,
        role: EbpfTlsUprobeRole::Plaintext {
            direction: EbpfTlsDirection::Inbound,
        },
        entry_program_name: EBPF_TLS_SSL_READ_EX_ENTER_PROGRAM_NAME,
        return_program_name: Some(EBPF_TLS_SSL_READ_EX_EXIT_PROGRAM_NAME),
    },
    EbpfTlsUprobeSpec {
        symbol: EbpfTlsLibsslSymbol::SslWriteEx,
        role: EbpfTlsUprobeRole::Plaintext {
            direction: EbpfTlsDirection::Outbound,
        },
        entry_program_name: EBPF_TLS_SSL_WRITE_EX_ENTER_PROGRAM_NAME,
        return_program_name: Some(EBPF_TLS_SSL_WRITE_EX_EXIT_PROGRAM_NAME),
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfTlsUprobeSpec {
    pub symbol: EbpfTlsLibsslSymbol,
    pub role: EbpfTlsUprobeRole,
    pub entry_program_name: &'static str,
    pub return_program_name: Option<&'static str>,
}

impl EbpfTlsUprobeSpec {
    pub const fn library_symbol(self) -> &'static str {
        self.symbol.as_str()
    }

    pub const fn program_count(self) -> usize {
        if self.return_program_name.is_some() {
            2
        } else {
            1
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfTlsUprobeRole {
    Plaintext { direction: EbpfTlsDirection },
    FdAssociation,
    StateReset,
    StateCleanup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EbpfTlsLibsslSymbol {
    SslSetFd,
    SslClear,
    SslFree,
    SslRead,
    SslWrite,
    SslReadEx,
    SslWriteEx,
}

impl EbpfTlsLibsslSymbol {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SslSetFd => "SSL_set_fd",
            Self::SslClear => "SSL_clear",
            Self::SslFree => "SSL_free",
            Self::SslRead => "SSL_read",
            Self::SslWrite => "SSL_write",
            Self::SslReadEx => "SSL_read_ex",
            Self::SslWriteEx => "SSL_write_ex",
        }
    }

    pub fn spec(self) -> &'static EbpfTlsUprobeSpec {
        EBPF_TLS_LIBSSL_UPROBE_SPECS
            .iter()
            .find(|spec| spec.symbol == self)
            .expect("libssl symbol should be listed in the canonical uprobe spec table")
    }

    pub fn role(self) -> EbpfTlsUprobeRole {
        self.spec().role
    }

    pub fn entry_program_name(self) -> &'static str {
        self.spec().entry_program_name
    }

    pub fn return_program_name(self) -> Option<&'static str> {
        self.spec().return_program_name
    }

    pub fn captures_plaintext(self) -> bool {
        matches!(self.role(), EbpfTlsUprobeRole::Plaintext { .. })
    }

    pub fn from_name(name: &str) -> Option<Self> {
        let stable_name = name.split('@').next().unwrap_or(name);
        match stable_name {
            "SSL_set_fd" => Some(Self::SslSetFd),
            "SSL_clear" => Some(Self::SslClear),
            "SSL_free" => Some(Self::SslFree),
            "SSL_read" => Some(Self::SslRead),
            "SSL_write" => Some(Self::SslWrite),
            "SSL_read_ex" => Some(Self::SslReadEx),
            "SSL_write_ex" => Some(Self::SslWriteEx),
            _ => None,
        }
    }

    pub fn supported_symbols() -> impl Iterator<Item = Self> {
        EBPF_TLS_LIBSSL_UPROBE_SPECS.iter().map(|spec| spec.symbol)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfTlsDirection {
    Inbound,
    Outbound,
}

impl EbpfTlsDirection {
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::Inbound => EBPF_TLS_DIRECTION_INBOUND,
            Self::Outbound => EBPF_TLS_DIRECTION_OUTBOUND,
        }
    }

    pub const fn from_wire_value(value: u8) -> Option<Self> {
        match value {
            EBPF_TLS_DIRECTION_INBOUND => Some(Self::Inbound),
            EBPF_TLS_DIRECTION_OUTBOUND => Some(Self::Outbound),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfTlsCallKey {
    pub pid_tgid: u64,
}

impl EbpfTlsCallKey {
    pub const fn new(pid_tgid: u64) -> Self {
        Self { pid_tgid }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfTlsCallState {
    pub ssl_pointer: u64,
    pub state_epoch: u64,
    pub buffer_pointer: u64,
    pub length_pointer: u64,
    pub requested_len: u32,
    pub fd: i32,
    pub direction: u8,
    pub call_kind: u8,
    pub reserved0: u16,
}

impl EbpfTlsCallState {
    pub const fn len_return_plaintext(
        ssl_pointer: u64,
        buffer_pointer: u64,
        requested_len: u32,
        direction: EbpfTlsDirection,
    ) -> Self {
        Self::plaintext(
            ssl_pointer,
            buffer_pointer,
            0,
            requested_len,
            direction,
            EBPF_TLS_CALL_KIND_LEN_RETURN,
        )
    }

    pub const fn size_pointer_plaintext(
        ssl_pointer: u64,
        buffer_pointer: u64,
        length_pointer: u64,
        requested_len: u32,
        direction: EbpfTlsDirection,
    ) -> Self {
        Self::plaintext(
            ssl_pointer,
            buffer_pointer,
            length_pointer,
            requested_len,
            direction,
            EBPF_TLS_CALL_KIND_SIZE_POINTER,
        )
    }

    pub const fn fd_association(ssl_pointer: u64, fd: i32) -> Self {
        Self {
            ssl_pointer,
            state_epoch: 0,
            buffer_pointer: 0,
            length_pointer: 0,
            requested_len: 0,
            fd,
            direction: 0,
            call_kind: EBPF_TLS_CALL_KIND_SET_FD,
            reserved0: 0,
        }
    }

    pub const fn clear(ssl_pointer: u64) -> Self {
        Self {
            ssl_pointer,
            state_epoch: 0,
            buffer_pointer: 0,
            length_pointer: 0,
            requested_len: 0,
            fd: -1,
            direction: 0,
            call_kind: EBPF_TLS_CALL_KIND_CLEAR,
            reserved0: 0,
        }
    }

    const fn plaintext(
        ssl_pointer: u64,
        buffer_pointer: u64,
        length_pointer: u64,
        requested_len: u32,
        direction: EbpfTlsDirection,
        call_kind: u8,
    ) -> Self {
        Self {
            ssl_pointer,
            state_epoch: 0,
            buffer_pointer,
            length_pointer,
            requested_len,
            fd: -1,
            direction: direction.wire_value(),
            call_kind,
            reserved0: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfTlsFdKey {
    pub tgid: u32,
    pub reserved0: u32,
    pub state_epoch: u64,
    pub ssl_pointer: u64,
}

impl EbpfTlsFdKey {
    pub const fn new(tgid: u32, state_epoch: u64, ssl_pointer: u64) -> Self {
        Self {
            tgid,
            reserved0: 0,
            state_epoch,
            ssl_pointer,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfTlsOffsetKey {
    pub tgid: u32,
    pub direction: u8,
    pub reserved0: [u8; 3],
    pub state_epoch: u64,
    pub ssl_pointer: u64,
}

impl EbpfTlsOffsetKey {
    pub const fn new(tgid: u32, direction: u8, state_epoch: u64, ssl_pointer: u64) -> Self {
        Self {
            tgid,
            direction,
            reserved0: [0; 3],
            state_epoch,
            ssl_pointer,
        }
    }
}

pub const EBPF_TLS_MAP_SPECS: [EbpfMapSpec; 7] = [
    EbpfMapSpec {
        name: EBPF_EVENTS_MAP_NAME,
        kind: EbpfMapKind::Ringbuf,
        key_size: 0,
        value_size: 0,
        max_entries: EBPF_RING_BUFFER_BYTES,
        map_flags: 0,
    },
    EbpfMapSpec {
        name: EBPF_TLS_CALLS_MAP_NAME,
        kind: EbpfMapKind::Hash,
        key_size: size_of_u32::<EbpfTlsCallKey>(),
        value_size: size_of_u32::<EbpfTlsCallState>(),
        max_entries: EBPF_TLS_CALLS_MAX_ENTRIES,
        map_flags: 0,
    },
    EbpfMapSpec {
        name: EBPF_TLS_FDS_MAP_NAME,
        kind: EbpfMapKind::LruHash,
        key_size: size_of_u32::<EbpfTlsFdKey>(),
        value_size: size_of_u32::<i32>(),
        max_entries: EBPF_TLS_FDS_MAX_ENTRIES,
        map_flags: 0,
    },
    EbpfMapSpec {
        name: EBPF_TLS_OFFSETS_MAP_NAME,
        kind: EbpfMapKind::LruHash,
        key_size: size_of_u32::<EbpfTlsOffsetKey>(),
        value_size: size_of_u32::<u64>(),
        max_entries: EBPF_TLS_OFFSETS_MAX_ENTRIES,
        map_flags: 0,
    },
    EbpfMapSpec {
        name: EBPF_TLS_STATE_EPOCHS_MAP_NAME,
        kind: EbpfMapKind::Hash,
        key_size: size_of_u32::<u32>(),
        value_size: size_of_u32::<u64>(),
        max_entries: EBPF_TLS_STATE_EPOCHS_MAX_ENTRIES,
        map_flags: 0,
    },
    EbpfMapSpec {
        name: EBPF_TLS_EVENT_SCRATCH_MAP_NAME,
        kind: EbpfMapKind::PerCpuArray,
        key_size: size_of_u32::<u32>(),
        value_size: size_of_u32::<EbpfTlsPlaintextEvent>(),
        max_entries: EBPF_TLS_EVENT_SCRATCH_MAX_ENTRIES,
        map_flags: 0,
    },
    EbpfMapSpec {
        name: EBPF_TLS_OUTPUT_LOSSES_MAP_NAME,
        kind: EbpfMapKind::PerCpuArray,
        key_size: size_of_u32::<u32>(),
        value_size: size_of_u32::<u64>(),
        max_entries: EBPF_TLS_OUTPUT_LOSSES_MAX_ENTRIES,
        map_flags: 0,
    },
];

const fn size_of_u32<T>() -> u32 {
    core::mem::size_of::<T>() as u32
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, offset_of, size_of};
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn libssl_uprobe_specs_are_unique_and_loader_complete() {
        let mut library_symbols = BTreeSet::new();
        let mut program_names = BTreeSet::new();
        let mut program_count = 0;
        for spec in EBPF_TLS_LIBSSL_UPROBE_SPECS {
            assert!(library_symbols.insert(spec.library_symbol()));
            assert_eq!(spec.symbol.spec(), &spec);
            assert!(program_names.insert(spec.entry_program_name));
            program_count += spec.program_count();
            if let Some(program_name) = spec.return_program_name {
                assert!(program_names.insert(program_name));
            }
            if let EbpfTlsUprobeRole::Plaintext { direction } = spec.role {
                assert!(matches!(
                    direction.wire_value(),
                    EBPF_TLS_DIRECTION_INBOUND | EBPF_TLS_DIRECTION_OUTBOUND
                ));
            }
        }

        assert_eq!(program_count, 13);
        assert_eq!(
            EbpfTlsLibsslSymbol::supported_symbols().count(),
            EBPF_TLS_LIBSSL_UPROBE_SPECS.len()
        );
        assert_eq!(
            EbpfTlsLibsslSymbol::from_name("SSL_read@@OPENSSL_3.0.0"),
            Some(EbpfTlsLibsslSymbol::SslRead)
        );
    }

    #[test]
    fn tls_map_specs_are_unique_and_layout_complete() {
        let mut map_names = BTreeSet::new();
        for spec in EBPF_TLS_MAP_SPECS {
            assert!(map_names.insert(spec.name));
            assert_eq!(spec.map_flags, 0);
        }

        assert_eq!(EBPF_TLS_MAP_SPECS.len(), 7);
        assert_eq!(EBPF_TLS_STATE_EPOCH_KEY, 0);
        assert!(EBPF_TLS_MAP_SPECS.contains(&EbpfMapSpec {
            name: EBPF_TLS_CALLS_MAP_NAME,
            kind: EbpfMapKind::Hash,
            key_size: size_of_u32::<EbpfTlsCallKey>(),
            value_size: size_of_u32::<EbpfTlsCallState>(),
            max_entries: EBPF_TLS_CALLS_MAX_ENTRIES,
            map_flags: 0,
        }));
        assert!(EBPF_TLS_MAP_SPECS.contains(&EbpfMapSpec {
            name: EBPF_TLS_STATE_EPOCHS_MAP_NAME,
            kind: EbpfMapKind::Hash,
            key_size: size_of_u32::<u32>(),
            value_size: size_of_u32::<u64>(),
            max_entries: EBPF_TLS_STATE_EPOCHS_MAX_ENTRIES,
            map_flags: 0,
        }));
        assert!(EBPF_TLS_MAP_SPECS.contains(&EbpfMapSpec {
            name: EBPF_TLS_EVENT_SCRATCH_MAP_NAME,
            kind: EbpfMapKind::PerCpuArray,
            key_size: size_of_u32::<u32>(),
            value_size: size_of_u32::<EbpfTlsPlaintextEvent>(),
            max_entries: EBPF_TLS_EVENT_SCRATCH_MAX_ENTRIES,
            map_flags: 0,
        }));
        assert!(EBPF_TLS_MAP_SPECS.contains(&EbpfMapSpec {
            name: EBPF_TLS_OUTPUT_LOSSES_MAP_NAME,
            kind: EbpfMapKind::PerCpuArray,
            key_size: size_of_u32::<u32>(),
            value_size: size_of_u32::<u64>(),
            max_entries: EBPF_TLS_OUTPUT_LOSSES_MAX_ENTRIES,
            map_flags: 0,
        }));
    }

    #[test]
    fn tls_state_map_contract_layout_is_stable() {
        assert_eq!(size_of::<EbpfTlsCallKey>(), 8);
        assert_eq!(align_of::<EbpfTlsCallKey>(), 8);
        assert_eq!(size_of::<EbpfTlsCallState>(), 48);
        assert_eq!(align_of::<EbpfTlsCallState>(), 8);
        assert_eq!(offset_of!(EbpfTlsCallState, ssl_pointer), 0);
        assert_eq!(offset_of!(EbpfTlsCallState, state_epoch), 8);
        assert_eq!(offset_of!(EbpfTlsCallState, buffer_pointer), 16);
        assert_eq!(offset_of!(EbpfTlsCallState, length_pointer), 24);
        assert_eq!(offset_of!(EbpfTlsCallState, requested_len), 32);
        assert_eq!(offset_of!(EbpfTlsCallState, fd), 36);
        assert_eq!(offset_of!(EbpfTlsCallState, direction), 40);
        assert_eq!(offset_of!(EbpfTlsCallState, call_kind), 41);
        assert_eq!(offset_of!(EbpfTlsCallState, reserved0), 42);
        assert_eq!(size_of::<EbpfTlsFdKey>(), 24);
        assert_eq!(align_of::<EbpfTlsFdKey>(), 8);
        assert_eq!(offset_of!(EbpfTlsFdKey, tgid), 0);
        assert_eq!(offset_of!(EbpfTlsFdKey, reserved0), 4);
        assert_eq!(offset_of!(EbpfTlsFdKey, state_epoch), 8);
        assert_eq!(offset_of!(EbpfTlsFdKey, ssl_pointer), 16);
        assert_eq!(size_of::<i32>(), 4);
        assert_eq!(size_of::<EbpfTlsOffsetKey>(), 24);
        assert_eq!(align_of::<EbpfTlsOffsetKey>(), 8);
        assert_eq!(offset_of!(EbpfTlsOffsetKey, tgid), 0);
        assert_eq!(offset_of!(EbpfTlsOffsetKey, direction), 4);
        assert_eq!(offset_of!(EbpfTlsOffsetKey, reserved0), 5);
        assert_eq!(offset_of!(EbpfTlsOffsetKey, state_epoch), 8);
        assert_eq!(offset_of!(EbpfTlsOffsetKey, ssl_pointer), 16);
        assert_eq!(size_of::<u64>(), 8);
    }
}
