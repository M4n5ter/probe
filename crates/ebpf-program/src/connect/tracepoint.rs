use aya_ebpf::programs::TracePointContext;
use ebpf_abi::{
    EBPF_SOCKET_FLOW_REMOTE_ENDPOINT_VALID, EBPF_SOCKET_FLOW_SOCKADDR_READ_FAILED,
    EBPF_SOCKET_FLOW_UNSUPPORTED_ADDRESS_FAMILY, EbpfConnectObservation,
};

use crate::sockaddr::{SockaddrReadBounds, UserSockaddrEndpoint, read_user_sockaddr_endpoint};

const CONNECT_FD_OFFSET: usize = 16;
const CONNECT_USER_SOCKADDR_OFFSET: usize = 24;
const CONNECT_ADDRLEN_OFFSET: usize = 32;

pub(crate) struct ConnectObservationResult {
    pub observation: EbpfConnectObservation,
    pub flags: u16,
}

pub(crate) fn connect_observation_from_tracepoint(
    ctx: &TracePointContext,
) -> ConnectObservationResult {
    connect_observation(connect_tracepoint_args(ctx))
}

#[derive(Clone, Copy)]
struct ConnectTracepointArgs {
    fd: i32,
    user_sockaddr: u64,
    addrlen: u32,
}

fn connect_tracepoint_args(ctx: &TracePointContext) -> ConnectTracepointArgs {
    ConnectTracepointArgs {
        fd: tracepoint_u64(ctx, CONNECT_FD_OFFSET) as i32,
        user_sockaddr: tracepoint_u64(ctx, CONNECT_USER_SOCKADDR_OFFSET),
        addrlen: tracepoint_u64(ctx, CONNECT_ADDRLEN_OFFSET) as u32,
    }
}

fn tracepoint_u64(ctx: &TracePointContext, offset: usize) -> u64 {
    // Offsets must match tracefs sys_enter_connect format; privileged e2e validation is required.
    unsafe { ctx.read_at::<u64>(offset) }.unwrap_or_default()
}

fn connect_observation(args: ConnectTracepointArgs) -> ConnectObservationResult {
    match read_user_sockaddr_endpoint(args.user_sockaddr, SockaddrReadBounds::exact(args.addrlen)) {
        UserSockaddrEndpoint::Remote {
            addrlen,
            address_family,
            remote_port,
            remote_address,
        } => remote_endpoint(
            args.fd,
            addrlen,
            address_family,
            remote_port,
            remote_address,
        ),
        UserSockaddrEndpoint::ReadFailed { .. } => read_failed(args),
        UserSockaddrEndpoint::UnsupportedAddressFamily { address_family, .. } => {
            unsupported_family(args, address_family)
        }
    }
}

fn read_failed(args: ConnectTracepointArgs) -> ConnectObservationResult {
    ConnectObservationResult {
        observation: EbpfConnectObservation::unavailable(args.fd, args.addrlen),
        flags: EBPF_SOCKET_FLOW_SOCKADDR_READ_FAILED,
    }
}

fn unsupported_family(args: ConnectTracepointArgs, family: u16) -> ConnectObservationResult {
    remote_endpoint(args.fd, args.addrlen, family, 0, [0; 16])
        .with_flags(EBPF_SOCKET_FLOW_UNSUPPORTED_ADDRESS_FAMILY)
}

fn remote_endpoint(
    fd: i32,
    addrlen: u32,
    address_family: u16,
    remote_port: u16,
    remote_address: [u8; 16],
) -> ConnectObservationResult {
    ConnectObservationResult {
        observation: EbpfConnectObservation::remote_endpoint(
            fd,
            addrlen,
            address_family,
            remote_port,
            remote_address,
        ),
        flags: EBPF_SOCKET_FLOW_REMOTE_ENDPOINT_VALID,
    }
}

impl ConnectObservationResult {
    fn with_flags(self, flags: u16) -> Self {
        Self { flags, ..self }
    }
}
