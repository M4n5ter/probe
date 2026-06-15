use aya_ebpf::{helpers::bpf_probe_read_user_buf, programs::TracePointContext};
use ebpf_abi::{
    EBPF_ADDRESS_FAMILY_INET, EBPF_ADDRESS_FAMILY_INET6, EBPF_CONNECT_REMOTE_ENDPOINT_VALID,
    EBPF_CONNECT_SOCKADDR_READ_FAILED, EBPF_CONNECT_UNSUPPORTED_ADDRESS_FAMILY,
    EbpfConnectObservation,
};

const CONNECT_FD_OFFSET: usize = 16;
const CONNECT_USER_SOCKADDR_OFFSET: usize = 24;
const CONNECT_ADDRLEN_OFFSET: usize = 32;
const SOCKADDR_FAMILY_OFFSET: usize = 0;
const SOCKADDR_PORT_OFFSET: usize = 2;
const SOCKADDR_IN_ADDRESS_OFFSET: usize = 4;
const SOCKADDR_IN6_ADDRESS_OFFSET: usize = 8;
const SOCKADDR_IN_LEN: u32 = 16;
const SOCKADDR_IN6_LEN: u32 = 28;

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
    if args.user_sockaddr == 0 || args.addrlen < 2 {
        return read_failed(args);
    }

    let Some(family) = read_sockaddr_family(args.user_sockaddr) else {
        return read_failed(args);
    };

    match family {
        EBPF_ADDRESS_FAMILY_INET if args.addrlen >= SOCKADDR_IN_LEN => {
            ipv4_connect_observation(args)
        }
        EBPF_ADDRESS_FAMILY_INET6 if args.addrlen >= SOCKADDR_IN6_LEN => {
            ipv6_connect_observation(args)
        }
        EBPF_ADDRESS_FAMILY_INET | EBPF_ADDRESS_FAMILY_INET6 => read_failed(args),
        unsupported => unsupported_family(args, unsupported),
    }
}

fn read_failed(args: ConnectTracepointArgs) -> ConnectObservationResult {
    ConnectObservationResult {
        observation: EbpfConnectObservation::unavailable(args.fd, args.addrlen),
        flags: EBPF_CONNECT_SOCKADDR_READ_FAILED,
    }
}

fn unsupported_family(args: ConnectTracepointArgs, family: u16) -> ConnectObservationResult {
    ConnectObservationResult {
        observation: EbpfConnectObservation::remote_endpoint(
            args.fd,
            args.addrlen,
            family,
            0,
            [0; 16],
        ),
        flags: EBPF_CONNECT_UNSUPPORTED_ADDRESS_FAMILY,
    }
}

fn ipv4_connect_observation(args: ConnectTracepointArgs) -> ConnectObservationResult {
    let Some(sockaddr) = read_user_bytes::<16>(args.user_sockaddr) else {
        return read_failed(args);
    };
    let address = [
        sockaddr[SOCKADDR_IN_ADDRESS_OFFSET],
        sockaddr[SOCKADDR_IN_ADDRESS_OFFSET + 1],
        sockaddr[SOCKADDR_IN_ADDRESS_OFFSET + 2],
        sockaddr[SOCKADDR_IN_ADDRESS_OFFSET + 3],
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    ConnectObservationResult {
        observation: EbpfConnectObservation::remote_endpoint(
            args.fd,
            args.addrlen,
            EBPF_ADDRESS_FAMILY_INET,
            sockaddr_port(sockaddr),
            address,
        ),
        flags: EBPF_CONNECT_REMOTE_ENDPOINT_VALID,
    }
}

fn ipv6_connect_observation(args: ConnectTracepointArgs) -> ConnectObservationResult {
    let Some(sockaddr) = read_user_bytes::<28>(args.user_sockaddr) else {
        return read_failed(args);
    };
    let address = [
        sockaddr[SOCKADDR_IN6_ADDRESS_OFFSET],
        sockaddr[SOCKADDR_IN6_ADDRESS_OFFSET + 1],
        sockaddr[SOCKADDR_IN6_ADDRESS_OFFSET + 2],
        sockaddr[SOCKADDR_IN6_ADDRESS_OFFSET + 3],
        sockaddr[SOCKADDR_IN6_ADDRESS_OFFSET + 4],
        sockaddr[SOCKADDR_IN6_ADDRESS_OFFSET + 5],
        sockaddr[SOCKADDR_IN6_ADDRESS_OFFSET + 6],
        sockaddr[SOCKADDR_IN6_ADDRESS_OFFSET + 7],
        sockaddr[SOCKADDR_IN6_ADDRESS_OFFSET + 8],
        sockaddr[SOCKADDR_IN6_ADDRESS_OFFSET + 9],
        sockaddr[SOCKADDR_IN6_ADDRESS_OFFSET + 10],
        sockaddr[SOCKADDR_IN6_ADDRESS_OFFSET + 11],
        sockaddr[SOCKADDR_IN6_ADDRESS_OFFSET + 12],
        sockaddr[SOCKADDR_IN6_ADDRESS_OFFSET + 13],
        sockaddr[SOCKADDR_IN6_ADDRESS_OFFSET + 14],
        sockaddr[SOCKADDR_IN6_ADDRESS_OFFSET + 15],
    ];
    ConnectObservationResult {
        observation: EbpfConnectObservation::remote_endpoint(
            args.fd,
            args.addrlen,
            EBPF_ADDRESS_FAMILY_INET6,
            sockaddr_port(sockaddr),
            address,
        ),
        flags: EBPF_CONNECT_REMOTE_ENDPOINT_VALID,
    }
}

fn read_sockaddr_family(user_sockaddr: u64) -> Option<u16> {
    let sockaddr = read_user_bytes::<2>(user_sockaddr)?;
    Some(u16::from_ne_bytes([
        sockaddr[SOCKADDR_FAMILY_OFFSET],
        sockaddr[SOCKADDR_FAMILY_OFFSET + 1],
    ]))
}

fn read_user_bytes<const N: usize>(address: u64) -> Option<[u8; N]> {
    let mut bytes = [0; N];
    // The pointer is a userspace syscall argument; the helper validates accessibility.
    unsafe { bpf_probe_read_user_buf(address as *const u8, &mut bytes) }.ok()?;
    Some(bytes)
}

fn sockaddr_port<const N: usize>(sockaddr: [u8; N]) -> u16 {
    u16::from_be_bytes([
        sockaddr[SOCKADDR_PORT_OFFSET],
        sockaddr[SOCKADDR_PORT_OFFSET + 1],
    ])
}
