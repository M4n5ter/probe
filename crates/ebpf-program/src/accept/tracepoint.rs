use aya_ebpf::programs::TracePointContext;
use ebpf_abi::{
    EBPF_SOCKET_FLOW_REMOTE_ENDPOINT_VALID, EBPF_SOCKET_FLOW_SOCKADDR_READ_FAILED,
    EBPF_SOCKET_FLOW_UNSUPPORTED_ADDRESS_FAMILY, EbpfAcceptObservation,
    EbpfPendingSocketAcceptAttempt,
};

use crate::{
    payload::syscall_result_from_tracepoint,
    sockaddr::{
        SockaddrReadBounds, UserSockaddrEndpoint, read_user_i32, read_user_sockaddr_endpoint,
    },
};

const ACCEPT_LISTEN_FD_OFFSET: usize = 16;
const ACCEPT_USER_SOCKADDR_OFFSET: usize = 24;
const ACCEPT_USER_ADDRLEN_OFFSET: usize = 32;
const ACCEPT_ADDRLEN_READ_FAILED: u32 = u32::MAX;

pub(crate) struct AcceptObservationResult {
    pub observation: EbpfAcceptObservation,
    pub flags: u16,
}

pub(crate) fn accept_attempt_from_tracepoint(
    ctx: &TracePointContext,
) -> Option<EbpfPendingSocketAcceptAttempt> {
    let listen_fd = tracepoint_u64(ctx, ACCEPT_LISTEN_FD_OFFSET)? as i32;
    if listen_fd < 0 {
        return None;
    }
    let user_sockaddr = tracepoint_u64(ctx, ACCEPT_USER_SOCKADDR_OFFSET)?;
    let user_addrlen = tracepoint_u64(ctx, ACCEPT_USER_ADDRLEN_OFFSET)?;
    let addrlen_capacity = read_accept_addrlen(user_addrlen).unwrap_or(ACCEPT_ADDRLEN_READ_FAILED);
    Some(EbpfPendingSocketAcceptAttempt {
        listen_fd,
        addrlen_capacity,
        user_sockaddr,
        user_addrlen,
    })
}

pub(crate) fn accept_observation_from_result(
    ctx: &TracePointContext,
    attempt: EbpfPendingSocketAcceptAttempt,
) -> Option<AcceptObservationResult> {
    Some(accept_observation(accepted_fd_from_result(ctx)?, attempt))
}

pub(crate) fn accepted_fd_from_result(ctx: &TracePointContext) -> Option<i32> {
    let accepted_fd = syscall_result_from_tracepoint(ctx)?;
    if accepted_fd < 0 || accepted_fd > i64::from(i32::MAX) {
        return None;
    }
    Some(accepted_fd as i32)
}

fn accept_observation(
    accepted_fd: i32,
    attempt: EbpfPendingSocketAcceptAttempt,
) -> AcceptObservationResult {
    let Some(reported_addrlen) = read_accept_addrlen(attempt.user_addrlen) else {
        return read_failed(accepted_fd, attempt, 0);
    };
    if attempt.user_sockaddr == 0 || attempt.user_addrlen == 0 {
        return missing_endpoint(accepted_fd, attempt, reported_addrlen);
    }
    if attempt.addrlen_capacity == ACCEPT_ADDRLEN_READ_FAILED {
        return read_failed(accepted_fd, attempt, reported_addrlen);
    }
    match read_user_sockaddr_endpoint(
        attempt.user_sockaddr,
        SockaddrReadBounds {
            readable_len: attempt.addrlen_capacity,
            reported_len: reported_addrlen,
        },
    ) {
        UserSockaddrEndpoint::Remote {
            addrlen,
            address_family,
            remote_port,
            remote_address,
        } => remote_endpoint(
            accepted_fd,
            attempt.listen_fd,
            addrlen,
            address_family,
            remote_port,
            remote_address,
        ),
        UserSockaddrEndpoint::ReadFailed { addrlen } => read_failed(accepted_fd, attempt, addrlen),
        UserSockaddrEndpoint::UnsupportedAddressFamily {
            addrlen,
            address_family,
        } => unsupported_family(accepted_fd, attempt, addrlen, address_family),
    }
}

fn read_accept_addrlen(user_addrlen: u64) -> Option<u32> {
    if user_addrlen == 0 {
        return Some(0);
    }
    let addrlen = read_user_i32(user_addrlen)?;
    (addrlen >= 0).then_some(addrlen as u32)
}

fn missing_endpoint(
    fd: i32,
    attempt: EbpfPendingSocketAcceptAttempt,
    addrlen: u32,
) -> AcceptObservationResult {
    AcceptObservationResult {
        observation: EbpfAcceptObservation::unavailable(fd, attempt.listen_fd, addrlen),
        flags: 0,
    }
}

fn read_failed(
    fd: i32,
    attempt: EbpfPendingSocketAcceptAttempt,
    addrlen: u32,
) -> AcceptObservationResult {
    AcceptObservationResult {
        observation: EbpfAcceptObservation::unavailable(fd, attempt.listen_fd, addrlen),
        flags: EBPF_SOCKET_FLOW_SOCKADDR_READ_FAILED,
    }
}

fn unsupported_family(
    fd: i32,
    attempt: EbpfPendingSocketAcceptAttempt,
    addrlen: u32,
    address_family: u16,
) -> AcceptObservationResult {
    remote_endpoint(fd, attempt.listen_fd, addrlen, address_family, 0, [0; 16])
        .with_flags(EBPF_SOCKET_FLOW_UNSUPPORTED_ADDRESS_FAMILY)
}

fn remote_endpoint(
    fd: i32,
    listen_fd: i32,
    addrlen: u32,
    address_family: u16,
    remote_port: u16,
    remote_address: [u8; 16],
) -> AcceptObservationResult {
    AcceptObservationResult {
        observation: EbpfAcceptObservation::remote_endpoint(
            fd,
            listen_fd,
            addrlen,
            address_family,
            remote_port,
            remote_address,
        ),
        flags: EBPF_SOCKET_FLOW_REMOTE_ENDPOINT_VALID,
    }
}

impl AcceptObservationResult {
    fn with_flags(self, flags: u16) -> Self {
        Self { flags, ..self }
    }
}

fn tracepoint_u64(ctx: &TracePointContext, offset: usize) -> Option<u64> {
    // Offsets must match Linux tracefs sys_enter_accept/sys_enter_accept4 format.
    unsafe { ctx.read_at::<u64>(offset) }.ok()
}
