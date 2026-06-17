use aya_ebpf::helpers::bpf_probe_read_user_buf;
use ebpf_abi::{EBPF_ADDRESS_FAMILY_INET, EBPF_ADDRESS_FAMILY_INET6};

const SOCKADDR_FAMILY_OFFSET: usize = 0;
const SOCKADDR_PORT_OFFSET: usize = 2;
const SOCKADDR_IN_ADDRESS_OFFSET: usize = 4;
const SOCKADDR_IN6_ADDRESS_OFFSET: usize = 8;
const SOCKADDR_IN_LEN: u32 = 16;
const SOCKADDR_IN6_LEN: u32 = 28;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserSockaddrEndpoint {
    Remote {
        addrlen: u32,
        address_family: u16,
        remote_port: u16,
        remote_address: [u8; 16],
    },
    ReadFailed {
        addrlen: u32,
    },
    UnsupportedAddressFamily {
        addrlen: u32,
        address_family: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SockaddrReadBounds {
    pub readable_len: u32,
    pub reported_len: u32,
}

impl SockaddrReadBounds {
    pub(crate) const fn exact(addrlen: u32) -> Self {
        Self {
            readable_len: addrlen,
            reported_len: addrlen,
        }
    }
}

pub(crate) fn read_user_sockaddr_endpoint(
    user_sockaddr: u64,
    bounds: SockaddrReadBounds,
) -> UserSockaddrEndpoint {
    if user_sockaddr == 0 || bounds.readable_len < 2 {
        return UserSockaddrEndpoint::ReadFailed {
            addrlen: bounds.reported_len,
        };
    }

    let Some(family) = read_sockaddr_family(user_sockaddr) else {
        return UserSockaddrEndpoint::ReadFailed {
            addrlen: bounds.reported_len,
        };
    };

    match family {
        EBPF_ADDRESS_FAMILY_INET if bounds.readable_len >= SOCKADDR_IN_LEN => {
            ipv4_sockaddr_endpoint(user_sockaddr, bounds.reported_len)
        }
        EBPF_ADDRESS_FAMILY_INET6 if bounds.readable_len >= SOCKADDR_IN6_LEN => {
            ipv6_sockaddr_endpoint(user_sockaddr, bounds.reported_len)
        }
        EBPF_ADDRESS_FAMILY_INET | EBPF_ADDRESS_FAMILY_INET6 => UserSockaddrEndpoint::ReadFailed {
            addrlen: bounds.reported_len,
        },
        unsupported => UserSockaddrEndpoint::UnsupportedAddressFamily {
            addrlen: bounds.reported_len,
            address_family: unsupported,
        },
    }
}

pub(crate) fn read_user_i32(address: u64) -> Option<i32> {
    let bytes = read_user_bytes::<4>(address)?;
    Some(i32::from_ne_bytes(bytes))
}

fn ipv4_sockaddr_endpoint(user_sockaddr: u64, addrlen: u32) -> UserSockaddrEndpoint {
    let Some(sockaddr) = read_user_bytes::<16>(user_sockaddr) else {
        return UserSockaddrEndpoint::ReadFailed { addrlen };
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
    UserSockaddrEndpoint::Remote {
        addrlen,
        address_family: EBPF_ADDRESS_FAMILY_INET,
        remote_port: sockaddr_port(sockaddr),
        remote_address: address,
    }
}

fn ipv6_sockaddr_endpoint(user_sockaddr: u64, addrlen: u32) -> UserSockaddrEndpoint {
    let Some(sockaddr) = read_user_bytes::<28>(user_sockaddr) else {
        return UserSockaddrEndpoint::ReadFailed { addrlen };
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
    UserSockaddrEndpoint::Remote {
        addrlen,
        address_family: EBPF_ADDRESS_FAMILY_INET6,
        remote_port: sockaddr_port(sockaddr),
        remote_address: address,
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
