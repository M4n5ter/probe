use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

use probe_core::{TcpConnection, TcpEndpoint};

use super::AttributionError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ProcfsTcpTableFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProcfsTcpTablePolicy {
    Required,
    OptionalBestEffort,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProcfsTcpTable {
    pub(super) family: ProcfsTcpTableFamily,
    pub(super) path: PathBuf,
    pub(super) policy: ProcfsTcpTablePolicy,
}

pub(super) fn procfs_tcp_tables(proc_root: &Path) -> [ProcfsTcpTable; 2] {
    [
        ProcfsTcpTable {
            family: ProcfsTcpTableFamily::Ipv4,
            path: proc_root.join("net/tcp"),
            policy: ProcfsTcpTablePolicy::Required,
        },
        ProcfsTcpTable {
            family: ProcfsTcpTableFamily::Ipv6,
            path: proc_root.join("net/tcp6"),
            policy: ProcfsTcpTablePolicy::OptionalBestEffort,
        },
    ]
}

pub(super) fn connection_uses_family(
    connection: TcpConnection,
    family: ProcfsTcpTableFamily,
) -> bool {
    endpoint_uses_family(connection.local, family)
        || endpoint_uses_family(connection.remote, family)
}

pub(super) fn endpoint_uses_family(endpoint: TcpEndpoint, family: ProcfsTcpTableFamily) -> bool {
    matches!(
        (endpoint.address, family),
        (IpAddr::V4(_), ProcfsTcpTableFamily::Ipv4) | (IpAddr::V6(_), ProcfsTcpTableFamily::Ipv6)
    )
}

pub(super) fn tcp_inode_map_from_table(
    table: &ProcfsTcpTable,
    content: &str,
) -> Result<HashMap<TcpConnection, u64>, AttributionError> {
    let mut inodes = HashMap::new();
    for line in content.lines().skip(1) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() <= 9 {
            continue;
        }
        let local = parse_tcp_endpoint(table, fields[1])?;
        let remote = parse_tcp_endpoint(table, fields[2])?;
        let inode = fields[9]
            .parse::<u64>()
            .map_err(|source| AttributionError::InvalidNetTcp {
                path: table.path.display().to_string(),
                reason: format!("invalid socket inode: {source}"),
            })?;
        inodes.insert(TcpConnection::new(local, remote), inode);
    }
    Ok(inodes)
}

pub(super) fn connections_by_inode(
    tcp_inodes: &HashMap<TcpConnection, u64>,
) -> HashMap<u64, Vec<TcpConnection>> {
    let mut connections = HashMap::<u64, Vec<TcpConnection>>::new();
    for (connection, inode) in tcp_inodes {
        connections.entry(*inode).or_default().push(*connection);
    }
    connections
}

fn parse_tcp_endpoint(
    table: &ProcfsTcpTable,
    value: &str,
) -> Result<TcpEndpoint, AttributionError> {
    let (address, port) = value
        .split_once(':')
        .ok_or_else(|| AttributionError::InvalidNetTcp {
            path: table.path.display().to_string(),
            reason: format!("invalid endpoint {value:?}"),
        })?;
    let address = parse_proc_net_tcp_address(table, address)?;
    let port = u16::from_str_radix(port, 16).map_err(|source| AttributionError::InvalidNetTcp {
        path: table.path.display().to_string(),
        reason: format!("invalid TCP endpoint port: {source}"),
    })?;
    Ok(TcpEndpoint::new(address, port))
}

fn parse_proc_net_tcp_address(
    table: &ProcfsTcpTable,
    address: &str,
) -> Result<IpAddr, AttributionError> {
    match table.family {
        ProcfsTcpTableFamily::Ipv4 => parse_proc_net_tcp4_address(&table.path, address),
        ProcfsTcpTableFamily::Ipv6 => parse_proc_net_tcp6_address(&table.path, address),
    }
}

fn parse_proc_net_tcp4_address(path: &Path, address: &str) -> Result<IpAddr, AttributionError> {
    if address.len() != 8 {
        return Err(AttributionError::InvalidNetTcp {
            path: path.display().to_string(),
            reason: format!("invalid IPv4 endpoint address {address:?}"),
        });
    }
    let raw_address =
        u32::from_str_radix(address, 16).map_err(|source| AttributionError::InvalidNetTcp {
            path: path.display().to_string(),
            reason: format!("invalid IPv4 endpoint address: {source}"),
        })?;
    Ok(IpAddr::V4(Ipv4Addr::from(raw_address.to_le_bytes())))
}

fn parse_proc_net_tcp6_address(path: &Path, address: &str) -> Result<IpAddr, AttributionError> {
    if address.len() != 32 {
        return Err(AttributionError::InvalidNetTcp {
            path: path.display().to_string(),
            reason: format!("invalid IPv6 endpoint address {address:?}"),
        });
    }
    let mut bytes = [0u8; 16];
    for (index, chunk) in address.as_bytes().chunks_exact(8).enumerate() {
        let chunk =
            std::str::from_utf8(chunk).map_err(|source| AttributionError::InvalidNetTcp {
                path: path.display().to_string(),
                reason: format!("invalid IPv6 endpoint address: {source}"),
            })?;
        let word =
            u32::from_str_radix(chunk, 16).map_err(|source| AttributionError::InvalidNetTcp {
                path: path.display().to_string(),
                reason: format!("invalid IPv6 endpoint address: {source}"),
            })?;
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    if bytes[..10].iter().all(|byte| *byte == 0) && bytes[10] == 0xff && bytes[11] == 0xff {
        return Ok(IpAddr::V4(Ipv4Addr::new(
            bytes[12], bytes[13], bytes[14], bytes[15],
        )));
    }
    Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
}
