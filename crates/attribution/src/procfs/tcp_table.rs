use std::{
    collections::{HashMap, HashSet},
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ProcfsTcpListenerEntry {
    pub(super) local: TcpEndpoint,
    pub(super) inode: u64,
    pub(super) namespace: Option<String>,
}

const TCP_LISTEN_STATE_VALUE: u8 = 0x0A;
const TCP_MIN_STATE_VALUE: u8 = 0x01;
const TCP_MAX_STATE_VALUE: u8 = 0x0C;

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

pub(super) fn tcp_entries_from_table(
    table: &ProcfsTcpTable,
    content: &str,
) -> Result<Vec<ProcfsTcpEntry>, AttributionError> {
    parse_tcp_entries(table, content)
}

pub(super) fn tcp_inode_map_from_entries(
    entries: &[ProcfsTcpEntry],
) -> HashMap<TcpConnection, u64> {
    let mut inodes = HashMap::new();
    for entry in entries {
        inodes.insert(TcpConnection::new(entry.local, entry.remote), entry.inode);
    }
    inodes
}

pub(super) fn tcp_listener_entries_from_entries(
    entries: &[ProcfsTcpEntry],
) -> Vec<ProcfsTcpListenerEntry> {
    tcp_listener_entries_from_entries_with_namespace(entries, None)
}

pub(super) fn tcp_listener_entries_from_entries_with_namespace(
    entries: &[ProcfsTcpEntry],
    namespace: Option<String>,
) -> Vec<ProcfsTcpListenerEntry> {
    entries
        .iter()
        .filter_map(|entry| {
            entry.is_listener.then_some(ProcfsTcpListenerEntry {
                local: entry.local,
                inode: entry.inode,
                namespace: namespace.clone(),
            })
        })
        .collect()
}

pub(super) fn tcp_local_addresses_from_entries(entries: &[ProcfsTcpEntry]) -> HashSet<IpAddr> {
    entries
        .iter()
        .map(|entry| entry.local.address)
        .filter(|address| !address.is_unspecified())
        .collect()
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProcfsTcpEntry {
    local: TcpEndpoint,
    remote: TcpEndpoint,
    is_listener: bool,
    inode: u64,
}

fn parse_tcp_entries(
    table: &ProcfsTcpTable,
    content: &str,
) -> Result<Vec<ProcfsTcpEntry>, AttributionError> {
    let mut entries = Vec::new();
    for line in content.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() <= 9 {
            return Err(AttributionError::InvalidNetTcp {
                path: table.path.display().to_string(),
                reason: format!("expected at least 10 fields, got {}", fields.len()),
            });
        }
        let local = parse_tcp_endpoint(table, fields[1])?;
        let remote = parse_tcp_endpoint(table, fields[2])?;
        let is_listener = parse_tcp_state(table, fields[3])? == TCP_LISTEN_STATE_VALUE;
        let inode = fields[9]
            .parse::<u64>()
            .map_err(|source| AttributionError::InvalidNetTcp {
                path: table.path.display().to_string(),
                reason: format!("invalid socket inode: {source}"),
            })?;
        entries.push(ProcfsTcpEntry {
            local,
            remote,
            is_listener,
            inode,
        });
    }
    Ok(entries)
}

fn parse_tcp_state(table: &ProcfsTcpTable, state: &str) -> Result<u8, AttributionError> {
    if state.len() != 2 {
        return Err(AttributionError::InvalidNetTcp {
            path: table.path.display().to_string(),
            reason: format!("invalid TCP state {state:?}"),
        });
    }
    let state =
        u8::from_str_radix(state, 16).map_err(|source| AttributionError::InvalidNetTcp {
            path: table.path.display().to_string(),
            reason: format!("invalid TCP state: {source}"),
        })?;
    if !(TCP_MIN_STATE_VALUE..=TCP_MAX_STATE_VALUE).contains(&state) {
        return Err(AttributionError::InvalidNetTcp {
            path: table.path.display().to_string(),
            reason: format!("unsupported TCP state 0x{state:02X}"),
        });
    }
    Ok(state)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_table_parser_rejects_short_data_rows() {
        let error = tcp_entries_from_table(&ipv4_table(), "header\n   0: 0100007F:20FB\n")
            .expect_err("short tcp row must fail closed");

        assert!(matches!(
            error,
            AttributionError::InvalidNetTcp { reason, .. }
                if reason.contains("expected at least 10 fields")
        ));
    }

    #[test]
    fn tcp_table_parser_rejects_invalid_state() {
        let error = tcp_entries_from_table(
            &ipv4_table(),
            "header\n   0: 0100007F:20FB 00000000:0000 ZZ 00000000:00000000 00:00000000 00000000 1000 0 424242 1 0000000000000000\n",
        )
        .expect_err("invalid tcp state must fail closed");

        assert!(matches!(
            error,
            AttributionError::InvalidNetTcp { reason, .. }
                if reason.contains("invalid TCP state")
        ));
    }

    #[test]
    fn tcp_table_parser_rejects_unsupported_state() {
        for state in ["00", "FF"] {
            let content = format!(
                "header\n   0: 0100007F:20FB 00000000:0000 {state} 00000000:00000000 00:00000000 00000000 1000 0 424242 1 0000000000000000\n",
            );
            let error = tcp_entries_from_table(&ipv4_table(), &content)
                .expect_err("unsupported tcp state must fail closed");

            assert!(matches!(
                error,
                AttributionError::InvalidNetTcp { reason, .. }
                    if reason.contains("unsupported TCP state")
            ));
        }
    }

    fn ipv4_table() -> ProcfsTcpTable {
        ProcfsTcpTable {
            family: ProcfsTcpTableFamily::Ipv4,
            path: PathBuf::from("/proc/net/tcp"),
            policy: ProcfsTcpTablePolicy::Required,
        }
    }
}
