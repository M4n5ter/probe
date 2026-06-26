use std::{
    collections::BTreeSet,
    fs, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};

use rustix::process::Pid;

const TCP_LISTEN_STATE: u8 = 0x0A;

pub(super) fn require_listener_owned_by_process_group(
    target: SocketAddr,
    process_group: Pid,
) -> Result<(), String> {
    require_listener_owned_by_process_group_in_proc(
        Path::new("/proc"),
        target,
        process_group.as_raw_pid(),
    )
}

fn require_listener_owned_by_process_group_in_proc(
    proc_root: &Path,
    target: SocketAddr,
    expected_process_group: i32,
) -> Result<(), String> {
    let inodes = listener_inodes(proc_root, target)?;
    let mut unmatched = Vec::new();

    for inode in inodes {
        let owner_pids = owner_pids_for_socket_inode(proc_root, inode)?;
        if owner_pids.is_empty() {
            return Err(format!(
                "managed L7 MITM backend readiness listener {target} has socket inode {inode}, but no process owner was found under /proc"
            ));
        }

        let mut owner_summaries = Vec::new();
        let mut inode_owned_by_expected_group = true;
        for pid in owner_pids {
            match process_group_for_pid(proc_root, pid)? {
                Some(owner_process_group) => {
                    inode_owned_by_expected_group &= owner_process_group == expected_process_group;
                    owner_summaries.push(format!("{pid}:{owner_process_group}"));
                }
                None => {
                    return Err(format!(
                        "managed L7 MITM backend readiness listener {target} has socket inode {inode}, but owner pid {pid} could not be confirmed"
                    ));
                }
            }
        }
        if inode_owned_by_expected_group {
            continue;
        }
        unmatched.push(format!("inode {inode}: {}", owner_summaries.join(", ")));
    }

    if unmatched.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "managed L7 MITM backend readiness listener {target} is not exclusively owned by managed process group {expected_process_group}; observed owner pid:pgid values: {}",
            unmatched.join("; ")
        ))
    }
}

fn listener_inodes(proc_root: &Path, target: SocketAddr) -> Result<BTreeSet<u64>, String> {
    let mut table_errors = Vec::new();
    let mut inodes = BTreeSet::new();
    for table in tcp_tables(proc_root) {
        match fs::read_to_string(&table.path) {
            Ok(content) => {
                inodes.extend(parse_listener_inodes(&table, &content, target)?);
            }
            Err(error) if table.optional && error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => table_errors.push(format!("{}: {error}", table.path.display())),
        }
    }

    if !table_errors.is_empty() {
        Err(format!(
            "failed to prove exclusive listener ownership for managed L7 MITM backend readiness target {target}; table read errors: {}",
            table_errors.join("; ")
        ))
    } else if inodes.is_empty() {
        Err(format!(
            "no listening TCP socket for managed L7 MITM backend readiness target {target} was found in /proc/net/tcp or /proc/net/tcp6"
        ))
    } else {
        Ok(inodes)
    }
}

fn parse_listener_inodes(
    table: &TcpTable,
    content: &str,
    target: SocketAddr,
) -> Result<BTreeSet<u64>, String> {
    let target_address = normalize_ip(target.ip());
    let mut inodes = BTreeSet::new();
    for line in content.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() <= 9 {
            return Err(format!(
                "invalid TCP table row in {}: expected at least 10 fields, got {}",
                table.path.display(),
                fields.len()
            ));
        }
        let local = parse_tcp_endpoint(table, fields[1])?;
        let state = u8::from_str_radix(fields[3], 16).map_err(|error| {
            format!(
                "invalid TCP state in {} for readiness listener lookup: {error}",
                table.path.display()
            )
        })?;
        if state != TCP_LISTEN_STATE {
            continue;
        }
        if local.address == target_address && local.port == target.port() {
            let inode = fields[9].parse::<u64>().map_err(|error| {
                format!(
                    "invalid TCP socket inode in {} for readiness listener lookup: {error}",
                    table.path.display()
                )
            })?;
            inodes.insert(inode);
        }
    }
    Ok(inodes)
}

fn owner_pids_for_socket_inode(proc_root: &Path, inode: u64) -> Result<BTreeSet<u32>, String> {
    let mut owners = BTreeSet::new();
    for entry in fs::read_dir(proc_root)
        .map_err(|error| format!("failed to read /proc for listener owner lookup: {error}"))?
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if is_racy_procfs_error(&error) => continue,
            Err(error) => {
                return Err(format!(
                    "failed to read /proc entry for listener owner lookup: {error}"
                ));
            }
        };
        let Some(pid) = numeric_pid(entry.file_name()) else {
            continue;
        };
        read_pid_socket_owners(&entry.path().join("fd"), pid, inode, &mut owners)?;
    }
    Ok(owners)
}

fn read_pid_socket_owners(
    fd_dir: &Path,
    pid: u32,
    inode: u64,
    owners: &mut BTreeSet<u32>,
) -> Result<(), String> {
    let entries = match fs::read_dir(fd_dir) {
        Ok(entries) => entries,
        Err(error) if is_racy_procfs_error(&error) => return Ok(()),
        Err(error) => {
            return Err(format!(
                "failed to read {} for listener owner lookup: {error}",
                fd_dir.display()
            ));
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if is_racy_procfs_error(&error) => continue,
            Err(error) => {
                return Err(format!(
                    "failed to read {} entry for listener owner lookup: {error}",
                    fd_dir.display()
                ));
            }
        };
        let target = match fs::read_link(entry.path()) {
            Ok(target) => target,
            Err(error) if is_racy_procfs_error(&error) => continue,
            Err(error) => {
                return Err(format!(
                    "failed to read {} for listener owner lookup: {error}",
                    entry.path().display()
                ));
            }
        };
        if socket_inode_from_link(&target) == Some(inode) {
            owners.insert(pid);
        }
    }
    Ok(())
}

fn process_group_for_pid(proc_root: &Path, pid: u32) -> Result<Option<i32>, String> {
    let stat_path = proc_root.join(pid.to_string()).join("stat");
    let stat = match fs::read_to_string(&stat_path) {
        Ok(stat) => stat,
        Err(error) if is_racy_procfs_error(&error) => return Ok(None),
        Err(error) => {
            return Err(format!(
                "failed to read {} for listener owner process group lookup: {error}",
                stat_path.display()
            ));
        }
    };
    parse_process_group_from_stat(&stat)
        .map(Some)
        .ok_or_else(|| {
            format!(
                "failed to parse process group from {} for listener owner lookup",
                stat_path.display()
            )
        })
}

fn parse_process_group_from_stat(stat: &str) -> Option<i32> {
    let fields_after_comm = stat.rsplit_once(") ")?.1;
    fields_after_comm
        .split_whitespace()
        .nth(2)?
        .parse::<i32>()
        .ok()
}

fn parse_tcp_endpoint(table: &TcpTable, value: &str) -> Result<TcpEndpoint, String> {
    let (address, port) = value
        .split_once(':')
        .ok_or_else(|| format!("invalid TCP endpoint {value:?} in {}", table.path.display()))?;
    let port = u16::from_str_radix(port, 16).map_err(|error| {
        format!(
            "invalid TCP endpoint port in {} for readiness listener lookup: {error}",
            table.path.display()
        )
    })?;
    Ok(TcpEndpoint {
        address: parse_tcp_address(table, address)?,
        port,
    })
}

fn parse_tcp_address(table: &TcpTable, address: &str) -> Result<IpAddr, String> {
    match table.family {
        TcpTableFamily::Ipv4 => parse_tcp4_address(&table.path, address),
        TcpTableFamily::Ipv6 => parse_tcp6_address(&table.path, address),
    }
}

fn parse_tcp4_address(path: &Path, address: &str) -> Result<IpAddr, String> {
    if address.len() != 8 {
        return Err(format!(
            "invalid IPv4 endpoint address {address:?} in {}",
            path.display()
        ));
    }
    let raw = u32::from_str_radix(address, 16).map_err(|error| {
        format!(
            "invalid IPv4 endpoint address in {} for readiness listener lookup: {error}",
            path.display()
        )
    })?;
    Ok(IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes())))
}

fn parse_tcp6_address(path: &Path, address: &str) -> Result<IpAddr, String> {
    if address.len() != 32 {
        return Err(format!(
            "invalid IPv6 endpoint address {address:?} in {}",
            path.display()
        ));
    }
    let mut bytes = [0u8; 16];
    for (index, chunk) in address.as_bytes().chunks_exact(8).enumerate() {
        let chunk = std::str::from_utf8(chunk).map_err(|error| {
            format!(
                "invalid IPv6 endpoint address in {} for readiness listener lookup: {error}",
                path.display()
            )
        })?;
        let word = u32::from_str_radix(chunk, 16).map_err(|error| {
            format!(
                "invalid IPv6 endpoint address in {} for readiness listener lookup: {error}",
                path.display()
            )
        })?;
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Ok(normalize_ip(IpAddr::V6(Ipv6Addr::from(bytes))))
}

fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(_) => address,
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
    }
}

fn numeric_pid(name: std::ffi::OsString) -> Option<u32> {
    name.to_string_lossy().parse::<u32>().ok()
}

fn socket_inode_from_link(target: &Path) -> Option<u64> {
    let target = target.to_str()?;
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn is_racy_procfs_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    )
}

fn tcp_tables(proc_root: &Path) -> [TcpTable; 2] {
    [
        TcpTable {
            family: TcpTableFamily::Ipv4,
            path: proc_root.join("net/tcp"),
            optional: false,
        },
        TcpTable {
            family: TcpTableFamily::Ipv6,
            path: proc_root.join("net/tcp6"),
            optional: true,
        },
    ]
}

#[derive(Clone, Copy)]
enum TcpTableFamily {
    Ipv4,
    Ipv6,
}

struct TcpTable {
    family: TcpTableFamily,
    path: PathBuf,
    optional: bool,
}

struct TcpEndpoint {
    address: IpAddr,
    port: u16,
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn parses_ipv4_listener_inodes() {
        let table = TcpTable {
            family: TcpTableFamily::Ipv4,
            path: PathBuf::from("/proc/net/tcp"),
            optional: false,
        };
        let content = "\
header
   0: 0100007F:3A9A 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 424242 1 0000000000000000
   1: 0100007F:3A9A 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 424243 1 0000000000000000
";

        let inodes = parse_listener_inodes(
            &table,
            content,
            "127.0.0.1:15002"
                .parse()
                .expect("test IPv4 listener address should parse"),
        )
        .expect("listener table should parse");

        assert_eq!(inodes.into_iter().collect::<Vec<_>>(), vec![424242, 424243]);
    }

    #[test]
    fn parses_ipv6_listener_inodes() {
        let table = TcpTable {
            family: TcpTableFamily::Ipv6,
            path: PathBuf::from("/proc/net/tcp6"),
            optional: true,
        };
        let content = "header\n   0: 00000000000000000000000001000000:3A9A 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 424242 1 0000000000000000\n";

        let inodes = parse_listener_inodes(
            &table,
            content,
            "[::1]:15002"
                .parse()
                .expect("test IPv6 listener address should parse"),
        )
        .expect("listener table should parse");

        assert_eq!(inodes.into_iter().collect::<Vec<_>>(), vec![424242]);
    }

    #[test]
    fn parses_process_group_with_parentheses_in_comm() {
        let stat = "1234 (backend worker) S 1 5678 5678 0 -1 4194560";

        assert_eq!(parse_process_group_from_stat(stat), Some(5678));
    }

    #[test]
    fn missing_owner_stat_is_skipped_as_procfs_race() {
        let proc_root = tempfile::tempdir().expect("test proc root should be created");

        assert_eq!(
            process_group_for_pid(proc_root.path(), 4242)
                .expect("missing pid stat should be treated as a race"),
            None
        );
    }

    #[test]
    fn ownership_check_accepts_only_when_all_listener_inodes_belong_to_process_group() {
        let proc_root = fake_proc_root([(424242, 1000, 7000), (424243, 1001, 7000)]);

        let result = require_listener_owned_by_process_group_in_proc(
            proc_root.path(),
            "127.0.0.1:15002"
                .parse()
                .expect("test listener target should parse"),
            7000,
        );

        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn ownership_check_ignores_unrelated_procfs_races_when_owner_is_confirmed() {
        let proc_root = fake_proc_root([(424242, 1000, 7000), (424243, 1001, 7000)]);
        fs::create_dir(proc_root.path().join("9999")).expect("racy pid dir should be created");

        let result = require_listener_owned_by_process_group_in_proc(
            proc_root.path(),
            "127.0.0.1:15002"
                .parse()
                .expect("test listener target should parse"),
            7000,
        );

        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn ownership_check_rejects_mixed_process_groups_on_same_listener_target() {
        let proc_root = fake_proc_root([(424242, 1000, 7000), (424243, 1001, 8000)]);

        let error = require_listener_owned_by_process_group_in_proc(
            proc_root.path(),
            "127.0.0.1:15002"
                .parse()
                .expect("test listener target should parse"),
            7000,
        )
        .expect_err("mixed listener process groups must fail closed");

        assert!(error.contains("not exclusively owned"), "{error}");
        assert!(error.contains("1001:8000"), "{error}");
    }

    #[test]
    fn parses_socket_inode_symlink() {
        assert_eq!(
            socket_inode_from_link(Path::new("socket:[424242]")),
            Some(424242)
        );
        assert_eq!(socket_inode_from_link(Path::new("pipe:[424242]")), None);
    }

    fn fake_proc_root(sockets: impl IntoIterator<Item = (u64, u32, i32)>) -> tempfile::TempDir {
        let proc_root = tempdir().expect("test proc root should be created");
        let net_dir = proc_root.path().join("net");
        fs::create_dir(&net_dir).expect("test proc net dir should be created");
        fs::write(net_dir.join("tcp"), fake_tcp_table([424242, 424243]))
            .expect("test tcp table should be written");

        for (inode, pid, process_group) in sockets {
            let pid_dir = proc_root.path().join(pid.to_string());
            let fd_dir = pid_dir.join("fd");
            fs::create_dir(&pid_dir).expect("test pid dir should be created");
            fs::create_dir(&fd_dir).expect("test fd dir should be created");
            fs::write(
                pid_dir.join("stat"),
                format!("{pid} (managed backend) S 1 {process_group} {process_group} 0\n"),
            )
            .expect("test proc stat should be written");
            symlink(format!("socket:[{inode}]"), fd_dir.join("3"))
                .expect("test socket fd symlink should be created");
        }

        proc_root
    }

    fn fake_tcp_table(inodes: impl IntoIterator<Item = u64>) -> String {
        let mut table = "header\n".to_string();
        for (index, inode) in inodes.into_iter().enumerate() {
            table.push_str(&format!(
                "   {index}: 0100007F:3A9A 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 {inode} 1 0000000000000000\n"
            ));
        }
        table
    }
}
