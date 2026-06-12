use std::{
    fs, io,
    net::{Ipv4Addr, Ipv6Addr},
    os::unix::fs::symlink,
    path::PathBuf,
    time::Duration,
};

use attribution::*;
use probe_core::{TcpConnection, TcpEndpoint};
use tempfile::{TempDir, tempdir};

#[test]
fn procfs_attributor_builds_stable_process_context() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let proc_root = temp.path().join("proc");
    let pid_dir = proc_root.join("123");
    let boot_id_path = proc_root.join("sys/kernel/random/boot_id");
    fs::create_dir_all(&pid_dir)?;
    fs::create_dir_all(boot_id_path.parent().expect("boot id parent"))?;
    fs::write(&boot_id_path, "boot-1\n")?;
    fs::write(
        pid_dir.join("stat"),
        "123 (demo worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 21\n",
    )?;
    fs::write(
        pid_dir.join("status"),
        "Name:\tdemo\nTgid:\t120\nUid:\t1000\t1000\t1000\t1000\nGid:\t1001\t1001\t1001\t1001\n",
    )?;
    fs::write(pid_dir.join("cmdline"), b"/usr/bin/demo\0--serve\0")?;
    fs::write(
        pid_dir.join("cgroup"),
        "0::/system.slice/demo.service/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope\n",
    )?;
    symlink("/usr/bin/demo", pid_dir.join("exe"))?;

    let attributor = ProcfsAttributor::with_paths(proc_root, boot_id_path);
    let process = attributor.identify(123)?;

    assert_eq!(process.name, "demo worker");
    assert_eq!(process.cmdline, vec!["/usr/bin/demo", "--serve"]);
    assert_eq!(process.identity.pid, 123);
    assert_eq!(process.identity.tgid, 120);
    assert_eq!(process.identity.start_time_ticks, 4242);
    assert_eq!(process.identity.boot_id, "boot-1");
    assert_eq!(process.identity.exe_path, "/usr/bin/demo");
    assert_eq!(process.identity.uid, 1000);
    assert_eq!(process.identity.gid, 1001);
    assert_eq!(
        process.identity.systemd_service.as_deref(),
        Some("demo.service")
    );
    assert_eq!(process.identity.runtime_hint.as_deref(), Some("docker"));
    assert_eq!(
        process.identity.container_id.as_deref(),
        Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    );
    Ok(())
}

const PROC_NET_TCP_HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
const PROC_NET_TCP6_HEADER: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
const TCP4_LOCALHOST_TO_PEER: &str = "0100007F:1F90 0200007F:C350";
const TCP6_DOC_TO_PEER: &str =
    "B80D0120000000000000000001000000:1F90 B80D0120000000000000000002000000:C350";
const TCP6_MAPPED_LOCALHOST_TO_PEER: &str =
    "0000000000000000FFFF00000100007F:1F90 0000000000000000FFFF00000200007F:C350";

struct ProcfsSocketFixture {
    _temp: TempDir,
    proc_root: PathBuf,
    boot_id_path: PathBuf,
    net_dir: PathBuf,
    pid_dir: PathBuf,
}

impl ProcfsSocketFixture {
    fn new(socket_inode: u64) -> Result<Self, Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let proc_root = temp.path().join("proc");
        let pid_dir = proc_root.join("321");
        let fd_dir = pid_dir.join("fd");
        let net_dir = proc_root.join("net");
        let boot_id_path = proc_root.join("sys/kernel/random/boot_id");
        fs::create_dir_all(&fd_dir)?;
        fs::create_dir_all(&net_dir)?;
        fs::create_dir_all(boot_id_path.parent().expect("boot id parent"))?;
        fs::write(&boot_id_path, "boot-2\n")?;
        fs::write(
            pid_dir.join("stat"),
            "321 (server) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 9000 21\n",
        )?;
        fs::write(
            pid_dir.join("status"),
            "Name:\tserver\nTgid:\t321\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n",
        )?;
        fs::write(pid_dir.join("cmdline"), b"/usr/bin/server\0")?;
        fs::write(pid_dir.join("cgroup"), "0::/system.slice/server.service\n")?;
        symlink("/usr/bin/server", pid_dir.join("exe"))?;
        symlink(format!("socket:[{socket_inode}]"), fd_dir.join("7"))?;
        Ok(Self {
            _temp: temp,
            proc_root,
            boot_id_path,
            net_dir,
            pid_dir,
        })
    }

    fn resolver(&self) -> ProcfsSocketResolver {
        ProcfsSocketResolver::with_paths(self.proc_root.clone(), self.boot_id_path.clone())
    }

    fn write_tcp(&self, entries: &str) -> io::Result<()> {
        fs::write(
            self.net_dir.join("tcp"),
            format!("{PROC_NET_TCP_HEADER}{entries}"),
        )
    }

    fn write_tcp6(&self, entries: &str) -> io::Result<()> {
        fs::write(
            self.net_dir.join("tcp6"),
            format!("{PROC_NET_TCP6_HEADER}{entries}"),
        )
    }

    fn write_status(&self, status: &str) -> io::Result<()> {
        fs::write(self.pid_dir.join("status"), status)
    }
}

fn tcp_table_entry(endpoints: &str, inode: u64) -> String {
    format!(
        "   0: {endpoints} 01 00000000:00000000 00:00000000 00000000 1000 0 {inode} 1 0000000000000000 100 0 0 10 0\n"
    )
}

#[test]
fn procfs_socket_attributor_maps_tcp_connection_to_process()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcfsSocketFixture::new(424242)?;
    fixture.write_tcp(&tcp_table_entry(TCP4_LOCALHOST_TO_PEER, 424242))?;

    let mut resolver = fixture.resolver();
    let process = resolver
        .resolve_tcp_connection(TcpConnection::new(
            TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080),
            TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 2).into(), 50_000),
        ))?
        .expect("expected socket process");

    assert_eq!(process.process.identity.pid, 321);
    assert_eq!(process.process.name, "server");
    assert_eq!(process.socket_inode, 424242);
    assert_eq!(process.confidence, 60);
    Ok(())
}

#[test]
fn procfs_socket_attributor_maps_tcp6_connection_to_process()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcfsSocketFixture::new(424243)?;
    fixture.write_tcp("")?;
    fixture.write_tcp6(&tcp_table_entry(TCP6_DOC_TO_PEER, 424243))?;

    let mut resolver = fixture.resolver();
    let process = resolver
        .resolve_tcp_connection(TcpConnection::new(
            TcpEndpoint::new(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1).into(), 8080),
            TcpEndpoint::new(
                Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2).into(),
                50_000,
            ),
        ))?
        .expect("expected socket process");

    assert_eq!(process.process.identity.pid, 321);
    assert_eq!(process.process.name, "server");
    assert_eq!(process.socket_inode, 424243);
    assert_eq!(process.confidence, 60);
    Ok(())
}

#[test]
fn procfs_socket_attributor_maps_ipv4_mapped_tcp6_connection_to_ipv4_process()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcfsSocketFixture::new(424244)?;
    fixture.write_tcp("")?;
    fixture.write_tcp6(&tcp_table_entry(TCP6_MAPPED_LOCALHOST_TO_PEER, 424244))?;

    let mut resolver = fixture.resolver();
    let process = resolver
        .resolve_tcp_connection(TcpConnection::new(
            TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080),
            TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 2).into(), 50_000),
        ))?
        .expect("expected socket process");

    assert_eq!(process.process.identity.pid, 321);
    assert_eq!(process.socket_inode, 424244);
    Ok(())
}

#[test]
fn procfs_socket_resolver_ignores_malformed_optional_tcp6_table_for_ipv4()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcfsSocketFixture::new(424242)?;
    fixture.write_tcp(&tcp_table_entry(TCP4_LOCALHOST_TO_PEER, 424242))?;
    fixture.write_tcp6(&tcp_table_entry(
        "not-an-address:1F90 00000000000000000000000000000000:C350",
        424244,
    ))?;

    let mut resolver = fixture.resolver();
    let process = resolver
        .resolve_tcp_connection(TcpConnection::new(
            TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080),
            TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 2).into(), 50_000),
        ))?
        .expect("expected socket process");

    assert_eq!(process.process.identity.pid, 321);
    assert_eq!(process.socket_inode, 424242);
    Ok(())
}

#[test]
fn procfs_socket_resolver_reports_missing_optional_tcp6_table_for_ipv6()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcfsSocketFixture::new(424243)?;
    fixture.write_tcp("")?;

    let mut resolver = fixture.resolver();
    let error = resolver
        .resolve_tcp_connection(TcpConnection::new(
            TcpEndpoint::new(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1).into(), 8080),
            TcpEndpoint::new(
                Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2).into(),
                50_000,
            ),
        ))
        .expect_err("missing tcp6 should be visible for IPv6 lookup");

    assert!(matches!(error, AttributionError::Read { path, .. } if path.ends_with("net/tcp6")));
    Ok(())
}

#[test]
fn procfs_socket_resolver_reports_malformed_optional_tcp6_table_for_ipv6()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcfsSocketFixture::new(424243)?;
    fixture.write_tcp("")?;
    fixture.write_tcp6(&tcp_table_entry(
        "not-an-address:1F90 00000000000000000000000000000000:C350",
        424244,
    ))?;

    let mut resolver = fixture.resolver();
    let error = resolver
        .resolve_tcp_connection(TcpConnection::new(
            TcpEndpoint::new(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1).into(), 8080),
            TcpEndpoint::new(
                Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2).into(),
                50_000,
            ),
        ))
        .expect_err("malformed tcp6 should be visible for IPv6 lookup");

    assert!(matches!(
        error,
        AttributionError::InvalidNetTcp { path, .. } if path.ends_with("net/tcp6")
    ));
    Ok(())
}

#[test]
fn procfs_socket_resolver_preserves_process_identity_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcfsSocketFixture::new(424242)?;
    fixture.write_status(
        "Name:\tserver\nTgid:\t321\nUid:\tnot-a-uid\nGid:\t1000\t1000\t1000\t1000\n",
    )?;
    fixture.write_tcp(&tcp_table_entry(TCP4_LOCALHOST_TO_PEER, 424242))?;

    let mut resolver = fixture.resolver();
    let error = resolver
        .resolve_tcp_connection(TcpConnection::new(
            TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080),
            TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 2).into(), 50_000),
        ))
        .expect_err("invalid process status must be observable");

    assert!(matches!(
        error,
        AttributionError::InvalidStatus { pid: 321, .. }
    ));
    Ok(())
}

#[test]
fn procfs_socket_resolver_reuses_snapshot_within_cache_ttl_until_invalidated()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcfsSocketFixture::new(424242)?;
    fixture.write_tcp(&tcp_table_entry(TCP4_LOCALHOST_TO_PEER, 424242))?;
    let connection = TcpConnection::new(
        TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080),
        TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 2).into(), 50_000),
    );
    let mut resolver = fixture.resolver().with_cache_ttl(Duration::from_secs(60));

    let first = resolver
        .resolve_tcp_connection(connection)?
        .expect("expected first socket process");
    fixture.write_tcp(&tcp_table_entry(TCP4_LOCALHOST_TO_PEER, 999999))?;
    let second = resolver
        .resolve_tcp_connection(connection)?
        .expect("expected cached socket process");
    resolver.invalidate_snapshot();
    let refreshed = resolver.resolve_tcp_connection(connection)?;

    assert_eq!(first.socket_inode, 424242);
    assert_eq!(second.socket_inode, 424242);
    assert!(refreshed.is_none());
    Ok(())
}
