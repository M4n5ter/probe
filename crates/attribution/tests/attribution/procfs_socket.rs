use std::{
    fs, io,
    net::{Ipv4Addr, Ipv6Addr},
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    time::Duration,
};

use attribution::{AttributionError, ProcfsSocketResolver, SocketFdLookup, SocketProcessHint};
use probe_core::{TcpConnection, TcpEndpoint};
use tempfile::{TempDir, tempdir};

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

    fn move_socket_fd_to_thread(
        &self,
        thread_pid: u32,
        fd: i32,
        socket_inode: u64,
    ) -> io::Result<()> {
        let tgid_fd = self.pid_dir.join("fd").join(fd.to_string());
        if tgid_fd.exists() {
            fs::remove_file(tgid_fd)?;
        }
        let thread_fd_dir = self.proc_root.join(thread_pid.to_string()).join("fd");
        fs::create_dir_all(&thread_fd_dir)?;
        symlink(
            format!("socket:[{socket_inode}]"),
            thread_fd_dir.join(fd.to_string()),
        )
    }

    fn create_process(
        &self,
        pid: u32,
        name: &str,
        socket_inode: Option<u64>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pid_dir = self.proc_root.join(pid.to_string());
        let fd_dir = pid_dir.join("fd");
        fs::create_dir_all(&fd_dir)?;
        fs::write(
            pid_dir.join("stat"),
            format!("{pid} ({name}) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 9000 21\n"),
        )?;
        fs::write(
            pid_dir.join("status"),
            format!(
                "Name:\t{name}\nTgid:\t{pid}\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n"
            ),
        )?;
        fs::write(
            pid_dir.join("cmdline"),
            format!("/usr/bin/{name}\0").as_bytes(),
        )?;
        fs::write(
            pid_dir.join("cgroup"),
            format!("0::/system.slice/{name}.service\n"),
        )?;
        symlink(format!("/usr/bin/{name}"), pid_dir.join("exe"))?;
        if let Some(socket_inode) = socket_inode {
            symlink(format!("socket:[{socket_inode}]"), fd_dir.join("7"))?;
        }
        Ok(())
    }

    fn create_namespace_alias_process(
        &self,
        visible_pid: u32,
        observed_tgid: u32,
        socket_inode: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.create_process(visible_pid, "server", Some(socket_inode))?;
        fs::write(
            self.proc_root.join(visible_pid.to_string()).join("status"),
            format!(
                "Name:\tserver\nTgid:\t{visible_pid}\nPid:\t{visible_pid}\nNStgid:\t{observed_tgid}\t{visible_pid}\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n"
            ),
        )?;
        Ok(())
    }
}

fn tcp_table_entry(endpoints: &str, inode: u64) -> String {
    format!(
        "   0: {endpoints} 01 00000000:00000000 00:00000000 00000000 1000 0 {inode} 1 0000000000000000 100 0 0 10 0\n"
    )
}

fn fd_lookup(expected_remote_endpoint: Option<TcpEndpoint>) -> SocketFdLookup {
    SocketFdLookup {
        tgid: 321,
        thread_pid: 321,
        fd: 7,
        expected_remote_endpoint,
        process_hint: None,
    }
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
fn procfs_socket_resolver_maps_pid_fd_to_tcp_connection() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = ProcfsSocketFixture::new(424245)?;
    fixture.write_tcp(&tcp_table_entry(TCP4_LOCALHOST_TO_PEER, 424245))?;
    let expected_remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 2).into(), 50_000);

    let mut resolver = fixture.resolver();
    let process = resolver
        .resolve_tcp_fd(fd_lookup(Some(expected_remote)))?
        .expect("expected fd socket process");

    assert_eq!(process.process.identity.pid, 321);
    assert_eq!(process.process.name, "server");
    assert_eq!(process.socket_inode, 424245);
    assert_eq!(process.confidence, 60);
    assert_eq!(
        process.connection,
        TcpConnection::new(
            TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080),
            expected_remote,
        )
    );
    Ok(())
}

#[test]
fn procfs_socket_resolver_reads_fd_from_thread_pid_and_attributes_tgid()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcfsSocketFixture::new(424248)?;
    fixture.move_socket_fd_to_thread(654, 7, 424248)?;
    fixture.write_tcp(&tcp_table_entry(TCP4_LOCALHOST_TO_PEER, 424248))?;
    let expected_remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 2).into(), 50_000);

    let mut resolver = fixture.resolver();
    let process = resolver
        .resolve_tcp_fd(SocketFdLookup {
            tgid: 321,
            thread_pid: 654,
            fd: 7,
            expected_remote_endpoint: Some(expected_remote),
            process_hint: None,
        })?
        .expect("expected fd socket process from thread pid");

    assert_eq!(process.process.identity.pid, 321);
    assert_eq!(process.process.identity.tgid, 321);
    assert_eq!(process.socket_inode, 424248);
    assert_eq!(
        process.connection,
        TcpConnection::new(
            TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080),
            expected_remote,
        )
    );
    Ok(())
}

#[test]
fn procfs_socket_resolver_falls_back_to_tgid_fd_when_thread_fd_disappears()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcfsSocketFixture::new(424250)?;
    fixture.write_tcp(&tcp_table_entry(TCP4_LOCALHOST_TO_PEER, 424250))?;
    let expected_remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 2).into(), 50_000);

    let mut resolver = fixture.resolver();
    let process = resolver
        .resolve_tcp_fd(SocketFdLookup {
            tgid: 321,
            thread_pid: 654,
            fd: 7,
            expected_remote_endpoint: Some(expected_remote),
            process_hint: None,
        })?
        .expect("expected fd socket process from tgid fallback");

    assert_eq!(process.process.identity.pid, 321);
    assert_eq!(process.socket_inode, 424250);
    assert_eq!(
        process.connection,
        TcpConnection::new(
            TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080),
            expected_remote,
        )
    );
    Ok(())
}

#[test]
fn procfs_socket_resolver_uses_namespace_alias_only_when_observed_tgid_is_not_visible()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcfsSocketFixture::new(424251)?;
    fixture.create_namespace_alias_process(7, 101, 424251)?;
    fixture.write_tcp(&tcp_table_entry(TCP4_LOCALHOST_TO_PEER, 424251))?;
    let expected_remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 2).into(), 50_000);

    let mut resolver = fixture.resolver();
    let process = resolver
        .resolve_tcp_fd(SocketFdLookup {
            tgid: 101,
            thread_pid: 101,
            fd: 7,
            expected_remote_endpoint: Some(expected_remote),
            process_hint: None,
        })?
        .expect("expected hidden observed tgid to resolve through namespace alias");

    assert_eq!(process.process.identity.pid, 7);
    assert_eq!(process.socket_inode, 424251);
    assert_eq!(process.confidence, 50);
    assert_eq!(
        process.connection,
        TcpConnection::new(
            TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080),
            expected_remote,
        )
    );
    Ok(())
}

#[test]
fn procfs_socket_resolver_does_not_alias_visible_tgid_with_missing_fd()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcfsSocketFixture::new(424252)?;
    fixture.create_process(101, "server", None)?;
    fixture.create_namespace_alias_process(7, 101, 424252)?;
    fixture.write_tcp(&tcp_table_entry(TCP4_LOCALHOST_TO_PEER, 424252))?;
    let expected_remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 2).into(), 50_000);

    let mut resolver = fixture.resolver();
    let process = resolver.resolve_tcp_fd(SocketFdLookup {
        tgid: 101,
        thread_pid: 101,
        fd: 7,
        expected_remote_endpoint: Some(expected_remote),
        process_hint: None,
    })?;

    assert!(process.is_none());
    Ok(())
}

#[test]
fn procfs_socket_resolver_rejects_namespace_alias_when_status_scan_is_incomplete()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcfsSocketFixture::new(424257)?;
    fixture.create_namespace_alias_process(7, 101, 424257)?;
    fixture.create_process(8, "server", None)?;
    let unreadable_status = fixture.proc_root.join("8/status");
    fs::set_permissions(&unreadable_status, fs::Permissions::from_mode(0o000))?;
    fixture.write_tcp(&tcp_table_entry(TCP4_LOCALHOST_TO_PEER, 424257))?;
    let expected_remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 2).into(), 50_000);

    let mut resolver = fixture.resolver();
    let process = resolver.resolve_tcp_fd(SocketFdLookup {
        tgid: 101,
        thread_pid: 101,
        fd: 7,
        expected_remote_endpoint: Some(expected_remote),
        process_hint: None,
    });
    fs::set_permissions(&unreadable_status, fs::Permissions::from_mode(0o600))?;

    assert!(process?.is_none());
    Ok(())
}

#[test]
fn procfs_socket_resolver_uses_unique_fd_process_hint_when_kernel_pid_is_hidden()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcfsSocketFixture::new(424253)?;
    fixture.write_tcp(&tcp_table_entry(TCP4_LOCALHOST_TO_PEER, 424253))?;
    let expected_remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 2).into(), 50_000);

    let mut resolver = fixture.resolver();
    let process = resolver
        .resolve_tcp_fd(SocketFdLookup {
            tgid: 999,
            thread_pid: 999,
            fd: 7,
            expected_remote_endpoint: Some(expected_remote),
            process_hint: Some(SocketProcessHint {
                name: "server".to_string(),
                uid: 1000,
                gid: 1000,
            }),
        })?
        .expect("expected unique fd/process hint candidate");

    assert_eq!(process.process.identity.pid, 321);
    assert_eq!(process.socket_inode, 424253);
    assert_eq!(process.confidence, 50);
    Ok(())
}

#[test]
fn procfs_socket_resolver_rejects_fd_process_hint_when_candidate_scan_is_incomplete()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcfsSocketFixture::new(424258)?;
    fixture.create_process(654, "server", None)?;
    let unreadable_fd_dir = fixture.proc_root.join("654/fd");
    fs::set_permissions(&unreadable_fd_dir, fs::Permissions::from_mode(0o000))?;
    fixture.write_tcp(&tcp_table_entry(TCP4_LOCALHOST_TO_PEER, 424258))?;
    let expected_remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 2).into(), 50_000);

    let mut resolver = fixture.resolver();
    let process = resolver.resolve_tcp_fd(SocketFdLookup {
        tgid: 999,
        thread_pid: 999,
        fd: 7,
        expected_remote_endpoint: Some(expected_remote),
        process_hint: Some(SocketProcessHint {
            name: "server".to_string(),
            uid: 1000,
            gid: 1000,
        }),
    });
    fs::set_permissions(&unreadable_fd_dir, fs::Permissions::from_mode(0o700))?;

    assert!(process?.is_none());
    Ok(())
}

#[test]
fn procfs_socket_resolver_rejects_fd_process_hint_name_mismatch()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcfsSocketFixture::new(424255)?;
    fixture.write_tcp(&tcp_table_entry(TCP4_LOCALHOST_TO_PEER, 424255))?;
    let expected_remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 2).into(), 50_000);

    let mut resolver = fixture.resolver();
    let process = resolver.resolve_tcp_fd(SocketFdLookup {
        tgid: 999,
        thread_pid: 999,
        fd: 7,
        expected_remote_endpoint: Some(expected_remote),
        process_hint: Some(SocketProcessHint {
            name: "curl".to_string(),
            uid: 1000,
            gid: 1000,
        }),
    })?;

    assert!(process.is_none());
    Ok(())
}

#[test]
fn procfs_socket_resolver_requires_expected_remote_for_fd_process_hint()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcfsSocketFixture::new(424256)?;
    fixture.write_tcp(&tcp_table_entry(TCP4_LOCALHOST_TO_PEER, 424256))?;

    let mut resolver = fixture.resolver();
    let process = resolver.resolve_tcp_fd(SocketFdLookup {
        tgid: 999,
        thread_pid: 999,
        fd: 7,
        expected_remote_endpoint: None,
        process_hint: Some(SocketProcessHint {
            name: "server".to_string(),
            uid: 1000,
            gid: 1000,
        }),
    })?;

    assert!(process.is_none());
    Ok(())
}

#[test]
fn procfs_socket_resolver_rejects_ambiguous_fd_process_hint_candidates()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcfsSocketFixture::new(424254)?;
    fixture.create_process(654, "server", Some(424254))?;
    fixture.write_tcp(&tcp_table_entry(TCP4_LOCALHOST_TO_PEER, 424254))?;
    let expected_remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 2).into(), 50_000);

    let mut resolver = fixture.resolver();
    let process = resolver.resolve_tcp_fd(SocketFdLookup {
        tgid: 999,
        thread_pid: 999,
        fd: 7,
        expected_remote_endpoint: Some(expected_remote),
        process_hint: Some(SocketProcessHint {
            name: "server".to_string(),
            uid: 1000,
            gid: 1000,
        }),
    })?;

    assert!(process.is_none());
    Ok(())
}

#[test]
fn procfs_socket_resolver_matches_ipv4_expected_remote_against_mapped_tcp6_fd()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcfsSocketFixture::new(424249)?;
    fixture.write_tcp("")?;
    fixture.write_tcp6(&tcp_table_entry(TCP6_MAPPED_LOCALHOST_TO_PEER, 424249))?;
    let expected_remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 2).into(), 50_000);

    let mut resolver = fixture.resolver();
    let process = resolver
        .resolve_tcp_fd(fd_lookup(Some(expected_remote)))?
        .expect("expected mapped tcp6 fd socket process");

    assert_eq!(process.process.identity.pid, 321);
    assert_eq!(process.socket_inode, 424249);
    assert_eq!(
        process.connection,
        TcpConnection::new(
            TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080),
            expected_remote,
        )
    );
    Ok(())
}

#[test]
fn procfs_socket_resolver_filters_pid_fd_by_expected_remote()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcfsSocketFixture::new(424246)?;
    fixture.write_tcp(&tcp_table_entry(TCP4_LOCALHOST_TO_PEER, 424246))?;

    let mut resolver = fixture.resolver();
    let process = resolver.resolve_tcp_fd(fd_lookup(Some(TcpEndpoint::new(
        Ipv4Addr::new(127, 0, 0, 3).into(),
        50_000,
    ))))?;

    assert!(process.is_none());
    Ok(())
}

#[test]
fn procfs_socket_resolver_reports_missing_tcp6_for_ipv6_fd_lookup()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcfsSocketFixture::new(424247)?;
    fixture.write_tcp("")?;

    let mut resolver = fixture.resolver();
    let error = resolver
        .resolve_tcp_fd(fd_lookup(Some(TcpEndpoint::new(
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2).into(),
            50_000,
        ))))
        .expect_err("missing tcp6 should be visible for IPv6 fd lookup");

    assert!(matches!(error, AttributionError::Read { path, .. } if path.ends_with("net/tcp6")));
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
