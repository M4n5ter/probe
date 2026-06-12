use std::{fs, os::unix::fs::symlink};

use attribution::{ProcessAttributor, ProcfsAttributor};
use tempfile::tempdir;

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
