use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Child,
    thread,
    time::{Duration, Instant},
};

use serde_json::json;

use super::{harness::e2e_error, loopback::send_admin_request};

const TLS_ATTACH_READY_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_TARGET_LIFECYCLE_READY_TIMEOUT: Duration = Duration::from_secs(8);
const TLS_ATTACH_READY_INTERVAL: Duration = Duration::from_millis(50);

pub(super) fn wait_for_tls_plaintext_active_target(
    agent: &mut Child,
    admin_socket_path: &Path,
    fixture_pid: u32,
) -> Result<TlsPlaintextAttachStatus, Box<dyn std::error::Error>> {
    wait_for_tls_plaintext_active_target_until(
        agent,
        admin_socket_path,
        fixture_pid,
        0,
        TLS_ATTACH_READY_TIMEOUT,
        "active target",
        |status| status.is_enabled() && status.has_active_target(fixture_pid),
    )
}

pub(super) fn wait_for_tls_plaintext_active_target_after_sequence(
    agent: &mut Child,
    admin_socket_path: &Path,
    fixture_pid: u32,
    sequence: u64,
) -> Result<TlsPlaintextAttachStatus, Box<dyn std::error::Error>> {
    wait_for_tls_plaintext_active_target_until(
        agent,
        admin_socket_path,
        fixture_pid,
        sequence,
        TLS_TARGET_LIFECYCLE_READY_TIMEOUT,
        "active target",
        |status| status.is_enabled() && status.has_active_target(fixture_pid),
    )
}

pub(super) fn wait_for_tls_plaintext_active_target_path_after_sequence(
    agent: &mut Child,
    admin_socket_path: &Path,
    fixture_pid: u32,
    mapped_path: &Path,
    sequence: u64,
) -> Result<TlsPlaintextAttachStatus, Box<dyn std::error::Error>> {
    wait_for_tls_plaintext_active_target_until(
        agent,
        admin_socket_path,
        fixture_pid,
        sequence,
        TLS_TARGET_LIFECYCLE_READY_TIMEOUT,
        "active target for mapped path",
        |status| status.is_enabled() && status.has_active_target_path(fixture_pid, mapped_path),
    )
}

pub(super) fn wait_for_tls_plaintext_no_active_target_after_sequence(
    agent: &mut Child,
    admin_socket_path: &Path,
    fixture_pid: u32,
    sequence: u64,
) -> Result<TlsPlaintextAttachStatus, Box<dyn std::error::Error>> {
    wait_for_tls_plaintext_active_target_until(
        agent,
        admin_socket_path,
        fixture_pid,
        sequence,
        TLS_ATTACH_READY_TIMEOUT,
        "no active target",
        |status| status.is_enabled() && status.has_no_active_targets(),
    )
}

fn wait_for_tls_plaintext_active_target_until(
    agent: &mut Child,
    admin_socket_path: &Path,
    fixture_pid: u32,
    min_sequence: u64,
    timeout: Duration,
    expectation: &'static str,
    predicate: impl Fn(&TlsPlaintextAttachStatus) -> bool,
) -> Result<TlsPlaintextAttachStatus, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        let status = match read_tls_plaintext_status(admin_socket_path) {
            Ok(status) if status.sequence > min_sequence && predicate(&status) => {
                return Ok(status);
            }
            Ok(status) => status,
            Err(error) => {
                if let Some(status) = agent.try_wait()? {
                    return Err(e2e_error(format!(
                        "agent exited with {status} before TLS plaintext status reached {expectation} for fixture pid {fixture_pid}: {error}"
                    ))
                    .into());
                }
                TlsPlaintextAttachStatus::error(error.to_string())
            }
        };
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for TLS plaintext {expectation} for pid {fixture_pid} after sequence {min_sequence}; last status: {}",
                status.summary()
            ))
            .into());
        }
        thread::sleep(TLS_ATTACH_READY_INTERVAL);
    }
}

pub(super) fn wait_for_tls_plaintext_detached_target(
    agent: &mut Child,
    admin_socket_path: &Path,
    fixture_pid: u32,
    active_sequence: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    wait_for_tls_plaintext_detached_target_status(
        agent,
        admin_socket_path,
        fixture_pid,
        active_sequence,
    )
    .map(|_| ())
}

pub(super) fn wait_for_tls_plaintext_detached_target_status(
    agent: &mut Child,
    admin_socket_path: &Path,
    fixture_pid: u32,
    active_sequence: u64,
) -> Result<TlsPlaintextAttachStatus, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + TLS_ATTACH_READY_TIMEOUT;
    loop {
        let status = match read_tls_plaintext_status(admin_socket_path) {
            Ok(status)
                if status.sequence > active_sequence
                    && status.is_enabled()
                    && (status.has_detached_target(fixture_pid)
                        || status.has_no_active_targets()) =>
            {
                return Ok(status);
            }
            Ok(status) => status,
            Err(error) => {
                if let Some(status) = agent.try_wait()? {
                    return Err(e2e_error(format!(
                        "agent exited with {status} before TLS plaintext detached fixture pid {fixture_pid}: {error}"
                    ))
                    .into());
                }
                TlsPlaintextAttachStatus::error(error.to_string())
            }
        };
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for TLS plaintext detach of fixture pid {fixture_pid}; last status: {}",
                status.summary()
            ))
            .into());
        }
        thread::sleep(TLS_ATTACH_READY_INTERVAL);
    }
}

pub(super) fn read_tls_plaintext_status(
    admin_socket_path: &Path,
) -> Result<TlsPlaintextAttachStatus, Box<dyn std::error::Error>> {
    let value = send_admin_request(admin_socket_path, json!({"command": "status"}))?;
    let runtime = required_value(
        &value,
        "/snapshot/tls/plaintext/instrumentation/runtime",
        "TLS plaintext instrumentation runtime",
    )?;
    let sequence = required_u64(
        runtime,
        "/last_reconcile/sequence",
        "last reconcile sequence",
    )?;
    let active = required_u64(
        runtime,
        "/last_reconcile/target_counts/active",
        "active target count",
    )?;
    let detached = required_u64(
        runtime,
        "/last_reconcile/target_counts/detached",
        "detached target count",
    )?;
    let active_omitted = required_u64(
        runtime,
        "/last_reconcile/targets/active/omitted",
        "active target omitted count",
    )?;
    let detached_omitted = required_u64(
        runtime,
        "/last_reconcile/targets/detached/omitted",
        "detached target omitted count",
    )?;
    let active_targets = target_set(
        required_value(
            runtime,
            "/last_reconcile/targets/active/targets",
            "active target list",
        )?,
        "active target",
    )?;
    let detached_targets = target_set(
        required_value(
            runtime,
            "/last_reconcile/targets/detached/targets",
            "detached target list",
        )?,
        "detached target",
    )?;
    Ok(TlsPlaintextAttachStatus {
        mode: Some(required_string(runtime, "/mode", "runtime mode")?),
        reason: optional_string(runtime, "/reason"),
        sequence,
        active,
        detached,
        active_omitted,
        detached_omitted,
        active_targets,
        detached_targets,
        error: None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TlsPlaintextAttachStatus {
    mode: Option<String>,
    reason: Option<String>,
    pub(super) sequence: u64,
    active: u64,
    detached: u64,
    active_omitted: u64,
    detached_omitted: u64,
    active_targets: BTreeSet<TlsPlaintextAttachTarget>,
    detached_targets: BTreeSet<TlsPlaintextAttachTarget>,
    error: Option<String>,
}

impl TlsPlaintextAttachStatus {
    fn error(error: String) -> Self {
        Self {
            mode: None,
            reason: None,
            sequence: 0,
            active: 0,
            detached: 0,
            active_omitted: 0,
            detached_omitted: 0,
            active_targets: BTreeSet::new(),
            detached_targets: BTreeSet::new(),
            error: Some(error),
        }
    }

    fn is_enabled(&self) -> bool {
        self.mode.as_deref() == Some("enabled")
    }

    fn has_no_active_targets(&self) -> bool {
        self.active == 0 && self.active_omitted == 0 && self.active_targets.is_empty()
    }

    fn has_active_target(&self, fixture_pid: u32) -> bool {
        self.active_targets
            .iter()
            .any(|target| target.pid == fixture_pid)
    }

    pub(super) fn has_active_target_path(&self, fixture_pid: u32, mapped_path: &Path) -> bool {
        self.active_targets
            .iter()
            .any(|target| target.pid == fixture_pid && target.mapped_path == mapped_path)
    }

    pub(super) fn active_target_paths_for_pid(&self, fixture_pid: u32) -> Vec<PathBuf> {
        self.active_targets
            .iter()
            .filter(|target| target.pid == fixture_pid)
            .map(|target| target.mapped_path.clone())
            .collect()
    }

    fn has_detached_target(&self, fixture_pid: u32) -> bool {
        self.detached_targets
            .iter()
            .any(|target| target.pid == fixture_pid)
    }

    fn summary(&self) -> String {
        if let Some(error) = &self.error {
            return format!("admin error: {error}");
        }
        format!(
            "mode={:?} reason={:?} sequence={} active={} active_omitted={} detached={} detached_omitted={} active_targets={:?} detached_targets={:?}",
            self.mode,
            self.reason,
            self.sequence,
            self.active,
            self.active_omitted,
            self.detached,
            self.detached_omitted,
            self.active_targets,
            self.detached_targets
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TlsPlaintextAttachTarget {
    pid: u32,
    mapped_path: PathBuf,
}

fn target_set(
    value: &serde_json::Value,
    label: &'static str,
) -> Result<BTreeSet<TlsPlaintextAttachTarget>, std::io::Error> {
    let targets = value.as_array().ok_or_else(|| {
        e2e_error(format!(
            "admin TLS plaintext status {label} list was not an array: {value}"
        ))
    })?;
    targets
        .iter()
        .enumerate()
        .map(|(index, target)| {
            let pid = target
                .get("pid")
                .and_then(serde_json::Value::as_u64)
                .and_then(|pid| u32::try_from(pid).ok())
                .ok_or_else(|| {
                    e2e_error(format!(
                        "admin TLS plaintext status {label} #{index} omitted valid pid: {target}"
                    ))
                })?;
            let mapped_path = target
                .get("mapped_path")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    e2e_error(format!(
                        "admin TLS plaintext status {label} #{index} omitted mapped_path: {target}"
                    ))
                })?;
            Ok(TlsPlaintextAttachTarget {
                pid,
                mapped_path: PathBuf::from(mapped_path),
            })
        })
        .collect()
}

fn required_value<'a>(
    value: &'a serde_json::Value,
    pointer: &'static str,
    label: &'static str,
) -> Result<&'a serde_json::Value, std::io::Error> {
    value.pointer(pointer).ok_or_else(|| {
        e2e_error(format!(
            "admin TLS plaintext status omitted {label} at {pointer}: {value}"
        ))
    })
}

fn required_u64(
    value: &serde_json::Value,
    pointer: &'static str,
    label: &'static str,
) -> Result<u64, std::io::Error> {
    required_value(value, pointer, label)?
        .as_u64()
        .ok_or_else(|| {
            e2e_error(format!(
                "admin TLS plaintext status {label} at {pointer} was not an unsigned integer: {value}"
            ))
        })
}

fn required_string(
    value: &serde_json::Value,
    pointer: &'static str,
    label: &'static str,
) -> Result<String, std::io::Error> {
    required_value(value, pointer, label)?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            e2e_error(format!(
                "admin TLS plaintext status {label} at {pointer} was not a string: {value}"
            ))
        })
}

fn optional_string(value: &serde_json::Value, pointer: &'static str) -> Option<String> {
    value
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}
