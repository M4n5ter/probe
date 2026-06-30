mod build;
mod codec;
mod http_source;
mod netns;
mod process;
mod temp;

pub(crate) use build::{
    debug_binary, ensure_e2e_packages_built, run_agent_with_max_events, trusted_system_command,
    workspace_root,
};
pub(crate) use codec::{decode_capture_event, decode_envelope};
pub(crate) use http_source::HttpSourceServer;
pub(crate) use netns::{
    reexec_current_case_in_fresh_network_namespace, verify_fresh_network_namespace,
};
pub(crate) use process::{
    ChildSupervisor, UnixSocketReadySignal, run_in_own_process_group, stop_running_child,
    wait_for_child_exit, wait_for_child_status, wait_for_file_or_child_exit,
    wait_for_ready_signal_or_child_exit,
};
pub(crate) use temp::{
    create_temp_root, publish_atomic_file, run_with_temp_root, wall_time_unix_ns,
};

pub(crate) fn e2e_error(message: impl Into<String>) -> std::io::Error {
    std::io::Error::other(message.into())
}
