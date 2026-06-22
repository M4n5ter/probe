use std::io;

pub(super) fn tcp_connect_failure_reason(error: &io::Error) -> String {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => "connection refused".to_string(),
        io::ErrorKind::TimedOut => "timed out".to_string(),
        io::ErrorKind::NetworkUnreachable => "network unreachable".to_string(),
        io::ErrorKind::HostUnreachable => "host unreachable".to_string(),
        io::ErrorKind::AddrNotAvailable => "address not available".to_string(),
        kind => format!("{kind:?}").to_ascii_lowercase(),
    }
}
