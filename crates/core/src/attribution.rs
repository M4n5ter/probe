use crate::{CaptureSource, FlowContext};

pub const LIBPCAP_FALLBACK_RUNTIME_HINT: &str = "libpcap_fallback";
pub const UNKNOWN_PROCESS_LABEL: &str = "unknown";

pub fn is_libpcap_unknown_process_candidate(source: CaptureSource, flow: &FlowContext) -> bool {
    source == CaptureSource::Libpcap
        && flow.attribution_confidence == 0
        && flow.process.identity.pid == 0
        && flow.process.identity.exe_path == UNKNOWN_PROCESS_LABEL
        && flow.process.identity.runtime_hint.as_deref() == Some(LIBPCAP_FALLBACK_RUNTIME_HINT)
}

#[cfg(test)]
mod tests {
    use crate::{
        AddressPort, CaptureSource, FlowContext, FlowIdentity, ProcessContext, ProcessIdentity,
        TransportProtocol,
    };

    use super::*;

    #[test]
    fn identifies_libpcap_unknown_process_candidate() {
        let flow = libpcap_unknown_process_flow();

        assert!(is_libpcap_unknown_process_candidate(
            CaptureSource::Libpcap,
            &flow
        ));
    }

    #[test]
    fn rejects_known_or_non_libpcap_flows() {
        let mut known_flow = libpcap_unknown_process_flow();
        known_flow.process.identity.pid = 42;

        assert!(!is_libpcap_unknown_process_candidate(
            CaptureSource::Libpcap,
            &known_flow
        ));
        assert!(!is_libpcap_unknown_process_candidate(
            CaptureSource::Replay,
            &libpcap_unknown_process_flow()
        ));
    }

    fn libpcap_unknown_process_flow() -> FlowContext {
        let process = ProcessIdentity {
            pid: 0,
            tgid: 0,
            start_time_ticks: 0,
            boot_id: "libpcap".to_string(),
            exe_path: UNKNOWN_PROCESS_LABEL.to_string(),
            cmdline_hash: UNKNOWN_PROCESS_LABEL.to_string(),
            uid: 0,
            gid: 0,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: Some(LIBPCAP_FALLBACK_RUNTIME_HINT.to_string()),
        };
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 50_000,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 80,
        };
        FlowContext {
            id: FlowIdentity::stable(&process, &local, &remote, TransportProtocol::Tcp, 1, None),
            process: ProcessContext {
                identity: process,
                name: UNKNOWN_PROCESS_LABEL.to_string(),
                cmdline: Vec::new(),
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 0,
        }
    }
}
