use probe_core::{CompiledSelector, EventEnvelope, ProcessContext, Selector, SelectorError};

pub struct TargetScope {
    selector: Option<CompiledSelector>,
}

impl TargetScope {
    pub fn compile(selector: Option<&Selector>) -> Result<Self, SelectorError> {
        Ok(Self {
            selector: selector.map(Selector::compile).transpose()?,
        })
    }

    pub fn may_include_process(&self, process: &ProcessContext) -> bool {
        self.selector
            .as_ref()
            .is_none_or(|selector| selector.may_match_process(process))
    }

    pub fn matches_trigger(&self, trigger: &EventEnvelope) -> bool {
        self.selector
            .as_ref()
            .is_none_or(|selector| selector.matches_event(trigger))
    }
}

#[cfg(test)]
mod tests {
    use probe_core::{
        AddressPort, CaptureSource, Direction, EventKind, FlowContext, FlowIdentity, HttpHeaders,
        ProcessIdentity, ProcessSelector, Selector, Timestamp, TrafficSelector, TransportProtocol,
    };

    use super::*;

    #[test]
    fn process_prefilter_excludes_definite_process_miss() -> Result<(), Box<dyn std::error::Error>>
    {
        let scope = TargetScope::compile(Some(&Selector::term(
            ProcessSelector {
                names: vec!["other".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        )))?;

        assert!(!scope.may_include_process(&demo_flow().process));
        Ok(())
    }

    #[test]
    fn process_prefilter_keeps_candidate_when_traffic_is_unknown()
    -> Result<(), Box<dyn std::error::Error>> {
        let scope = TargetScope::compile(Some(&Selector::term(
            ProcessSelector {
                names: vec!["demo".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        )))?;

        assert!(scope.may_include_process(&demo_flow().process));
        Ok(())
    }

    #[test]
    fn trigger_matching_uses_full_flow_and_direction() -> Result<(), Box<dyn std::error::Error>> {
        let scope = TargetScope::compile(Some(&Selector::term(
            ProcessSelector {
                names: vec!["demo".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                remote_ports: vec![80],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        )))?;

        assert!(scope.matches_trigger(&request_event(Direction::Outbound)));
        assert!(!scope.matches_trigger(&request_event(Direction::Inbound)));
        Ok(())
    }

    fn request_event(direction: Direction) -> EventEnvelope {
        EventEnvelope::new(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            demo_flow(),
            CaptureSource::Replay,
            "test",
            EventKind::HttpRequestHeaders(HttpHeaders {
                direction,
                stream_sequence: 1,
                method: Some("GET".to_string()),
                target: Some("/".to_string()),
                status: None,
                reason: None,
                version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
            }),
        )
    }

    fn demo_flow() -> FlowContext {
        let process = ProcessIdentity {
            pid: 100,
            tgid: 100,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "/usr/bin/demo".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 1000,
            gid: 1000,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
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
                name: "demo".to_string(),
                cmdline: vec!["demo".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 100,
        }
    }
}
