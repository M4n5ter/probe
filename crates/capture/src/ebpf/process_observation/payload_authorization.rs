use probe_core::{CompiledSelector, Direction, FlowContext};

use super::payload_direction::PayloadDirections;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SocketPayloadSampleAuthorization {
    tgid: u32,
    fd: i32,
    fd_table_epoch: u64,
    payload_directions: PayloadDirections,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SocketPayloadSampleSource {
    tgid: u32,
    fd: i32,
    fd_table_epoch: u64,
}

impl SocketPayloadSampleSource {
    pub(super) const fn new(tgid: u32, fd: i32, fd_table_epoch: u64) -> Self {
        Self {
            tgid,
            fd,
            fd_table_epoch,
        }
    }
}

impl SocketPayloadSampleAuthorization {
    pub(super) fn from_selector(
        source: SocketPayloadSampleSource,
        flow: &FlowContext,
        selector: Option<&CompiledSelector>,
    ) -> Option<Self> {
        let selector = selector?;
        Self::new(source, payload_directions_for_flow(flow, selector))
    }

    pub(super) fn tgid(self) -> u32 {
        self.tgid
    }

    pub(super) fn fd(self) -> i32 {
        self.fd
    }

    pub(super) fn fd_table_epoch(self) -> u64 {
        self.fd_table_epoch
    }

    pub(super) fn payload_directions(self) -> PayloadDirections {
        self.payload_directions
    }

    fn new(
        source: SocketPayloadSampleSource,
        payload_directions: PayloadDirections,
    ) -> Option<Self> {
        let authorization = Self {
            tgid: source.tgid,
            fd: source.fd,
            fd_table_epoch: source.fd_table_epoch,
            payload_directions,
        };
        authorization.is_valid().then_some(authorization)
    }

    fn is_valid(self) -> bool {
        self.fd >= 0 && self.fd_table_epoch != 0 && !self.payload_directions.is_empty()
    }
}

fn payload_directions_for_flow(
    flow: &FlowContext,
    selector: &CompiledSelector,
) -> PayloadDirections {
    let mut payload_directions = PayloadDirections::empty();
    if selector.matches_flow(flow, Direction::Outbound) {
        payload_directions.insert(Direction::Outbound);
    }
    if selector.matches_flow(flow, Direction::Inbound) {
        payload_directions.insert(Direction::Inbound);
    }
    payload_directions
}

#[cfg(test)]
mod tests {
    use probe_core::{
        AddressPort, FlowIdentity, ProcessContext, ProcessIdentity, ProcessSelector, Selector,
        TrafficSelector, TransportProtocol,
    };

    use super::*;

    #[test]
    fn authorization_projects_outbound_selector_to_write_payload_direction()
    -> Result<(), Box<dyn std::error::Error>> {
        let authorization =
            authorization_for_directions([Direction::Outbound])?.expect("expected authorization");

        assert_eq!(authorization.tgid(), 100);
        assert_eq!(authorization.fd(), 7);
        assert_eq!(authorization.fd_table_epoch(), 9);
        assert!(
            authorization
                .payload_directions()
                .allows(Direction::Outbound)
        );
        assert!(
            !authorization
                .payload_directions()
                .allows(Direction::Inbound)
        );
        Ok(())
    }

    #[test]
    fn authorization_projects_inbound_selector_to_read_payload_direction()
    -> Result<(), Box<dyn std::error::Error>> {
        let authorization =
            authorization_for_directions([Direction::Inbound])?.expect("expected authorization");

        assert!(
            authorization
                .payload_directions()
                .allows(Direction::Inbound)
        );
        assert!(
            !authorization
                .payload_directions()
                .allows(Direction::Outbound)
        );
        Ok(())
    }

    #[test]
    fn authorization_combines_bidirectional_selector() -> Result<(), Box<dyn std::error::Error>> {
        let authorization =
            authorization_for_directions([Direction::Outbound, Direction::Inbound])?
                .expect("expected authorization");

        assert!(
            authorization
                .payload_directions()
                .allows(Direction::Outbound)
        );
        assert!(
            authorization
                .payload_directions()
                .allows(Direction::Inbound)
        );
        Ok(())
    }

    #[test]
    fn authorization_rejects_selector_miss() -> Result<(), Box<dyn std::error::Error>> {
        let selector = selector([Direction::Outbound], 8080)?;

        let authorization =
            SocketPayloadSampleAuthorization::from_selector(source(), &flow(), Some(&selector));

        assert!(authorization.is_none());
        Ok(())
    }

    #[test]
    fn authorization_rejects_invalid_descriptor_or_epoch() -> Result<(), Box<dyn std::error::Error>>
    {
        let selector = selector([Direction::Outbound], 443)?;
        let invalid_fd = SocketPayloadSampleSource::new(100, -1, 9);
        let invalid_epoch = SocketPayloadSampleSource::new(100, 7, 0);

        assert!(
            SocketPayloadSampleAuthorization::from_selector(invalid_fd, &flow(), Some(&selector))
                .is_none()
        );
        assert!(
            SocketPayloadSampleAuthorization::from_selector(
                invalid_epoch,
                &flow(),
                Some(&selector),
            )
            .is_none()
        );
        Ok(())
    }

    fn authorization_for_directions(
        directions: impl IntoIterator<Item = Direction>,
    ) -> Result<Option<SocketPayloadSampleAuthorization>, Box<dyn std::error::Error>> {
        let selector = selector(directions, 443)?;
        Ok(SocketPayloadSampleAuthorization::from_selector(
            source(),
            &flow(),
            Some(&selector),
        ))
    }

    fn selector(
        directions: impl IntoIterator<Item = Direction>,
        remote_port: u16,
    ) -> Result<CompiledSelector, Box<dyn std::error::Error>> {
        Ok(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![remote_port],
                directions: directions.into_iter().collect(),
                ..TrafficSelector::default()
            },
        )
        .compile()?)
    }

    fn source() -> SocketPayloadSampleSource {
        SocketPayloadSampleSource::new(100, 7, 9)
    }

    fn flow() -> FlowContext {
        FlowContext {
            id: FlowIdentity("flow-7".to_string()),
            process: ProcessContext {
                identity: ProcessIdentity {
                    pid: 100,
                    tgid: 100,
                    start_time_ticks: 1234,
                    boot_id: "boot".to_string(),
                    exe_path: "/usr/bin/curl".to_string(),
                    cmdline_hash: "cmd".to_string(),
                    uid: 1000,
                    gid: 1000,
                    cgroup: None,
                    systemd_service: None,
                    container_id: None,
                    runtime_hint: None,
                },
                name: "curl".to_string(),
                cmdline: vec!["curl".to_string()],
            },
            protocol: TransportProtocol::Tcp,
            local: AddressPort {
                address: "127.0.0.1".to_string(),
                port: 50_000,
            },
            remote: AddressPort {
                address: "127.0.0.1".to_string(),
                port: 443,
            },
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 90,
        }
    }
}
