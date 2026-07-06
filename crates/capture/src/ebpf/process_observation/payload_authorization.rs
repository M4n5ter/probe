use probe_core::{CompiledSelector, Direction, FlowContext, ProcessContext};

use super::{descriptor_lease::DescriptorLease, payload_direction::PayloadDirections};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessPayloadSampleAuthorization {
    tgid: u32,
    payload_directions: PayloadDirections,
}

impl ProcessPayloadSampleAuthorization {
    pub fn from_unattributed_selector(
        tgid: u32,
        process: &ProcessContext,
        selector: &CompiledSelector,
    ) -> Option<Self> {
        let mut payload_directions = PayloadDirections::empty();
        if selector.matches_unattributed_flow(process, Direction::Inbound) {
            payload_directions.insert(Direction::Inbound);
        }
        if selector.matches_unattributed_flow(process, Direction::Outbound) {
            payload_directions.insert(Direction::Outbound);
        }
        Self::new(tgid, payload_directions)
    }

    fn new(tgid: u32, payload_directions: PayloadDirections) -> Option<Self> {
        (tgid != 0 && !payload_directions.is_empty()).then_some(Self {
            tgid,
            payload_directions,
        })
    }

    pub(super) fn tgid(self) -> u32 {
        self.tgid
    }

    pub(super) fn payload_directions(self) -> PayloadDirections {
        self.payload_directions
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SocketPayloadSampleAuthorization {
    lease: DescriptorLease,
    payload_directions: PayloadDirections,
}

impl SocketPayloadSampleAuthorization {
    pub(super) fn from_selector(
        lease: DescriptorLease,
        flow: &FlowContext,
        selector: Option<&CompiledSelector>,
    ) -> Option<Self> {
        let selector = selector?;
        Self::new(lease, payload_directions_for_flow(flow, selector))
    }

    pub(super) fn tgid(self) -> u32 {
        self.lease.tgid()
    }

    pub(super) fn fd(self) -> i32 {
        self.lease.fd()
    }

    pub(super) fn fd_table_epoch(self) -> u64 {
        self.lease.fd_table_epoch()
    }

    pub(super) fn fd_generation(self) -> u64 {
        self.lease.fd_generation()
    }

    pub(super) fn payload_directions(self) -> PayloadDirections {
        self.payload_directions
    }

    fn new(lease: DescriptorLease, payload_directions: PayloadDirections) -> Option<Self> {
        (!payload_directions.is_empty()).then_some(Self {
            lease,
            payload_directions,
        })
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

pub fn process_payload_hint_command_key(name: &str) -> [u8; 16] {
    let mut command = [0; 16];
    for (slot, byte) in command.iter_mut().zip(name.bytes()) {
        *slot = byte;
    }
    command
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
        assert_eq!(authorization.fd_generation(), 10);
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
    fn authorization_rejects_invalid_descriptor_or_lease() -> Result<(), Box<dyn std::error::Error>>
    {
        let selector = selector([Direction::Outbound], 443)?;

        assert!(
            DescriptorLease::new(100, -1, 9, 10)
                .and_then(|lease| SocketPayloadSampleAuthorization::from_selector(
                    lease,
                    &flow(),
                    Some(&selector),
                ))
                .is_none()
        );
        assert!(
            DescriptorLease::new(100, 7, 0, 10)
                .and_then(|lease| SocketPayloadSampleAuthorization::from_selector(
                    lease,
                    &flow(),
                    Some(&selector),
                ))
                .is_none()
        );
        assert!(
            DescriptorLease::new(100, 7, 9, 0)
                .and_then(|lease| SocketPayloadSampleAuthorization::from_selector(
                    lease,
                    &flow(),
                    Some(&selector),
                ))
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn process_authorization_projects_unattributed_direction()
    -> Result<(), Box<dyn std::error::Error>> {
        let selector = process_direction_selector([Direction::Inbound])?;
        let authorization = ProcessPayloadSampleAuthorization::from_unattributed_selector(
            100,
            &flow().process,
            &selector,
        )
        .expect("expected process authorization");

        assert_eq!(authorization.tgid(), 100);
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
    fn process_authorization_rejects_flow_only_selector() -> Result<(), Box<dyn std::error::Error>>
    {
        let selector = selector([Direction::Outbound], 443)?;

        let authorization = ProcessPayloadSampleAuthorization::from_unattributed_selector(
            100,
            &flow().process,
            &selector,
        );

        assert!(authorization.is_none());
        Ok(())
    }

    #[test]
    fn process_authorization_rejects_flow_dependent_process_selector()
    -> Result<(), Box<dyn std::error::Error>> {
        let selector = Selector::All {
            selectors: vec![
                Selector::term(
                    ProcessSelector {
                        names: vec!["curl".to_string()],
                        ..ProcessSelector::default()
                    },
                    TrafficSelector::default(),
                ),
                Selector::term(
                    ProcessSelector::default(),
                    TrafficSelector {
                        remote_ports: vec![443],
                        directions: vec![Direction::Outbound],
                        ..TrafficSelector::default()
                    },
                ),
            ],
        }
        .compile()?;

        let authorization = ProcessPayloadSampleAuthorization::from_unattributed_selector(
            100,
            &flow().process,
            &selector,
        );

        assert!(authorization.is_none());
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

    fn process_direction_selector(
        directions: impl IntoIterator<Item = Direction>,
    ) -> Result<CompiledSelector, Box<dyn std::error::Error>> {
        named_process_direction_selector("curl", directions)
    }

    fn named_process_direction_selector(
        name: &str,
        directions: impl IntoIterator<Item = Direction>,
    ) -> Result<CompiledSelector, Box<dyn std::error::Error>> {
        Ok(Selector::term(
            ProcessSelector {
                names: vec![name.to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                directions: directions.into_iter().collect(),
                ..TrafficSelector::default()
            },
        )
        .compile()?)
    }

    fn source() -> DescriptorLease {
        DescriptorLease::new(100, 7, 9, 10).expect("test descriptor lease should be valid")
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
