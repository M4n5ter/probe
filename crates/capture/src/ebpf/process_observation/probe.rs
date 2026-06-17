use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

use aya::{
    Ebpf, EbpfError,
    maps::{HashMap as AyaHashMap, MapData, PerCpuArray, RingBuf},
    programs::{ProgramError, TracePoint},
};
use ebpf_abi::{
    EBPF_ADDRESS_FAMILY_INET, EBPF_ADDRESS_FAMILY_INET6, EBPF_ALLOWED_SOCKET_FDS_MAP_NAME,
    EBPF_EVENTS_MAP_NAME, EBPF_PROCESS_OUTPUT_LOSSES_MAP_NAME, EBPF_PROCESS_TRACEPOINT_SPECS,
    EBPF_SOCKET_FLOW_REMOTE_ENDPOINT_VALID, EBPF_SOCKET_FLOW_SOCKADDR_READ_FAILED,
    EBPF_SOCKET_FLOW_UNSUPPORTED_ADDRESS_FAMILY, EBPF_SOCKET_READ_READ_FAILED,
    EBPF_SOCKET_READ_TRUNCATED, EBPF_SOCKET_WRITE_READ_FAILED, EBPF_SOCKET_WRITE_TRUNCATED,
    EbpfAcceptObservation, EbpfConnectObservation, EbpfEventDecodeError, EbpfProcessProbeEvent,
    EbpfProcessTracepointSpec, EbpfSocketFdKey, EbpfSocketPayloadAllowance, EbpfSocketReadSample,
    EbpfSocketWriteSample, decode_process_probe_event,
};
use ebpf_object::{
    EbpfObjectProbe, EbpfObjectProbeConfig, EbpfObjectProbeReport, EbpfPreflightedObject,
};
use probe_core::TcpEndpoint;
use thiserror::Error;

use super::{
    EbpfAcceptTracepointObservation, EbpfCloseTracepointObservation,
    EbpfConnectTracepointObservation, EbpfObservedProcess, EbpfProcessObservation,
    EbpfSocketEndpoint, EbpfSocketReadObservation, EbpfSocketWriteObservation,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfProcessObservationProbeConfig {
    pub object_path: PathBuf,
}

impl EbpfProcessObservationProbeConfig {
    pub fn new(object_path: impl Into<PathBuf>) -> Self {
        Self {
            object_path: object_path.into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum EbpfProcessObservationProbeError {
    #[error("eBPF object preflight failed: {summary}")]
    ObjectPreflight {
        summary: String,
        report: Box<EbpfObjectProbeReport>,
    },
    #[error("failed to load eBPF object with aya: {source}")]
    Load { source: EbpfError },
    #[error("eBPF object is missing program {name}")]
    MissingProgram { name: &'static str },
    #[error("failed to {action} eBPF program {name}: {source}")]
    Program {
        name: &'static str,
        action: &'static str,
        source: ProgramError,
    },
    #[error("eBPF object is missing map {name}")]
    MissingMap { name: &'static str },
    #[error("failed to access eBPF map {name}: {source}")]
    Map {
        name: &'static str,
        source: aya::maps::MapError,
    },
    #[error("failed to decode eBPF process observation: {error:?}")]
    Decode { error: EbpfEventDecodeError },
}

impl EbpfProcessObservationProbeError {
    pub fn preflight_report(&self) -> Option<&EbpfObjectProbeReport> {
        match self {
            Self::ObjectPreflight { report, .. } => Some(report),
            _ => None,
        }
    }
}

pub struct EbpfProcessObservationProbe {
    _ebpf: Ebpf,
    events: RingBuf<MapData>,
    allowed_socket_fds: SocketAllowMap,
    output_losses: OutputLossMap,
}

impl EbpfProcessObservationProbe {
    pub fn load(
        config: EbpfProcessObservationProbeConfig,
    ) -> Result<Self, EbpfProcessObservationProbeError> {
        let object = EbpfObjectProbe::preflight(&EbpfObjectProbeConfig::process_observation(
            config.object_path,
        ))
        .map_err(|report| EbpfProcessObservationProbeError::ObjectPreflight {
            summary: report.summary(),
            report,
        })?;
        Self::load_preflighted(object)
    }

    fn load_preflighted(
        object: EbpfPreflightedObject,
    ) -> Result<Self, EbpfProcessObservationProbeError> {
        let mut ebpf = Ebpf::load(object.bytes())
            .map_err(|source| EbpfProcessObservationProbeError::Load { source })?;
        for spec in EBPF_PROCESS_TRACEPOINT_SPECS {
            load_and_attach_tracepoint(&mut ebpf, spec)?;
        }
        let events = open_events_ringbuf(&mut ebpf)?;
        let allowed_socket_fds = open_socket_allow_map(&mut ebpf)?;
        let output_losses = open_output_loss_map(&mut ebpf)?;
        Ok(Self {
            _ebpf: ebpf,
            events,
            allowed_socket_fds,
            output_losses,
        })
    }

    pub fn next_observation(
        &mut self,
    ) -> Result<Option<EbpfProcessObservation>, EbpfProcessObservationProbeError> {
        let Some(item) = self.events.next() else {
            return Ok(None);
        };
        decode_process_observation(&item).map(Some)
    }

    pub fn allow_socket_payload_sample(
        &mut self,
        tgid: u32,
        fd: i32,
        fd_table_epoch: u64,
        direction_mask: u8,
    ) -> Result<(), EbpfProcessObservationProbeError> {
        let key = EbpfSocketFdKey::new(tgid, fd).to_bpfel_bytes();
        let allowance = EbpfSocketPayloadAllowance::new(fd_table_epoch, direction_mask);
        self.allowed_socket_fds
            .insert(key, allowance.to_bpfel_bytes(), 0)
            .map_err(|source| EbpfProcessObservationProbeError::Map {
                name: EBPF_ALLOWED_SOCKET_FDS_MAP_NAME,
                source,
            })
    }

    pub fn process_output_loss_count(&mut self) -> Result<u64, EbpfProcessObservationProbeError> {
        let values = self.output_losses.get(&0, 0).map_err(|source| {
            EbpfProcessObservationProbeError::Map {
                name: EBPF_PROCESS_OUTPUT_LOSSES_MAP_NAME,
                source,
            }
        })?;
        Ok(values
            .iter()
            .copied()
            .fold(0u64, |total, value| total.saturating_add(value)))
    }
}

type SocketAllowMap = AyaHashMap<
    MapData,
    [u8; core::mem::size_of::<EbpfSocketFdKey>()],
    [u8; core::mem::size_of::<EbpfSocketPayloadAllowance>()],
>;
type OutputLossMap = PerCpuArray<MapData, u64>;

fn load_and_attach_tracepoint(
    ebpf: &mut Ebpf,
    spec: EbpfProcessTracepointSpec,
) -> Result<(), EbpfProcessObservationProbeError> {
    let program_name = spec.program_name;
    let program = ebpf
        .program_mut(program_name)
        .ok_or(EbpfProcessObservationProbeError::MissingProgram { name: program_name })?;
    let program: &mut TracePoint =
        program
            .try_into()
            .map_err(|source| EbpfProcessObservationProbeError::Program {
                name: program_name,
                action: "cast",
                source,
            })?;
    program
        .load()
        .map_err(|source| EbpfProcessObservationProbeError::Program {
            name: program_name,
            action: "load",
            source,
        })?;
    program
        .attach(spec.category, spec.tracepoint_name)
        .map_err(|source| EbpfProcessObservationProbeError::Program {
            name: program_name,
            action: "attach",
            source,
        })?;
    Ok(())
}

fn open_events_ringbuf(
    ebpf: &mut Ebpf,
) -> Result<RingBuf<MapData>, EbpfProcessObservationProbeError> {
    let map = ebpf.take_map(EBPF_EVENTS_MAP_NAME).ok_or(
        EbpfProcessObservationProbeError::MissingMap {
            name: EBPF_EVENTS_MAP_NAME,
        },
    )?;
    RingBuf::try_from(map).map_err(|source| EbpfProcessObservationProbeError::Map {
        name: EBPF_EVENTS_MAP_NAME,
        source,
    })
}

fn open_socket_allow_map(
    ebpf: &mut Ebpf,
) -> Result<SocketAllowMap, EbpfProcessObservationProbeError> {
    let map = ebpf.take_map(EBPF_ALLOWED_SOCKET_FDS_MAP_NAME).ok_or(
        EbpfProcessObservationProbeError::MissingMap {
            name: EBPF_ALLOWED_SOCKET_FDS_MAP_NAME,
        },
    )?;
    SocketAllowMap::try_from(map).map_err(|source| EbpfProcessObservationProbeError::Map {
        name: EBPF_ALLOWED_SOCKET_FDS_MAP_NAME,
        source,
    })
}

fn open_output_loss_map(
    ebpf: &mut Ebpf,
) -> Result<OutputLossMap, EbpfProcessObservationProbeError> {
    let map = ebpf.take_map(EBPF_PROCESS_OUTPUT_LOSSES_MAP_NAME).ok_or(
        EbpfProcessObservationProbeError::MissingMap {
            name: EBPF_PROCESS_OUTPUT_LOSSES_MAP_NAME,
        },
    )?;
    OutputLossMap::try_from(map).map_err(|source| EbpfProcessObservationProbeError::Map {
        name: EBPF_PROCESS_OUTPUT_LOSSES_MAP_NAME,
        source,
    })
}

fn decode_process_observation(
    bytes: &[u8],
) -> Result<EbpfProcessObservation, EbpfProcessObservationProbeError> {
    process_observation_from_event(
        decode_process_probe_event(bytes)
            .map_err(|error| EbpfProcessObservationProbeError::Decode { error })?,
    )
}

fn process_observation_from_event(
    event: EbpfProcessProbeEvent,
) -> Result<EbpfProcessObservation, EbpfProcessObservationProbeError> {
    match event.kind() {
        Some(ebpf_abi::EbpfEventKind::ConnectTracepointObserved) => {
            let connect = connect_observation_from_event(&event);
            Ok(EbpfProcessObservation::Connect(
                EbpfConnectTracepointObservation {
                    process: observed_process_from_event(&event),
                    fd: connect.fd,
                    addrlen: connect.addrlen,
                    fd_table_epoch: connect.fd_table_epoch,
                    endpoint: connect_endpoint_from_event(&event),
                },
            ))
        }
        Some(ebpf_abi::EbpfEventKind::AcceptTracepointObserved) => {
            let accept = accept_observation_from_event(&event);
            Ok(EbpfProcessObservation::Accept(
                EbpfAcceptTracepointObservation {
                    process: observed_process_from_event(&event),
                    fd: accept.fd,
                    listen_fd: accept.listen_fd,
                    addrlen: accept.addrlen,
                    fd_table_epoch: accept.fd_table_epoch,
                    endpoint: accept_endpoint_from_event(&event),
                },
            ))
        }
        Some(ebpf_abi::EbpfEventKind::CloseTracepointObserved) => {
            let close = close_observation_from_event(&event);
            Ok(EbpfProcessObservation::Close(
                EbpfCloseTracepointObservation {
                    process: observed_process_from_event(&event),
                    fd: close.fd,
                },
            ))
        }
        Some(ebpf_abi::EbpfEventKind::SocketWriteSampled) => {
            let sample = socket_write_sample_from_event(&event);
            Ok(EbpfProcessObservation::Write(EbpfSocketWriteObservation {
                process: observed_process_from_event(&event),
                fd: sample.fd,
                original_len: sample.original_len,
                buffer: sample.buffer[..usize::from(sample.captured_len)].to_vec(),
                truncated: event.flags() & EBPF_SOCKET_WRITE_TRUNCATED != 0,
                read_failed: event.flags() & EBPF_SOCKET_WRITE_READ_FAILED != 0,
            }))
        }
        Some(ebpf_abi::EbpfEventKind::SocketReadSampled) => {
            let sample = socket_read_sample_from_event(&event);
            Ok(EbpfProcessObservation::Read(EbpfSocketReadObservation {
                process: observed_process_from_event(&event),
                fd: sample.fd,
                original_len: sample.original_len,
                buffer: sample.buffer[..usize::from(sample.captured_len)].to_vec(),
                truncated: event.flags() & EBPF_SOCKET_READ_TRUNCATED != 0,
                read_failed: event.flags() & EBPF_SOCKET_READ_READ_FAILED != 0,
            }))
        }
        _ => unreachable!("decode_process_probe_event only accepts process observation events"),
    }
}

fn observed_process_from_event(event: &EbpfProcessProbeEvent) -> EbpfObservedProcess {
    let header = event.header();
    EbpfObservedProcess {
        pid: header.pid,
        tgid: header.tgid,
        uid: header.uid,
        gid: header.gid,
        command: event.command(),
    }
}

fn connect_endpoint_from_event(event: &EbpfProcessProbeEvent) -> EbpfSocketEndpoint {
    let connect = connect_observation_from_event(event);
    socket_flow_endpoint_from_flags(
        event.flags(),
        connect.address_family,
        connect.remote_port,
        connect.remote_address,
    )
}

fn accept_endpoint_from_event(event: &EbpfProcessProbeEvent) -> EbpfSocketEndpoint {
    let accept = accept_observation_from_event(event);
    socket_flow_endpoint_from_flags(
        event.flags(),
        accept.address_family,
        accept.remote_port,
        accept.remote_address,
    )
}

fn socket_flow_endpoint_from_flags(
    flags: u16,
    address_family: u16,
    remote_port: u16,
    remote_address: [u8; 16],
) -> EbpfSocketEndpoint {
    if flags & EBPF_SOCKET_FLOW_REMOTE_ENDPOINT_VALID != 0 {
        return remote_endpoint_from_parts(address_family, remote_port, remote_address)
            .map(EbpfSocketEndpoint::Remote)
            .unwrap_or(EbpfSocketEndpoint::UnsupportedAddressFamily {
                value: address_family,
            });
    }
    if flags & EBPF_SOCKET_FLOW_SOCKADDR_READ_FAILED != 0 {
        return EbpfSocketEndpoint::SockaddrReadFailed;
    }
    if flags & EBPF_SOCKET_FLOW_UNSUPPORTED_ADDRESS_FAMILY != 0 {
        return EbpfSocketEndpoint::UnsupportedAddressFamily {
            value: address_family,
        };
    }
    EbpfSocketEndpoint::Missing
}

fn connect_observation_from_event(event: &EbpfProcessProbeEvent) -> EbpfConnectObservation {
    event
        .connect_observation()
        .expect("connect event kind should expose connect observation")
}

fn accept_observation_from_event(event: &EbpfProcessProbeEvent) -> EbpfAcceptObservation {
    event
        .accept_observation()
        .expect("accept event kind should expose accept observation")
}

fn close_observation_from_event(event: &EbpfProcessProbeEvent) -> ebpf_abi::EbpfCloseObservation {
    event
        .close_observation()
        .expect("close event kind should expose close observation")
}

fn socket_write_sample_from_event(event: &EbpfProcessProbeEvent) -> EbpfSocketWriteSample {
    event
        .socket_write_sample()
        .expect("write event kind should expose socket write sample")
}

fn socket_read_sample_from_event(event: &EbpfProcessProbeEvent) -> EbpfSocketReadSample {
    event
        .socket_read_sample()
        .expect("read event kind should expose socket read sample")
}

fn remote_endpoint_from_parts(
    address_family: u16,
    remote_port: u16,
    remote_address: [u8; 16],
) -> Option<TcpEndpoint> {
    let address = match address_family {
        EBPF_ADDRESS_FAMILY_INET => IpAddr::V4(Ipv4Addr::new(
            remote_address[0],
            remote_address[1],
            remote_address[2],
            remote_address[3],
        )),
        EBPF_ADDRESS_FAMILY_INET6 => {
            let address = Ipv6Addr::from(remote_address);
            address
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(address))
        }
        _ => return None,
    };
    Some(TcpEndpoint::new(address, remote_port))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use ebpf_abi::{
        EBPF_ACCEPT_REMOTE_ENDPOINT_VALID, EBPF_ADDRESS_FAMILY_INET, EBPF_ADDRESS_FAMILY_INET6,
        EBPF_CONNECT_REMOTE_ENDPOINT_VALID, EBPF_CONNECT_SOCKADDR_READ_FAILED,
        EBPF_SOCKET_READ_SAMPLE_BYTES, EBPF_SOCKET_READ_TRUNCATED, EBPF_SOCKET_WRITE_SAMPLE_BYTES,
        EBPF_SOCKET_WRITE_TRUNCATED, EbpfAcceptObservation, EbpfCloseObservation,
        EbpfConnectObservation, EbpfProcessProbeEvent, EbpfSocketReadSample, EbpfSocketWriteSample,
    };
    use probe_core::TcpEndpoint;

    use super::*;

    #[test]
    fn process_observation_decodes_valid_wire_event() -> Result<(), Box<dyn std::error::Error>> {
        let event = EbpfProcessProbeEvent::connect_tracepoint_observed(
            11,
            22,
            33,
            44,
            nul_padded_command("curl"),
            EbpfConnectObservation::remote_endpoint(
                7,
                16,
                EBPF_ADDRESS_FAMILY_INET,
                443,
                [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            )
            .with_fd_table_epoch(9),
            EBPF_CONNECT_REMOTE_ENDPOINT_VALID,
        );

        let observation =
            decode_process_observation(&ebpf_abi::encode_process_probe_event(&event))?;
        match observation {
            EbpfProcessObservation::Connect(connect) => {
                assert_eq!(connect.process.pid, 11);
                assert_eq!(connect.process.tgid, 22);
                assert_eq!(connect.process.uid, 33);
                assert_eq!(connect.process.gid, 44);
                assert_eq!(connect.process.command_lossy(), "curl");
                assert_eq!(connect.fd, 7);
                assert_eq!(connect.addrlen, 16);
                assert_eq!(connect.fd_table_epoch, 9);
                assert_eq!(
                    connect.endpoint,
                    EbpfSocketEndpoint::Remote(TcpEndpoint::new(
                        Ipv4Addr::new(127, 0, 0, 1).into(),
                        443
                    ))
                );
            }
            observation => panic!("unexpected observation: {observation:?}"),
        }
        Ok(())
    }

    #[test]
    fn process_observation_decodes_valid_accept_wire_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let event = EbpfProcessProbeEvent::accept_tracepoint_observed(
            11,
            22,
            33,
            44,
            nul_padded_command("server"),
            EbpfAcceptObservation::remote_endpoint(
                9,
                3,
                16,
                EBPF_ADDRESS_FAMILY_INET,
                50_000,
                [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            )
            .with_fd_table_epoch(12),
            EBPF_ACCEPT_REMOTE_ENDPOINT_VALID,
        );

        let observation =
            decode_process_observation(&ebpf_abi::encode_process_probe_event(&event))?;
        match observation {
            EbpfProcessObservation::Accept(accept) => {
                assert_eq!(accept.process.pid, 11);
                assert_eq!(accept.process.tgid, 22);
                assert_eq!(accept.process.command_lossy(), "server");
                assert_eq!(accept.fd, 9);
                assert_eq!(accept.listen_fd, 3);
                assert_eq!(accept.addrlen, 16);
                assert_eq!(accept.fd_table_epoch, 12);
                assert_eq!(
                    accept.endpoint,
                    EbpfSocketEndpoint::Remote(TcpEndpoint::new(
                        Ipv4Addr::new(127, 0, 0, 1).into(),
                        50_000
                    ))
                );
            }
            observation => panic!("unexpected observation: {observation:?}"),
        }
        Ok(())
    }

    #[test]
    fn process_observation_decodes_valid_close_wire_event() -> Result<(), Box<dyn std::error::Error>>
    {
        let event = EbpfProcessProbeEvent::close_tracepoint_observed(
            11,
            22,
            33,
            44,
            nul_padded_command("curl"),
            EbpfCloseObservation::observed(7),
        );

        let observation =
            decode_process_observation(&ebpf_abi::encode_process_probe_event(&event))?;
        match observation {
            EbpfProcessObservation::Close(close) => {
                assert_eq!(close.process.pid, 11);
                assert_eq!(close.process.tgid, 22);
                assert_eq!(close.process.uid, 33);
                assert_eq!(close.process.gid, 44);
                assert_eq!(close.process.command_lossy(), "curl");
                assert_eq!(close.fd, 7);
            }
            observation => panic!("unexpected observation: {observation:?}"),
        }
        Ok(())
    }

    #[test]
    fn process_observation_decodes_socket_write_sample() -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = [0; EBPF_SOCKET_WRITE_SAMPLE_BYTES];
        buffer[..5].copy_from_slice(b"GET /");
        let event = EbpfProcessProbeEvent::socket_write_sampled(
            11,
            22,
            33,
            44,
            nul_padded_command("curl"),
            EbpfSocketWriteSample::new(7, 10, 5, buffer),
            EBPF_SOCKET_WRITE_TRUNCATED,
        );

        let observation =
            decode_process_observation(&ebpf_abi::encode_process_probe_event(&event))?;
        match observation {
            EbpfProcessObservation::Write(write) => {
                assert_eq!(write.process.pid, 11);
                assert_eq!(write.process.tgid, 22);
                assert_eq!(write.process.uid, 33);
                assert_eq!(write.process.gid, 44);
                assert_eq!(write.process.command_lossy(), "curl");
                assert_eq!(write.fd, 7);
                assert_eq!(write.original_len, 10);
                assert_eq!(write.buffer, b"GET /");
                assert!(write.truncated);
                assert!(!write.read_failed);
            }
            observation => panic!("unexpected observation: {observation:?}"),
        }
        Ok(())
    }

    #[test]
    fn process_observation_decodes_socket_read_sample() -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = [0; EBPF_SOCKET_READ_SAMPLE_BYTES];
        buffer[..5].copy_from_slice(b"HTTP/");
        let event = EbpfProcessProbeEvent::socket_read_sampled(
            11,
            22,
            33,
            44,
            nul_padded_command("curl"),
            EbpfSocketReadSample::new(7, 10, 5, buffer),
            EBPF_SOCKET_READ_TRUNCATED,
        );

        let observation =
            decode_process_observation(&ebpf_abi::encode_process_probe_event(&event))?;
        match observation {
            EbpfProcessObservation::Read(read) => {
                assert_eq!(read.process.pid, 11);
                assert_eq!(read.process.tgid, 22);
                assert_eq!(read.process.uid, 33);
                assert_eq!(read.process.gid, 44);
                assert_eq!(read.process.command_lossy(), "curl");
                assert_eq!(read.fd, 7);
                assert_eq!(read.original_len, 10);
                assert_eq!(read.buffer, b"HTTP/");
                assert!(read.truncated);
                assert!(!read.read_failed);
            }
            observation => panic!("unexpected observation: {observation:?}"),
        }
        Ok(())
    }

    #[test]
    fn process_observation_decodes_empty_truncated_socket_write_sample()
    -> Result<(), Box<dyn std::error::Error>> {
        let event = EbpfProcessProbeEvent::socket_write_sampled(
            11,
            22,
            33,
            44,
            nul_padded_command("curl"),
            EbpfSocketWriteSample::new(7, 10, 0, [0; EBPF_SOCKET_WRITE_SAMPLE_BYTES]),
            EBPF_SOCKET_WRITE_TRUNCATED,
        );

        let observation =
            decode_process_observation(&ebpf_abi::encode_process_probe_event(&event))?;
        match observation {
            EbpfProcessObservation::Write(write) => {
                assert_eq!(write.fd, 7);
                assert_eq!(write.original_len, 10);
                assert!(write.buffer.is_empty());
                assert!(write.truncated);
                assert!(!write.read_failed);
            }
            observation => panic!("unexpected observation: {observation:?}"),
        }
        Ok(())
    }

    #[test]
    fn process_observation_normalizes_ipv4_mapped_ipv6_remote_endpoint()
    -> Result<(), Box<dyn std::error::Error>> {
        let event = EbpfProcessProbeEvent::connect_tracepoint_observed(
            11,
            22,
            33,
            44,
            nul_padded_command("curl"),
            EbpfConnectObservation::remote_endpoint(
                7,
                28,
                EBPF_ADDRESS_FAMILY_INET6,
                443,
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1],
            ),
            EBPF_CONNECT_REMOTE_ENDPOINT_VALID,
        );

        let observation =
            decode_process_observation(&ebpf_abi::encode_process_probe_event(&event))?;
        match observation {
            EbpfProcessObservation::Connect(connect) => {
                assert_eq!(
                    connect.endpoint,
                    EbpfSocketEndpoint::Remote(TcpEndpoint::new(
                        Ipv4Addr::new(127, 0, 0, 1).into(),
                        443
                    ))
                );
            }
            observation => panic!("unexpected observation: {observation:?}"),
        }
        Ok(())
    }

    #[test]
    fn process_observation_marks_unavailable_remote_endpoint()
    -> Result<(), Box<dyn std::error::Error>> {
        let event = EbpfProcessProbeEvent::connect_tracepoint_observed(
            11,
            22,
            33,
            44,
            nul_padded_command("curl"),
            EbpfConnectObservation::unavailable(7, 0),
            EBPF_CONNECT_SOCKADDR_READ_FAILED,
        );

        let observation =
            decode_process_observation(&ebpf_abi::encode_process_probe_event(&event))?;

        match observation {
            EbpfProcessObservation::Connect(connect) => {
                assert_eq!(connect.endpoint, EbpfSocketEndpoint::SockaddrReadFailed);
            }
            observation => panic!("unexpected observation: {observation:?}"),
        }
        Ok(())
    }

    #[test]
    fn process_observation_probe_load_fails_before_aya_for_missing_object()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let error = match EbpfProcessObservationProbe::load(EbpfProcessObservationProbeConfig::new(
            temp.path().join("missing.bpf.o"),
        )) {
            Ok(_) => panic!("missing object should fail during preflight"),
            Err(error) => error,
        };

        let report = error
            .preflight_report()
            .expect("missing object should preserve preflight report");
        assert!(!report.object_available());
        assert!(!report.preflight_available());
        assert!(report.summary().contains("does not exist"));
        Ok(())
    }

    fn nul_padded_command(command: &str) -> [u8; 16] {
        let mut bytes = [0; 16];
        for (target, source) in bytes.iter_mut().zip(command.as_bytes()) {
            *target = *source;
        }
        bytes
    }
}
