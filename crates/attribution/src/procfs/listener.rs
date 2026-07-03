use std::net::IpAddr;

use probe_core::{ProcessContext, TcpEndpoint};

pub const PROCFS_SOCKET_CONFIDENCE: u8 = 60;
pub const DOCKER_PROXY_TARGET_CONFIDENCE: u8 = 55;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpListenerProcessContext {
    pub observed: TcpListenerObservedSocket,
    pub owner: TcpListenerOwnerContext,
}

impl TcpListenerProcessContext {
    pub fn from_observed_socket(observed: TcpListenerObservedSocket) -> Self {
        let owner = TcpListenerOwnerContext {
            process: observed.process.clone(),
            confidence: observed.confidence,
            source: TcpListenerOwnerSource::SocketHolder,
        };
        Self { observed, owner }
    }

    pub fn with_owner(self, owner: TcpListenerOwnerContext) -> Self {
        Self { owner, ..self }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpListenerObservedSocket {
    pub process: ProcessContext,
    pub confidence: u8,
    pub socket_inode: u64,
    pub local: TcpEndpoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpListenerOwnerContext {
    pub process: ProcessContext,
    pub confidence: u8,
    pub source: TcpListenerOwnerSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpListenerOwnerSource {
    SocketHolder,
    DockerProxyTarget {
        target_local: TcpEndpoint,
        target_socket_inode: u64,
    },
}

pub(super) fn docker_proxy_target_endpoint(process: &ProcessContext) -> Option<TcpEndpoint> {
    if !is_docker_proxy_process(process) {
        return None;
    }
    let container_ip = cmdline_flag_value(&process.cmdline, "-container-ip")?
        .parse::<IpAddr>()
        .ok()?;
    let container_port = cmdline_flag_value(&process.cmdline, "-container-port")?
        .parse::<u16>()
        .ok()?;
    Some(TcpEndpoint::new(container_ip, container_port))
}

fn is_docker_proxy_process(process: &ProcessContext) -> bool {
    process.name == "docker-proxy"
        || process
            .cmdline
            .first()
            .and_then(|arg| arg.rsplit('/').next())
            .is_some_and(|name| name == "docker-proxy")
}

fn cmdline_flag_value<'a>(cmdline: &'a [String], flag: &str) -> Option<&'a str> {
    let mut args = cmdline.iter();
    while let Some(arg) = args.next() {
        if arg == flag {
            return args.next().map(String::as_str);
        }
        if let Some(value) = arg
            .strip_prefix(flag)
            .and_then(|rest| rest.strip_prefix('='))
        {
            return Some(value);
        }
    }
    None
}
