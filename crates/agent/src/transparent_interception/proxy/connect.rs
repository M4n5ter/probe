use std::{
    io,
    net::{SocketAddr, TcpStream},
    time::Duration,
};

use probe_io::{TcpConnectOptions, TcpSocketMark, connect_tcp as connect_tcp_with_options};

#[derive(Clone, Copy, Debug)]
pub(super) struct TransparentProxyUpstreamConnectPlan {
    timeout: Duration,
    proxy_bypass_mark: Option<TcpSocketMark>,
}

impl TransparentProxyUpstreamConnectPlan {
    pub(super) fn new(timeout: Duration, proxy_bypass_mark: Option<TcpSocketMark>) -> Self {
        Self {
            timeout,
            proxy_bypass_mark,
        }
    }

    pub(super) fn proxy_bypass_mark(&self) -> Option<TcpSocketMark> {
        self.proxy_bypass_mark
    }
}

pub(super) fn connect_tcp(
    target: SocketAddr,
    plan: TransparentProxyUpstreamConnectPlan,
) -> io::Result<TcpStream> {
    let mut options = TcpConnectOptions::new(plan.timeout);
    if let Some(mark) = plan.proxy_bypass_mark() {
        options = options.with_socket_mark(mark);
    }
    connect_tcp_with_options(target, options)
}
