use std::{
    io,
    net::{SocketAddr, TcpListener},
};

use probe_io::{TransparentTcpFamily, bind_transparent_tcp_listener};

use super::MitmProxyConfig;
use crate::{MitmProxyError, error::io_error};

pub(super) struct ProxyListeners {
    pub(super) data: TcpListener,
    pub(super) policy_hook: Option<TcpListener>,
}

impl ProxyListeners {
    pub(super) fn bind(config: &MitmProxyConfig) -> Result<Self, MitmProxyError> {
        Ok(Self {
            data: bind_data_listener(config.listen, config.transparent_listen)
                .map_err(io_error("bind MITM proxy data listener"))?,
            policy_hook: config
                .policy_hook_listen
                .map(bind_listener)
                .transpose()
                .map_err(io_error("bind MITM proxy policy hook listener"))?,
        })
    }

    #[cfg(test)]
    pub(super) fn from_bound(
        data: TcpListener,
        policy_hook: Option<TcpListener>,
    ) -> Result<Self, io::Error> {
        Ok(Self {
            data: prepare_listener(data)?,
            policy_hook: policy_hook.map(prepare_listener).transpose()?,
        })
    }
}

fn bind_data_listener(listen: SocketAddr, transparent: bool) -> io::Result<TcpListener> {
    if transparent {
        return bind_transparent_listener(listen);
    }
    bind_listener(listen)
}

fn bind_listener(listen: SocketAddr) -> io::Result<TcpListener> {
    prepare_listener(TcpListener::bind(listen)?)
}

fn bind_transparent_listener(listen: SocketAddr) -> io::Result<TcpListener> {
    bind_transparent_tcp_listener(
        TransparentTcpFamily::for_address(listen),
        listen.port(),
        256,
    )
}

fn prepare_listener(listener: TcpListener) -> io::Result<TcpListener> {
    listener.set_nonblocking(true)?;
    Ok(listener)
}
