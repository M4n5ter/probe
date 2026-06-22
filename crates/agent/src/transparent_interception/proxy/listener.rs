use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddrV4, SocketAddrV6, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use super::{
    proxy_io_error, registry::RelayRegistry, relay::spawn_relay, state::TransparentProxyRuntime,
};
use crate::transparent_interception::{
    TransparentInterceptionError, TransparentInterceptionIpFamily,
};

const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(20);

pub(super) struct ManagedTransparentProxyListener {
    pub(super) family: TransparentInterceptionIpFamily,
    pub(super) thread: JoinHandle<Result<(), String>>,
}

pub(super) fn start_listeners(
    listen_port: u16,
    families: Vec<TransparentInterceptionIpFamily>,
    shutdown_requested: Arc<AtomicBool>,
    relays: RelayRegistry,
    runtime: TransparentProxyRuntime,
) -> Result<Vec<ManagedTransparentProxyListener>, TransparentInterceptionError> {
    let mut listeners = Vec::new();
    for family in families {
        match transparent_listener(family, listen_port) {
            Ok(listener) => listeners.push((family, listener)),
            Err(error) => {
                runtime.record_listener_failure(family);
                return Err(error);
            }
        }
    }
    runtime.mark_running(
        listeners
            .iter()
            .map(|(family, _)| *family)
            .collect::<Vec<_>>(),
    );
    Ok(listeners
        .into_iter()
        .map(|(family, listener)| {
            let shutdown = Arc::clone(&shutdown_requested);
            let relay_registry = relays.clone();
            let proxy_runtime = runtime.clone();
            let thread = thread::spawn(move || {
                listener_loop(
                    listener,
                    family,
                    listen_port,
                    shutdown,
                    relay_registry,
                    proxy_runtime,
                )
            });
            ManagedTransparentProxyListener { family, thread }
        })
        .collect())
}

fn transparent_listener(
    family: TransparentInterceptionIpFamily,
    port: u16,
) -> Result<Socket, TransparentInterceptionError> {
    let socket = match family {
        TransparentInterceptionIpFamily::Ipv4 => {
            Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
                .map_err(proxy_io_error("create IPv4 transparent listener"))?
        }
        TransparentInterceptionIpFamily::Ipv6 => {
            Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))
                .map_err(proxy_io_error("create IPv6 transparent listener"))?
        }
    };
    socket
        .set_reuse_address(true)
        .map_err(proxy_io_error("set transparent listener reuse address"))?;
    match family {
        TransparentInterceptionIpFamily::Ipv4 => {
            socket
                .set_ip_transparent_v4(true)
                .map_err(proxy_io_error("set IPv4 IP_TRANSPARENT"))?;
            socket
                .bind(&SockAddr::from(SocketAddrV4::new(
                    Ipv4Addr::UNSPECIFIED,
                    port,
                )))
                .map_err(proxy_io_error("bind IPv4 transparent listener"))?;
        }
        TransparentInterceptionIpFamily::Ipv6 => {
            socket
                .set_only_v6(true)
                .map_err(proxy_io_error("set IPv6-only transparent listener"))?;
            socket
                .set_ip_transparent_v6(true)
                .map_err(proxy_io_error("set IPv6 IP_TRANSPARENT"))?;
            socket
                .bind(&SockAddr::from(SocketAddrV6::new(
                    Ipv6Addr::UNSPECIFIED,
                    port,
                    0,
                    0,
                )))
                .map_err(proxy_io_error("bind IPv6 transparent listener"))?;
        }
    }
    socket
        .listen(256)
        .map_err(proxy_io_error("listen on transparent listener"))?;
    socket
        .set_nonblocking(true)
        .map_err(proxy_io_error("set transparent listener nonblocking"))?;
    Ok(socket)
}

fn listener_loop(
    listener: Socket,
    family: TransparentInterceptionIpFamily,
    listen_port: u16,
    shutdown_requested: Arc<AtomicBool>,
    relay_registry: RelayRegistry,
    runtime: TransparentProxyRuntime,
) -> Result<(), String> {
    let mut relay_threads = Vec::new();
    while !shutdown_requested.load(Ordering::SeqCst) {
        reap_finished_relays(&mut relay_threads);
        match listener.accept() {
            Ok((accepted, peer)) => match relay_registry.try_acquire_slot() {
                Some(slot) => {
                    runtime.record_accepted_relay();
                    relay_threads.push(spawn_relay(
                        accepted,
                        peer,
                        listen_port,
                        Arc::clone(&shutdown_requested),
                        relay_registry.clone(),
                        slot,
                        runtime.clone(),
                    ));
                }
                None => {
                    runtime.record_rejected_relay();
                    let _ = TcpStream::from(accepted).shutdown(Shutdown::Both);
                    eprintln!(
                        "managed transparent proxy rejected connection because active relay limit is reached"
                    );
                }
            },
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                runtime.record_listener_failure(family);
                return Err(format!("accept transparent connection: {error}"));
            }
        }
    }
    relay_registry.shutdown_all();
    join_relays(relay_threads);
    Ok(())
}

fn reap_finished_relays(relays: &mut Vec<JoinHandle<()>>) {
    let mut index = 0;
    while index < relays.len() {
        if relays[index].is_finished() {
            let relay = relays.swap_remove(index);
            if relay.join().is_err() {
                eprintln!("managed transparent proxy relay thread panicked");
            }
        } else {
            index += 1;
        }
    }
}

fn join_relays(relays: Vec<JoinHandle<()>>) {
    for relay in relays {
        if relay.join().is_err() {
            eprintln!("managed transparent proxy relay thread panicked");
        }
    }
}
