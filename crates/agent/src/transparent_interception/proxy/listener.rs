use std::{
    io,
    net::{Shutdown, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use socket2::Socket;

use super::{
    proxy_io_error,
    registry::RelayRegistry,
    relay::{TransparentProxyRelayPlan, spawn_relay},
    state::TransparentProxyRuntime,
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
    relay_plan: TransparentProxyRelayPlan,
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
            let listener_relay_plan = relay_plan.clone();
            let thread = thread::spawn(move || {
                listener_loop(
                    listener,
                    family,
                    listener_relay_plan,
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
    probe_io::bind_transparent_tcp_socket(transparent_tcp_family(family), port, 256)
        .map_err(proxy_io_error("bind transparent listener"))
}

fn transparent_tcp_family(
    family: TransparentInterceptionIpFamily,
) -> probe_io::TransparentTcpFamily {
    match family {
        TransparentInterceptionIpFamily::Ipv4 => probe_io::TransparentTcpFamily::Ipv4,
        TransparentInterceptionIpFamily::Ipv6 => probe_io::TransparentTcpFamily::Ipv6,
    }
}

fn listener_loop(
    listener: Socket,
    family: TransparentInterceptionIpFamily,
    plan: TransparentProxyRelayPlan,
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
                    relay_threads.push(spawn_relay(
                        accepted,
                        peer,
                        plan.clone(),
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
