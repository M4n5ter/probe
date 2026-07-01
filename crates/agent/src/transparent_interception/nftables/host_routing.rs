use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

use futures_util::TryStreamExt;
use rtnetlink::{
    Handle, RouteMessageBuilder, new_connection,
    packet_route::{
        address::AddressAttribute,
        route::{RouteMessage, RouteProtocol, RouteScope, RouteType},
    },
};
use transparent_linux::{PolicyRouteOperation, TransparentLinuxIpFamily};

use crate::transparent_interception::TransparentInterceptionError;

const HOST_ROUTING_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) type SharedHostRouting = Arc<dyn HostRouting + Send + Sync>;

pub(super) trait HostRouting {
    fn local_addresses(&self) -> Result<Vec<IpAddr>, TransparentInterceptionError>;

    fn apply_policy_route_operation(
        &self,
        operation: PolicyRouteOperation,
    ) -> Result<(), TransparentInterceptionError>;
}

pub(super) struct RtnetlinkHostRouting {
    requests: mpsc::Sender<HostRoutingRequest>,
}

impl RtnetlinkHostRouting {
    pub(super) fn new() -> Result<Self, TransparentInterceptionError> {
        let (requests, receiver) = mpsc::channel();
        let (ready_sender, ready_receiver) = mpsc::channel();
        thread::Builder::new()
            .name("traffic-probe-rtnetlink".to_string())
            .spawn(move || run_worker(receiver, ready_sender))
            .map_err(|error| {
                host_routing_error(format!("failed to start RTNETLINK worker: {error}"))
            })?;

        ready_receiver
            .recv_timeout(HOST_ROUTING_TIMEOUT)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => host_routing_error(format!(
                    "RTNETLINK worker did not start within {}ms",
                    HOST_ROUTING_TIMEOUT.as_millis()
                )),
                mpsc::RecvTimeoutError::Disconnected => {
                    host_routing_error("RTNETLINK worker did not start")
                }
            })?
            .map_err(host_routing_error)?;
        Ok(Self { requests })
    }

    fn request<T>(
        &self,
        request: impl FnOnce(mpsc::Sender<Result<T, String>>) -> HostRoutingRequest,
    ) -> Result<T, TransparentInterceptionError> {
        let (reply_sender, reply_receiver) = mpsc::channel();
        self.requests.send(request(reply_sender)).map_err(|error| {
            host_routing_error(format!("RTNETLINK worker is unavailable: {error}"))
        })?;
        reply_receiver
            .recv_timeout(HOST_ROUTING_TIMEOUT)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => host_routing_error(format!(
                    "RTNETLINK worker did not reply within {}ms",
                    HOST_ROUTING_TIMEOUT.as_millis()
                )),
                mpsc::RecvTimeoutError::Disconnected => {
                    host_routing_error("RTNETLINK worker dropped reply")
                }
            })?
            .map_err(host_routing_error)
    }
}

impl HostRouting for RtnetlinkHostRouting {
    fn local_addresses(&self) -> Result<Vec<IpAddr>, TransparentInterceptionError> {
        self.request(|reply| HostRoutingRequest::LocalAddresses { reply })
    }

    fn apply_policy_route_operation(
        &self,
        operation: PolicyRouteOperation,
    ) -> Result<(), TransparentInterceptionError> {
        self.request(|reply| HostRoutingRequest::ApplyPolicyRouteOperation { operation, reply })
    }
}

enum HostRoutingRequest {
    LocalAddresses {
        reply: mpsc::Sender<Result<Vec<IpAddr>, String>>,
    },
    ApplyPolicyRouteOperation {
        operation: PolicyRouteOperation,
        reply: mpsc::Sender<Result<(), String>>,
    },
}

fn run_worker(
    receiver: mpsc::Receiver<HostRoutingRequest>,
    ready_sender: mpsc::Sender<Result<(), String>>,
) {
    let ready_sender_for_runtime = ready_sender.clone();
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| format!("failed to build RTNETLINK runtime: {error}"))
        .and_then(|runtime| {
            runtime.block_on(async move {
                let (connection, handle, _) = new_connection()
                    .map_err(|error| format!("failed to open RTNETLINK socket: {error}"))?;
                tokio::spawn(connection);
                let _ = ready_sender_for_runtime.send(Ok(()));
                while let Ok(request) = receiver.recv() {
                    handle_request(&handle, request).await;
                }
                Ok(())
            })
        });

    if let Err(error) = result {
        let _ = ready_sender.send(Err(error));
    }
}

async fn handle_request(handle: &Handle, request: HostRoutingRequest) {
    match request {
        HostRoutingRequest::LocalAddresses { reply } => {
            let _ = reply.send(
                with_host_routing_timeout("read RTNETLINK addresses", load_local_addresses(handle))
                    .await,
            );
        }
        HostRoutingRequest::ApplyPolicyRouteOperation { operation, reply } => {
            let _ = reply.send(
                with_host_routing_timeout(
                    "apply RTNETLINK policy route operation",
                    apply_policy_route_operation(handle, operation),
                )
                .await,
            );
        }
    }
}

async fn with_host_routing_timeout<T>(
    action: &'static str,
    future: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    tokio::time::timeout(HOST_ROUTING_TIMEOUT, future)
        .await
        .map_err(|_| {
            format!(
                "{action} timed out after {}ms",
                HOST_ROUTING_TIMEOUT.as_millis()
            )
        })?
}

async fn load_local_addresses(handle: &Handle) -> Result<Vec<IpAddr>, String> {
    let mut addresses = Vec::new();
    let mut stream = handle.address().get().execute();
    while let Some(message) = stream
        .try_next()
        .await
        .map_err(|error| format!("failed to read RTNETLINK addresses: {error}"))?
    {
        addresses.extend(local_addresses_from_message(&message.attributes));
    }
    Ok(addresses)
}

fn local_addresses_from_message(attributes: &[AddressAttribute]) -> Vec<IpAddr> {
    let mut addresses = Vec::new();
    let mut fallback = None;
    for attribute in attributes {
        match attribute {
            AddressAttribute::Local(address) => addresses.push(*address),
            AddressAttribute::Address(address) => fallback = Some(*address),
            _ => {}
        }
    }
    if addresses.is_empty()
        && let Some(address) = fallback
    {
        addresses.push(address);
    }
    addresses
}

async fn apply_policy_route_operation(
    handle: &Handle,
    operation: PolicyRouteOperation,
) -> Result<(), String> {
    match operation {
        PolicyRouteOperation::AddFwmarkRule(rule) => {
            add_fwmark_rule(handle, rule.family(), rule.mark(), rule.route_table()).await
        }
        PolicyRouteOperation::DeleteFwmarkRule(rule) => {
            delete_fwmark_rule(handle, rule.family(), rule.mark(), rule.route_table()).await
        }
        PolicyRouteOperation::ReplaceLocalRoute(route) => {
            replace_local_route(handle, route.family(), route.route_table()).await
        }
        PolicyRouteOperation::DeleteLocalRoute(route) => {
            delete_local_route(handle, route.family(), route.route_table()).await
        }
    }
}

async fn add_fwmark_rule(
    handle: &Handle,
    family: TransparentLinuxIpFamily,
    mark: u32,
    route_table: u32,
) -> Result<(), String> {
    let request = handle.rule().add().fw_mark(mark).table_id(route_table);
    match family {
        TransparentLinuxIpFamily::Ipv4 => request.v4().execute().await,
        TransparentLinuxIpFamily::Ipv6 => request.v6().execute().await,
    }
    .map_err(|error| format!("failed to add RTNETLINK fwmark rule: {error}"))
}

async fn delete_fwmark_rule(
    handle: &Handle,
    family: TransparentLinuxIpFamily,
    mark: u32,
    route_table: u32,
) -> Result<(), String> {
    let request = handle.rule().add().fw_mark(mark).table_id(route_table);
    let message = match family {
        TransparentLinuxIpFamily::Ipv4 => request.v4().message_mut().clone(),
        TransparentLinuxIpFamily::Ipv6 => request.v6().message_mut().clone(),
    };
    handle
        .rule()
        .del(message)
        .execute()
        .await
        .map_err(|error| format!("failed to delete RTNETLINK fwmark rule: {error}"))
}

async fn replace_local_route(
    handle: &Handle,
    family: TransparentLinuxIpFamily,
    route_table: u32,
) -> Result<(), String> {
    let loopback_index = loopback_interface_index(handle).await?;
    let route = local_route_message(family, route_table, loopback_index);
    handle
        .route()
        .add(route)
        .replace()
        .execute()
        .await
        .map_err(|error| format!("failed to replace RTNETLINK local route: {error}"))
}

async fn delete_local_route(
    handle: &Handle,
    family: TransparentLinuxIpFamily,
    route_table: u32,
) -> Result<(), String> {
    let loopback_index = loopback_interface_index(handle).await?;
    let route = local_route_message(family, route_table, loopback_index);
    handle
        .route()
        .del(route)
        .execute()
        .await
        .map_err(|error| format!("failed to delete RTNETLINK local route: {error}"))
}

async fn loopback_interface_index(handle: &Handle) -> Result<u32, String> {
    let mut links = handle.link().get().match_name("lo".to_string()).execute();
    let Some(message) = links
        .try_next()
        .await
        .map_err(|error| format!("failed to query loopback interface: {error}"))?
    else {
        return Err("failed to query loopback interface: lo not found".to_string());
    };
    Ok(message.header.index)
}

fn local_route_message(
    family: TransparentLinuxIpFamily,
    route_table: u32,
    loopback_index: u32,
) -> RouteMessage {
    match family {
        TransparentLinuxIpFamily::Ipv4 => RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
            .table_id(route_table)
            .output_interface(loopback_index)
            .kind(RouteType::Local)
            .scope(RouteScope::Host)
            .protocol(RouteProtocol::Static)
            .build(),
        TransparentLinuxIpFamily::Ipv6 => RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
            .table_id(route_table)
            .output_interface(loopback_index)
            .kind(RouteType::Local)
            .scope(RouteScope::Host)
            .protocol(RouteProtocol::Static)
            .build(),
    }
}

fn host_routing_error(reason: impl Into<String>) -> TransparentInterceptionError {
    TransparentInterceptionError::Nftables(reason.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_local_address_attributes() -> Result<(), Box<dyn std::error::Error>> {
        let addresses = local_addresses_from_message(&[
            AddressAttribute::Address("192.0.2.10".parse()?),
            AddressAttribute::Local("192.0.2.11".parse()?),
            AddressAttribute::Local("2001:db8::10".parse()?),
        ]);

        assert_eq!(
            addresses,
            vec![
                IpAddr::V4("192.0.2.11".parse()?),
                IpAddr::V6("2001:db8::10".parse()?),
            ]
        );
        Ok(())
    }

    #[test]
    fn falls_back_to_address_attribute_when_local_is_absent()
    -> Result<(), Box<dyn std::error::Error>> {
        let addresses =
            local_addresses_from_message(&[AddressAttribute::Address("192.0.2.10".parse()?)]);

        assert_eq!(addresses, vec![IpAddr::V4("192.0.2.10".parse()?)]);
        Ok(())
    }
}
