mod connect;
mod health_probe;
mod listener;
mod registry;
mod relay;
mod state;
mod target;

use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use ::runtime::TransparentInterceptionInboundTproxyPlan;
use probe_config::TransparentInterceptionProxyModeConfig;

use self::{
    health_probe::{prepare_health_probe, start_health_probe},
    listener::{ManagedTransparentProxyListener, start_listeners},
    registry::RelayRegistry,
};
use super::{TransparentInterceptionError, TransparentInterceptionIpFamily};

pub(super) type LocalAddressInventory =
    Arc<dyn Fn() -> Result<Vec<IpAddr>, TransparentInterceptionError> + Send + Sync>;

pub(in crate::transparent_interception) use state::TransparentProxyRuntime;
pub(crate) use state::{
    TransparentProxyHealthProbeMode, TransparentProxyRuntimeHandle, TransparentProxyRuntimeMode,
    TransparentProxyRuntimeSnapshot,
};

#[derive(Debug)]
pub(in crate::transparent_interception) struct TransparentProxyLifecyclePlan {
    managed: Option<ManagedTransparentProxyPlan>,
    health_probe: Option<health_probe::TransparentProxyHealthProbePlan>,
}

#[derive(Debug)]
struct ManagedTransparentProxyPlan {
    listen_port: u16,
    families: Vec<TransparentInterceptionIpFamily>,
}

pub(in crate::transparent_interception) struct TransparentProxyGuard {
    managed: Option<ManagedTransparentProxyGuard>,
    health_probe: Option<health_probe::TransparentProxyHealthProbeGuard>,
}

pub(in crate::transparent_interception) fn prepare_proxy_lifecycle(
    inbound_plan: &TransparentInterceptionInboundTproxyPlan,
    families: Vec<TransparentInterceptionIpFamily>,
    load_local_addresses: LocalAddressInventory,
) -> Result<TransparentProxyLifecyclePlan, TransparentInterceptionError> {
    let managed = prepare_managed_proxy(inbound_plan, families)?;
    let health_probe = prepare_health_probe(
        inbound_plan.health_probe(),
        managed.as_ref(),
        load_local_addresses,
    )?;
    Ok(TransparentProxyLifecyclePlan {
        managed,
        health_probe,
    })
}

pub(in crate::transparent_interception) fn start_proxy_lifecycle(
    plan: TransparentProxyLifecyclePlan,
    runtime: TransparentProxyRuntime,
) -> Result<Option<TransparentProxyGuard>, TransparentInterceptionError> {
    let managed = start_managed_proxy(plan.managed, runtime.clone())?;
    let health_probe = start_health_probe(plan.health_probe, runtime);
    if managed.is_none() && health_probe.is_none() {
        return Ok(None);
    }
    Ok(Some(TransparentProxyGuard {
        managed,
        health_probe,
    }))
}

impl TransparentProxyGuard {
    pub(in crate::transparent_interception) fn stop(
        self,
    ) -> Result<(), TransparentInterceptionError> {
        let health_result = stop_health_probe(self.health_probe);
        let managed_result = stop_managed_proxy(self.managed);
        health_result.and(managed_result)
    }
}

struct ManagedTransparentProxyGuard {
    shutdown_requested: Arc<AtomicBool>,
    relays: RelayRegistry,
    listeners: Vec<ManagedTransparentProxyListener>,
    runtime: TransparentProxyRuntime,
}

fn prepare_managed_proxy(
    inbound_plan: &TransparentInterceptionInboundTproxyPlan,
    families: Vec<TransparentInterceptionIpFamily>,
) -> Result<Option<ManagedTransparentProxyPlan>, TransparentInterceptionError> {
    let TransparentInterceptionProxyModeConfig::ManagedTcpRelay = inbound_plan.proxy_mode() else {
        return Ok(None);
    };
    if families.is_empty() {
        return Err(TransparentInterceptionError::Proxy(
            "managed TCP relay requires at least one listener family".to_string(),
        ));
    }
    Ok(Some(ManagedTransparentProxyPlan {
        listen_port: inbound_plan.listen_port().get(),
        families,
    }))
}

fn start_managed_proxy(
    plan: Option<ManagedTransparentProxyPlan>,
    runtime: TransparentProxyRuntime,
) -> Result<Option<ManagedTransparentProxyGuard>, TransparentInterceptionError> {
    match plan {
        Some(plan) => {
            ManagedTransparentProxyGuard::start(plan.listen_port, plan.families, runtime).map(Some)
        }
        None => Ok(None),
    }
}

fn stop_managed_proxy(
    proxy: Option<ManagedTransparentProxyGuard>,
) -> Result<(), TransparentInterceptionError> {
    match proxy {
        Some(proxy) => proxy.stop(),
        None => Ok(()),
    }
}

fn stop_health_probe(
    health_probe: Option<health_probe::TransparentProxyHealthProbeGuard>,
) -> Result<(), TransparentInterceptionError> {
    match health_probe {
        Some(health_probe) => health_probe.stop(),
        None => Ok(()),
    }
}

impl ManagedTransparentProxyGuard {
    fn start(
        listen_port: u16,
        families: Vec<TransparentInterceptionIpFamily>,
        runtime: TransparentProxyRuntime,
    ) -> Result<Self, TransparentInterceptionError> {
        let shutdown_requested = Arc::new(AtomicBool::new(false));
        let relays = RelayRegistry::new(runtime.clone());
        let listeners = start_listeners(
            listen_port,
            families,
            Arc::clone(&shutdown_requested),
            relays.clone(),
            runtime.clone(),
        )?;
        Ok(Self {
            shutdown_requested,
            relays,
            listeners,
            runtime,
        })
    }

    pub(crate) fn stop(mut self) -> Result<(), TransparentInterceptionError> {
        self.shutdown_requested.store(true, Ordering::SeqCst);
        self.relays.shutdown_all();
        let mut errors = Vec::new();
        for listener in std::mem::take(&mut self.listeners) {
            match listener.thread.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => errors.push(format!("{:?}: {error}", listener.family)),
                Err(_) => errors.push(format!("{:?}: listener thread panicked", listener.family)),
            }
        }
        if errors.is_empty() {
            self.runtime.mark_stopped();
            Ok(())
        } else {
            self.runtime.mark_stopped();
            Err(TransparentInterceptionError::Proxy(errors.join("; ")))
        }
    }
}

impl Drop for ManagedTransparentProxyGuard {
    fn drop(&mut self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
        self.runtime.mark_stopped();
    }
}

fn proxy_io_error(
    context: impl Into<String>,
) -> impl FnOnce(std::io::Error) -> TransparentInterceptionError {
    let context = context.into();
    move |source| TransparentInterceptionError::Proxy(format!("{context}: {source}"))
}

fn proxy_error(message: impl Into<String>) -> TransparentInterceptionError {
    TransparentInterceptionError::Proxy(message.into())
}

pub(in crate::transparent_interception) fn outbound_original_destination_recovery_name()
-> &'static str {
    target::TransparentProxyTargetRecovery::LinuxOriginalDestination.description()
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{Ipv4Addr, TcpListener, TcpStream},
        sync::Arc,
    };

    use probe_config::TransparentInterceptionStrategyConfig;
    use runtime::TransparentInterceptionExecutionPlan;

    use super::*;

    #[test]
    fn external_proxy_mode_does_not_start_managed_listener() {
        let config = probe_config::EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
            proxy: probe_config::TransparentInterceptionProxyConfig {
                mode: TransparentInterceptionProxyModeConfig::External,
                listen_port: Some(15001),
                ..probe_config::TransparentInterceptionProxyConfig::default()
            },
            ..probe_config::EnforcementInterceptionConfig::default()
        };
        let execution_plan = TransparentInterceptionExecutionPlan::try_from_config(&config)
            .expect("test transparent interception config should be valid");
        let TransparentInterceptionExecutionPlan::InboundTproxy(inbound_plan) =
            execution_plan.clone()
        else {
            panic!("test transparent interception config should use inbound TPROXY");
        };

        let plan = prepare_proxy_lifecycle(&inbound_plan, Vec::new(), Arc::new(|| Ok(Vec::new())))
            .expect("external mode without health probe should be prepared");
        let guard = start_proxy_lifecycle(
            plan,
            TransparentProxyRuntime::for_execution_plan(&execution_plan),
        )
        .expect("external mode without health probe should start no proxy lifecycle");

        assert!(guard.is_none());
    }

    #[test]
    fn managed_proxy_rejects_empty_listener_family_set() {
        let config = probe_config::EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
            proxy: probe_config::TransparentInterceptionProxyConfig {
                mode: TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
                listen_port: Some(15001),
                ..probe_config::TransparentInterceptionProxyConfig::default()
            },
            ..probe_config::EnforcementInterceptionConfig::default()
        };
        let execution_plan = TransparentInterceptionExecutionPlan::try_from_config(&config)
            .expect("test transparent interception config should be valid");
        let TransparentInterceptionExecutionPlan::InboundTproxy(inbound_plan) = execution_plan
        else {
            panic!("test transparent interception config should use inbound TPROXY");
        };

        let error =
            match prepare_proxy_lifecycle(&inbound_plan, Vec::new(), Arc::new(|| Ok(Vec::new()))) {
                Ok(_) => panic!("managed relay should require at least one listener family"),
                Err(error) => error,
            };

        assert!(error.to_string().contains("at least one listener family"));
    }

    #[test]
    fn guard_stop_shuts_down_registered_active_streams() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        let mut downstream = TcpStream::connect(address)?;
        let (mut upstream, _) = listener.accept()?;
        let registry = RelayRegistry::default();
        let _registration = registry.register(&downstream, &upstream)?;
        let guard = ManagedTransparentProxyGuard {
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            relays: registry,
            listeners: Vec::new(),
            runtime: TransparentProxyRuntime::for_test_config(
                &probe_config::EnforcementInterceptionConfig::default(),
            ),
        };

        guard.stop()?;

        let mut buffer = [0_u8; 1];
        assert_eq!(downstream.read(&mut buffer)?, 0);
        assert!(upstream.write_all(b"x").is_err());
        Ok(())
    }
}
