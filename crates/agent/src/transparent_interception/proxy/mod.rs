mod listener;
mod registry;
mod relay;
mod state;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use probe_config::{
    EnforcementInterceptionConfig, TransparentInterceptionProxyModeConfig,
    TransparentInterceptionStrategyConfig,
};

use self::{
    listener::{ManagedTransparentProxyListener, start_listeners},
    registry::RelayRegistry,
};
use super::{TransparentInterceptionError, TransparentInterceptionIpFamily};

pub(in crate::transparent_interception) use state::TransparentProxyRuntime;
pub(crate) use state::{
    TransparentProxyRuntimeHandle, TransparentProxyRuntimeMode, TransparentProxyRuntimeSnapshot,
};

pub(crate) struct ManagedTransparentProxyGuard {
    shutdown_requested: Arc<AtomicBool>,
    relays: RelayRegistry,
    listeners: Vec<ManagedTransparentProxyListener>,
    runtime: TransparentProxyRuntime,
}

pub(crate) fn start_managed_proxy(
    config: &EnforcementInterceptionConfig,
    families: Vec<TransparentInterceptionIpFamily>,
    runtime: TransparentProxyRuntime,
) -> Result<Option<ManagedTransparentProxyGuard>, TransparentInterceptionError> {
    if config.proxy.mode == TransparentInterceptionProxyModeConfig::External {
        return Ok(None);
    }
    if config.proxy.mode != TransparentInterceptionProxyModeConfig::ManagedTcpRelay {
        return Err(TransparentInterceptionError::Proxy(format!(
            "unsupported transparent proxy mode {:?}",
            config.proxy.mode
        )));
    }
    if config.strategy != TransparentInterceptionStrategyConfig::InboundTproxy {
        return Err(TransparentInterceptionError::Proxy(
            "managed TCP relay proxy mode is only executable for inbound TPROXY".to_string(),
        ));
    }
    let listen_port = config.proxy.listen_port.ok_or_else(|| {
        TransparentInterceptionError::Proxy(
            "managed TCP relay requires a proxy listen port".to_string(),
        )
    })?;
    if families.is_empty() {
        return Err(TransparentInterceptionError::Proxy(
            "managed TCP relay requires at least one listener family".to_string(),
        ));
    }
    ManagedTransparentProxyGuard::start(listen_port, families, runtime).map(Some)
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

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{Ipv4Addr, TcpListener, TcpStream},
        sync::Arc,
    };

    use super::*;

    #[test]
    fn external_proxy_mode_does_not_start_managed_listener() {
        let config = EnforcementInterceptionConfig::default();

        let guard = start_managed_proxy(
            &config,
            Vec::new(),
            TransparentProxyRuntime::for_config(&config),
        )
        .expect("external mode should be ignored");

        assert!(guard.is_none());
    }

    #[test]
    fn managed_proxy_rejects_empty_listener_family_set() {
        let config = EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
            proxy: probe_config::TransparentInterceptionProxyConfig {
                mode: TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
                listen_port: Some(15001),
            },
            ..EnforcementInterceptionConfig::default()
        };

        let error = match start_managed_proxy(
            &config,
            Vec::new(),
            TransparentProxyRuntime::for_config(&config),
        ) {
            Ok(_) => panic!("managed relay should require at least one listener"),
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
            runtime: TransparentProxyRuntime::for_config(&EnforcementInterceptionConfig::default()),
        };

        guard.stop()?;

        let mut buffer = [0_u8; 1];
        assert_eq!(downstream.read(&mut buffer)?, 0);
        assert!(upstream.write_all(b"x").is_err());
        Ok(())
    }
}
