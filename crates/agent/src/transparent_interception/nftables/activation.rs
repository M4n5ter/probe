use std::sync::{Arc, Mutex, MutexGuard};

use super::{
    command::{CommandResult, IpCommand, NftCommand},
    local_addresses,
    owner_lock::{NftablesOwnerLock, NftablesOwnerLockGuard},
};
use crate::transparent_interception::{
    TransparentInterceptionError,
    proxy::{LocalAddressInventory, TransparentProxyGuard},
};

pub(super) type SharedIpCommand = Arc<Mutex<Box<dyn IpCommand + Send>>>;

pub(super) fn local_address_inventory(ip: Option<SharedIpCommand>) -> LocalAddressInventory {
    Arc::new(move || {
        let Some(ip) = ip.as_ref() else {
            return Err(TransparentInterceptionError::Nftables(
                "local address inventory requires ip at a trusted system path".to_string(),
            ));
        };
        let mut ip = lock_ip_command(ip)?;
        local_addresses::load(ip.as_mut())
    })
}

pub(super) fn lock_ip_command(
    ip: &SharedIpCommand,
) -> Result<MutexGuard<'_, Box<dyn IpCommand + Send>>, TransparentInterceptionError> {
    ip.lock().map_err(|_| {
        TransparentInterceptionError::Nftables("ip command mutex is poisoned".to_string())
    })
}

pub(super) fn apply_nft_script(
    nft: &mut dyn NftCommand,
    script: &str,
    command_name: &str,
) -> Result<(), TransparentInterceptionError> {
    let result = nft
        .apply(script)
        .map_err(|error| TransparentInterceptionError::Nftables(error.to_string()))?;
    command_success(result, command_name)
}

pub(super) fn stop_proxy_best_effort(
    proxy: Option<TransparentProxyGuard>,
) -> Result<(), TransparentInterceptionError> {
    match proxy {
        Some(proxy) => proxy.stop(),
        None => Ok(()),
    }
}

pub(super) fn check_nft_script(
    nft: &mut dyn NftCommand,
    script: &str,
) -> Result<(), TransparentInterceptionError> {
    let result = nft
        .check(script)
        .map_err(|error| TransparentInterceptionError::Nftables(error.to_string()))?;
    command_success(result, "nft --check")
}

pub(super) fn checked_nft_setup_owner(
    nft: &mut dyn NftCommand,
    owner_lock: &mut dyn NftablesOwnerLock,
    setup_script: &str,
    owner_name: &str,
) -> Result<NftablesOwnerLockGuard, TransparentInterceptionError> {
    check_nft_script(nft, setup_script)?;
    owner_lock.acquire(owner_name)
}

pub(super) fn apply_ip_command(
    ip: &mut dyn IpCommand,
    args: &[String],
    command_name: &str,
) -> Result<(), TransparentInterceptionError> {
    let result = ip
        .run(args)
        .map_err(|error| TransparentInterceptionError::Nftables(error.to_string()))?;
    command_success(result, command_name)
}

fn command_success(
    result: CommandResult,
    command_name: &str,
) -> Result<(), TransparentInterceptionError> {
    if result.success {
        Ok(())
    } else {
        Err(TransparentInterceptionError::Nftables(
            result.failure_reason(command_name),
        ))
    }
}
