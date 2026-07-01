use std::sync::Arc;

use super::{
    command::{CommandResult, NftCommand},
    host_routing::SharedHostRouting,
    owner_lock::{NftablesOwnerLock, NftablesOwnerLockGuard},
};
use crate::transparent_interception::{
    TransparentInterceptionError,
    proxy::{LocalAddressInventory, TransparentProxyGuard},
};
use transparent_linux::PolicyRouteOperation;

pub(super) fn local_address_inventory(host_routing: SharedHostRouting) -> LocalAddressInventory {
    Arc::new(move || host_routing.local_addresses())
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

pub(super) fn apply_policy_route_operation(
    host_routing: &SharedHostRouting,
    operation: PolicyRouteOperation,
) -> Result<(), TransparentInterceptionError> {
    host_routing.apply_policy_route_operation(operation)
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
