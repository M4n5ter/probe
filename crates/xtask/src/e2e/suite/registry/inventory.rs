use serde::Serialize;

#[cfg(test)]
use super::case::E2eRequirementMetadata;
use super::{
    capability::{E2eCapabilityInventoryRow, inventory_rows as capability_inventory_rows},
    case::{E2eCaseMetadata, cases},
    profile::{capability_ids_for_cases, profiles, requirement_ids, select_profile_cases},
};

const E2E_INVENTORY_SCHEMA_VERSION: u16 = 2;

pub(in crate::e2e::suite) fn inventory() -> Result<E2eInventory, String> {
    Ok(E2eInventory {
        schema_version: E2E_INVENTORY_SCHEMA_VERSION,
        capabilities: capability_inventory_rows(),
        cases: cases().iter().map(E2eCaseMetadata::from_case).collect(),
        profiles: profile_inventory_rows()?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(in crate::e2e::suite) struct E2eInventory {
    pub(super) schema_version: u16,
    pub(super) capabilities: Vec<E2eCapabilityInventoryRow>,
    pub(super) cases: Vec<E2eCaseMetadata>,
    pub(super) profiles: Vec<E2eProfileInventoryRow>,
}

fn profile_inventory_rows() -> Result<Vec<E2eProfileInventoryRow>, String> {
    profiles()
        .iter()
        .map(|profile| {
            let cases = select_profile_cases(profile.id)?;
            Ok(E2eProfileInventoryRow {
                name: profile.name,
                description: profile.description,
                include_in_product: profile.include_in_product,
                requirements: requirement_ids(&cases),
                capabilities: capability_ids_for_cases(&cases),
                cases: cases.iter().map(|case| case.name).collect(),
            })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct E2eProfileInventoryRow {
    pub(super) name: &'static str,
    pub(super) description: &'static str,
    pub(super) include_in_product: bool,
    pub(super) requirements: Vec<&'static str>,
    pub(super) capabilities: Vec<&'static str>,
    pub(super) cases: Vec<&'static str>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e::suite::registry::{capability::E2eCapability, profile::E2eProfileId};

    #[test]
    fn inventory_rows_are_derived_from_profile_selection() {
        let inventory = inventory().expect("inventory should build from registry");
        let product = inventory
            .profiles
            .iter()
            .find(|row| row.name == "product")
            .expect("product profile should be included");

        assert_eq!(inventory.schema_version, 2);
        assert_eq!(inventory.capabilities.len(), E2eCapability::ALL.len());
        assert_eq!(inventory.cases.len(), cases().len());
        assert!(!product.include_in_product);
        assert_eq!(
            product.requirements,
            ["user", "root_cap_net_raw", "root_bpffs", "root_net_admin"]
        );
        assert_eq!(
            product.capabilities,
            E2eCapability::ALL
                .iter()
                .map(|capability| capability.id())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            inventory
                .cases
                .iter()
                .find(|case| case.name == "e2e-replay")
                .expect("replay case should be in inventory")
                .requirement,
            E2eRequirementMetadata {
                id: "user",
                label: "user",
                privileged: false,
            }
        );
        assert_eq!(
            inventory
                .cases
                .iter()
                .find(|case| case.name == "e2e-replay")
                .expect("replay case should be in inventory")
                .capabilities,
            [
                "replay_pipeline",
                "http_parsing",
                "durable_spool_export",
                "lua_policy_bundle"
            ]
        );
        assert_eq!(
            product.cases,
            select_profile_cases(E2eProfileId::Product)
                .expect("product profile should resolve")
                .iter()
                .map(|case| case.name)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn inventory_serializes_public_schema() {
        let value =
            serde_json::to_value(inventory().expect("inventory should build from registry"))
                .expect("inventory should serialize");

        assert_eq!(value["schema_version"], 2);
        assert_eq!(value["capabilities"][0]["id"], "replay_pipeline");
        assert_eq!(value["capabilities"][0]["label"], "replay pipeline");
        assert_eq!(value["capabilities"][0]["category"]["id"], "capture_input");
        assert_eq!(value["cases"][0]["name"], "e2e-replay");
        assert_eq!(value["cases"][0]["requirement"]["id"], "user");
        assert_eq!(value["cases"][0]["requirement"]["label"], "user");
        assert_eq!(value["cases"][0]["requirement"]["privileged"], false);
        assert_eq!(
            value["cases"][0]["capabilities"],
            serde_json::json!([
                "replay_pipeline",
                "http_parsing",
                "durable_spool_export",
                "lua_policy_bundle"
            ])
        );
        let product = value["profiles"]
            .as_array()
            .expect("profiles should be an array")
            .iter()
            .find(|profile| profile["name"] == "product")
            .expect("product profile should serialize");
        assert_eq!(product["include_in_product"], false);
        assert_eq!(
            product["requirements"],
            serde_json::json!(["user", "root_cap_net_raw", "root_bpffs", "root_net_admin"])
        );
        assert_eq!(
            product["capabilities"],
            serde_json::to_value(
                E2eCapability::ALL
                    .iter()
                    .map(|capability| capability.id())
                    .collect::<Vec<_>>()
            )
            .expect("capabilities should serialize")
        );
    }
}
