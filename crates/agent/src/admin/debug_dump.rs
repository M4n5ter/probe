use serde::Serialize;

use super::protocol::{AdminProtocolSnapshot, admin_protocol_snapshot};

#[derive(Debug, Serialize)]
pub(super) struct AdminDebugDump {
    pub status: Box<crate::status::AgentStatusSnapshot>,
    pub protocol: AdminProtocolSnapshot,
    pub privacy: AdminDebugDumpPrivacy,
}

impl AdminDebugDump {
    pub(super) fn new(status: crate::status::AgentStatusSnapshot) -> Self {
        Self {
            status: Box::new(status),
            protocol: admin_protocol_snapshot(),
            privacy: AdminDebugDumpPrivacy {
                includes_raw_config: false,
                includes_runtime_plan: true,
                includes_local_paths: true,
                includes_secret_material_bytes: false,
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct AdminDebugDumpPrivacy {
    pub includes_raw_config: bool,
    pub includes_runtime_plan: bool,
    pub includes_local_paths: bool,
    pub includes_secret_material_bytes: bool,
}
