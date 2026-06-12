use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfObjectProbeConfig {
    pub object_path: PathBuf,
    pub contract: EbpfObjectContract,
}

impl EbpfObjectProbeConfig {
    pub fn new(object_path: impl Into<PathBuf>) -> Self {
        Self {
            object_path: object_path.into(),
            contract: EbpfObjectContract::process_probe_scaffold(),
        }
    }

    pub fn with_contract(object_path: impl Into<PathBuf>, contract: EbpfObjectContract) -> Self {
        Self {
            object_path: object_path.into(),
            contract,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfPreflightedObject {
    pub report: EbpfObjectProbeReport,
    pub(super) bytes: Vec<u8>,
}

impl EbpfPreflightedObject {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfObjectProbeReport {
    pub object_path: PathBuf,
    pub object: EbpfProbeCheck,
    pub contract: EbpfObjectContractReport,
    pub programs: Vec<EbpfObjectProgram>,
    pub maps: Vec<EbpfObjectMap>,
}

impl EbpfObjectProbeReport {
    pub fn object_available(&self) -> bool {
        self.object.is_available()
    }

    pub fn preflight_available(&self) -> bool {
        self.object.is_available() && self.contract.is_available()
    }

    pub fn summary(&self) -> String {
        match &self.object {
            EbpfProbeCheck::Available => format!(
                "object {} parsed, contract={}, programs={}, maps={}",
                self.object_path.display(),
                self.contract.summary(),
                named_list_summary(self.programs.iter().map(|program| program.name.as_str())),
                named_list_summary(self.maps.iter().map(|map| map.name.as_str()))
            ),
            EbpfProbeCheck::Unavailable { reason } => {
                format!(
                    "object {} unavailable: {reason}",
                    self.object_path.display()
                )
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfObjectContractReport {
    pub status: EbpfProbeCheck,
    pub maps: Vec<EbpfObjectContractCheck>,
    pub programs: Vec<EbpfObjectContractCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfObjectContract {
    pub maps: Vec<EbpfExpectedMap>,
    pub programs: Vec<EbpfExpectedProgram>,
    pub inventory_policy: EbpfObjectContractInventoryPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EbpfObjectContractInventoryPolicy {
    RequiredOnly,
    Strict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfExpectedMap {
    pub name: String,
    pub kind: EbpfObjectMapKind,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub pinning: EbpfObjectMapPinning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfExpectedProgram {
    pub name: String,
    pub kind: EbpfObjectProgramKind,
    pub section: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfObjectContractCheck {
    pub name: String,
    pub check: EbpfProbeCheck,
}

impl EbpfObjectContractCheck {
    pub fn is_available(&self) -> bool {
        self.check.is_available()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfObjectProgram {
    pub name: String,
    pub kind: EbpfObjectProgramKind,
    pub section: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EbpfObjectProgramKind {
    Tracepoint,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfObjectMap {
    pub name: String,
    pub kind: EbpfObjectMapKind,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub pinning: EbpfObjectMapPinning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EbpfObjectMapKind {
    Ringbuf,
    Other { value: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EbpfObjectMapPinning {
    None,
    ByName,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum EbpfProbeCheck {
    Available,
    Unavailable { reason: String },
}

impl EbpfProbeCheck {
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available)
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Available => None,
            Self::Unavailable { reason } => Some(reason),
        }
    }

    pub fn available() -> Self {
        Self::Available
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
        }
    }

    pub fn summary(&self) -> String {
        match self {
            Self::Available => "available".to_string(),
            Self::Unavailable { reason } => reason.clone(),
        }
    }
}

fn named_list_summary<'a>(items: impl Iterator<Item = &'a str>) -> String {
    let values = items.collect::<Vec<_>>();
    if values.is_empty() {
        return "none".to_string();
    }
    values.join(",")
}
