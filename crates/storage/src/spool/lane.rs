pub(super) const LAST_INGRESS_SEQUENCE: &[u8] = b"last_ingress_sequence";
pub(super) const LAST_EXPORT_SEQUENCE: &[u8] = b"last_export_sequence";
pub(super) const LIVE_INGRESS_RECORDS: &[u8] = b"live_ingress_records";
pub(super) const LIVE_EXPORT_RECORDS: &[u8] = b"live_export_records";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SpoolLane {
    Ingress,
    Export,
}

impl SpoolLane {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Export => "export",
        }
    }

    pub(super) fn last_sequence_key(self) -> &'static [u8] {
        match self {
            Self::Ingress => LAST_INGRESS_SEQUENCE,
            Self::Export => LAST_EXPORT_SEQUENCE,
        }
    }

    pub(super) fn live_records_key(self) -> &'static [u8] {
        match self {
            Self::Ingress => LIVE_INGRESS_RECORDS,
            Self::Export => LIVE_EXPORT_RECORDS,
        }
    }
}
