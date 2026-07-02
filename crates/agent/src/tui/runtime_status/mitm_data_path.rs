use crate::tui::copy::{MITM_HTTP_PATH_LABEL, MITM_TLS_PATH_LABEL};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MitmDataPathDiagnosis {
    path_labels: String,
    plain_http: String,
    tls_http: String,
    plain_http_status: MitmPathStatus,
    tls_http_status: MitmPathStatus,
    next_action: String,
}

impl MitmDataPathDiagnosis {
    pub(super) fn disabled(
        path_labels: impl Into<String>,
        plain_http: impl Into<String>,
        tls_http: impl Into<String>,
        plain_http_status: MitmPathStatus,
        tls_http_status: MitmPathStatus,
        next_action: impl Into<String>,
    ) -> Self {
        Self {
            path_labels: path_labels.into(),
            plain_http: plain_http.into(),
            tls_http: tls_http.into(),
            plain_http_status,
            tls_http_status,
            next_action: next_action.into(),
        }
    }

    pub(super) fn labeled(
        plain_http: impl Into<String>,
        tls_http: impl Into<String>,
        plain_http_status: MitmPathStatus,
        tls_http_status: MitmPathStatus,
        next_action: impl Into<String>,
    ) -> Self {
        Self {
            path_labels: format!(
                "path labels: {MITM_HTTP_PATH_LABEL}=plain HTTP, {MITM_TLS_PATH_LABEL}=TLS-decrypted HTTP"
            ),
            plain_http: plain_http.into(),
            tls_http: tls_http.into(),
            plain_http_status,
            tls_http_status,
            next_action: next_action.into(),
        }
    }

    pub(super) fn visibility_lines(self) -> Vec<String> {
        vec![self.path_labels, self.plain_http, self.tls_http]
    }

    pub(super) fn status_summary(&self) -> &'static str {
        match (self.plain_http_status, self.tls_http_status) {
            (MitmPathStatus::Ready, MitmPathStatus::Ready) => {
                "MITM bridge ready for plain HTTP and TLS-decrypted HTTP after client trust"
            }
            (MitmPathStatus::Ready, MitmPathStatus::Blocked) => {
                "MITM bridge ready for plain HTTP; TLS-decrypted HTTP is blocked"
            }
            (MitmPathStatus::Ready, MitmPathStatus::Unknown) => {
                "MITM bridge ready for plain HTTP; TLS-decrypted HTTP status is unknown"
            }
            (MitmPathStatus::Ready, MitmPathStatus::Unavailable) => {
                "MITM bridge ready for plain HTTP; TLS-decrypted HTTP is unavailable"
            }
            (MitmPathStatus::Blocked, _) | (_, MitmPathStatus::Blocked) => {
                "MITM bridge data path is blocked"
            }
            (MitmPathStatus::Unknown, _) | (_, MitmPathStatus::Unknown) => {
                "MITM bridge data path status is unknown"
            }
            (MitmPathStatus::Unavailable, _) => "MITM bridge data path is unavailable",
        }
    }

    pub(super) fn status_message_kind(&self) -> MitmDataPathMessageKind {
        match (self.plain_http_status, self.tls_http_status) {
            (MitmPathStatus::Ready, MitmPathStatus::Ready) => MitmDataPathMessageKind::Info,
            _ => MitmDataPathMessageKind::Warning,
        }
    }

    pub(super) fn next_action(&self) -> &str {
        &self.next_action
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MitmPathStatus {
    Ready,
    Blocked,
    Unknown,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MitmDataPathMessageKind {
    Info,
    Warning,
}
