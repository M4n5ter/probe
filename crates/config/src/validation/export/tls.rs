use std::collections::BTreeMap;

use url::Url;

use crate::{ConfigViolation, ExporterConfig, ExporterTlsConfig, TlsMaterialKind};

pub(super) fn validate_exporter_tls(
    exporter: &ExporterConfig,
    endpoint: &str,
    tls: &ExporterTlsConfig,
    materials_by_id: &BTreeMap<&str, TlsMaterialKind>,
    violations: &mut Vec<ConfigViolation>,
) {
    if exporter_tls_configured(tls) && !webhook_endpoint_is_https(endpoint) {
        violations.push(ConfigViolation {
            field: format!("exporters.{}.tls", exporter.id),
            reason: "exporter TLS material refs require an HTTPS webhook endpoint".to_string(),
        });
    }
    for reference in &tls.trust_anchor_refs {
        crate::tls::validate_material_ref(
            format!("exporters.{}.tls.trust_anchor_refs", exporter.id),
            reference,
            TlsMaterialKind::TrustAnchor,
            materials_by_id,
            violations,
            "TLS material",
        );
    }
    for reference in &tls.client_certificate_refs {
        crate::tls::validate_material_ref(
            format!("exporters.{}.tls.client_certificate_refs", exporter.id),
            reference,
            TlsMaterialKind::ClientCertificate,
            materials_by_id,
            violations,
            "TLS material",
        );
    }
    if let Some(reference) = &tls.client_private_key_ref {
        crate::tls::validate_material_ref(
            format!("exporters.{}.tls.client_private_key_ref", exporter.id),
            reference,
            TlsMaterialKind::ClientPrivateKey,
            materials_by_id,
            violations,
            "TLS material",
        );
    }
    if !tls.client_certificate_refs.is_empty() && tls.client_private_key_ref.is_none() {
        violations.push(ConfigViolation {
            field: format!("exporters.{}.tls.client_private_key_ref", exporter.id),
            reason: "client certificate refs require a client private key ref".to_string(),
        });
    }
    if tls.client_certificate_refs.is_empty() && tls.client_private_key_ref.is_some() {
        violations.push(ConfigViolation {
            field: format!("exporters.{}.tls.client_certificate_refs", exporter.id),
            reason: "client private key ref requires at least one client certificate ref"
                .to_string(),
        });
    }
}

fn exporter_tls_configured(tls: &ExporterTlsConfig) -> bool {
    !tls.trust_anchor_refs.is_empty()
        || !tls.client_certificate_refs.is_empty()
        || tls.client_private_key_ref.is_some()
}

fn webhook_endpoint_is_https(endpoint: &str) -> bool {
    Url::parse(endpoint).is_ok_and(|url| url.scheme() == "https")
}
