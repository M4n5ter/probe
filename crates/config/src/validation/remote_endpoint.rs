use url::Url;

use crate::ConfigViolation;

pub(super) fn validate_remote_endpoint(
    endpoint: &str,
    field: impl Into<String>,
    label: &'static str,
    violations: &mut Vec<ConfigViolation>,
) {
    let field = field.into();
    let Ok(url) = Url::parse(endpoint) else {
        violations.push(ConfigViolation {
            field,
            reason: format!("{label} endpoint must be an absolute URL"),
        });
        return;
    };

    if !url.username().is_empty() || url.password().is_some() {
        violations.push(ConfigViolation {
            field,
            reason: format!("{label} endpoint must not contain credentials"),
        });
        return;
    }
    if remote_endpoint_uses_allowed_transport(&url) {
        return;
    }
    violations.push(ConfigViolation {
        field,
        reason: format!("{label} endpoint must use HTTPS, except loopback HTTP for local testing"),
    });
}

fn remote_endpoint_uses_allowed_transport(url: &Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => url.host_str().is_some_and(loopback_host),
        _ => false,
    }
}

fn loopback_host(host: &str) -> bool {
    let normalized = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    normalized.eq_ignore_ascii_case("localhost")
        || normalized
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}
