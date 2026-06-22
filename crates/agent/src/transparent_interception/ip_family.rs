use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TransparentInterceptionIpFamily {
    Ipv4,
    Ipv6,
}
