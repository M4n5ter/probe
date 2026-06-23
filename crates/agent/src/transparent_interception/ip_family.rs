use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TransparentInterceptionIpFamily {
    Ipv4,
    Ipv6,
}

impl From<transparent_linux::TransparentLinuxIpFamily> for TransparentInterceptionIpFamily {
    fn from(family: transparent_linux::TransparentLinuxIpFamily) -> Self {
        match family {
            transparent_linux::TransparentLinuxIpFamily::Ipv4 => Self::Ipv4,
            transparent_linux::TransparentLinuxIpFamily::Ipv6 => Self::Ipv6,
        }
    }
}
