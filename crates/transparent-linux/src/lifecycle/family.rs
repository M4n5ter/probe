#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparentLinuxIpFamily {
    Ipv4,
    Ipv6,
}

impl TransparentLinuxIpFamily {
    pub(super) fn all() -> [Self; 2] {
        [Self::Ipv4, Self::Ipv6]
    }
}
