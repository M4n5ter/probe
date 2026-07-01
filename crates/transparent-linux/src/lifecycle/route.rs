use super::TransparentLinuxIpFamily;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyRouteOperation {
    AddFwmarkRule(PolicyRule),
    DeleteFwmarkRule(PolicyRule),
    ReplaceLocalRoute(LocalRoute),
    DeleteLocalRoute(LocalRoute),
}

impl PolicyRouteOperation {
    pub fn add_fwmark_rule(family: TransparentLinuxIpFamily, mark: u32, route_table: u32) -> Self {
        Self::AddFwmarkRule(PolicyRule::new(family, mark, route_table))
    }

    pub fn delete_fwmark_rule(
        family: TransparentLinuxIpFamily,
        mark: u32,
        route_table: u32,
    ) -> Self {
        Self::DeleteFwmarkRule(PolicyRule::new(family, mark, route_table))
    }

    pub fn replace_local_route(family: TransparentLinuxIpFamily, route_table: u32) -> Self {
        Self::ReplaceLocalRoute(LocalRoute::new(family, route_table))
    }

    pub fn delete_local_route(family: TransparentLinuxIpFamily, route_table: u32) -> Self {
        Self::DeleteLocalRoute(LocalRoute::new(family, route_table))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyRule {
    family: TransparentLinuxIpFamily,
    mark: u32,
    route_table: u32,
}

impl PolicyRule {
    fn new(family: TransparentLinuxIpFamily, mark: u32, route_table: u32) -> Self {
        Self {
            family,
            mark,
            route_table,
        }
    }

    pub fn family(self) -> TransparentLinuxIpFamily {
        self.family
    }

    pub fn mark(self) -> u32 {
        self.mark
    }

    pub fn route_table(self) -> u32 {
        self.route_table
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalRoute {
    family: TransparentLinuxIpFamily,
    route_table: u32,
}

impl LocalRoute {
    fn new(family: TransparentLinuxIpFamily, route_table: u32) -> Self {
        Self {
            family,
            route_table,
        }
    }

    pub fn family(self) -> TransparentLinuxIpFamily {
        self.family
    }

    pub fn route_table(self) -> u32 {
        self.route_table
    }

    pub fn destination(self) -> &'static str {
        match self.family {
            TransparentLinuxIpFamily::Ipv4 => "0.0.0.0/0",
            TransparentLinuxIpFamily::Ipv6 => "::/0",
        }
    }
}

pub fn cleanup_all_policy_route_operations(
    mark: u32,
    route_table: u32,
) -> Vec<PolicyRouteOperation> {
    TransparentLinuxIpFamily::all()
        .into_iter()
        .flat_map(|family| {
            [
                PolicyRouteOperation::delete_fwmark_rule(family, mark, route_table),
                PolicyRouteOperation::delete_local_route(family, route_table),
            ]
        })
        .collect()
}
