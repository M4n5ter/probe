use super::hex_mark;
use crate::transparent_interception::TransparentInterceptionIpFamily;

impl TransparentInterceptionIpFamily {
    pub(super) fn all() -> [Self; 2] {
        [Self::Ipv4, Self::Ipv6]
    }

    pub(super) fn rule_command(self, operation: &str, mark: u32, route_table: u32) -> Vec<String> {
        let mut command = self.command_prefix();
        command.extend([
            "rule".to_string(),
            operation.to_string(),
            "fwmark".to_string(),
            hex_mark(mark),
            "lookup".to_string(),
            route_table.to_string(),
        ]);
        command
    }

    pub(super) fn route_command(self, operation: &str, route_table: u32) -> Vec<String> {
        let mut command = self.command_prefix();
        command.extend([
            "route".to_string(),
            operation.to_string(),
            "local".to_string(),
            self.local_route().to_string(),
            "dev".to_string(),
            "lo".to_string(),
            "table".to_string(),
            route_table.to_string(),
        ]);
        command
    }

    fn command_prefix(self) -> Vec<String> {
        match self {
            Self::Ipv4 => Vec::new(),
            Self::Ipv6 => vec!["-6".to_string()],
        }
    }

    fn local_route(self) -> &'static str {
        match self {
            Self::Ipv4 => "0.0.0.0/0",
            Self::Ipv6 => "::/0",
        }
    }
}
