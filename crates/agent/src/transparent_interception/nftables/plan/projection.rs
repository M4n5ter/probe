use interception::{TransparentInterceptionHostRuleScope, TransparentInterceptionPortScope};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NftSelectorProjection {
    rules: Vec<NftRule>,
}

impl NftSelectorProjection {
    pub(super) fn into_rules(self) -> Vec<NftRule> {
        self.rules
    }

    pub(super) fn from_host_rule_scope(scope: TransparentInterceptionHostRuleScope) -> Self {
        let traffic_projection = NftTrafficProjection::from_host_rule_scope(&scope);
        let mut rules = Vec::new();
        let addresses = scope.remote_addresses();
        match (addresses.ipv4().is_empty(), addresses.ipv6().is_empty()) {
            (true, true) => {
                rules.push(traffic_projection.rule(NftFamily::Ipv4, None));
                rules.push(traffic_projection.rule(NftFamily::Ipv6, None));
            }
            (false, true) => rules.push(
                traffic_projection.rule(NftFamily::Ipv4, Some(string_values(addresses.ipv4()))),
            ),
            (true, false) => rules.push(
                traffic_projection.rule(NftFamily::Ipv6, Some(string_values(addresses.ipv6()))),
            ),
            (false, false) => {
                rules.push(
                    traffic_projection.rule(NftFamily::Ipv4, Some(string_values(addresses.ipv4()))),
                );
                rules.push(
                    traffic_projection.rule(NftFamily::Ipv6, Some(string_values(addresses.ipv6()))),
                );
            }
        }
        Self { rules }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NftTrafficProjection {
    local_port_field: &'static str,
    remote_port_field: &'static str,
    local_ports: TransparentInterceptionPortScope,
    remote_ports: TransparentInterceptionPortScope,
}

impl NftTrafficProjection {
    fn from_host_rule_scope(scope: &TransparentInterceptionHostRuleScope) -> Self {
        Self {
            local_port_field: "tcp dport",
            remote_port_field: "tcp sport",
            local_ports: scope.local_ports().clone(),
            remote_ports: scope.remote_ports().clone(),
        }
    }

    fn rule(&self, family: NftFamily, remote_addresses: Option<Vec<String>>) -> NftRule {
        NftRule {
            family,
            traffic: self.clone(),
            remote_addresses,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NftRule {
    family: NftFamily,
    traffic: NftTrafficProjection,
    remote_addresses: Option<Vec<String>>,
}

impl NftRule {
    pub(super) fn family(&self) -> NftFamily {
        self.family
    }

    pub(super) fn match_expression(&self) -> String {
        let mut clauses = vec!["meta l4proto tcp".to_string()];
        clauses.push(format!("meta nfproto {}", self.family.nfproto_name()));
        if let Some(ports) = self.traffic.local_ports.only_values() {
            clauses.push(port_match(self.traffic.local_port_field, ports));
        }
        if let Some(ports) = self.traffic.remote_ports.only_values() {
            clauses.push(port_match(self.traffic.remote_port_field, ports));
        }
        if let Some(addresses) = &self.remote_addresses {
            clauses.push(self.remote_address_match_expression(addresses));
        }
        clauses.join(" ")
    }

    fn remote_address_match_expression(&self, addresses: &[String]) -> String {
        let field = format!("{} saddr", self.family.nft_address_family());
        format!("{field} {}", nft_set_or_value(addresses))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NftFamily {
    Ipv4,
    Ipv6,
}

impl NftFamily {
    fn nfproto_name(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }

    pub(super) fn nft_address_family(self) -> &'static str {
        match self {
            Self::Ipv4 => "ip",
            Self::Ipv6 => "ip6",
        }
    }
}

fn port_match(field: &str, ports: &[u16]) -> String {
    format!("{field} {}", nft_set_or_value(ports))
}

fn string_values<T: ToString>(values: &[T]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

fn nft_set_or_value<T>(values: &[T]) -> String
where
    T: ToString,
{
    if values.len() == 1 {
        values[0].to_string()
    } else {
        format!(
            "{{ {} }}",
            values
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use interception::{
        TransparentInterceptionPortScope, TransparentInterceptionRemoteAddressScope,
    };

    use super::*;

    #[test]
    fn host_rule_scope_renders_exact_ipv4_rule() {
        let expressions = match_expressions(scope_with_remote_addresses(["203.0.113.10"]));

        assert_eq!(
            expressions,
            vec![
                "meta l4proto tcp meta nfproto ipv4 tcp dport { 8443, 9443 } tcp sport 443 ip saddr 203.0.113.10",
            ]
        );
    }

    #[test]
    fn host_rule_scope_renders_exact_ipv6_rule() {
        let expressions = match_expressions(scope_with_remote_addresses(["2001:db8::1"]));

        assert_eq!(
            expressions,
            vec![
                "meta l4proto tcp meta nfproto ipv6 tcp dport { 8443, 9443 } tcp sport 443 ip6 saddr 2001:db8::1",
            ]
        );
    }

    #[test]
    fn host_rule_scope_renders_exact_dual_stack_rules() {
        let expressions =
            match_expressions(scope_with_remote_addresses(["203.0.113.10", "2001:db8::1"]));

        assert_eq!(
            expressions,
            vec![
                "meta l4proto tcp meta nfproto ipv4 tcp dport { 8443, 9443 } tcp sport 443 ip saddr 203.0.113.10",
                "meta l4proto tcp meta nfproto ipv6 tcp dport { 8443, 9443 } tcp sport 443 ip6 saddr 2001:db8::1",
            ]
        );
    }

    #[test]
    fn host_rule_scope_without_remote_address_renders_both_families_without_address_clause() {
        let expressions = match_expressions(scope_with_remote_addresses([]));

        assert_eq!(
            expressions,
            vec![
                "meta l4proto tcp meta nfproto ipv4 tcp dport { 8443, 9443 } tcp sport 443",
                "meta l4proto tcp meta nfproto ipv6 tcp dport { 8443, 9443 } tcp sport 443",
            ]
        );
    }

    fn match_expressions(scope: TransparentInterceptionHostRuleScope) -> Vec<String> {
        NftSelectorProjection::from_host_rule_scope(scope)
            .into_rules()
            .into_iter()
            .map(|rule| rule.match_expression())
            .collect()
    }

    fn scope_with_remote_addresses<const N: usize>(
        remote_addresses: [&str; N],
    ) -> TransparentInterceptionHostRuleScope {
        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        for address in remote_addresses {
            match address {
                "203.0.113.10" => ipv4.push(Ipv4Addr::new(203, 0, 113, 10)),
                "2001:db8::1" => ipv6.push(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
                _ => panic!("unexpected test address"),
            }
        }
        TransparentInterceptionHostRuleScope::new(
            TransparentInterceptionPortScope::only(vec![8443, 9443]),
            TransparentInterceptionPortScope::only(vec![443]),
            TransparentInterceptionRemoteAddressScope::new(ipv4, ipv6),
        )
        .expect("test scope should contain host-rule constraints")
    }
}
