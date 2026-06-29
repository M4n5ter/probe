use interception::{
    TransparentInterceptionHostRuleScope, TransparentInterceptionPortScope,
    TransparentInterceptionRemoteAddressScope, TransparentInterceptionSocketOwnerScope,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NftSelectorProjection {
    rules: Vec<NftRule>,
}

impl NftSelectorProjection {
    pub(super) fn into_rules(self) -> Vec<NftRule> {
        self.rules
    }

    pub(super) fn inbound_tproxy(scope: TransparentInterceptionHostRuleScope) -> Self {
        let traffic_projection = NftTrafficProjection::inbound_tproxy(&scope);
        let rules = rules_for_remote_addresses(traffic_projection, scope.remote_addresses());
        Self { rules }
    }

    pub(super) fn outbound_redirect(scope: TransparentInterceptionHostRuleScope) -> Self {
        let traffic_projection = NftTrafficProjection::outbound_redirect(&scope);
        let rules = rules_for_remote_addresses(traffic_projection, scope.remote_addresses());
        Self { rules }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NftTrafficProjection {
    local_port_field: &'static str,
    remote_port_field: &'static str,
    remote_address_side: NftAddressSide,
    local_ports: TransparentInterceptionPortScope,
    remote_ports: TransparentInterceptionPortScope,
    socket_owners: TransparentInterceptionSocketOwnerScope,
}

impl NftTrafficProjection {
    fn inbound_tproxy(scope: &TransparentInterceptionHostRuleScope) -> Self {
        Self {
            local_port_field: "tcp dport",
            remote_port_field: "tcp sport",
            remote_address_side: NftAddressSide::Source,
            local_ports: scope.local_ports().clone(),
            remote_ports: scope.remote_ports().clone(),
            socket_owners: TransparentInterceptionSocketOwnerScope::any(),
        }
    }

    fn outbound_redirect(scope: &TransparentInterceptionHostRuleScope) -> Self {
        Self {
            local_port_field: "tcp sport",
            remote_port_field: "tcp dport",
            remote_address_side: NftAddressSide::Destination,
            local_ports: scope.local_ports().clone(),
            remote_ports: scope.remote_ports().clone(),
            socket_owners: scope.socket_owners().clone(),
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
        clauses.extend(socket_owner_match_expressions(&self.traffic.socket_owners));
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
        let field = format!(
            "{} {}",
            self.family.nft_address_family(),
            self.traffic.remote_address_side.nft_field()
        );
        format!("{field} {}", nft_set_or_value(addresses))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NftAddressSide {
    Source,
    Destination,
}

impl NftAddressSide {
    fn nft_field(self) -> &'static str {
        match self {
            Self::Source => "saddr",
            Self::Destination => "daddr",
        }
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

fn socket_owner_match_expressions(owners: &TransparentInterceptionSocketOwnerScope) -> Vec<String> {
    let mut expressions = Vec::new();
    if !owners.uids().is_empty() {
        expressions.push(format!("meta skuid {}", nft_set_or_value(owners.uids())));
    }
    if !owners.gids().is_empty() {
        expressions.push(format!("meta skgid {}", nft_set_or_value(owners.gids())));
    }
    expressions
}

fn string_values<T: ToString>(values: &[T]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

fn rules_for_remote_addresses(
    traffic_projection: NftTrafficProjection,
    addresses: &TransparentInterceptionRemoteAddressScope,
) -> Vec<NftRule> {
    let mut rules = Vec::new();
    if addresses.ipv4_any() {
        rules.push(traffic_projection.rule(NftFamily::Ipv4, None));
    } else if !addresses.ipv4().is_empty() {
        rules.push(traffic_projection.rule(NftFamily::Ipv4, Some(string_values(addresses.ipv4()))));
    }
    if addresses.ipv6_any() {
        rules.push(traffic_projection.rule(NftFamily::Ipv6, None));
    } else if !addresses.ipv6().is_empty() {
        rules.push(traffic_projection.rule(NftFamily::Ipv6, Some(string_values(addresses.ipv6()))));
    }
    rules
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
        TransparentInterceptionSocketOwnerScope,
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

    #[test]
    fn host_rule_scope_with_ipv4_family_wildcard_renders_only_ipv4_rule() {
        let expressions = match_expressions(scope_with_remote_scope(
            TransparentInterceptionRemoteAddressScope::any_ipv4(),
        ));

        assert_eq!(
            expressions,
            vec!["meta l4proto tcp meta nfproto ipv4 tcp dport { 8443, 9443 } tcp sport 443",]
        );
    }

    #[test]
    fn outbound_host_rule_scope_renders_destination_matches() {
        let expressions = NftSelectorProjection::outbound_redirect(outbound_scope())
            .into_rules()
            .into_iter()
            .map(|rule| rule.match_expression())
            .collect::<Vec<_>>();

        assert_eq!(
            expressions,
            vec!["meta l4proto tcp meta nfproto ipv4 tcp dport 443 ip daddr 203.0.113.10",]
        );
    }

    #[test]
    fn outbound_host_rule_scope_renders_socket_owner_matches() {
        let expressions = NftSelectorProjection::outbound_redirect(outbound_owner_scope())
            .into_rules()
            .into_iter()
            .map(|rule| rule.match_expression())
            .collect::<Vec<_>>();

        assert_eq!(
            expressions,
            vec![
                "meta l4proto tcp meta nfproto ipv4 meta skuid { 1000, 1001 } meta skgid 2000 tcp dport 443 ip daddr 203.0.113.10",
            ]
        );
    }

    fn match_expressions(scope: TransparentInterceptionHostRuleScope) -> Vec<String> {
        NftSelectorProjection::inbound_tproxy(scope)
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
        scope_with_remote_scope(TransparentInterceptionRemoteAddressScope::new(ipv4, ipv6))
    }

    fn scope_with_remote_scope(
        remote_addresses: TransparentInterceptionRemoteAddressScope,
    ) -> TransparentInterceptionHostRuleScope {
        TransparentInterceptionHostRuleScope::new(
            TransparentInterceptionPortScope::only(vec![8443, 9443]),
            TransparentInterceptionPortScope::only(vec![443]),
            remote_addresses,
        )
        .expect("test scope should contain host-rule constraints")
    }

    fn outbound_scope() -> TransparentInterceptionHostRuleScope {
        TransparentInterceptionHostRuleScope::new(
            TransparentInterceptionPortScope::any(),
            TransparentInterceptionPortScope::only(vec![443]),
            TransparentInterceptionRemoteAddressScope::new(
                vec![Ipv4Addr::new(203, 0, 113, 10)],
                Vec::new(),
            ),
        )
        .expect("test scope should contain outbound host-rule constraints")
    }

    fn outbound_owner_scope() -> TransparentInterceptionHostRuleScope {
        TransparentInterceptionHostRuleScope::with_socket_owners(
            TransparentInterceptionPortScope::any(),
            TransparentInterceptionPortScope::only(vec![443]),
            TransparentInterceptionRemoteAddressScope::new(
                vec![Ipv4Addr::new(203, 0, 113, 10)],
                Vec::new(),
            ),
            TransparentInterceptionSocketOwnerScope::new(vec![1000, 1001], vec![2000]),
        )
        .expect("test scope should contain outbound owner host-rule constraints")
    }
}
