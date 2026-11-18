use std::net::SocketAddr;

use dns_config::{AccessAction, Config};

/// Access control decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Recursive service is allowed.
    Allow,
    /// Recursive service is allowed and the query is answered as if RD was
    /// set (`allow_setrd`).
    AllowSetrd,
    /// Cache-only access (`allow_snoop`).
    AllowSnoop,
    /// The query is refused.
    Refuse,
    /// The query is dropped without a response.
    Deny,
    /// Only locally served data is answered; anything else is dropped.
    DenyNonLocal,
    /// Only locally served data is answered; anything else is refused.
    RefuseNonLocal,
}

impl From<AccessAction> for Decision {
    fn from(action: AccessAction) -> Self {
        match action {
            AccessAction::Allow => Decision::Allow,
            AccessAction::AllowSetrd => Decision::AllowSetrd,
            // Cookie enforcement is not implemented; the configuration layer
            // warns when the action is used.
            AccessAction::AllowCookie => Decision::Allow,
            AccessAction::AllowSnoop => Decision::AllowSnoop,
            AccessAction::Refuse => Decision::Refuse,
            AccessAction::Deny => Decision::Deny,
            AccessAction::DenyNonLocal => Decision::DenyNonLocal,
            AccessAction::RefuseNonLocal => Decision::RefuseNonLocal,
        }
    }
}

/// Check access for a client address against the configuration.
///
/// Unbound uses the most specific netblock that matches, independent of the
/// order of the `access-control` statements. Later statements win ties, which
/// matches Unbound's netblock tree where a repeated netblock replaces the
/// earlier entry. When nothing matches the client is refused.
///
/// The scan is linear because configurations contain a handful of rules; it
/// allocates nothing and runs once per query.
pub fn check(config: &Config, addr: &SocketAddr) -> Decision {
    let ip = addr.ip();
    let mut best: Option<(u8, Decision)> = None;
    for rule in &config.server.access_control {
        if !rule.network.contains(&ip) {
            continue;
        }
        let prefix = rule.network.prefix_len();
        if best.is_none_or(|(best_prefix, _)| prefix >= best_prefix) {
            best = Some((prefix, rule.action.into()));
        }
    }
    best.map_or(Decision::Refuse, |(_, decision)| decision)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use dns_config::{AccessControl, Config};

    use super::{Decision, check};

    fn client(address: [u8; 4]) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(address)), 1234)
    }

    fn with_rules(rules: &[&str]) -> Config {
        let mut config = Config::default();
        config.server.access_control = rules
            .iter()
            .map(|rule| rule.parse::<AccessControl>().expect("access-control rule"))
            .collect();
        config
    }

    #[test]
    fn allows_loopback() {
        let config = Config::default();
        let decision = check(&config, &client([127, 0, 0, 1]));
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn refuses_unknown() {
        let config = Config::default();
        let decision = check(&config, &client([192, 168, 1, 1]));
        assert_eq!(decision, Decision::Refuse);
    }

    #[test]
    fn most_specific_rule_wins_regardless_of_order() {
        let config = with_rules(&["0.0.0.0/0 allow", "192.168.1.0/24 refuse"]);
        assert_eq!(check(&config, &client([192, 168, 1, 10])), Decision::Refuse);
        assert_eq!(check(&config, &client([192, 168, 2, 10])), Decision::Allow);

        let config = with_rules(&["192.168.1.0/24 refuse", "0.0.0.0/0 allow"]);
        assert_eq!(check(&config, &client([192, 168, 1, 10])), Decision::Refuse);
        assert_eq!(check(&config, &client([192, 168, 2, 10])), Decision::Allow);
    }

    #[test]
    fn deeper_prefix_wins_over_broader_allow() {
        let config = with_rules(&["10.0.0.0/8 allow", "10.1.0.0/16 deny"]);
        assert_eq!(check(&config, &client([10, 1, 2, 3])), Decision::Deny);
        assert_eq!(check(&config, &client([10, 2, 2, 3])), Decision::Allow);
    }

    #[test]
    fn later_rule_wins_identical_netblocks() {
        let config = with_rules(&["192.0.2.0/24 allow", "192.0.2.0/24 refuse"]);
        assert_eq!(check(&config, &client([192, 0, 2, 5])), Decision::Refuse);
    }

    #[test]
    fn allow_setrd_maps_to_its_own_decision() {
        let config = with_rules(&["192.0.2.0/24 allow_setrd"]);
        assert_eq!(
            check(&config, &client([192, 0, 2, 5])),
            Decision::AllowSetrd
        );
    }
}
