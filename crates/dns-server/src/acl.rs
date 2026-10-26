use std::net::SocketAddr;

use dns_config::{AccessAction, Config};

/// Access control decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    AllowSnoop,
    Refuse,
    Deny,
    DenyNonLocal,
    RefuseNonLocal,
}

impl From<AccessAction> for Decision {
    fn from(action: AccessAction) -> Self {
        match action {
            AccessAction::Allow => Decision::Allow,
            AccessAction::AllowSnoop => Decision::AllowSnoop,
            AccessAction::Refuse => Decision::Refuse,
            AccessAction::Deny => Decision::Deny,
            AccessAction::DenyNonLocal => Decision::DenyNonLocal,
            AccessAction::RefuseNonLocal => Decision::RefuseNonLocal,
        }
    }
}

/// Check access for a client address against the configuration.
pub fn check(config: &Config, addr: &SocketAddr) -> Decision {
    let ip = addr.ip();
    for rule in &config.server.access_control {
        if rule.network.contains(&ip) {
            return rule.action.into();
        }
    }
    // Default to refuse if no rule matches (Unbound-like behavior)
    Decision::Refuse
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use dns_config::Config;

    use super::{Decision, check};

    #[test]
    fn allows_loopback() {
        let config = Config::default();
        let decision = check(
            &config,
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
        );
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn refuses_unknown() {
        let config = Config::default();
        let decision = check(
            &config,
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 1234),
        );
        assert_eq!(decision, Decision::Refuse);
    }
}
