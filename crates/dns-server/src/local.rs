//! Local zones, authority zones, and built-in local data.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use dns_config::{AuthZoneConfig, Config, LocalZoneConfig, LocalZoneType};
use dns_proto::{
    Message, MessageType, Name, OpCode, Query, RData, Record, RecordType, ResponseCode, SOA,
    parse_zone_records,
};
use ipnet::IpNet;
use tracing::{info, warn};

/// What the local policy decided to do with a query.
pub enum LocalAction {
    /// No local zone matched; continue normal processing.
    NotHandled,
    /// Drop the query without a reply (`deny` and `inform_deny`).
    Drop,
    /// Answer with a locally generated message.
    Answer(Box<Message>),
}

/// One local zone plus the records that belong to it.
#[derive(Clone)]
struct Zone {
    name: Name,
    zone_type: LocalZoneType,
    records: HashMap<Name, Vec<Record>>,
}

impl Zone {
    fn new(name: Name, zone_type: LocalZoneType) -> Self {
        Self {
            name,
            zone_type,
            records: HashMap::new(),
        }
    }

    fn insert(&mut self, record: Record) {
        self.records
            .entry(record.name.clone())
            .or_default()
            .push(record);
    }

    fn records_for(&self, name: &Name) -> Option<&Vec<Record>> {
        self.records.get(name)
    }

    fn soa(&self) -> Option<&Record> {
        self.records_for(&self.name).and_then(|records| {
            records
                .iter()
                .find(|record| record.record_type() == RecordType::SOA)
        })
    }
}

/// A set of local zones evaluated in most-specific-first order.
#[derive(Clone)]
pub struct LocalZones {
    zones: Vec<Zone>,
    authoritative: bool,
}

impl LocalZones {
    /// Build the policy from configured zones and global `local-data`.
    pub fn from_config(zones: &[LocalZoneConfig], data: &[String]) -> Self {
        let mut this = Self {
            zones: zones
                .iter()
                .filter_map(|zone| {
                    Name::from_ascii(&zone.name)
                        .ok()
                        .map(|name| Zone::new(name, zone.zone_type))
                })
                .collect(),
            authoritative: true,
        };
        for zone in zones {
            let Some(target) = this
                .zones
                .iter_mut()
                .find(|candidate| candidate.name.to_ascii().eq_ignore_ascii_case(&zone.name))
            else {
                continue;
            };
            for text in &zone.data {
                for record in parse_records(text) {
                    target.insert(record);
                }
            }
        }
        for text in data {
            this.insert_data(text);
        }
        this
    }

    /// Build an empty policy.
    pub fn empty() -> Self {
        Self {
            zones: Vec::new(),
            authoritative: true,
        }
    }

    /// Mark answers as authoritative (downstream) or recursive (upstream data).
    pub fn set_authoritative(&mut self, authoritative: bool) {
        self.authoritative = authoritative;
    }

    /// Add records, creating an implicit transparent zone when no configured
    /// zone contains the owner name.
    fn insert_data(&mut self, text: &str) {
        for record in parse_records(text) {
            let owner = record.name.clone();
            let index = self
                .zones
                .iter()
                .enumerate()
                .filter(|(_, zone)| zone.name.zone_of(&owner))
                .max_by_key(|(_, zone)| zone.name.num_labels())
                .map(|(index, _)| index);
            let index = match index {
                Some(index) => index,
                None => {
                    self.zones
                        .push(Zone::new(owner.clone(), LocalZoneType::Transparent));
                    self.zones.len() - 1
                }
            };
            self.zones[index].insert(record);
        }
    }

    /// Whether a configured zone covers `name`. Used to suppress built-ins.
    pub fn covers(&self, name: &Name) -> bool {
        self.zones.iter().any(|zone| zone.name.zone_of(name))
    }

    /// Apply the local-zone policy to a query.
    pub fn answer(&self, query: &Query) -> LocalAction {
        let Some(zone) = self
            .zones
            .iter()
            .filter(|zone| zone.name.zone_of(&query.name))
            .max_by_key(|zone| zone.name.num_labels())
        else {
            return LocalAction::NotHandled;
        };
        self.apply(zone, query)
    }

    fn apply(&self, zone: &Zone, query: &Query) -> LocalAction {
        let action = self.apply_zone(zone, query);
        match action {
            LocalAction::Answer(mut message) => {
                message.metadata.authoritative = self.authoritative;
                LocalAction::Answer(message)
            }
            other => other,
        }
    }

    fn apply_zone(&self, zone: &Zone, query: &Query) -> LocalAction {
        let zone_type = zone.zone_type;
        if zone_type == LocalZoneType::Nodefault {
            return LocalAction::NotHandled;
        }

        if matches!(
            zone_type,
            LocalZoneType::Inform | LocalZoneType::InformDeny | LocalZoneType::InformRedirect
        ) {
            info!(
                zone = %zone.name,
                qname = %query.name,
                qtype = ?query.query_type,
                "inform local-zone query"
            );
        }

        let exact = zone.records_for(&query.name);
        let matched = exact.is_some_and(|records| records_match(records, query.query_type));

        match zone_type {
            LocalZoneType::AlwaysTransparent | LocalZoneType::Nodefault => LocalAction::NotHandled,
            LocalZoneType::AlwaysDeny | LocalZoneType::Deny | LocalZoneType::InformDeny => {
                if matched {
                    answer_from(zone, exact, query)
                } else {
                    LocalAction::Drop
                }
            }
            LocalZoneType::AlwaysRefuse | LocalZoneType::Refuse => {
                if matched {
                    answer_from(zone, exact, query)
                } else {
                    LocalAction::Answer(Box::new(refused(query)))
                }
            }
            LocalZoneType::AlwaysNxdomain => {
                LocalAction::Answer(Box::new(negative(zone, query, ResponseCode::NXDomain)))
            }
            LocalZoneType::AlwaysNodata => {
                LocalAction::Answer(Box::new(negative(zone, query, ResponseCode::NoError)))
            }
            LocalZoneType::AlwaysNull => LocalAction::Answer(Box::new(null_answer(query))),
            LocalZoneType::BlockA => {
                if query.query_type == RecordType::A {
                    LocalAction::Answer(Box::new(negative(zone, query, ResponseCode::NoError)))
                } else {
                    LocalAction::NotHandled
                }
            }
            LocalZoneType::BlockAaaa => {
                if query.query_type == RecordType::AAAA {
                    LocalAction::Answer(Box::new(negative(zone, query, ResponseCode::NoError)))
                } else {
                    LocalAction::NotHandled
                }
            }
            LocalZoneType::BlockAWdata => {
                if query.query_type == RecordType::A {
                    LocalAction::Answer(Box::new(negative(zone, query, ResponseCode::NoError)))
                } else if matched {
                    answer_from(zone, exact, query)
                } else {
                    LocalAction::NotHandled
                }
            }
            LocalZoneType::BlockAaaaWdata => {
                if query.query_type == RecordType::AAAA {
                    LocalAction::Answer(Box::new(negative(zone, query, ResponseCode::NoError)))
                } else if matched {
                    answer_from(zone, exact, query)
                } else {
                    LocalAction::NotHandled
                }
            }
            LocalZoneType::Static => {
                if matched {
                    answer_from(zone, exact, query)
                } else if exact.is_some() {
                    LocalAction::Answer(Box::new(negative(zone, query, ResponseCode::NoError)))
                } else {
                    LocalAction::Answer(Box::new(negative(zone, query, ResponseCode::NXDomain)))
                }
            }
            LocalZoneType::Transparent | LocalZoneType::Inform => {
                if matched {
                    answer_from(zone, exact, query)
                } else if exact.is_some() {
                    LocalAction::Answer(Box::new(negative(zone, query, ResponseCode::NoError)))
                } else {
                    LocalAction::NotHandled
                }
            }
            LocalZoneType::Typetransparent => {
                if matched {
                    answer_from(zone, exact, query)
                } else {
                    LocalAction::NotHandled
                }
            }
            LocalZoneType::Redirect | LocalZoneType::InformRedirect => {
                let apex = zone.records_for(&zone.name);
                if apex.is_some_and(|records| records_match(records, query.query_type)) {
                    answer_from(zone, apex, query)
                } else {
                    LocalAction::Answer(Box::new(negative(zone, query, ResponseCode::NoError)))
                }
            }
        }
    }
}

/// A set of views plus the global fallback.
#[derive(Clone)]
pub struct LocalPolicy {
    global: LocalZones,
    views: Vec<ViewZones>,
    access: Vec<(IpNet, String)>,
}

#[derive(Clone)]
struct ViewZones {
    name: String,
    zones: LocalZones,
    view_first: bool,
}

impl LocalPolicy {
    /// Build the global and per-view policies.
    pub fn from_config(config: &Config) -> Self {
        let global = LocalZones::from_config(&config.local_zones, &config.local_data);
        let views = config
            .views
            .iter()
            .map(|view| ViewZones {
                name: view.name.clone(),
                zones: LocalZones::from_config(&view.local_zones, &view.local_data),
                view_first: view.view_first,
            })
            .collect();
        Self {
            global,
            views,
            access: config
                .server
                .access_control_view
                .iter()
                .map(|mapping| (mapping.network, mapping.view.clone()))
                .collect(),
        }
    }

    fn view_for(&self, client: IpAddr) -> Option<&ViewZones> {
        let name = self
            .access
            .iter()
            .filter(|(network, _)| network.contains(&client))
            .max_by_key(|(network, _)| network.prefix_len())
            .map(|(_, name)| name)?;
        self.views
            .iter()
            .find(|view| view.name.eq_ignore_ascii_case(name))
    }

    /// Apply the local policy for a client.
    pub fn answer(&self, client: IpAddr, query: &Query) -> LocalAction {
        if let Some(view) = self.view_for(client) {
            match view.zones.answer(query) {
                LocalAction::NotHandled if view.view_first => self.global.answer(query),
                other => other,
            }
        } else {
            self.global.answer(query)
        }
    }

    /// Whether any policy (view or global) covers `name`.
    pub fn covers(&self, client: IpAddr, name: &Name) -> bool {
        let in_view = self
            .view_for(client)
            .is_some_and(|view| view.zones.covers(name));
        in_view || self.global.covers(name)
    }
}

fn parse_records(text: &str) -> Vec<Record> {
    match parse_zone_records(text, None) {
        Ok(records) => records,
        Err(error) => {
            warn!(%error, data = %text, "ignoring invalid local-data record");
            Vec::new()
        }
    }
}

fn records_match(records: &[Record], qtype: RecordType) -> bool {
    qtype == RecordType::ANY
        || records.iter().any(|record| {
            record.record_type() == qtype || record.record_type() == RecordType::CNAME
        })
}

fn answer_from(zone: &Zone, records: Option<&Vec<Record>>, query: &Query) -> LocalAction {
    let Some(records) = records else {
        return LocalAction::Answer(Box::new(negative(zone, query, ResponseCode::NoError)));
    };
    let mut message = base_response(query);
    let mut added = false;
    for record in records {
        if query.query_type == RecordType::ANY
            || record.record_type() == query.query_type
            || record.record_type() == RecordType::CNAME
        {
            let mut record = record.clone();
            // Redirect zones answer every subdomain with the apex data.
            if record.name != query.name {
                record.name = query.name.clone();
            }
            message.add_answer(record);
            added = true;
        }
    }
    if !added {
        message.metadata.response_code = ResponseCode::NoError;
        add_soa(&mut message, zone);
    }
    LocalAction::Answer(Box::new(message))
}

fn null_answer(query: &Query) -> Message {
    let mut message = base_response(query);
    if matches!(query.query_type, RecordType::A | RecordType::ANY) {
        message.add_answer(Record::from_rdata(
            query.name.clone(),
            60,
            RData::A(Ipv4Addr::UNSPECIFIED.into()),
        ));
    }
    if matches!(query.query_type, RecordType::AAAA | RecordType::ANY) {
        message.add_answer(Record::from_rdata(
            query.name.clone(),
            60,
            RData::AAAA(Ipv6Addr::UNSPECIFIED.into()),
        ));
    }
    message
}

fn refused(query: &Query) -> Message {
    let mut message = base_response(query);
    message.metadata.response_code = ResponseCode::Refused;
    message
}

fn negative(zone: &Zone, query: &Query, code: ResponseCode) -> Message {
    let mut message = base_response(query);
    message.metadata.response_code = code;
    add_soa(&mut message, zone);
    message
}

fn add_soa(message: &mut Message, zone: &Zone) {
    if let Some(soa) = zone.soa() {
        message.add_authority(soa.clone());
    } else if let Some(soa) = synthetic_soa(zone) {
        message.add_authority(soa);
    }
}

fn synthetic_soa(zone: &Zone) -> Option<Record> {
    let name = zone.name.clone();
    Some(Record::from_rdata(
        name,
        60,
        RData::SOA(SOA::new(
            Name::from_ascii("localhost.").ok()?,
            Name::from_ascii("hostmaster.localhost.").ok()?,
            1,
            3600,
            600,
            86_400,
            60,
        )),
    ))
}

fn base_response(query: &Query) -> Message {
    let mut message = Message::new(0, MessageType::Response, OpCode::Query);
    message.metadata.authoritative = true;
    message.metadata.recursion_available = true;
    message.add_query(query.clone());
    message
}

/// Built-in names, parsed once so the per-query path compares [`Name`] values
/// instead of formatting the QNAME into a lowercased `String`.
struct BuiltinNames {
    localhost: Name,
    server_id: Name,
    hostname: Name,
}

static BUILTIN_NAMES: LazyLock<BuiltinNames> = LazyLock::new(|| BuiltinNames {
    localhost: Name::from_ascii("localhost.").expect("built-in name is valid"),
    server_id: Name::from_ascii("id.server.").expect("built-in name is valid"),
    hostname: Name::from_ascii("hostname.bind.").expect("built-in name is valid"),
});

/// Generate a local static response for known built-in names.
pub fn maybe_respond(query: &Query) -> Option<Message> {
    let names = &*BUILTIN_NAMES;
    if query.name == names.localhost {
        let mut message = base_response(query);
        if matches!(query.query_type, RecordType::A | RecordType::ANY) {
            message.add_answer(Record::from_rdata(
                query.name.clone(),
                60,
                RData::A(Ipv4Addr::LOCALHOST.into()),
            ));
        }
        if matches!(query.query_type, RecordType::AAAA | RecordType::ANY) {
            message.add_answer(Record::from_rdata(
                query.name.clone(),
                60,
                RData::AAAA(Ipv6Addr::LOCALHOST.into()),
            ));
        }
        Some(message)
    } else if query.name == names.server_id || query.name == names.hostname {
        Some(base_response(query))
    } else {
        None
    }
}

/// Load authority-zone files into a local zone set.
///
/// `downstream` selects zones served to clients; otherwise zones used as
/// local upstream data are loaded.
pub fn auth_zones(zones: &[AuthZoneConfig], downstream: bool) -> LocalZones {
    let mut local = LocalZones::empty();
    local.set_authoritative(downstream);
    for zone in zones {
        if (downstream && !zone.for_downstream) || (!downstream && !zone.for_upstream) {
            continue;
        }
        let Some(path) = &zone.zonefile else {
            warn!(
                zone = %zone.name,
                "auth-zone without a zonefile is not loaded; AXFR/URL fetching is not implemented"
            );
            continue;
        };
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) => {
                warn!(
                    zone = %zone.name,
                    path = %path.display(),
                    %error,
                    "failed to read auth-zone zonefile"
                );
                continue;
            }
        };
        let origin = Name::from_ascii(&zone.name).ok();
        let records = match parse_zone_records(&text, origin.as_ref()) {
            Ok(records) => records,
            Err(error) => {
                warn!(
                    zone = %zone.name,
                    path = %path.display(),
                    %error,
                    "failed to parse auth-zone zonefile"
                );
                continue;
            }
        };
        let Some(name) = origin else {
            continue;
        };
        let mut auth = Zone::new(name, LocalZoneType::Static);
        for record in records {
            auth.insert(record);
        }
        local.zones.push(auth);
    }
    local
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: RecordType) -> Query {
        Query::query(Name::from_ascii(name).expect("name"), qtype)
    }

    fn zones(zone_type: LocalZoneType, data: &[&str]) -> LocalZones {
        let zone = LocalZoneConfig {
            name: "example.test.".to_owned(),
            zone_type,
            data: data.iter().map(|value| (*value).to_owned()).collect(),
        };
        LocalZones::from_config(&[zone], &[])
    }

    fn answer(zones: &LocalZones, qname: &str, qtype: RecordType) -> Message {
        match zones.answer(&query(qname, qtype)) {
            LocalAction::Answer(message) => *message,
            _ => panic!("expected an answer for {qname} {qtype:?}"),
        }
    }

    #[test]
    fn static_zone_answers_and_negates() {
        let zones = zones(
            LocalZoneType::Static,
            &[
                "example.test. 300 IN A 192.0.2.10",
                "example.test. 300 IN SOA ns.example.test. hostmaster.example.test. 1 3600 600 86400 60",
                "www.example.test. 300 IN A 192.0.2.11",
            ],
        );

        let message = answer(&zones, "www.example.test.", RecordType::A);
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        assert_eq!(message.answers.len(), 1);
        assert!(message.metadata.authoritative);

        let nodata = answer(&zones, "www.example.test.", RecordType::AAAA);
        assert_eq!(nodata.metadata.response_code, ResponseCode::NoError);
        assert!(nodata.answers.is_empty());
        assert_eq!(nodata.authorities.len(), 1);

        let nxdomain = answer(&zones, "missing.example.test.", RecordType::A);
        assert_eq!(nxdomain.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(nxdomain.authorities.len(), 1);
    }

    #[test]
    fn transparent_zone_falls_through_for_unknown_names() {
        let zones = zones(
            LocalZoneType::Transparent,
            &["example.test. 300 IN A 192.0.2.10"],
        );
        assert!(matches!(
            zones.answer(&query("unknown.example.test.", RecordType::A)),
            LocalAction::NotHandled
        ));
        // A name with data but not this type is NODATA.
        let message = answer(&zones, "example.test.", RecordType::AAAA);
        assert!(message.answers.is_empty());
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    }

    #[test]
    fn redirect_zone_answers_subdomains_from_apex() {
        let zones = zones(
            LocalZoneType::Redirect,
            &["example.test. 300 IN A 192.0.2.10"],
        );
        let message = answer(&zones, "deep.www.example.test.", RecordType::A);
        assert_eq!(message.answers.len(), 1);
        assert_eq!(message.answers[0].name.to_ascii(), "deep.www.example.test.");
    }

    #[test]
    fn deny_and_refuse_do_not_leak_data() {
        let deny = zones(LocalZoneType::Deny, &[]);
        assert!(matches!(
            deny.answer(&query("example.test.", RecordType::A)),
            LocalAction::Drop
        ));

        let refuse = zones(LocalZoneType::Refuse, &[]);
        let message = answer(&refuse, "example.test.", RecordType::A);
        assert_eq!(message.metadata.response_code, ResponseCode::Refused);
    }

    #[test]
    fn implicit_transparent_zone_from_local_data() {
        let zones = LocalZones::from_config(&[], &["host.test. 60 IN A 198.51.100.1".to_owned()]);
        let message = answer(&zones, "host.test.", RecordType::A);
        assert_eq!(message.answers.len(), 1);
        assert!(matches!(
            zones.answer(&query("other.test.", RecordType::A)),
            LocalAction::NotHandled
        ));
    }

    #[test]
    fn view_overrides_global_and_can_fall_back() {
        let mut config = Config::default();
        config.server.access_control_view = vec![dns_config::AccessControlView {
            network: "127.0.0.0/8".parse().expect("network"),
            view: "trusted".to_owned(),
        }];
        config.local_zones = vec![LocalZoneConfig {
            name: "example.test.".to_owned(),
            zone_type: LocalZoneType::Static,
            data: vec!["example.test. 60 IN A 192.0.2.1".to_owned()],
        }];
        config.views = vec![dns_config::ViewConfig {
            name: "trusted".to_owned(),
            view_first: true,
            local_zones: Vec::new(),
            local_data: vec!["example.test. 60 IN A 10.0.0.1".to_owned()],
        }];
        let policy = LocalPolicy::from_config(&config);

        let local = policy.answer(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &query("example.test.", RecordType::A),
        );
        let LocalAction::Answer(message) = local else {
            panic!("view must answer");
        };
        assert_eq!(message.answers[0].data.to_string(), "10.0.0.1");

        let global = policy.answer(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            &query("example.test.", RecordType::A),
        );
        let LocalAction::Answer(message) = global else {
            panic!("global must answer");
        };
        assert_eq!(message.answers[0].data.to_string(), "192.0.2.1");
    }

    #[test]
    fn builtin_names_match_case_insensitively() {
        let a = maybe_respond(&query("LoCaLhOsT.", RecordType::A)).expect("localhost answer");
        assert_eq!(a.answers.len(), 1);
        assert_eq!(a.answers[0].data.to_string(), "127.0.0.1");

        let any = maybe_respond(&query("localhost.", RecordType::ANY)).expect("any answer");
        assert_eq!(any.answers.len(), 2);
    }

    #[test]
    fn builtin_server_id_answers_without_records() {
        let message =
            maybe_respond(&query("HOSTNAME.BIND.", RecordType::TXT)).expect("server id answer");
        assert!(message.answers.is_empty());
    }

    #[test]
    fn builtin_names_require_a_qualified_name() {
        let bare = Query::query(Name::from_ascii("localhost").expect("name"), RecordType::A);
        assert!(maybe_respond(&bare).is_none());
        assert!(maybe_respond(&query("example.test.", RecordType::A)).is_none());
    }

    #[test]
    fn loads_auth_zone_file() {
        let directory = std::env::temp_dir().join(format!("dns-rs-auth-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("tempdir");
        let path = directory.join("auth.test.zone");
        std::fs::write(
            &path,
            "$ORIGIN auth.test.\n@ 60 IN SOA ns.auth.test. hostmaster.auth.test. 1 3600 600 86400 60\nwww 60 IN A 192.0.2.42\n",
        )
        .expect("zonefile");

        let zones = auth_zones(
            &[AuthZoneConfig {
                name: "auth.test.".to_owned(),
                zonefile: Some(path.clone()),
                ..AuthZoneConfig::default()
            }],
            true,
        );
        let message = answer(&zones, "www.auth.test.", RecordType::A);
        assert_eq!(message.answers.len(), 1);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir(directory);
    }
}
