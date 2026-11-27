//! Local zones, authority zones, and built-in local data.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use dns_config::{AuthZoneConfig, Config, LocalZoneConfig, LocalZoneType, parse_local_data};
use dns_proto::{
    Message, MessageType, Name, OpCode, Query, RData, Record, RecordType, ResponseCode, SOA,
    parse_zone_records,
};
use ipnet::IpNet;
use tracing::{debug, info, warn};

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
    /// Allocated only when a record is inserted. Name-independent policies and
    /// empty zones never touch the heap for records.
    ///
    /// The box keeps the field one pointer wide instead of the 48 bytes of
    /// `HashMap`, which matters when a blocklist holds tens of thousands of
    /// zones that carry no records.
    #[allow(clippy::box_collection)]
    records: Option<Box<HashMap<Name, Vec<Record>>>>,
}

impl Zone {
    fn new(name: Name, zone_type: LocalZoneType) -> Self {
        Self {
            name,
            zone_type,
            records: None,
        }
    }

    fn insert(&mut self, record: Record) {
        let records = self.records.get_or_insert_with(|| Box::new(HashMap::new()));
        records.entry(record.name.clone()).or_default().push(record);
    }

    fn records_for(&self, name: &Name) -> Option<&Vec<Record>> {
        self.records
            .as_deref()
            .and_then(|records| records.get(name))
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
///
/// Zones are sorted by their labels in reverse order, so a query can find each
/// matching suffix with one binary search per label. The ordering is
/// case-insensitive, and an ancestor sorts before its descendants.
#[derive(Clone)]
pub struct LocalZones {
    zones: Vec<Zone>,
    authoritative: bool,
}

impl LocalZones {
    /// Build the policy from configured zones and global `local-data`.
    ///
    /// Name-independent zones whose closest ancestor has the same policy are
    /// dropped as redundant. This is the normal shape of a generated blocklist,
    /// where `always_nxdomain` is repeated for a parent and its children; the
    /// ancestor produces the same response for every name in the child.
    pub fn from_config(zones: &[LocalZoneConfig], data: &[String]) -> Self {
        let mut this = Self {
            zones: Vec::with_capacity(zones.len()),
            authoritative: true,
        };
        for zone in zones {
            let Ok(name) = Name::from_ascii(&zone.name) else {
                continue;
            };
            let mut built = Zone::new(name, zone.zone_type);
            // Name-independent policies never read local data, so parsing it
            // would only cost startup time and memory.
            if zone.zone_type.uses_local_data() {
                for text in &zone.data {
                    for record in parse_records(text) {
                        built.insert(record);
                    }
                }
            }
            this.zones.push(built);
        }
        this.sort_zones();

        let suppressed = this.suppress_redundant();
        this.insert_data(data);

        if suppressed > 0 {
            info!(suppressed, "suppressed redundant local-zone entries");
        }
        this
    }

    /// Drop zones that repeat the policy of their closest ancestor or the name
    /// of an earlier zone, compacting the sorted vector in place.
    ///
    /// Sorting puts every ancestor before its descendants, so a stack of kept
    /// zones on the current path yields the closest ancestor in amortized
    /// constant time. Returns the number of removed zones.
    fn suppress_redundant(&mut self) -> usize {
        // Indices of kept zones that are ancestors of the current position.
        // A query name has at most 128 labels, so this chain stays short.
        let mut ancestors: Vec<usize> = Vec::new();
        let mut kept = 0usize;
        for read in 0..self.zones.len() {
            let name = &self.zones[read].name;
            while let Some(&top) = ancestors.last() {
                if self.zones[top].name.zone_of(name) {
                    break;
                }
                ancestors.pop();
            }
            let duplicate = ancestors.last().is_some_and(|&top| {
                compare_reversed_labels(&self.zones[top].name, name) == Ordering::Equal
            });
            let redundant = !duplicate
                && self.zones[read].zone_type.is_name_independent()
                && ancestors
                    .last()
                    .is_some_and(|&top| self.zones[top].zone_type == self.zones[read].zone_type);
            if duplicate || redundant {
                continue;
            }
            if kept != read {
                self.zones.swap(kept, read);
            }
            ancestors.push(kept);
            kept += 1;
        }
        let suppressed = self.zones.len() - kept;
        self.zones.truncate(kept);
        if suppressed > 0 {
            // Release the slots and inline name storage of dropped zones.
            self.zones.shrink_to_fit();
        }
        suppressed
    }

    /// Attach global `local-data` records to the most specific zone.
    ///
    /// A record outside every configured zone creates an implicit transparent
    /// zone. Implicit zones are appended and merged once, so this stays linear
    /// in the number of records plus one sort.
    fn insert_data(&mut self, data: &[String]) {
        if data.is_empty() {
            return;
        }
        let mut implicit: Vec<Zone> = Vec::new();
        // Created lazily: a list that only feeds configured zones allocates no
        // map, and only implicit zone owners are ever inserted.
        let mut implicit_index: HashMap<Name, usize> = HashMap::new();
        for text in data {
            for record in parse_records(text) {
                if let Some(index) = self.find_zone(&record.name) {
                    self.zones[index].insert(record);
                    continue;
                }
                let index = match deepest_implicit(&implicit_index, &record.name) {
                    Some(index) => index,
                    None => {
                        let index = implicit.len();
                        implicit.push(Zone::new(record.name.clone(), LocalZoneType::Transparent));
                        implicit_index.insert(record.name.clone(), index);
                        index
                    }
                };
                implicit[index].insert(record);
            }
        }
        if implicit.is_empty() {
            return;
        }
        self.zones.extend(implicit);
        self.sort_zones();
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

    /// Restore the ordering that [`Self::find_zone`] relies on.
    fn sort_zones(&mut self) {
        self.zones
            .sort_unstable_by(|left, right| compare_reversed_labels(&left.name, &right.name));
    }

    /// Index of the most specific zone that covers `name`.
    fn find_zone(&self, name: &Name) -> Option<usize> {
        // `Name` keeps short names inline, so the usual query allocates
        // nothing while walking up to the root.
        let mut suffix = name.clone();
        loop {
            if let Ok(index) = self
                .zones
                .binary_search_by(|zone| compare_reversed_labels(&zone.name, &suffix))
            {
                return Some(index);
            }
            if suffix.is_root() {
                return None;
            }
            suffix = suffix.base_name();
        }
    }

    /// Whether a configured zone covers `name`. Used to suppress built-ins.
    pub fn covers(&self, name: &Name) -> bool {
        self.find_zone(name).is_some()
    }

    /// Apply the local-zone policy to a query.
    ///
    /// Handled queries emit a debug line naming the matched zone, its policy,
    /// and the resulting action so blocklist decisions can be traced.
    pub fn answer(&self, query: &Query) -> LocalAction {
        let Some(index) = self.find_zone(&query.name) else {
            return LocalAction::NotHandled;
        };
        let zone = &self.zones[index];
        let action = self.apply(zone, query);
        let outcome = match &action {
            LocalAction::Answer(_) => "answer",
            LocalAction::Drop => "drop",
            LocalAction::NotHandled => return action,
        };
        debug!(
            zone = %zone.name,
            reason = %zone.zone_type,
            qname = %query.name,
            qtype = ?query.query_type,
            outcome,
            "local-zone decision"
        );
        action
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

/// Compare names by their labels from the root down.
///
/// This is the order that lets [`LocalZones::find_zone`] binary-search every
/// suffix of a query name: an ancestor sorts before its descendants. The
/// comparison is case-insensitive, matching [`Name::zone_of`].
fn compare_reversed_labels(left: &Name, right: &Name) -> Ordering {
    let mut left_labels = left.iter().rev();
    let mut right_labels = right.iter().rev();
    loop {
        match (left_labels.next(), right_labels.next()) {
            (Some(left_label), Some(right_label)) => {
                let ordering = left_label
                    .iter()
                    .map(u8::to_ascii_lowercase)
                    .cmp(right_label.iter().map(u8::to_ascii_lowercase));
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            (Some(_), None) => return Ordering::Greater,
            (None, Some(_)) => return Ordering::Less,
            (None, None) => return Ordering::Equal,
        }
    }
}

/// Index of the most specific implicit zone that covers `name`.
fn deepest_implicit(index: &HashMap<Name, usize>, name: &Name) -> Option<usize> {
    let mut suffix = name.clone();
    loop {
        if let Some(&found) = index.get(&suffix) {
            return Some(found);
        }
        if suffix.is_root() {
            return None;
        }
        suffix = suffix.base_name();
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
    match parse_local_data(text) {
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
    local.sort_zones();
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
    fn local_data_attaches_to_configured_and_implicit_zones() {
        let zones = LocalZones::from_config(
            &[zone_config("example.test.", LocalZoneType::Static)],
            &[
                "host.example.test. 60 IN A 198.51.100.1".to_owned(),
                "other.test. 60 IN A 198.51.100.2".to_owned(),
                "deep.other.test. 60 IN A 198.51.100.3".to_owned(),
            ],
        );

        // Records under the configured zone are answered from it.
        let host = answer(&zones, "host.example.test.", RecordType::A);
        assert_eq!(host.answers[0].data.to_string(), "198.51.100.1");
        // Uncovered owners share one implicit transparent zone.
        let other = answer(&zones, "other.test.", RecordType::A);
        assert_eq!(other.answers[0].data.to_string(), "198.51.100.2");
        let deep = answer(&zones, "deep.other.test.", RecordType::A);
        assert_eq!(deep.answers[0].data.to_string(), "198.51.100.3");
        assert_eq!(zones.zones.len(), 2);
    }

    fn zone_config(name: &str, zone_type: LocalZoneType) -> LocalZoneConfig {
        LocalZoneConfig {
            name: name.to_owned(),
            zone_type,
            data: Vec::new(),
        }
    }

    #[test]
    fn most_specific_zone_wins() {
        let zones = LocalZones::from_config(
            &[
                LocalZoneConfig {
                    name: "example.test.".to_owned(),
                    zone_type: LocalZoneType::Static,
                    data: vec!["example.test. 60 IN A 192.0.2.1".to_owned()],
                },
                LocalZoneConfig {
                    name: "sub.example.test.".to_owned(),
                    zone_type: LocalZoneType::Static,
                    data: vec!["sub.example.test. 60 IN A 192.0.2.2".to_owned()],
                },
            ],
            &[],
        );

        let apex = answer(&zones, "example.test.", RecordType::A);
        assert_eq!(apex.answers[0].data.to_string(), "192.0.2.1");
        let child = answer(&zones, "sub.example.test.", RecordType::A);
        assert_eq!(child.answers[0].data.to_string(), "192.0.2.2");
    }

    #[test]
    fn zone_lookup_is_case_insensitive() {
        let zones = LocalZones::from_config(
            &[LocalZoneConfig {
                name: "Example.Test.".to_owned(),
                zone_type: LocalZoneType::Static,
                data: vec!["WWW.Example.Test. 60 IN A 192.0.2.7".to_owned()],
            }],
            &[],
        );

        let message = answer(&zones, "www.example.test.", RecordType::A);
        assert_eq!(message.answers[0].data.to_string(), "192.0.2.7");
        assert!(zones.covers(&Name::from_ascii("other.EXAMPLE.test.").expect("name")));
    }

    #[test]
    fn redundant_name_independent_zones_are_suppressed() {
        let zones = LocalZones::from_config(
            &[
                zone_config("ads.test.", LocalZoneType::AlwaysNxdomain),
                zone_config("tracker.ads.test.", LocalZoneType::AlwaysNxdomain),
                zone_config("deep.tracker.ads.test.", LocalZoneType::AlwaysNxdomain),
                // A different policy under the same ancestor must be kept.
                zone_config("keep.ads.test.", LocalZoneType::AlwaysNodata),
                // A descendant of the different policy must also be kept.
                zone_config("allowed.keep.ads.test.", LocalZoneType::AlwaysNxdomain),
            ],
            &[],
        );

        assert_eq!(zones.zones.len(), 3);
        for name in [
            "tracker.ads.test.",
            "deep.tracker.ads.test.",
            "x.deep.tracker.ads.test.",
        ] {
            let message = answer(&zones, name, RecordType::A);
            assert_eq!(message.metadata.response_code, ResponseCode::NXDomain);
        }
        let nodata = answer(&zones, "keep.ads.test.", RecordType::A);
        assert_eq!(nodata.metadata.response_code, ResponseCode::NoError);
        assert!(nodata.answers.is_empty());
        let allowed = answer(&zones, "x.allowed.keep.ads.test.", RecordType::A);
        assert_eq!(allowed.metadata.response_code, ResponseCode::NXDomain);

        // The surviving ancestor still reports the covered name as local.
        assert!(zones.covers(&Name::from_ascii("x.tracker.ads.test.").expect("name")));
    }

    #[test]
    fn a_root_zone_suppresses_matching_descendants() {
        let zones = LocalZones::from_config(
            &[
                zone_config(".", LocalZoneType::AlwaysNxdomain),
                zone_config("child.test.", LocalZoneType::AlwaysNxdomain),
            ],
            &[],
        );
        assert_eq!(zones.zones.len(), 1);
        let message = answer(&zones, "child.test.", RecordType::A);
        assert_eq!(message.metadata.response_code, ResponseCode::NXDomain);
    }

    #[test]
    fn long_names_match_through_base_name_walks() {
        let zone = "a-very-long-label-that-does-not-fit-inline.example.test.";
        let zones =
            LocalZones::from_config(&[zone_config(zone, LocalZoneType::AlwaysNxdomain)], &[]);

        let deep = format!("deep.{zone}");
        let message = answer(&zones, &deep, RecordType::A);
        assert_eq!(message.metadata.response_code, ResponseCode::NXDomain);
        assert!(zones.covers(&Name::from_ascii(&deep).expect("long name")));
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
