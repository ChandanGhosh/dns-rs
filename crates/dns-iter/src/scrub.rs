//! Response scrubbing and referral extraction.
//!
//! Every upstream response passes through these checks before any of its data
//! is used or cached. They implement the bailiwick, question-match, class and
//! TTL rules from RFC 2181, RFC 4035 and Unbound's hardening defaults.

use dns_proto::{DNSClass, Message, Name, RData, Record, RecordType, ResponseCode};

/// A validated delegation.
#[derive(Clone, Debug)]
pub struct Referral {
    pub zone: Name,
    pub nameservers: Vec<Name>,
    pub nameserver_records: Vec<Record>,
    pub glue: Vec<Record>,
}

/// Check that a response answers the question we asked.
///
/// When `require_case` is set (DNS 0x20), the QNAME case must match exactly.
pub fn question_matches(
    sent_name: &Name,
    qtype: RecordType,
    response: &Message,
    require_case: bool,
) -> bool {
    if response.queries.len() != 1 {
        return false;
    }
    let question = &response.queries[0];
    if question.query_type != qtype || question.query_class != DNSClass::IN {
        return false;
    }

    // `Name` equality is case-insensitive; the 0x20 path compares the raw
    // label bytes so the echoed case must match exactly, without formatting
    // either name into a `String`.
    if require_case {
        sent_name.is_fqdn() == question.name.is_fqdn() && sent_name.iter().eq(question.name.iter())
    } else {
        sent_name == &question.name
    }
}

/// Strip data we never trust: non-IN records, OPT pseudo-records in the
/// additional section, and TTLs outside the configured bounds.
pub fn sanitize(message: &mut Message, min_ttl: u32, max_ttl: u32) {
    for section in [
        &mut message.answers,
        &mut message.authorities,
        &mut message.additionals,
    ] {
        section.retain(|record| {
            record.record_type() != RecordType::OPT && record.dns_class == DNSClass::IN
        });
        for record in section.iter_mut() {
            record.ttl = record.ttl.clamp(min_ttl, max_ttl.max(min_ttl));
        }
    }
}

/// True for an authoritative negative answer (NXDOMAIN or NODATA).
pub fn is_negative(response: &Message) -> bool {
    if response.metadata.response_code == ResponseCode::NXDomain {
        return true;
    }
    response.metadata.response_code == ResponseCode::NoError
        && response.answers.is_empty()
        && response
            .authorities
            .iter()
            .any(|record| record.record_type() == RecordType::SOA)
}

/// Keep only authority records that are relevant to `qname`.
pub fn scrub_authorities(response: &mut Message, qname: &Name) {
    // RFC 2181 §5.4.1: a resolver must not trust data from outside the
    // authoritative zone it was querying. For negative answers the SOA owner
    // must be an ancestor of the query name.
    response
        .authorities
        .retain(|record| record.record_type() != RecordType::SOA || record.name.zone_of(qname));
}

/// Extract the closest delegation from a referral response.
///
/// `source_zone` is the zone the responding servers are authoritative for.
/// Glue is always restricted to the delegated NS names. With `harden_glue`
/// set, the responding server must also be authoritative for the glue owner
/// (so root and TLD glue works, but out-of-bailiwick glue from a child zone is
/// discarded). Returns `None` when the response is not a referral, when the
/// delegation is not an ancestor of the query, or when the NS set is empty.
pub fn extract_referral(
    response: &Message,
    qname: &Name,
    source_zone: &Name,
    harden_glue: bool,
) -> Option<Referral> {
    let mut zone: Option<Name> = None;

    // Delegations normally live in the authority section, but some servers
    // (and some middleboxes) put them in the answer section. Accept both.
    for record in response.authorities.iter().chain(response.answers.iter()) {
        if record.record_type() != RecordType::NS {
            continue;
        }
        if !record.name.zone_of(qname) {
            // Delegation outside the query's ancestry: ignore (bailiwick).
            continue;
        }
        let is_deeper = zone
            .as_ref()
            .is_none_or(|current| record.name.num_labels() > current.num_labels());
        if is_deeper {
            zone = Some(record.name.clone());
        }
    }

    let zone = zone?;

    let nameserver_records: Vec<Record> = response
        .authorities
        .iter()
        .chain(response.answers.iter())
        .filter(|record| record.record_type() == RecordType::NS && record.name == zone)
        .cloned()
        .collect();

    let nameservers: Vec<Name> = nameserver_records
        .iter()
        .filter_map(|record| match &record.data {
            RData::NS(target) => Some(target.0.clone()),
            _ => None,
        })
        .collect();

    if nameservers.is_empty() {
        return None;
    }

    let glue = response
        .additionals
        .iter()
        .filter(|record| {
            if !matches!(record.data, RData::A(_) | RData::AAAA(_)) {
                return false;
            }
            nameservers.iter().any(|ns| ns == &record.name)
                && (!harden_glue || source_zone.zone_of(&record.name))
        })
        .cloned()
        .collect();

    Some(Referral {
        zone,
        nameservers,
        nameserver_records,
        glue,
    })
}

/// Addresses carried by A/AAAA records.
pub fn addresses(records: &[Record]) -> Vec<std::net::IpAddr> {
    records
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(address) => Some(std::net::IpAddr::V4(address.0)),
            RData::AAAA(address) => Some(std::net::IpAddr::V6(address.0)),
            _ => None,
        })
        .collect()
}

/// Find the CNAME target for `name`, if the response contains one.
pub fn cname_target(response: &Message, name: &Name) -> Option<Name> {
    response.answers.iter().find_map(|record| {
        if record.record_type() == RecordType::CNAME && &record.name == name {
            match &record.data {
                RData::CNAME(target) => Some(target.0.clone()),
                _ => None,
            }
        } else {
            None
        }
    })
}

/// Identify a response that carries no usable answer (lame server).
pub fn is_lame(response: &Message) -> bool {
    match response.metadata.response_code {
        ResponseCode::NoError => {
            response.answers.is_empty()
                && !response
                    .authorities
                    .iter()
                    .any(|record| matches!(record.record_type(), RecordType::NS | RecordType::SOA))
        }
        ResponseCode::NXDomain => false,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use dns_proto::{Message, MessageType, Name, OpCode, RData, Record, RecordType};

    use super::{extract_referral, question_matches, sanitize};

    fn name(text: &str) -> Name {
        Name::from_ascii(text).expect("valid name")
    }

    fn referral(zone: &str, ns: &str, glue: &str) -> Message {
        let mut message = Message::new(1, MessageType::Response, OpCode::Query);
        message.add_query(dns_proto::Query::query(name(ns), RecordType::NS));
        message.add_authority(Record::from_rdata(
            name(zone),
            3600,
            RData::NS(dns_proto::NS(name(ns))),
        ));
        message.add_additional(Record::from_rdata(
            name(glue),
            3600,
            RData::A(Ipv4Addr::new(192, 0, 2, 1).into()),
        ));
        message
    }

    #[test]
    fn accepts_root_glue_for_tlds() {
        let response = referral("com.", "a.gtld-servers.net.", "a.gtld-servers.net.");
        let found = extract_referral(&response, &name("www.example.com."), &name("."), true)
            .expect("referral");
        assert_eq!(found.zone, name("com."));
        assert_eq!(found.glue.len(), 1);
    }

    #[test]
    fn rejects_referral_outside_query_ancestry() {
        let response = referral("other.net.", "ns.other.net.", "ns.other.net.");
        assert!(extract_referral(&response, &name("www.example.com."), &name("."), true).is_none());
    }

    #[test]
    fn rejects_glue_outside_server_authority() {
        let response = referral("example.com.", "ns.other.net.", "ns.other.net.");
        let found = extract_referral(&response, &name("www.example.com."), &name("com."), true)
            .expect("referral");
        assert!(found.glue.is_empty());
    }

    #[test]
    fn rejects_unrelated_glue() {
        let response = referral("example.com.", "ns.example.com.", "evil.example.com.");
        let found = extract_referral(&response, &name("www.example.com."), &name("."), true)
            .expect("referral");
        assert!(found.glue.is_empty());
    }

    #[test]
    fn relaxed_glue_accepts_out_of_bailiwick_ns_address() {
        let response = referral("example.com.", "ns.other.net.", "ns.other.net.");
        let found = extract_referral(&response, &name("www.example.com."), &name("com."), false)
            .expect("referral");
        assert_eq!(found.glue.len(), 1);
    }

    #[test]
    fn relaxed_glue_rejects_unrelated_additional() {
        let response = referral("example.com.", "ns.example.com.", "evil.example.com.");
        let found = extract_referral(&response, &name("www.example.com."), &name("."), false)
            .expect("referral");
        assert!(found.glue.is_empty());
    }

    #[test]
    fn strips_non_internet_and_caps_ttl() {
        let mut message = Message::new(1, MessageType::Response, OpCode::Query);
        message.add_answer(Record::from_rdata(
            name("example.com."),
            999_999,
            RData::A(Ipv4Addr::new(192, 0, 2, 1).into()),
        ));
        sanitize(&mut message, 0, 60);
        assert_eq!(message.answers.len(), 1);
        assert_eq!(message.answers[0].ttl, 60);
    }

    #[test]
    fn enforces_question_case_when_requested() {
        let mut query = Message::new(1, MessageType::Query, OpCode::Query);
        query.add_query(dns_proto::Query::query(name("ExAmPlE.CoM."), RecordType::A));
        assert!(question_matches(
            &name("ExAmPlE.CoM."),
            RecordType::A,
            &query,
            true
        ));
        assert!(!question_matches(
            &name("example.com."),
            RecordType::A,
            &query,
            true
        ));
    }
}
