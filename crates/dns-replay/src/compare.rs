//! Semantic DNS message comparison for replay assertions.

use std::collections::HashMap;
use std::net::IpAddr;

use dns_proto::{Message, Record};

use crate::model::{Entry, RecordLine, Reply};

/// Compare a replay entry with a resolver message.
///
/// Header flags are checked only when the replay entry asserts them as true.
/// Record TTLs are ignored; compression, record order, and the fake-network
/// address aliases do not affect the result.
pub fn compare_answer(
    expected: &Entry,
    actual: &Message,
    aliases: &HashMap<IpAddr, IpAddr>,
) -> Vec<String> {
    let Some(reply) = expected.first_reply() else {
        return vec!["entry has no reply".to_owned()];
    };
    let mut problems = Vec::new();
    compare_header(reply, actual, &mut problems);
    let questions = actual
        .queries
        .iter()
        .map(|query| RecordLine {
            owner: query.name().to_string(),
            ttl: None,
            class: query.query_class().to_string(),
            rtype: query.query_type().to_string(),
            rdata: Vec::new(),
        })
        .collect::<Vec<_>>();
    compare_text_records("question", &reply.question, &questions, &mut problems);
    compare_wire_records(
        "answer",
        &reply.answer,
        &actual.answers,
        aliases,
        &mut problems,
    );
    compare_wire_records(
        "authority",
        &reply.authority,
        &actual.authorities,
        aliases,
        &mut problems,
    );
    compare_wire_records(
        "additional",
        &reply.additional,
        &actual.additionals,
        aliases,
        &mut problems,
    );
    problems
}

fn compare_header(reply: &Reply, actual: &Message, problems: &mut Vec<String>) {
    if reply.rcode != actual.metadata.response_code {
        problems.push(format!(
            "rcode: expected {:?}, got {:?}",
            reply.rcode, actual.metadata.response_code
        ));
    }
    let flags = reply.flags;
    if flags.qr && actual.metadata.message_type != dns_proto::MessageType::Response {
        problems.push("QR flag: expected response".to_owned());
    }
    if flags.aa && !actual.metadata.authoritative {
        problems.push("AA flag: expected authoritative answer".to_owned());
    }
    if flags.tc && !actual.metadata.truncation {
        problems.push("TC flag: expected truncated answer".to_owned());
    }
    if flags.rd && !actual.metadata.recursion_desired {
        problems.push("RD flag: expected recursion desired".to_owned());
    }
    if flags.ra && !actual.metadata.recursion_available {
        problems.push("RA flag: expected recursion available".to_owned());
    }
    if flags.ad && !actual.metadata.authentic_data {
        problems.push("AD flag: expected authentic data".to_owned());
    }
    if flags.cd && !actual.metadata.checking_disabled {
        problems.push("CD flag: expected checking disabled".to_owned());
    }
}

fn compare_wire_records(
    section: &str,
    expected: &[RecordLine],
    actual: &[Record],
    aliases: &HashMap<IpAddr, IpAddr>,
    problems: &mut Vec<String>,
) {
    let expected_lines = expected.iter().map(canonical_expected).collect::<Vec<_>>();
    let actual_lines = actual
        .iter()
        .map(|record| canonical_actual(record, aliases))
        .collect::<Vec<_>>();
    compare_sorted(section, &expected_lines, &actual_lines, problems);
}

fn compare_text_records(
    section: &str,
    expected: &[RecordLine],
    actual: &[RecordLine],
    problems: &mut Vec<String>,
) {
    let expected_lines = expected.iter().map(canonical_expected).collect::<Vec<_>>();
    let actual_lines = actual.iter().map(canonical_expected).collect::<Vec<_>>();
    compare_sorted(section, &expected_lines, &actual_lines, problems);
}

fn compare_sorted(
    section: &str,
    expected: &[String],
    actual: &[String],
    problems: &mut Vec<String>,
) {
    let mut expected_lines = expected.to_vec();
    let mut actual_lines = actual.to_vec();
    expected_lines.sort_unstable();
    actual_lines.sort_unstable();
    if expected_lines != actual_lines {
        problems.push(format!(
            "{section}: expected {expected_lines:?}, got {actual_lines:?}"
        ));
    }
}

fn canonical_expected(record: &RecordLine) -> String {
    format!(
        "{} {} {} {}",
        normalize_name(&record.owner),
        record.class.to_ascii_uppercase(),
        record.rtype.to_ascii_uppercase(),
        record
            .rdata
            .join(" ")
            .trim_matches('"')
            .to_ascii_lowercase()
    )
}

fn canonical_actual(record: &Record, aliases: &HashMap<IpAddr, IpAddr>) -> String {
    let data = record
        .data
        .to_string()
        .split_whitespace()
        .map(|token| match token.parse::<IpAddr>() {
            Ok(address) => aliases
                .get(&address)
                .map(ToString::to_string)
                .unwrap_or_else(|| token.to_owned()),
            Err(_) => token.to_owned(),
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{} {} {} {}",
        normalize_name(&record.name.to_string()),
        record.dns_class,
        record.record_type(),
        data.trim_matches('"').to_ascii_lowercase()
    )
}

fn normalize_name(name: &str) -> String {
    name.trim_end_matches('.')
        .trim_matches('"')
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use dns_proto::{Message, MessageType, Name, OpCode, Query, RecordType};

    use super::compare_answer;
    use crate::model::{Entry, EntryFlags, RecordLine, Reply};

    #[test]
    fn compares_semantic_message_fields() {
        let name = Name::from_ascii("www.example.com.").expect("name");
        let mut actual = Message::new(7, MessageType::Response, OpCode::Query);
        actual.queries.push(Query::query(name, RecordType::A));
        let entry = Entry {
            replies: vec![Reply {
                flags: EntryFlags {
                    qr: true,
                    ..EntryFlags::default()
                },
                question: vec![RecordLine {
                    owner: "www.example.com.".to_owned(),
                    class: "IN".to_owned(),
                    rtype: "A".to_owned(),
                    ..RecordLine::default()
                }],
                ..Reply::default()
            }],
            ..Entry::default()
        };
        assert!(compare_answer(&entry, &actual, &HashMap::new()).is_empty());
    }

    #[test]
    fn reports_response_code_mismatches() {
        let actual = Message::new(7, MessageType::Response, OpCode::Query);
        let entry = Entry {
            replies: vec![Reply {
                rcode: dns_proto::ResponseCode::NXDomain,
                ..Reply::default()
            }],
            ..Entry::default()
        };
        let problems = compare_answer(&entry, &actual, &HashMap::new());
        assert!(problems.iter().any(|problem| problem.starts_with("rcode:")));
    }
}
