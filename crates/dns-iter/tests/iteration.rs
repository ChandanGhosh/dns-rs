//! Deterministic iteration tests against a fake authoritative server.
//!
//! The live root is a shared, sometimes unreliable service, so these tests pin
//! the resolver to a local UDP/TCP server that speaks just enough DNS to drive
//! each hardening path: QNAME minimisation, CNAME chasing, negative answers,
//! bailiwick checks, 0x20 fallback, truncation and DNS COOKIEs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use dns_iter::{
    ForwardZone, IteratorConfig, IteratorResolver, ResolveError, ResolveOptions, StubZone,
};
use dns_proto::{
    CNAME, EDNS_COOKIE, Edns, EdnsOption, Message, MessageType, NS, Name, OpCode, RData, Record,
    RecordType, ResponseCode, SOA, decode, encode,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// A query seen by the fake server, in the order it arrived.
#[derive(Clone, Debug)]
struct Observed {
    name: String,
    raw_name: String,
    qtype: RecordType,
    tcp: bool,
    cookie_len: Option<usize>,
    recursion_desired: bool,
    checking_disabled: bool,
}

type Handler = Arc<dyn Fn(&Message, bool) -> Option<Message> + Send + Sync>;

struct MockAuth {
    addr: SocketAddr,
    queries: Arc<Mutex<Vec<Observed>>>,
}

impl MockAuth {
    async fn start<F>(handler: F) -> Self
    where
        F: Fn(&Message, bool) -> Option<Message> + Send + Sync + 'static,
    {
        let handler: Handler = Arc::new(handler);
        let udp = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind fake UDP server");
        let addr = udp.local_addr().expect("fake UDP address");
        let tcp = TcpListener::bind(addr).await.expect("bind fake TCP server");
        let queries = Arc::new(Mutex::new(Vec::new()));

        {
            let queries = Arc::clone(&queries);
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 65_535];
                loop {
                    let Ok((length, peer)) = udp.recv_from(&mut buffer).await else {
                        break;
                    };
                    let Ok(query) = decode(&buffer[..length]) else {
                        continue;
                    };
                    record(&queries, &query, false);
                    if let Some(response) = handler(&query, false)
                        && let Ok(wire) = encode(&response)
                    {
                        let _ = udp.send_to(&wire, peer).await;
                    }
                }
            });
        }

        {
            let queries = Arc::clone(&queries);
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = tcp.accept().await else {
                        break;
                    };
                    let queries = Arc::clone(&queries);
                    let handler = Arc::clone(&handler);
                    tokio::spawn(async move {
                        let mut length = [0u8; 2];
                        if stream.read_exact(&mut length).await.is_err() {
                            return;
                        }
                        let length = usize::from(u16::from_be_bytes(length));
                        let mut buffer = vec![0u8; length];
                        if stream.read_exact(&mut buffer).await.is_err() {
                            return;
                        }
                        let Ok(query) = decode(&buffer) else {
                            return;
                        };
                        record(&queries, &query, true);
                        if let Some(response) = handler(&query, true)
                            && let Ok(wire) = encode(&response)
                        {
                            let mut framed = Vec::with_capacity(wire.len() + 2);
                            framed.extend_from_slice(&(wire.len() as u16).to_be_bytes());
                            framed.extend_from_slice(&wire);
                            let _ = stream.write_all(&framed).await;
                        }
                    });
                }
            });
        }

        Self { addr, queries }
    }

    fn observed(&self) -> Vec<Observed> {
        self.queries.lock().expect("query log lock").clone()
    }
}

fn record(queries: &Mutex<Vec<Observed>>, query: &Message, tcp: bool) {
    let Some(question) = query.queries.first() else {
        return;
    };
    let cookie_len = query
        .edns
        .as_ref()
        .and_then(|edns| match edns.option(EDNS_COOKIE) {
            Some(EdnsOption::Unknown(_, data)) => Some(data.len()),
            _ => None,
        });
    queries.lock().expect("query log lock").push(Observed {
        name: question.name.to_ascii().to_ascii_lowercase(),
        raw_name: question.name.to_ascii(),
        qtype: question.query_type,
        tcp,
        cookie_len,
        recursion_desired: query.metadata.recursion_desired,
        checking_disabled: query.metadata.checking_disabled,
    });
}

fn resolver_config(server: SocketAddr) -> IteratorConfig {
    IteratorConfig {
        root_servers: Some(vec![server]),
        nameserver_port: server.port(),
        case_randomization: false,
        cookies: false,
        qname_minimization: true,
        harden_glue: true,
        ..IteratorConfig::default()
    }
}

fn resolver(server: SocketAddr) -> IteratorResolver {
    IteratorResolver::with_config(resolver_config(server), None).expect("resolver")
}

fn n(text: &str) -> Name {
    Name::from_ascii(text).expect("valid test name")
}

fn reply(query: &Message, rcode: ResponseCode) -> Message {
    let mut message = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    message.metadata.authoritative = true;
    message.metadata.recursion_available = true;
    message.metadata.response_code = rcode;
    if let Some(question) = query.queries.first() {
        message.add_query(question.clone());
    }
    message
}

fn a(owner: &str, octets: [u8; 4]) -> Record {
    Record::from_rdata(n(owner), 300, RData::A(Ipv4Addr::from(octets).into()))
}

fn ns(zone: &str, target: &str) -> Record {
    Record::from_rdata(n(zone), 300, RData::NS(NS(n(target))))
}

fn cname(owner: &str, target: &str) -> Record {
    Record::from_rdata(n(owner), 300, RData::CNAME(CNAME(n(target))))
}

/// Build `links` CNAME hops from `www.example.com.` to a terminal A record.
///
/// Eight links is the real-world chain used by Azure Traffic Manager for
/// `dc.services.visualstudio.com`; the resolver must accept it.
fn cname_chain(links: usize, terminal: [u8; 4]) -> Vec<Record> {
    let names: Vec<String> = (0..=links)
        .map(|index| {
            if index == 0 {
                "www.example.com.".to_owned()
            } else {
                format!("alias{index}.example.com.")
            }
        })
        .collect();
    let mut records: Vec<Record> = names
        .windows(2)
        .map(|pair| cname(&pair[0], &pair[1]))
        .collect();
    records.push(a(
        names.last().expect("chain has a terminal name"),
        terminal,
    ));
    records
}

fn soa(zone: &str) -> Record {
    Record::from_rdata(
        n(zone),
        60,
        RData::SOA(SOA::new(
            n("ns.example.com."),
            n("hostmaster.example.com."),
            1,
            3600,
            600,
            86_400,
            60,
        )),
    )
}

fn answer(query: &Message, records: Vec<Record>) -> Message {
    let mut message = reply(query, ResponseCode::NoError);
    message.add_answers(records);
    message
}

fn referral(query: &Message, zone: &str, target: &str, glue: [u8; 4]) -> Message {
    let mut message = reply(query, ResponseCode::NoError);
    message.add_authority(ns(zone, target));
    message.add_additional(a(target, glue));
    message
}

/// Answer the standard `com.` -> `example.com.` delegation chain and delegate
/// the final `www.example.com. A` lookup to `final_answer`.
fn chain_response<F>(query: &Message, final_answer: F) -> Option<Message>
where
    F: FnOnce(&Message) -> Message,
{
    let question = query.queries.first()?;
    let qname = question.name.to_ascii().to_ascii_lowercase();
    let response = match (qname.as_str(), question.query_type) {
        ("com.", RecordType::NS) => referral(query, "com.", "ns.com.", [127, 0, 0, 1]),
        ("example.com.", RecordType::NS) => {
            referral(query, "example.com.", "ns.example.com.", [127, 0, 0, 1])
        }
        ("www.example.com.", RecordType::A) => final_answer(query),
        _ => reply(query, ResponseCode::ServFail),
    };
    Some(response)
}

fn with_zone<F>(final_answer: F) -> impl Fn(&Message, bool) -> Option<Message> + Send + Sync
where
    F: Fn(&Message) -> Message + Send + Sync + 'static,
{
    move |query, _tcp| chain_response(query, &final_answer)
}

fn query_cookie(query: &Message) -> Option<Vec<u8>> {
    let edns = query.edns.as_ref()?;
    match edns.option(EDNS_COOKIE) {
        Some(EdnsOption::Unknown(_, data)) => Some(data.clone()),
        _ => None,
    }
}

fn echo_cookie(message: &mut Message, query: &Message, corrupt: bool) {
    let Some(cookie) = query_cookie(query) else {
        return;
    };
    let mut data = if corrupt {
        vec![0xAA; 8]
    } else {
        cookie[..8].to_vec()
    };
    data.extend_from_slice(&[0x5A; 8]);

    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    edns.options_mut().insert(EdnsOption::Unknown(10, data));
    message.edns = Some(edns);
}

fn with_zone_cookie<F>(
    final_answer: F,
    corrupt: bool,
) -> impl Fn(&Message, bool) -> Option<Message> + Send + Sync
where
    F: Fn(&Message) -> Message + Send + Sync + 'static,
{
    move |query, _tcp| {
        let mut message = chain_response(query, &final_answer)?;
        echo_cookie(&mut message, query, corrupt);
        Some(message)
    }
}

#[tokio::test]
async fn minimisation_queries_advance_one_label_at_a_time() {
    let server = MockAuth::start(with_zone(|query| {
        answer(query, vec![a("www.example.com.", [192, 0, 2, 1])])
    }))
    .await;
    let resolver = resolver(server.addr);

    let message = resolver
        .resolve("www.example.com.", RecordType::A)
        .await
        .expect("resolution succeeds");

    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.answers.len(), 1);

    let observed = server.observed();
    let names: Vec<(&str, RecordType)> = observed
        .iter()
        .map(|query| (query.name.as_str(), query.qtype))
        .collect();
    assert_eq!(
        names,
        vec![
            ("com.", RecordType::NS),
            ("example.com.", RecordType::NS),
            ("www.example.com.", RecordType::A),
        ]
    );
}

#[tokio::test]
async fn cname_chain_in_single_message() {
    let server = MockAuth::start(with_zone(|query| {
        answer(
            query,
            vec![
                cname("www.example.com.", "target.example.com."),
                a("target.example.com.", [192, 0, 2, 7]),
            ],
        )
    }))
    .await;
    let resolver = resolver(server.addr);

    let message = resolver
        .resolve("www.example.com.", RecordType::A)
        .await
        .expect("resolution succeeds");

    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.answers.len(), 2);
    assert!(
        message
            .answers
            .iter()
            .any(|record| matches!(record.data, RData::CNAME(_)))
    );
    assert!(
        message
            .answers
            .iter()
            .any(|record| matches!(record.data, RData::A(_)))
    );
}

#[tokio::test]
async fn cname_chain_at_the_limit_resolves() {
    let server = MockAuth::start(with_zone(|query| {
        answer(query, cname_chain(8, [192, 0, 2, 7]))
    }))
    .await;
    let resolver = resolver(server.addr);

    let message = resolver
        .resolve("www.example.com.", RecordType::A)
        .await
        .expect("eight CNAME links followed by an address must resolve");

    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert!(
        message
            .answers
            .iter()
            .any(|record| matches!(record.data, RData::A(_)))
    );
}

#[tokio::test]
async fn cname_chain_over_the_limit_is_rejected() {
    let server = MockAuth::start(with_zone(|query| {
        answer(query, cname_chain(9, [192, 0, 2, 8]))
    }))
    .await;
    let resolver = resolver(server.addr);

    let result = resolver.resolve("www.example.com.", RecordType::A).await;
    assert!(matches!(result, Err(ResolveError::CnameChainTooLong)));
}

#[tokio::test]
async fn cname_chain_resolves_external_target() {
    fn handler(query: &Message, _tcp: bool) -> Option<Message> {
        let question = query.queries.first()?;
        let qname = question.name.to_ascii().to_ascii_lowercase();
        let response = match (qname.as_str(), question.query_type) {
            ("com.", RecordType::NS) => referral(query, "com.", "ns.com.", [127, 0, 0, 1]),
            ("example.com.", RecordType::NS) => {
                referral(query, "example.com.", "ns.example.com.", [127, 0, 0, 1])
            }
            ("www.example.com.", RecordType::A) => {
                answer(query, vec![cname("www.example.com.", "target.other.test.")])
            }
            ("target.other.test.", RecordType::A) => {
                answer(query, vec![a("target.other.test.", [192, 0, 2, 9])])
            }
            _ => reply(query, ResponseCode::ServFail),
        };
        Some(response)
    }

    let server = MockAuth::start(handler).await;
    let resolver = resolver(server.addr);

    let message = resolver
        .resolve("www.example.com.", RecordType::A)
        .await
        .expect("resolution succeeds");

    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.answers.len(), 2);
    assert!(
        message
            .answers
            .iter()
            .any(|record| record.name == n("target.other.test.")
                && matches!(record.data, RData::A(_)))
    );

    let observed = server.observed();
    assert!(
        observed
            .iter()
            .any(|query| query.name == "target.other.test." && query.qtype == RecordType::A)
    );
}

#[tokio::test]
async fn nxdomain_carries_soa() {
    let server = MockAuth::start(with_zone(|query| {
        let mut message = reply(query, ResponseCode::NXDomain);
        message.add_authority(soa("example.com."));
        message
    }))
    .await;
    let resolver = resolver(server.addr);

    let message = resolver
        .resolve("www.example.com.", RecordType::A)
        .await
        .expect("NXDOMAIN is a valid response");

    assert_eq!(message.metadata.response_code, ResponseCode::NXDomain);
    assert!(message.answers.is_empty());
    assert!(
        message
            .authorities
            .iter()
            .any(|record| record.record_type() == RecordType::SOA)
    );
}

#[tokio::test]
async fn nodata_carries_soa() {
    let server = MockAuth::start(with_zone(|query| {
        let mut message = reply(query, ResponseCode::NoError);
        message.add_authority(soa("example.com."));
        message
    }))
    .await;
    let resolver = resolver(server.addr);

    let message = resolver
        .resolve("www.example.com.", RecordType::A)
        .await
        .expect("NODATA is a valid response");

    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert!(message.answers.is_empty());
    assert!(
        message
            .authorities
            .iter()
            .any(|record| record.record_type() == RecordType::SOA)
    );
}

#[tokio::test]
async fn out_of_bailiwick_glue_is_not_used() {
    fn handler(query: &Message, _tcp: bool) -> Option<Message> {
        let question = query.queries.first()?;
        let qname = question.name.to_ascii().to_ascii_lowercase();
        let response = match (qname.as_str(), question.query_type) {
            ("com.", RecordType::NS) => referral(query, "com.", "ns.com.", [127, 0, 0, 1]),
            ("example.com.", RecordType::NS) => {
                // The glue owner is outside the com. bailiwick, so a hardened
                // resolver must discard it and resolve the NS address itself.
                let mut message = reply(query, ResponseCode::NoError);
                message.add_authority(ns("example.com.", "ns.other.net."));
                message.add_additional(a("ns.other.net.", [203, 0, 113, 9]));
                message
            }
            ("ns.other.net.", RecordType::A) => {
                answer(query, vec![a("ns.other.net.", [127, 0, 0, 1])])
            }
            ("www.example.com.", RecordType::A) => {
                answer(query, vec![a("www.example.com.", [192, 0, 2, 1])])
            }
            _ => reply(query, ResponseCode::ServFail),
        };
        Some(response)
    }

    let server = MockAuth::start(handler).await;
    let resolver = resolver(server.addr);

    let message = resolver
        .resolve("www.example.com.", RecordType::A)
        .await
        .expect("resolution succeeds via the real NS address");

    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.answers.len(), 1);

    let observed = server.observed();
    assert!(
        observed
            .iter()
            .any(|query| query.name == "ns.other.net." && query.qtype == RecordType::A),
        "out-of-bailiwick glue must be ignored, forcing an NS address lookup"
    );
}

#[tokio::test]
async fn poisoned_additional_is_dropped() {
    let server = MockAuth::start(with_zone(|query| {
        let mut message = answer(query, vec![a("www.example.com.", [192, 0, 2, 1])]);
        message.add_additional(a("evil.example.net.", [6, 6, 6, 6]));
        message
    }))
    .await;
    let resolver = resolver(server.addr);

    let message = resolver
        .resolve("www.example.com.", RecordType::A)
        .await
        .expect("resolution succeeds");

    assert!(message.additionals.is_empty());
    assert_eq!(message.answers.len(), 1);
    match &message.answers[0].data {
        RData::A(address) => assert_eq!(address.0, Ipv4Addr::new(192, 0, 2, 1)),
        other => panic!("unexpected answer: {other:?}"),
    }
}

#[tokio::test]
async fn wrong_id_is_rejected() {
    let server = MockAuth::start(with_zone(|query| {
        let mut message = answer(query, vec![a("www.example.com.", [192, 0, 2, 1])]);
        message.metadata.id = message.metadata.id.wrapping_add(1);
        message
    }))
    .await;
    let resolver = resolver(server.addr);

    // The UDP transport discards datagrams that do not echo the query's
    // transaction ID, so a server that only ever replies with the wrong ID
    // makes the exchange fail instead of returning the poisoned message.
    let result = resolver.resolve("www.example.com.", RecordType::A).await;
    assert!(
        matches!(
            result,
            Err(ResolveError::InvalidResponse(_) | ResolveError::NoNameservers)
        ),
        "wrong ID must not be accepted: {result:?}"
    );
}

#[tokio::test]
async fn wrong_question_is_rejected() {
    let server = MockAuth::start(with_zone(|query| {
        let mut message = answer(query, vec![a("www.example.com.", [192, 0, 2, 1])]);
        message.queries[0].query_type = RecordType::AAAA;
        message
    }))
    .await;
    let resolver = resolver(server.addr);

    let result = resolver.resolve("www.example.com.", RecordType::A).await;
    assert!(
        matches!(result, Err(ResolveError::InvalidResponse(_))),
        "wrong question must not be accepted: {result:?}"
    );
}

#[tokio::test]
async fn case_mismatch_falls_back_to_lowercase() {
    let server = MockAuth::start(with_zone(|query| {
        let sent = query.queries[0].name.to_ascii();
        let mut message = answer(query, vec![a("www.example.com.", [192, 0, 2, 1])]);
        if sent.chars().any(|character| character.is_ascii_uppercase()) {
            message.queries[0].name = n(&sent.to_ascii_lowercase());
        }
        message
    }))
    .await;

    let mut config = resolver_config(server.addr);
    config.case_randomization = true;
    let resolver = IteratorResolver::with_config(config, None).expect("resolver");

    let message = resolver
        .resolve("www.example.com.", RecordType::A)
        .await
        .expect("resolver retries without 0x20");

    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.answers.len(), 1);

    let observed = server.observed();
    let a_queries: Vec<&Observed> = observed
        .iter()
        .filter(|query| query.qtype == RecordType::A)
        .collect();
    assert_eq!(a_queries.len(), 2, "one mixed-case attempt and one retry");
    assert!(
        a_queries[0]
            .raw_name
            .chars()
            .any(|character| character.is_ascii_uppercase())
    );
    assert_eq!(a_queries[1].raw_name, "www.example.com.");
}

#[tokio::test]
async fn truncated_udp_retries_over_tcp() {
    fn handler(query: &Message, tcp: bool) -> Option<Message> {
        let question = query.queries.first()?;
        let qname = question.name.to_ascii().to_ascii_lowercase();
        let response = match (qname.as_str(), question.query_type) {
            ("com.", RecordType::NS) => referral(query, "com.", "ns.com.", [127, 0, 0, 1]),
            ("example.com.", RecordType::NS) => {
                referral(query, "example.com.", "ns.example.com.", [127, 0, 0, 1])
            }
            ("www.example.com.", RecordType::A) => {
                if tcp {
                    answer(query, vec![a("www.example.com.", [192, 0, 2, 1])])
                } else {
                    let mut message = reply(query, ResponseCode::NoError);
                    message.metadata.truncation = true;
                    message
                }
            }
            _ => reply(query, ResponseCode::ServFail),
        };
        Some(response)
    }

    let server = MockAuth::start(handler).await;
    let resolver = resolver(server.addr);

    let message = resolver
        .resolve("www.example.com.", RecordType::A)
        .await
        .expect("TCP retry succeeds");

    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.answers.len(), 1);

    let observed = server.observed();
    assert!(
        observed
            .iter()
            .any(|query| query.qtype == RecordType::A && query.tcp),
        "truncated UDP response must trigger a TCP retry"
    );
}

#[tokio::test]
async fn cookie_is_echoed_and_learned() {
    let server = MockAuth::start(with_zone_cookie(
        |query| answer(query, vec![a("www.example.com.", [192, 0, 2, 1])]),
        false,
    ))
    .await;

    let mut config = resolver_config(server.addr);
    config.cookies = true;
    let resolver = IteratorResolver::with_config(config, None).expect("resolver");

    let message = resolver
        .resolve("www.example.com.", RecordType::A)
        .await
        .expect("cookie validation succeeds");

    assert_eq!(message.metadata.response_code, ResponseCode::NoError);

    let observed = server.observed();
    assert_eq!(observed[0].cookie_len, Some(8), "initial client cookie");
    assert_eq!(
        observed.last().expect("queries").cookie_len,
        Some(16),
        "server cookie should be remembered"
    );
}

#[tokio::test]
async fn cookie_mismatch_is_rejected() {
    let server = MockAuth::start(with_zone_cookie(
        |query| answer(query, vec![a("www.example.com.", [192, 0, 2, 1])]),
        true,
    ))
    .await;

    let mut config = resolver_config(server.addr);
    config.cookies = true;
    let resolver = IteratorResolver::with_config(config, None).expect("resolver");

    let result = resolver.resolve("www.example.com.", RecordType::A).await;
    assert!(
        matches!(result, Err(ResolveError::InvalidResponse(_))),
        "a mismatched client cookie must be rejected: {result:?}"
    );
}

fn forwarding_config(server: SocketAddr, forward_first: bool) -> IteratorConfig {
    IteratorConfig {
        case_randomization: false,
        cookies: false,
        qname_minimization: true,
        harden_glue: true,
        forward_zones: vec![ForwardZone {
            zone: Name::root(),
            servers: vec![server.into()],
            forward_first,
            forward_fallback: false,
        }],
        ..IteratorConfig::default()
    }
}

#[tokio::test]
async fn forward_zone_sends_recursive_queries_directly() {
    let server = MockAuth::start(|query, _tcp| {
        Some(answer(query, vec![a("apple.com.", [17, 253, 144, 10])]))
    })
    .await;

    let resolver = IteratorResolver::with_config(forwarding_config(server.addr, false), None)
        .expect("resolver");
    let message = resolver
        .resolve("apple.com.", RecordType::A)
        .await
        .expect("forwarded resolution succeeds");

    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.answers.len(), 1);

    let observed = server.observed();
    assert_eq!(
        observed.len(),
        1,
        "forwarders must be asked once, not walked"
    );
    assert_eq!(observed[0].name, "apple.com.");
    assert!(
        observed[0].recursion_desired,
        "forwarded queries must set RD so the upstream recurses for us"
    );
    assert!(
        !observed[0].checking_disabled,
        "a non-validating resolver must trust the forwarder's validation"
    );
}

#[tokio::test]
async fn local_namespace_uses_only_the_plain_local_zone() {
    let server = MockAuth::start(|query, _tcp| {
        Some(answer(
            query,
            vec![a("nas.localdomain.", [192, 168, 1, 10])],
        ))
    })
    .await;
    let config = IteratorConfig {
        case_randomization: false,
        cookies: false,
        forward_zones: vec![
            ForwardZone {
                zone: n("."),
                servers: vec![
                    "8.8.8.8:53"
                        .parse::<SocketAddr>()
                        .expect("public forwarder")
                        .into(),
                ],
                forward_first: false,
                forward_fallback: false,
            },
            ForwardZone {
                zone: n("localdomain."),
                servers: vec![server.addr.into()],
                forward_first: false,
                forward_fallback: false,
            },
        ],
        ..IteratorConfig::default()
    };

    let resolver = IteratorResolver::with_config(config, None).expect("resolver");
    let message = resolver
        .resolve("nas.localdomain.", RecordType::A)
        .await
        .expect("local resolution succeeds");

    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert!(
        message
            .answers
            .iter()
            .any(|record| *record == a("nas.localdomain.", [192, 168, 1, 10]))
    );
    assert_eq!(
        server.observed().len(),
        1,
        "only the local forwarder was queried"
    );
}

#[tokio::test]
async fn forward_zone_accepts_nodata_without_soa() {
    // nextdns.io answers `*.test.nextdns.io HTTPS` with NOERROR and nothing
    // else: no answer records and no SOA in the authority section.
    let server = MockAuth::start(|query, _tcp| Some(reply(query, ResponseCode::NoError))).await;

    let resolver = IteratorResolver::with_config(forwarding_config(server.addr, false), None)
        .expect("resolver");
    let message = resolver
        .resolve("1l0b6k73l0d-421534.test.nextdns.io.", RecordType::HTTPS)
        .await
        .expect("a NODATA reply is a valid answer");

    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert!(message.answers.is_empty());
    assert_eq!(
        server.observed().len(),
        1,
        "the forwarder must not be retried for a valid NODATA reply"
    );
}

#[tokio::test]
async fn validating_resolver_sets_cd_on_forwarded_queries() {
    let server = MockAuth::start(|query, _tcp| {
        let question = query.queries.first()?;
        let owner = question.name.to_ascii();
        Some(answer(query, vec![a(&owner, [192, 0, 2, 1])]))
    })
    .await;

    let mut config = forwarding_config(server.addr, false);
    config.dnssec_validation = true;
    let resolver = IteratorResolver::with_config(config, None).expect("resolver");
    let _ = resolver
        .resolve_with_options("apple.com.", RecordType::A, ResolveOptions::default())
        .await;

    let observed = server.observed();
    assert!(!observed.is_empty(), "the forwarder must have been queried");
    assert!(
        observed.iter().all(|query| query.checking_disabled),
        "a validating resolver must ask the forwarder for unvalidated data"
    );
}

#[tokio::test]
async fn non_validating_resolver_honours_client_cd() {
    let server = MockAuth::start(|query, _tcp| {
        let question = query.queries.first()?;
        let owner = question.name.to_ascii();
        Some(answer(query, vec![a(&owner, [192, 0, 2, 1])]))
    })
    .await;

    let resolver = IteratorResolver::with_config(forwarding_config(server.addr, false), None)
        .expect("resolver");
    resolver
        .resolve_with_options(
            "apple.com.",
            RecordType::A,
            ResolveOptions {
                dnssec_ok: false,
                checking_disabled: true,
            },
        )
        .await
        .expect("forwarded resolution succeeds");

    let observed = server.observed();
    assert!(!observed.is_empty());
    assert!(
        observed.iter().all(|query| query.checking_disabled),
        "a CD client must have CD propagated to the forwarder"
    );
}

#[tokio::test]
async fn root_priming_learns_the_root_delegation() {
    let root = MockAuth::start(|query, _tcp| {
        let question = query.queries.first()?;
        if question.name != Name::root() || question.query_type != RecordType::NS {
            return None;
        }
        let mut response = reply(query, ResponseCode::NoError);
        response.add_answer(ns(".", "a.root.test."));
        response.add_additional(a("a.root.test.", [127, 0, 0, 1]));
        Some(response)
    })
    .await;

    let authoritative = MockAuth::start(|query, _tcp| {
        let question = query.queries.first()?;
        if question
            .name
            .to_ascii()
            .eq_ignore_ascii_case("www.example.com.")
            && question.query_type == RecordType::A
        {
            Some(answer(query, vec![a("www.example.com.", [192, 0, 2, 55])]))
        } else {
            None
        }
    })
    .await;

    let config = IteratorConfig {
        root_servers: None,
        bootstrap_servers: Some(vec![root.addr]),
        // Priming maps learned glue onto the configured nameserver port, so
        // the fake root can point at a server on an ephemeral port.
        nameserver_port: authoritative.addr.port(),
        case_randomization: false,
        cookies: false,
        qname_minimization: false,
        harden_glue: true,
        ..IteratorConfig::default()
    };
    let resolver = IteratorResolver::with_config(config, None).expect("resolver");

    let message = resolver
        .resolve("www.example.com.", RecordType::A)
        .await
        .expect("resolves through the primed root");

    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert!(message.answers.iter().any(|record| {
        matches!(record.data, RData::A(address) if address.0 == Ipv4Addr::new(192, 0, 2, 55))
    }));

    let root_queries = root.observed();
    assert!(
        root_queries
            .iter()
            .any(|query| query.name == "." && query.qtype == RecordType::NS),
        "the resolver must prime the root with an NS query"
    );
    assert!(
        !authoritative.observed().is_empty(),
        "the learned root glue must be used for the follow-up query"
    );
}

#[tokio::test]
async fn root_priming_is_skipped_for_pinned_roots() {
    let server = MockAuth::start(|query, _tcp| {
        Some(answer(query, vec![a("www.example.com.", [192, 0, 2, 1])]))
    })
    .await;
    let resolver = resolver(server.addr);

    let message = resolver
        .resolve("www.example.com.", RecordType::A)
        .await
        .expect("resolves from the pinned root");

    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    let observed = server.observed();
    assert!(
        observed
            .iter()
            .all(|query| !(query.name == "." && query.qtype == RecordType::NS)),
        "pinned roots must not be replaced by a priming query"
    );
}

#[tokio::test]
async fn forward_first_falls_back_to_iteration() {
    let failing = MockAuth::start(|query, _tcp| Some(reply(query, ResponseCode::ServFail))).await;
    let root = MockAuth::start(with_zone(|query| {
        answer(query, vec![a("www.example.com.", [192, 0, 2, 1])])
    }))
    .await;

    let config = IteratorConfig {
        forward_zones: vec![ForwardZone {
            zone: Name::root(),
            servers: vec![failing.addr.into()],
            forward_first: true,
            forward_fallback: false,
        }],
        root_servers: Some(vec![root.addr]),
        nameserver_port: root.addr.port(),
        case_randomization: false,
        cookies: false,
        qname_minimization: true,
        harden_glue: true,
        ..IteratorConfig::default()
    };
    let resolver = IteratorResolver::with_config(config, None).expect("resolver");

    let message = resolver
        .resolve("www.example.com.", RecordType::A)
        .await
        .expect("falls back to iteration");

    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.answers.len(), 1);
    assert!(
        !failing.observed().is_empty(),
        "forwarder must be tried first"
    );
    assert!(
        !root.observed().is_empty(),
        "iteration must run after forwarding fails"
    );
}

#[tokio::test]
async fn forward_fallback_uses_forwarders_when_iteration_fails() {
    // Every authoritative query is refused, so iteration gives up with a
    // reachability error instead of returning an answer.
    let root = MockAuth::start(|query, _tcp| Some(reply(query, ResponseCode::Refused))).await;
    let forwarder = MockAuth::start(|query, _tcp| {
        Some(answer(query, vec![a("www.example.com.", [192, 0, 2, 44])]))
    })
    .await;

    let config = IteratorConfig {
        forward_zones: vec![ForwardZone {
            zone: Name::root(),
            servers: vec![forwarder.addr.into()],
            forward_first: false,
            forward_fallback: true,
        }],
        root_servers: Some(vec![root.addr]),
        nameserver_port: root.addr.port(),
        case_randomization: false,
        cookies: false,
        qname_minimization: false,
        harden_glue: true,
        ..IteratorConfig::default()
    };
    let resolver = IteratorResolver::with_config(config, None).expect("resolver");

    let message = resolver
        .resolve("www.example.com.", RecordType::A)
        .await
        .expect("falls back to the forwarder");

    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.answers.len(), 1);
    assert!(
        !root.observed().is_empty(),
        "iteration must run before the forwarders"
    );
    let forwarded = forwarder.observed();
    assert_eq!(forwarded.len(), 1, "the forwarder must be asked once");
    assert!(
        forwarded[0].recursion_desired,
        "a fallback query must still be recursive"
    );
}

#[tokio::test]
async fn forward_fallback_does_not_override_authoritative_negative() {
    let root = MockAuth::start(|query, _tcp| Some(reply(query, ResponseCode::NXDomain))).await;
    let forwarder = MockAuth::start(|query, _tcp| {
        Some(answer(query, vec![a("www.example.com.", [192, 0, 2, 99])]))
    })
    .await;

    let config = IteratorConfig {
        forward_zones: vec![ForwardZone {
            zone: Name::root(),
            servers: vec![forwarder.addr.into()],
            forward_first: false,
            forward_fallback: true,
        }],
        root_servers: Some(vec![root.addr]),
        nameserver_port: root.addr.port(),
        case_randomization: false,
        cookies: false,
        qname_minimization: false,
        harden_glue: true,
        ..IteratorConfig::default()
    };
    let resolver = IteratorResolver::with_config(config, None).expect("resolver");

    let message = resolver
        .resolve("www.example.com.", RecordType::A)
        .await
        .expect("an authoritative NXDOMAIN is an answer");

    assert_eq!(message.metadata.response_code, ResponseCode::NXDomain);
    assert!(message.answers.is_empty());
    assert!(
        forwarder.observed().is_empty(),
        "an authoritative negative answer must not trigger the fallback"
    );
}

#[tokio::test]
async fn minimisation_falls_back_when_the_last_server_is_unreachable() {
    // Simulates the flaky upstream that returns SERVFAIL for minimised NS
    // queries while still answering the full query, followed by an
    // unreachable IPv6 server. The transport error must not abort the walk.
    let server = MockAuth::start(|query, _tcp| {
        let question = query.queries.first()?;
        let qname = question.name.to_ascii().to_ascii_lowercase();
        let response = match (qname.as_str(), question.query_type) {
            ("com.", RecordType::NS) => reply(query, ResponseCode::ServFail),
            ("apple.com.", RecordType::A) => {
                answer(query, vec![a("apple.com.", [17, 253, 144, 10])])
            }
            _ => reply(query, ResponseCode::ServFail),
        };
        Some(response)
    })
    .await;

    // A loopback address with no listener yields ECONNREFUSED or, on hosts
    // without IPv6, ENETUNREACH. Either way the last server errors.
    let unreachable = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9);

    let config = IteratorConfig {
        root_servers: Some(vec![server.addr, unreachable]),
        nameserver_port: server.addr.port(),
        case_randomization: false,
        cookies: false,
        qname_minimization: true,
        harden_glue: true,
        ..IteratorConfig::default()
    };
    let resolver = IteratorResolver::with_config(config, None).expect("resolver");

    let message = resolver
        .resolve("apple.com.", RecordType::A)
        .await
        .expect("minimisation must fall back to the full query");

    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.answers.len(), 1);
}

fn stub_config(
    stub: SocketAddr,
    root: SocketAddr,
    stub_first: bool,
    no_cache: bool,
) -> IteratorConfig {
    IteratorConfig {
        root_servers: Some(vec![root]),
        nameserver_port: root.port(),
        case_randomization: false,
        cookies: false,
        qname_minimization: true,
        harden_glue: true,
        stub_zones: vec![StubZone {
            zone: n("corp.test."),
            servers: vec![stub.into()],
            stub_first,
            prime: false,
            no_cache,
        }],
        ..IteratorConfig::default()
    }
}

#[tokio::test]
async fn stub_zone_queries_authorities_directly_without_recursion() {
    let stub = MockAuth::start(|query, _tcp| {
        Some(answer(query, vec![a("www.corp.test.", [192, 0, 2, 50])]))
    })
    .await;
    // If the stub is used, the root must never be touched.
    let root = MockAuth::start(|query, _tcp| Some(reply(query, ResponseCode::ServFail))).await;

    let resolver =
        IteratorResolver::with_config(stub_config(stub.addr, root.addr, false, false), None)
            .expect("resolver");

    let message = resolver
        .resolve("www.corp.test.", RecordType::A)
        .await
        .expect("stub resolution succeeds");

    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.answers.len(), 1);

    let observed = stub.observed();
    assert_eq!(observed.len(), 1, "the stub authority is asked once");
    assert_eq!(observed[0].name, "www.corp.test.");
    assert!(
        !observed[0].recursion_desired,
        "stub queries are sent to authoritative servers with RD=0"
    );
    assert!(
        root.observed().is_empty(),
        "a matching stub zone must not walk from the root"
    );
}

#[tokio::test]
async fn stub_first_falls_back_to_normal_resolution() {
    let stub = MockAuth::start(|query, _tcp| Some(reply(query, ResponseCode::ServFail))).await;
    let root = MockAuth::start(with_zone(|query| {
        answer(query, vec![a("www.example.com.", [192, 0, 2, 1])])
    }))
    .await;

    // The stub zone covers example.com; when it fails, `stub-first` must let
    // the normal delegation walk answer instead.
    let mut config = stub_config(stub.addr, root.addr, true, false);
    config.stub_zones[0].zone = n("example.com.");
    let resolver = IteratorResolver::with_config(config, None).expect("resolver");

    let message = resolver
        .resolve("www.example.com.", RecordType::A)
        .await
        .expect("stub-first falls back");

    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.answers.len(), 1);
    assert!(!stub.observed().is_empty(), "stub must be tried first");
    assert!(
        !root.observed().is_empty(),
        "normal iteration must run after the stub fails"
    );
}

#[tokio::test]
async fn stub_without_first_does_not_escape_the_zone() {
    let stub = MockAuth::start(|query, _tcp| Some(reply(query, ResponseCode::ServFail))).await;
    let root = MockAuth::start(with_zone(|query| {
        answer(query, vec![a("www.example.com.", [192, 0, 2, 1])])
    }))
    .await;

    let mut config = stub_config(stub.addr, root.addr, false, false);
    config.stub_zones[0].zone = n("example.com.");
    let resolver = IteratorResolver::with_config(config, None).expect("resolver");

    let result = resolver.resolve("www.example.com.", RecordType::A).await;
    assert!(
        result.is_err(),
        "without stub-first a failed stub must not fall back: {result:?}"
    );
    assert!(
        root.observed().is_empty(),
        "normal iteration must not run without stub-first"
    );
}
