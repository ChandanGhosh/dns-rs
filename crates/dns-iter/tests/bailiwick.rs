//! Bailiwick regression tests for answer-section caching.
//!
//! A malicious authoritative server for `evil.test` must not be able to append
//! RRsets for a foreign name (`victim.test`) to a CNAME chain and have them
//! cached. The walk models the real hierarchy (root, `test`, `evil.test`,
//! `victim.test`) so the answering zone for the attacker's response is
//! `evil.test`, not the root.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use dns_cache::{InfraCache, RrsetCache};
use dns_iter::{IteratorConfig, IteratorResolver};
use dns_proto::{
    CNAME, Message, MessageType, NS, Name, OpCode, RData, Record, RecordType, ResponseCode, decode,
    encode,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

const ROOT: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const TLD: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const ATTACKER: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
const VICTIM: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 4);

type Handler = Arc<dyn Fn(&Message) -> Option<Message> + Send + Sync>;

#[derive(Clone)]
struct Mock {
    addr: SocketAddr,
    queries: Arc<Mutex<Vec<String>>>,
}

impl Mock {
    async fn start(ip: IpAddr, port: u16, handler: Handler) -> Self {
        let udp = UdpSocket::bind(SocketAddr::new(ip, port))
            .await
            .expect("bind udp");
        let addr = udp.local_addr().expect("addr");
        let tcp = TcpListener::bind(addr).await.expect("bind tcp");
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
                    note(&queries, &query);
                    if let Some(response) = handler(&query)
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
                        let mut buffer = vec![0u8; usize::from(u16::from_be_bytes(length))];
                        if stream.read_exact(&mut buffer).await.is_err() {
                            return;
                        }
                        let Ok(query) = decode(&buffer) else {
                            return;
                        };
                        note(&queries, &query);
                        if let Some(response) = handler(&query)
                            && let Ok(wire) = encode(&response)
                        {
                            let mut framed = (wire.len() as u16).to_be_bytes().to_vec();
                            framed.extend_from_slice(&wire);
                            let _ = stream.write_all(&framed).await;
                        }
                    });
                }
            });
        }
        Self { addr, queries }
    }

    fn observed(&self) -> Vec<String> {
        self.queries.lock().expect("lock").clone()
    }
}

fn note(queries: &Mutex<Vec<String>>, query: &Message) {
    if let Some(question) = query.queries.first() {
        queries.lock().expect("lock").push(format!(
            "{} {:?}",
            question.name.to_ascii().to_ascii_lowercase(),
            question.query_type
        ));
    }
}

fn n(text: &str) -> Name {
    Name::from_ascii(text).expect("name")
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

fn answer(query: &Message, records: Vec<Record>) -> Message {
    let mut message = reply(query, ResponseCode::NoError);
    message.add_answers(records);
    message
}

fn referral(
    query: &Message,
    zone: &str,
    nameserver: &str,
    glue: Option<(&str, [u8; 4])>,
) -> Message {
    let mut message = reply(query, ResponseCode::NoError);
    message.metadata.authoritative = false;
    message.add_authority(ns(zone, nameserver));
    if let Some((owner, octets)) = glue {
        message.add_additional(a(owner, octets));
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

fn address_of(message: &Message) -> Ipv4Addr {
    message
        .answers
        .iter()
        .find_map(|record| match &record.data {
            RData::A(address) => Some(address.0),
            _ => None,
        })
        .expect("A answer")
}

fn ns_targets(message: &Message, owner: &str) -> Vec<String> {
    message
        .answers
        .iter()
        .filter(|record| record.name == n(owner) && record.record_type() == RecordType::NS)
        .filter_map(|record| match &record.data {
            RData::NS(target) => Some(target.0.to_ascii()),
            _ => None,
        })
        .collect()
}

/// Start the four authorities used by both tests.
///
/// The root refers `test.` and the victim, `test.` refers `evil.test.`, the
/// attacker answers for `evil.test.`, and the victim server is authoritative
/// for `victim.test.`.
async fn hierarchy() -> (Mock, Mock, Mock, Mock, u16) {
    let root = Mock::start(
        IpAddr::V4(ROOT),
        0,
        Arc::new(|query: &Message| {
            let question = query.queries.first()?;
            let name = question.name.to_ascii().to_ascii_lowercase();
            let response = match (name.as_str(), question.query_type) {
                ("x.evil.test.", _) => {
                    referral(query, "test.", "ns.test.", Some(("ns.test.", TLD.octets())))
                }
                ("victim.test.", _) | ("www.victim.test.", _) => {
                    // No glue: the resolver must look the nameserver address up
                    // itself, which is where a poisoned address would be used.
                    referral(query, "victim.test.", "ns.victim.test.", None)
                }
                ("ns.victim.test.", RecordType::A) => {
                    answer(query, vec![a("ns.victim.test.", VICTIM.octets())])
                }
                _ => reply(query, ResponseCode::ServFail),
            };
            Some(response)
        }),
    )
    .await;
    let port = root.addr.port();

    let tld = Mock::start(
        IpAddr::V4(TLD),
        port,
        Arc::new(|query: &Message| {
            let question = query.queries.first()?;
            let name = question.name.to_ascii().to_ascii_lowercase();
            let response = match (name.as_str(), question.query_type) {
                ("x.evil.test.", _) => referral(
                    query,
                    "evil.test.",
                    "ns.evil.test.",
                    Some(("ns.evil.test.", ATTACKER.octets())),
                ),
                ("victim.test.", _) | ("www.victim.test.", _) => {
                    referral(query, "victim.test.", "ns.victim.test.", None)
                }
                ("ns.victim.test.", RecordType::A) => {
                    answer(query, vec![a("ns.victim.test.", VICTIM.octets())])
                }
                _ => reply(query, ResponseCode::ServFail),
            };
            Some(response)
        }),
    )
    .await;

    let attacker = Mock::start(
        IpAddr::V4(ATTACKER),
        port,
        Arc::new(|query: &Message| {
            let question = query.queries.first()?;
            let name = question.name.to_ascii().to_ascii_lowercase();
            let response = match (name.as_str(), question.query_type) {
                // Variant A: alias into the victim's namespace and smuggle a
                // forged delegation for it.
                ("x.evil.test.", RecordType::NS) => answer(
                    query,
                    vec![
                        cname("x.evil.test.", "victim.test."),
                        ns("victim.test.", "ns.evil.test."),
                    ],
                ),
                // Variant B: alias the victim's nameserver and smuggle a forged
                // address for it. The forged address is the attacker itself.
                ("x.evil.test.", RecordType::A) => answer(
                    query,
                    vec![
                        cname("x.evil.test.", "ns.victim.test."),
                        a("ns.victim.test.", ATTACKER.octets()),
                    ],
                ),
                // Only reachable if the poisoning succeeded.
                ("victim.test.", RecordType::A) | ("www.victim.test.", RecordType::A) => {
                    answer(query, vec![a(&name, [6, 6, 6, 6])])
                }
                _ => reply(query, ResponseCode::ServFail),
            };
            Some(response)
        }),
    )
    .await;

    let victim = Mock::start(
        IpAddr::V4(VICTIM),
        port,
        Arc::new(|query: &Message| {
            let question = query.queries.first()?;
            let name = question.name.to_ascii().to_ascii_lowercase();
            let response = match (name.as_str(), question.query_type) {
                ("victim.test.", RecordType::NS) => {
                    answer(query, vec![ns("victim.test.", "ns.victim.test.")])
                }
                ("victim.test.", RecordType::A) | ("www.victim.test.", RecordType::A) => {
                    answer(query, vec![a(&name, [203, 0, 113, 1])])
                }
                ("ns.victim.test.", RecordType::A) => {
                    answer(query, vec![a("ns.victim.test.", VICTIM.octets())])
                }
                _ => reply(query, ResponseCode::ServFail),
            };
            Some(response)
        }),
    )
    .await;

    (root, tld, attacker, victim, port)
}

fn resolver(root: SocketAddr, port: u16, rrsets: Arc<RrsetCache>) -> IteratorResolver {
    let config = IteratorConfig {
        root_servers: Some(vec![root]),
        nameserver_port: port,
        case_randomization: false,
        cookies: false,
        qname_minimization: false,
        harden_glue: true,
        ..IteratorConfig::default()
    };
    IteratorResolver::with_config(config, None)
        .expect("resolver")
        .with_caches(rrsets, Arc::new(InfraCache::new(64)))
}

#[tokio::test]
async fn foreign_ns_in_answer_section_is_not_cached() {
    let (root, _tld, attacker, victim, port) = hierarchy().await;
    let rrsets = Arc::new(RrsetCache::new(64));
    let resolver = resolver(root.addr, port, Arc::clone(&rrsets));

    // The attacker's answer carries `victim.test NS ns.evil.test`.
    let poisoned = resolver
        .resolve("x.evil.test.", RecordType::NS)
        .await
        .expect("poison query succeeds");
    assert_eq!(
        ns_targets(&poisoned, "victim.test."),
        vec!["ns.victim.test.".to_owned()],
        "the real delegation must be used, not the smuggled one"
    );

    // The forged NS RRset must not have entered the cache.
    let cached = rrsets.get(&n("victim.test."), RecordType::NS);
    if let Some(cached) = cached {
        let targets: Vec<String> = cached
            .records
            .iter()
            .filter_map(|record| match &record.data {
                RData::NS(target) => Some(target.0.to_ascii()),
                _ => None,
            })
            .collect();
        assert_eq!(targets, vec!["ns.victim.test.".to_owned()]);
    }

    // A victim query must reach the real nameserver.
    let message = resolver
        .resolve("victim.test.", RecordType::A)
        .await
        .expect("victim query succeeds");
    assert_eq!(address_of(&message), Ipv4Addr::new(203, 0, 113, 1));
    assert!(
        victim
            .observed()
            .iter()
            .any(|query| query == "victim.test. A"),
        "the real victim nameserver answered"
    );
    assert!(
        !attacker
            .observed()
            .iter()
            .any(|query| query == "victim.test. A"),
        "the injected delegation must not be followed"
    );
}

#[tokio::test]
async fn foreign_a_record_in_answer_section_is_not_cached() {
    let (root, _tld, attacker, victim, port) = hierarchy().await;
    let rrsets = Arc::new(RrsetCache::new(64));
    let resolver = resolver(root.addr, port, Arc::clone(&rrsets));

    // The attacker's answer carries `ns.victim.test A <attacker>`.
    let poisoned = resolver
        .resolve("x.evil.test.", RecordType::A)
        .await
        .expect("poison query succeeds");
    assert_eq!(
        address_of(&poisoned),
        VICTIM,
        "the real nameserver address must be used, not the smuggled one"
    );

    // The forged address must not have entered the cache.
    let cached = rrsets
        .get(&n("ns.victim.test."), RecordType::A)
        .expect("real nameserver address is cached");
    let addresses: Vec<Ipv4Addr> = cached
        .records
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(address) => Some(address.0),
            _ => None,
        })
        .collect();
    assert_eq!(addresses, vec![VICTIM]);

    // A later victim query must use the real nameserver address.
    let message = resolver
        .resolve("www.victim.test.", RecordType::A)
        .await
        .expect("victim query succeeds");
    assert_eq!(address_of(&message), Ipv4Addr::new(203, 0, 113, 1));
    assert!(
        victim
            .observed()
            .iter()
            .any(|query| query == "www.victim.test. A"),
        "the real victim nameserver answered"
    );
    assert!(
        !attacker
            .observed()
            .iter()
            .any(|query| query == "www.victim.test. A"),
        "the poisoned nameserver address must not be followed"
    );
}
