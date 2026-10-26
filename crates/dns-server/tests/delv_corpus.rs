//! `delv` corpus parity for DNSSEC validation.
//!
//! The test builds a signed hierarchy (root -> com -> example.com, plus an
//! unsigned delegation and a tampered RRset) and serves it through a fake
//! recursive forwarder. Two resolver instances share that forwarder:
//!
//! * A validating instance checks the AD bit and EDE codes.
//! * A non-validating instance acts as a conduit so `delv` can fetch the raw
//!   chain and validate it independently with the same fake root anchor.
//!
//! This is deterministic and offline: no public DNS or network access is
//! required. The test is skipped when `delv` is not installed.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use data_encoding::BASE64;
use dns_config::{Config, ForwardTarget, ForwardZoneConfig, ListenAddress};
use dns_proto::{
    Algorithm, DNSClass, DNSKEY, DNSSECRData, DS, DigestType, Edns, EdnsCode, EdnsOption, Message,
    MessageType, NS, NSEC, Name, OpCode, PublicKey, PublicKeyBuf, Query, RData, RRSIG, Record,
    RecordType, ResponseCode, SOA, SerialNumber, SigInput, TBS, decode, encode,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Signed test hierarchy
// ---------------------------------------------------------------------------

fn n(text: &str) -> Name {
    Name::from_ascii(text).expect("valid name")
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

struct SigningKey {
    pair: Ed25519KeyPair,
    dnskey: DNSKEY,
}

impl SigningKey {
    fn generate() -> Self {
        let random = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).expect("generate key");
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse key");
        let dnskey = DNSKEY::with_flags(
            257,
            PublicKeyBuf::new(pair.public_key().as_ref().to_vec(), Algorithm::ED25519),
        );
        Self { pair, dnskey }
    }

    fn record(&self, zone: &str) -> Record {
        Record::from_rdata(
            n(zone),
            3600,
            RData::DNSSEC(DNSSECRData::DNSKEY(self.dnskey.clone())),
        )
    }

    fn tag(&self) -> u16 {
        self.dnskey.calculate_key_tag().expect("key tag")
    }

    fn anchor_line(&self) -> String {
        format!(
            ". 3600 IN DNSKEY 257 3 {} {}",
            u8::from(self.dnskey.public_key().algorithm()),
            BASE64.encode(self.dnskey.public_key().public_bytes())
        )
    }
}

fn sign_rrset(rrset: &[Record], key: &SigningKey, signer: &str, now: u32) -> Record {
    let owner = rrset[0].name.clone();
    let input = SigInput {
        type_covered: rrset[0].record_type(),
        algorithm: Algorithm::ED25519,
        num_labels: owner.num_labels(),
        original_ttl: rrset[0].ttl,
        sig_expiration: SerialNumber::from(now + 3600),
        sig_inception: SerialNumber::from(now.saturating_sub(60)),
        key_tag: key.tag(),
        signer_name: n(signer),
    };
    let tbs = TBS::from_input(&owner, DNSClass::IN, &input, rrset.iter()).expect("tbs");
    let signature = key.pair.sign(tbs.as_ref());
    Record::from_rdata(
        owner,
        rrset[0].ttl,
        RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(
            input,
            signature.as_ref().to_vec(),
        ))),
    )
}

fn signed(rrset: Vec<Record>, key: &SigningKey, signer: &str, now: u32) -> Vec<Record> {
    let signature = sign_rrset(&rrset, key, signer, now);
    let mut records = rrset;
    records.push(signature);
    records
}

fn ds_record(child: &SigningKey, child_zone: &str, parent: &SigningKey, now: u32) -> Vec<Record> {
    let zone = n(child_zone);
    let digest = child
        .dnskey
        .to_digest(&zone, DigestType::SHA256)
        .expect("digest");
    let ds = Record::from_rdata(
        zone,
        3600,
        RData::DNSSEC(DNSSECRData::DS(DS::new(
            child.tag(),
            Algorithm::ED25519,
            DigestType::SHA256,
            digest.as_ref().to_vec(),
        ))),
    );
    signed(vec![ds], parent, parent_zone(child_zone), now)
}

fn parent_zone(zone: &str) -> &str {
    match zone {
        "com." => ".",
        "example.com." | "unsigned.com." => "com.",
        _ => ".",
    }
}

fn nsec(
    owner: &str,
    next: &str,
    types: &[RecordType],
    key: &SigningKey,
    zone: &str,
    now: u32,
) -> Vec<Record> {
    let record = Record::from_rdata(
        n(owner),
        60,
        RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(n(next), types.to_vec()))),
    );
    signed(vec![record], key, zone, now)
}

struct Hierarchy {
    root_dnskey: Vec<Record>,
    com_dnskey: Vec<Record>,
    example_dnskey: Vec<Record>,
    root_ds_com: Vec<Record>,
    com_ds_example: Vec<Record>,
    www: Vec<Record>,
    bad: Vec<Record>,
    nsec_apex: Vec<Record>,
    nsec_www: Vec<Record>,
    unsigned_ds_denial: Vec<Record>,
    example_soa: Vec<Record>,
    com_soa: Vec<Record>,
    unsigned_www: Record,
    unsigned_ns: Record,
}

impl Hierarchy {
    fn build() -> (Self, SigningKey) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_secs() as u32;
        let root = SigningKey::generate();
        let com = SigningKey::generate();
        let example = SigningKey::generate();

        let root_dnskey = signed(vec![root.record(".")], &root, ".", now);
        let com_dnskey = signed(vec![com.record("com.")], &com, "com.", now);
        let example_dnskey = signed(
            vec![example.record("example.com.")],
            &example,
            "example.com.",
            now,
        );
        let root_ds_com = ds_record(&com, "com.", &root, now);
        let com_ds_example = ds_record(&example, "example.com.", &com, now);

        let www = signed(
            vec![Record::from_rdata(
                n("www.example.com."),
                300,
                RData::A(Ipv4Addr::new(192, 0, 2, 1).into()),
            )],
            &example,
            "example.com.",
            now,
        );

        // A tampered RRset: the signature was made for 192.0.2.1 but the
        // address was changed afterwards.
        let mut bad = signed(
            vec![Record::from_rdata(
                n("bad.example.com."),
                300,
                RData::A(Ipv4Addr::new(192, 0, 2, 1).into()),
            )],
            &example,
            "example.com.",
            now,
        );
        bad[0] = Record::from_rdata(
            n("bad.example.com."),
            300,
            RData::A(Ipv4Addr::new(203, 0, 113, 66).into()),
        );

        let nsec_apex = nsec(
            "example.com.",
            "example.com.",
            &[
                RecordType::SOA,
                RecordType::NS,
                RecordType::DNSKEY,
                RecordType::RRSIG,
                RecordType::NSEC,
            ],
            &example,
            "example.com.",
            now,
        );
        let nsec_www = nsec(
            "www.example.com.",
            "zzz.example.com.",
            &[RecordType::A, RecordType::RRSIG, RecordType::NSEC],
            &example,
            "example.com.",
            now,
        );
        let unsigned_ds_denial = nsec(
            "unsigned.com.",
            "zzz.com.",
            &[RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
            &com,
            "com.",
            now,
        );
        let example_soa = signed(vec![soa("example.com.")], &example, "example.com.", now);
        let com_soa = signed(vec![soa("com.")], &com, "com.", now);

        (
            Self {
                root_dnskey,
                com_dnskey,
                example_dnskey,
                root_ds_com,
                com_ds_example,
                www,
                bad,
                nsec_apex,
                nsec_www,
                unsigned_ds_denial,
                example_soa,
                com_soa,
                unsigned_www: Record::from_rdata(
                    n("www.unsigned.com."),
                    300,
                    RData::A(Ipv4Addr::new(198, 51, 100, 7).into()),
                ),
                unsigned_ns: Record::from_rdata(
                    n("unsigned.com."),
                    300,
                    RData::NS(NS(n("ns.unsigned.com."))),
                ),
            },
            root,
        )
    }

    fn respond(&self, query: &Message) -> Option<Message> {
        let question = query.queries.first()?;
        let qname = question.name.to_ascii().to_ascii_lowercase();
        let mut response = match (qname.as_str(), question.query_type) {
            (".", RecordType::DNSKEY) => answer(query, self.root_dnskey.clone()),
            ("com.", RecordType::DNSKEY) => answer(query, self.com_dnskey.clone()),
            ("com.", RecordType::DS) => answer(query, self.root_ds_com.clone()),
            ("example.com.", RecordType::DNSKEY) => answer(query, self.example_dnskey.clone()),
            ("example.com.", RecordType::DS) => answer(query, self.com_ds_example.clone()),
            ("www.example.com.", RecordType::A) => answer(query, self.www.clone()),
            ("bad.example.com.", RecordType::A) => answer(query, self.bad.clone()),
            ("nope.example.com.", RecordType::A) => {
                let mut message = reply(query, ResponseCode::NXDomain);
                for record in self.example_soa.clone() {
                    message.add_authority(record);
                }
                for record in self.nsec_apex.clone() {
                    message.add_authority(record);
                }
                message
            }
            ("www.example.com.", RecordType::AAAA) => {
                let mut message = reply(query, ResponseCode::NoError);
                for record in self.example_soa.clone() {
                    message.add_authority(record);
                }
                for record in self.nsec_www.clone() {
                    message.add_authority(record);
                }
                message
            }
            ("unsigned.com.", RecordType::DS) => {
                let mut message = reply(query, ResponseCode::NoError);
                for record in self.com_soa.clone() {
                    message.add_authority(record);
                }
                for record in self.unsigned_ds_denial.clone() {
                    message.add_authority(record);
                }
                message
            }
            ("unsigned.com.", RecordType::NS) => answer(query, vec![self.unsigned_ns.clone()]),
            ("www.unsigned.com.", RecordType::A) => answer(query, vec![self.unsigned_www.clone()]),
            _ => reply(query, ResponseCode::ServFail),
        };
        // The iterator validates the upstream cookie; echo the request's
        // EDNS option so the fake forwarder is treated as cookie-aware.
        response.edns = query.edns.clone();
        Some(response)
    }
}

/// Serve the signed hierarchy as a recursive forwarder over UDP.
async fn start_fake_forwarder(hierarchy: Arc<Hierarchy>) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind fake forwarder");
    let addr = socket.local_addr().expect("fake forwarder address");
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_535];
        loop {
            let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                break;
            };
            let Ok(query) = decode(&buffer[..length]) else {
                continue;
            };
            if let Some(response) = hierarchy.respond(&query)
                && let Ok(wire) = encode(&response)
            {
                let _ = socket.send_to(&wire, peer).await;
            }
        }
    });
    addr
}

// ---------------------------------------------------------------------------
// Resolver instances
// ---------------------------------------------------------------------------

struct TestServer {
    addr: SocketAddr,
    shutdown: CancellationToken,
}

impl TestServer {
    async fn start(forwarder: SocketAddr, validating: bool, anchor: Option<String>) -> Self {
        let port = free_port();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

        let mut config = Config::default();
        config.server.interfaces = vec![ListenAddress::new(addr.ip(), Some(port))];
        config.server.port = port;
        config.server.num_threads = 1;
        config.server.do_ip6 = false;
        config.server.qname_minimisation = false;
        config.server.use_caps_for_id = false;
        config.server.dnssec_validation = validating;
        if let Some(anchor) = anchor {
            config.server.trust_anchor = vec![anchor];
        }
        config.forward_zones = vec![ForwardZoneConfig {
            name: ".".to_owned(),
            forward_addrs: vec![ForwardTarget::new(forwarder, None)],
            forward_hosts: Vec::new(),
            forward_first: false,
            tls_upstream: false,
        }];
        config.validate().expect("valid test configuration");

        let shutdown = CancellationToken::new();
        let server_shutdown = shutdown.clone();
        tokio::spawn(async move {
            dns_server::serve(Arc::new(config), server_shutdown)
                .await
                .expect("server runs");
        });
        wait_ready(addr).await;
        Self { addr, shutdown }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

fn free_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind free port");
    socket.local_addr().expect("local address").port()
}

async fn wait_ready(addr: SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("probe socket");
    let query = query_wire(0x1234, "probe.invalid.", RecordType::A, true);
    for _ in 0..100 {
        let _ = socket.send_to(&query, addr).await;
        let mut buffer = [0u8; 512];
        if tokio::time::timeout(Duration::from_millis(50), socket.recv_from(&mut buffer))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("server did not become ready");
}

fn query_wire(id: u16, name: &str, qtype: RecordType, dnssec_ok: bool) -> Vec<u8> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(n(name), qtype));
    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    edns.set_dnssec_ok(dnssec_ok);
    message.edns = Some(edns);
    encode(&message).expect("encode query")
}

async fn query(server: SocketAddr, name: &str, qtype: RecordType) -> Message {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("query socket");
    let wire = query_wire(0x4242, name, qtype, true);
    socket.send_to(&wire, server).await.expect("send query");
    let mut buffer = [0u8; 4096];
    let (length, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer))
        .await
        .expect("query timed out")
        .expect("receive response");
    decode(&buffer[..length]).expect("decode response")
}

fn ede_codes(message: &Message) -> Vec<u16> {
    let Some(edns) = message.edns.as_ref() else {
        return Vec::new();
    };
    let Some(EdnsOption::Unknown(_, data)) = edns.option(EdnsCode::Unknown(15)) else {
        return Vec::new();
    };
    if data.len() < 2 {
        return Vec::new();
    }
    vec![u16::from_be_bytes([data[0], data[1]])]
}

// ---------------------------------------------------------------------------
// `delv` corpus
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Expected {
    SecurePositive,
    SecureNegative,
    Insecure,
    Bogus,
}

struct Case {
    name: &'static str,
    qtype: RecordType,
    expected: Expected,
}

const CORPUS: &[Case] = &[
    Case {
        name: "www.example.com.",
        qtype: RecordType::A,
        expected: Expected::SecurePositive,
    },
    Case {
        name: "nope.example.com.",
        qtype: RecordType::A,
        expected: Expected::SecureNegative,
    },
    Case {
        name: "www.example.com.",
        qtype: RecordType::AAAA,
        expected: Expected::SecureNegative,
    },
    Case {
        name: "www.unsigned.com.",
        qtype: RecordType::A,
        expected: Expected::Insecure,
    },
    Case {
        name: "bad.example.com.",
        qtype: RecordType::A,
        expected: Expected::Bogus,
    },
];

fn delv_available() -> bool {
    Command::new("delv")
        .arg("-v")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn write_delv_anchor(path: &PathBuf, root: &SigningKey) {
    let contents = format!(
        "trust-anchors {{\n    . static-key 257 3 {} \"{}\";\n}};\n",
        u8::from(root.dnskey.public_key().algorithm()),
        BASE64.encode(root.dnskey.public_key().public_bytes())
    );
    std::fs::write(path, contents).expect("write delv anchor");
}

async fn run_delv(server: SocketAddr, anchor: PathBuf, name: String, qtype: RecordType) -> String {
    tokio::task::spawn_blocking(move || {
        let output = Command::new("timeout")
            .arg("20")
            .arg("delv")
            .arg(format!("@{}", server.ip()))
            .arg("-p")
            .arg(server.port().to_string())
            .arg("-a")
            .arg(&anchor)
            .arg(&name)
            .arg(format!("{qtype}"))
            .output()
            .expect("run delv");
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        text
    })
    .await
    .expect("delv task")
}

#[tokio::test]
async fn delv_corpus_matches_resolver_security_status() {
    if !delv_available() {
        eprintln!("delv is not installed; skipping the corpus parity test");
        return;
    }

    let (hierarchy, root) = Hierarchy::build();
    let hierarchy = Arc::new(hierarchy);
    let forwarder = start_fake_forwarder(Arc::clone(&hierarchy)).await;

    let anchor_line = root.anchor_line();
    let validating = TestServer::start(forwarder, true, Some(anchor_line)).await;
    let conduit = TestServer::start(forwarder, false, None).await;

    let anchor_path = std::env::temp_dir().join(format!(
        "dns-rs-delv-anchor-{}-{}.key",
        std::process::id(),
        conduit.addr.port()
    ));
    write_delv_anchor(&anchor_path, &root);

    for case in CORPUS {
        let response = query(validating.addr, case.name, case.qtype).await;
        let ad = response.metadata.authentic_data;
        match case.expected {
            Expected::SecurePositive => {
                assert_eq!(
                    response.metadata.response_code,
                    ResponseCode::NoError,
                    "{} {:?}",
                    case.name,
                    case.qtype
                );
                assert!(ad, "{} {:?} must set AD", case.name, case.qtype);
                assert!(!response.answers.is_empty(), "expected an answer");
            }
            Expected::SecureNegative => {
                assert!(ad, "{} {:?} must set AD", case.name, case.qtype);
                assert!(
                    matches!(
                        response.metadata.response_code,
                        ResponseCode::NoError | ResponseCode::NXDomain
                    ),
                    "unexpected rcode for {} {:?}: {:?}",
                    case.name,
                    case.qtype,
                    response.metadata.response_code
                );
                assert!(
                    response.answers.is_empty(),
                    "negative response must not carry answers"
                );
            }
            Expected::Insecure => {
                assert_eq!(
                    response.metadata.response_code,
                    ResponseCode::NoError,
                    "{} {:?}",
                    case.name,
                    case.qtype
                );
                assert!(!ad, "{} {:?} must not set AD", case.name, case.qtype);
                assert!(!response.answers.is_empty(), "expected an answer");
            }
            Expected::Bogus => {
                assert_eq!(
                    response.metadata.response_code,
                    ResponseCode::ServFail,
                    "{} {:?} must fail validation",
                    case.name,
                    case.qtype
                );
                assert!(!ad, "bogus data must not be authenticated");
                assert!(
                    ede_codes(&response).contains(&6),
                    "bogus data must carry EDE 6, got {:?}",
                    ede_codes(&response)
                );
            }
        }

        let report = run_delv(
            conduit.addr,
            anchor_path.clone(),
            case.name.to_owned(),
            case.qtype,
        )
        .await;
        match case.expected {
            Expected::SecurePositive => {
                assert!(
                    report.contains("fully validated"),
                    "delv did not validate {} {:?}:\n{report}",
                    case.name,
                    case.qtype
                );
                assert!(
                    !report.contains("negative response"),
                    "delv reported an unexpected negative for {} {:?}:\n{report}",
                    case.name,
                    case.qtype
                );
            }
            Expected::SecureNegative => {
                assert!(
                    report.contains("negative response, fully validated"),
                    "delv did not validate the denial for {} {:?}:\n{report}",
                    case.name,
                    case.qtype
                );
            }
            Expected::Insecure => {
                assert!(
                    report.contains("unsigned answer"),
                    "delv did not report an insecure answer for {} {:?}:\n{report}",
                    case.name,
                    case.qtype
                );
            }
            Expected::Bogus => {
                // BIND reports a failed signature check rather than the word
                // "bogus"; both mean the validator rejected the RRset.
                let rejected = report.contains("bogus")
                    || report.contains("RRSIG failed to verify")
                    || report.contains("no valid signature found");
                assert!(
                    rejected,
                    "delv did not reject the bogus RRset for {} {:?}:\n{report}",
                    case.name, case.qtype
                );
            }
        }
    }

    let _ = std::fs::remove_file(&anchor_path);
}
