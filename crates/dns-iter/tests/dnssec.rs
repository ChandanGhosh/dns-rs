//! Deterministic DNSSEC tests against signed fake zones.
//!
//! The fake hierarchy is root -> com -> example.com. Every zone is signed with
//! a fresh ED25519 key, and the resolver is given the fake root DNSKEY as its
//! trust anchor. This exercises DS/DNSKEY chaining, positive RRset validation,
//! NSEC denial proofs, insecure delegations, and bogus data.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use dns_dnssec::{AutoTrustAnchor, Security, TrustAnchor, TrustStore};
use dns_iter::{ForwardZone, IteratorConfig, IteratorResolver, ResolveOptions};
use dns_proto::{
    Algorithm, CNAME, DNSClass, DNSKEY, DNSSECRData, DS, DigestType, Message, MessageType, NS,
    NSEC, NSEC3, Name, Nsec3HashAlgorithm, OpCode, PublicKeyBuf, RData, RRSIG, Record, RecordType,
    ResponseCode, SOA, SerialNumber, SigInput, TBS, decode, encode,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use tokio::net::UdpSocket;

struct MockAuth {
    addr: SocketAddr,
}

impl MockAuth {
    async fn start<F>(handler: F) -> Self
    where
        F: Fn(&Message) -> Option<Message> + Send + Sync + 'static,
    {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind fake UDP server");
        let addr = socket.local_addr().expect("fake address");
        let handler = Arc::new(handler);
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 65_535];
            loop {
                let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                    break;
                };
                let Ok(query) = decode(&buffer[..length]) else {
                    continue;
                };
                if let Some(response) = handler(&query)
                    && let Ok(wire) = encode(&response)
                {
                    let _ = socket.send_to(&wire, peer).await;
                }
            }
        });
        Self { addr }
    }
}

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

fn referral(query: &Message, zone: &str, target: &str) -> Message {
    let mut message = reply(query, ResponseCode::NoError);
    message.add_authority(Record::from_rdata(n(zone), 300, RData::NS(NS(n(target)))));
    message.add_additional(Record::from_rdata(
        n(target),
        300,
        RData::A(Ipv4Addr::LOCALHOST.into()),
    ));
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

fn signed_zone_config(server: SocketAddr, root_key: &SigningKey) -> IteratorConfig {
    let store = TrustStore::builtin();
    store.insert(TrustAnchor::from_keys(
        Name::root(),
        vec![root_key.record(".")],
    ));
    IteratorConfig {
        root_servers: Some(vec![server]),
        nameserver_port: server.port(),
        case_randomization: false,
        cookies: false,
        qname_minimization: true,
        harden_glue: true,
        dnssec_validation: true,
        trust_store: store,
        harden_dnssec_stripped: true,
        ..IteratorConfig::default()
    }
}

fn build_hierarchy() -> (SigningKey, SigningKey, SigningKey, u32) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_secs() as u32;
    (
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
        now,
    )
}

#[tokio::test]
async fn secure_positive_answer_validates_and_sets_ad() {
    let (root, com, example, now) = build_hierarchy();
    let server = {
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

        MockAuth::start(move |query| {
            let question = query.queries.first()?;
            let qname = question.name.to_ascii().to_ascii_lowercase();
            let response = match (qname.as_str(), question.query_type) {
                (".", RecordType::DNSKEY) => answer(query, root_dnskey.clone()),
                ("com.", RecordType::DNSKEY) => answer(query, com_dnskey.clone()),
                ("com.", RecordType::DS) => answer(query, root_ds_com.clone()),
                ("com.", RecordType::NS) => referral(query, "com.", "ns.com."),
                ("example.com.", RecordType::DNSKEY) => answer(query, example_dnskey.clone()),
                ("example.com.", RecordType::DS) => answer(query, com_ds_example.clone()),
                ("example.com.", RecordType::NS) => {
                    referral(query, "example.com.", "ns.example.com.")
                }
                ("www.example.com.", RecordType::A) => answer(query, www.clone()),
                _ => reply(query, ResponseCode::ServFail),
            };
            Some(response)
        })
        .await
    };

    let resolver = IteratorResolver::with_config(signed_zone_config(server.addr, &root), None)
        .expect("resolver");

    let resolved = resolver
        .resolve_with_options("www.example.com.", RecordType::A, ResolveOptions::default())
        .await
        .expect("resolution succeeds");
    assert_eq!(resolved.security, Security::Secure);
    assert!(resolved.message.metadata.authentic_data);
    assert!(
        resolved
            .message
            .answers
            .iter()
            .all(|record| record.record_type() == RecordType::A),
        "non-DO clients must not receive RRSIGs"
    );

    let with_dnssec = resolver
        .resolve_with_options(
            "www.example.com.",
            RecordType::A,
            ResolveOptions {
                dnssec_ok: true,
                checking_disabled: false,
            },
        )
        .await
        .expect("resolution succeeds");
    assert_eq!(with_dnssec.security, Security::Secure);
    assert!(
        with_dnssec
            .message
            .answers
            .iter()
            .any(|record| record.record_type() == RecordType::RRSIG),
        "DO clients must receive signatures"
    );
}

#[tokio::test]
async fn probe_returns_authenticated_dnskey_rrset() {
    let (root, _com, _example, now) = build_hierarchy();
    let new_key = SigningKey::generate();
    let server = {
        let rrset = signed(vec![root.record("."), new_key.record(".")], &root, ".", now);
        MockAuth::start(move |query| {
            let question = query.queries.first()?;
            if question.name.is_root() && question.query_type == RecordType::DNSKEY {
                Some(answer(query, rrset.clone()))
            } else {
                Some(referral(query, "com.", "ns.com."))
            }
        })
        .await
    };

    let resolver = IteratorResolver::with_config(signed_zone_config(server.addr, &root), None)
        .expect("resolver");
    let probed = resolver
        .probe_dnskey(&Name::root())
        .await
        .expect("DNSKEY probe succeeds");
    assert_eq!(probed.keys.len(), 2);
    assert!(probed.revoked.is_empty());

    let anchor = TrustAnchor::from_keys(Name::root(), vec![root.record(".")]);
    let mut tracker = AutoTrustAnchor::from_trust_anchor(&anchor, u64::from(now));
    tracker.update(&probed.keys, u64::from(now));
    assert_eq!(tracker.trusted_keys().len(), 1);
    assert_eq!(tracker.keys.len(), 2);
    assert_eq!(tracker.keys[1].state, dns_dnssec::KeyState::AddPend);
}

#[tokio::test]
async fn tampered_signature_is_bogus() {
    let (root, com, example, now) = build_hierarchy();
    let server = {
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
        // Change the address after signing.
        bad[0] = Record::from_rdata(
            n("bad.example.com."),
            300,
            RData::A(Ipv4Addr::new(203, 0, 113, 66).into()),
        );

        MockAuth::start(move |query| {
            let question = query.queries.first()?;
            let qname = question.name.to_ascii().to_ascii_lowercase();
            let response = match (qname.as_str(), question.query_type) {
                (".", RecordType::DNSKEY) => answer(query, root_dnskey.clone()),
                ("com.", RecordType::DNSKEY) => answer(query, com_dnskey.clone()),
                ("com.", RecordType::DS) => answer(query, root_ds_com.clone()),
                ("com.", RecordType::NS) => referral(query, "com.", "ns.com."),
                ("example.com.", RecordType::DNSKEY) => answer(query, example_dnskey.clone()),
                ("example.com.", RecordType::DS) => answer(query, com_ds_example.clone()),
                ("example.com.", RecordType::NS) => {
                    referral(query, "example.com.", "ns.example.com.")
                }
                ("bad.example.com.", RecordType::A) => answer(query, bad.clone()),
                _ => reply(query, ResponseCode::ServFail),
            };
            Some(response)
        })
        .await
    };

    let resolver = IteratorResolver::with_config(signed_zone_config(server.addr, &root), None)
        .expect("resolver");
    let resolved = resolver
        .resolve_with_options("bad.example.com.", RecordType::A, ResolveOptions::default())
        .await
        .expect("resolution completes");

    assert!(matches!(resolved.security, Security::Bogus(_)));
    assert!(!resolved.message.metadata.authentic_data);
}

#[tokio::test]
async fn nxdomain_and_nodata_proofs_validate() {
    let (root, com, example, now) = build_hierarchy();
    let server = {
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

        // A single NSEC at the apex covers every other name, including the
        // queried name and its wildcard.
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

        MockAuth::start(move |query| {
            let question = query.queries.first()?;
            let qname = question.name.to_ascii().to_ascii_lowercase();
            let response = match (qname.as_str(), question.query_type) {
                (".", RecordType::DNSKEY) => answer(query, root_dnskey.clone()),
                ("com.", RecordType::DNSKEY) => answer(query, com_dnskey.clone()),
                ("com.", RecordType::DS) => answer(query, root_ds_com.clone()),
                ("com.", RecordType::NS) => referral(query, "com.", "ns.com."),
                ("example.com.", RecordType::DNSKEY) => answer(query, example_dnskey.clone()),
                ("example.com.", RecordType::DS) => answer(query, com_ds_example.clone()),
                ("example.com.", RecordType::NS) => {
                    referral(query, "example.com.", "ns.example.com.")
                }
                ("nope.example.com.", RecordType::A) => {
                    let mut message = reply(query, ResponseCode::NXDomain);
                    message.add_authority(soa("example.com."));
                    for record in nsec_apex.clone() {
                        message.add_authority(record);
                    }
                    message
                }
                ("www.example.com.", RecordType::AAAA) => {
                    let mut message = reply(query, ResponseCode::NoError);
                    message.add_authority(soa("example.com."));
                    for record in nsec_www.clone() {
                        message.add_authority(record);
                    }
                    message
                }
                _ => reply(query, ResponseCode::ServFail),
            };
            Some(response)
        })
        .await
    };

    let resolver = IteratorResolver::with_config(signed_zone_config(server.addr, &root), None)
        .expect("resolver");

    let nxdomain = resolver
        .resolve_with_options(
            "nope.example.com.",
            RecordType::A,
            ResolveOptions::default(),
        )
        .await
        .expect("NXDOMAIN resolves");
    assert_eq!(
        nxdomain.message.metadata.response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(nxdomain.security, Security::Secure);

    let nodata = resolver
        .resolve_with_options(
            "www.example.com.",
            RecordType::AAAA,
            ResolveOptions::default(),
        )
        .await
        .expect("NODATA resolves");
    assert_eq!(nodata.message.metadata.response_code, ResponseCode::NoError);
    assert!(nodata.message.answers.is_empty());
    assert_eq!(nodata.security, Security::Secure);
}

#[tokio::test]
async fn unsigned_delegation_is_insecure() {
    let (root, com, example, now) = build_hierarchy();
    let server = {
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
        let unsigned_ds_denial = nsec(
            "unsigned.com.",
            "zzz.com.",
            &[RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
            &com,
            "com.",
            now,
        );

        MockAuth::start(move |query| {
            let question = query.queries.first()?;
            let qname = question.name.to_ascii().to_ascii_lowercase();
            let response = match (qname.as_str(), question.query_type) {
                (".", RecordType::DNSKEY) => answer(query, root_dnskey.clone()),
                ("com.", RecordType::DNSKEY) => answer(query, com_dnskey.clone()),
                ("com.", RecordType::DS) => answer(query, root_ds_com.clone()),
                ("com.", RecordType::NS) => referral(query, "com.", "ns.com."),
                ("example.com.", RecordType::DNSKEY) => answer(query, example_dnskey.clone()),
                ("example.com.", RecordType::DS) => answer(query, com_ds_example.clone()),
                ("example.com.", RecordType::NS) => {
                    referral(query, "example.com.", "ns.example.com.")
                }
                ("unsigned.com.", RecordType::NS) => {
                    referral(query, "unsigned.com.", "ns.unsigned.com.")
                }
                ("unsigned.com.", RecordType::DS) => {
                    let mut message = reply(query, ResponseCode::NoError);
                    message.add_authority(soa("com."));
                    for record in unsigned_ds_denial.clone() {
                        message.add_authority(record);
                    }
                    message
                }
                ("www.unsigned.com.", RecordType::A) => answer(
                    query,
                    vec![Record::from_rdata(
                        n("www.unsigned.com."),
                        300,
                        RData::A(Ipv4Addr::new(198, 51, 100, 7).into()),
                    )],
                ),
                ("www.unsigned.com.", RecordType::DS) => {
                    let mut message = reply(query, ResponseCode::NoError);
                    message.add_authority(soa("unsigned.com."));
                    message
                }
                _ => reply(query, ResponseCode::ServFail),
            };
            Some(response)
        })
        .await
    };

    let resolver = IteratorResolver::with_config(signed_zone_config(server.addr, &root), None)
        .expect("resolver");
    let resolved = resolver
        .resolve_with_options(
            "www.unsigned.com.",
            RecordType::A,
            ResolveOptions::default(),
        )
        .await
        .expect("resolution succeeds");

    assert_eq!(resolved.security, Security::Insecure);
    assert!(!resolved.message.metadata.authentic_data);
    assert_eq!(resolved.message.answers.len(), 1);
}

/// A server authoritative for both a parent and child can answer a DS query at
/// the child apex from the child zone, placing the child's own SOA in the
/// authority section instead of the parent's. The validator must not treat
/// that SOA as the parent and recurse into the same zone until the depth cap;
/// it must walk up to the unsigned parent and classify the subtree insecure.
#[tokio::test]
async fn child_soa_on_ds_probe_does_not_recurse() {
    let (root, com, _example, now) = build_hierarchy();
    let child_ds_probes = Arc::new(AtomicUsize::new(0));
    let server = {
        let child_ds_probes = Arc::clone(&child_ds_probes);
        let root_dnskey = signed(vec![root.record(".")], &root, ".", now);
        let com_dnskey = signed(vec![com.record("com.")], &com, "com.", now);
        let root_ds_com = ds_record(&com, "com.", &root, now);
        // com proves that google.com is an unsigned delegation.
        let google_ds_denial = nsec(
            "google.com.",
            "zzz.com.",
            &[RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
            &com,
            "com.",
            now,
        );
        let www = Record::from_rdata(
            n("www.l.google.com."),
            300,
            RData::A(Ipv4Addr::new(198, 51, 100, 9).into()),
        );

        MockAuth::start(move |query| {
            let question = query.queries.first()?;
            let qname = question.name.to_ascii().to_ascii_lowercase();
            let response = match (qname.as_str(), question.query_type) {
                (".", RecordType::DNSKEY) => answer(query, root_dnskey.clone()),
                ("com.", RecordType::DNSKEY) => answer(query, com_dnskey.clone()),
                ("com.", RecordType::DS) => answer(query, root_ds_com.clone()),
                ("com.", RecordType::NS) => referral(query, "com.", "ns.com."),
                ("google.com.", RecordType::NS) => referral(query, "google.com.", "ns.google.com."),
                ("google.com.", RecordType::DS) => {
                    let mut message = reply(query, ResponseCode::NoError);
                    message.add_authority(soa("com."));
                    for record in google_ds_denial.clone() {
                        message.add_authority(record);
                    }
                    message
                }
                ("l.google.com.", RecordType::NS) => {
                    referral(query, "l.google.com.", "ns.l.google.com.")
                }
                // Same-server child response: its own SOA, no parent proof.
                ("l.google.com." | "www.l.google.com.", RecordType::DS) => {
                    child_ds_probes.fetch_add(1, Ordering::Relaxed);
                    let mut message = reply(query, ResponseCode::NoError);
                    message.add_authority(soa("l.google.com."));
                    message
                }
                ("www.l.google.com.", RecordType::A) => answer(query, vec![www.clone()]),
                _ => reply(query, ResponseCode::ServFail),
            };
            Some(response)
        })
        .await
    };

    let resolver = IteratorResolver::with_config(signed_zone_config(server.addr, &root), None)
        .expect("resolver");
    let resolved = resolver
        .resolve_with_options(
            "www.l.google.com.",
            RecordType::A,
            ResolveOptions::default(),
        )
        .await
        .expect("resolution completes");

    assert_eq!(resolved.security, Security::Insecure);
    assert!(!resolved.message.metadata.authentic_data);
    assert_eq!(resolved.message.answers.len(), 1);
    let probes = child_ds_probes.load(Ordering::Relaxed);
    assert!(
        probes < 8,
        "DS probe at the child apex must not recurse, saw {probes} probes"
    );
}

/// A cached insecure ancestor makes every descendant insecure: the validator
/// must not probe DS again for a child zone below it (RFC 4035 section 5.2,
/// mirroring Unbound's key-entry inheritance). Otherwise every resolution
/// below an unsigned delegation pays for a provably redundant probe.
#[tokio::test]
async fn cached_insecure_ancestor_skips_descendant_ds_probe() {
    let (root, com, _example, now) = build_hierarchy();
    let child_ds_probes = Arc::new(AtomicUsize::new(0));
    let server = {
        let child_ds_probes = Arc::clone(&child_ds_probes);
        let root_dnskey = signed(vec![root.record(".")], &root, ".", now);
        let com_dnskey = signed(vec![com.record("com.")], &com, "com.", now);
        let root_ds_com = ds_record(&com, "com.", &root, now);
        // com proves that google.com is an unsigned delegation.
        let google_ds_denial = nsec(
            "google.com.",
            "zzz.com.",
            &[RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
            &com,
            "com.",
            now,
        );
        let www_google = Record::from_rdata(
            n("www.google.com."),
            300,
            RData::A(Ipv4Addr::new(198, 51, 100, 20).into()),
        );
        let www_l_google = Record::from_rdata(
            n("www.l.google.com."),
            300,
            RData::A(Ipv4Addr::new(198, 51, 100, 21).into()),
        );

        MockAuth::start(move |query| {
            let question = query.queries.first()?;
            let qname = question.name.to_ascii().to_ascii_lowercase();
            let response = match (qname.as_str(), question.query_type) {
                (".", RecordType::DNSKEY) => answer(query, root_dnskey.clone()),
                ("com.", RecordType::DNSKEY) => answer(query, com_dnskey.clone()),
                ("com.", RecordType::DS) => answer(query, root_ds_com.clone()),
                ("com.", RecordType::NS) => referral(query, "com.", "ns.com."),
                ("google.com.", RecordType::NS) => referral(query, "google.com.", "ns.google.com."),
                ("google.com.", RecordType::DS) => {
                    let mut message = reply(query, ResponseCode::NoError);
                    message.add_authority(soa("com."));
                    for record in google_ds_denial.clone() {
                        message.add_authority(record);
                    }
                    message
                }
                ("www.google.com.", RecordType::A) => answer(query, vec![www_google.clone()]),
                ("l.google.com.", RecordType::NS) => {
                    referral(query, "l.google.com.", "ns.l.google.com.")
                }
                ("l.google.com.", RecordType::DS) => {
                    child_ds_probes.fetch_add(1, Ordering::Relaxed);
                    let mut message = reply(query, ResponseCode::NoError);
                    message.add_authority(soa("l.google.com."));
                    message
                }
                ("www.l.google.com.", RecordType::A) => answer(query, vec![www_l_google.clone()]),
                _ => reply(query, ResponseCode::ServFail),
            };
            Some(response)
        })
        .await
    };

    let resolver = IteratorResolver::with_config(signed_zone_config(server.addr, &root), None)
        .expect("resolver");

    // Warm the enclosing zone status through a name directly under it.
    let warm = resolver
        .resolve_with_options("www.google.com.", RecordType::A, ResolveOptions::default())
        .await
        .expect("resolution completes");
    assert_eq!(warm.security, Security::Insecure);

    let resolved = resolver
        .resolve_with_options(
            "www.l.google.com.",
            RecordType::A,
            ResolveOptions::default(),
        )
        .await
        .expect("resolution completes");
    assert_eq!(resolved.security, Security::Insecure);
    assert!(!resolved.message.metadata.authentic_data);
    assert_eq!(
        child_ds_probes.load(Ordering::Relaxed),
        0,
        "a cached insecure ancestor must satisfy the child zone without a DS probe"
    );
}

/// An explicit trust anchor creates a signed island below an unsigned parent.
/// The insecure status of the parent must not leak into that island: an
/// unsigned RRset inside it is bogus, not insecure.
#[tokio::test]
async fn trust_anchor_island_below_insecure_parent_stays_validated() {
    let (root, com, _example, now) = build_hierarchy();
    let island = SigningKey::generate();
    let server = {
        let root_dnskey = signed(vec![root.record(".")], &root, ".", now);
        let com_dnskey = signed(vec![com.record("com.")], &com, "com.", now);
        let root_ds_com = ds_record(&com, "com.", &root, now);
        let google_ds_denial = nsec(
            "google.com.",
            "zzz.com.",
            &[RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
            &com,
            "com.",
            now,
        );
        let island_dnskey = signed(
            vec![island.record("secure.l.google.com.")],
            &island,
            "secure.l.google.com.",
            now,
        );
        let unsigned_leaf = Record::from_rdata(
            n("bad.secure.l.google.com."),
            300,
            RData::A(Ipv4Addr::new(198, 51, 100, 22).into()),
        );
        // The island proves the leaf is not a delegation, so a missing
        // signature on the A RRset is a stripped-signature attack.
        let leaf_ds_denial = nsec(
            "bad.secure.l.google.com.",
            "zzz.secure.l.google.com.",
            &[RecordType::A, RecordType::RRSIG, RecordType::NSEC],
            &island,
            "secure.l.google.com.",
            now,
        );
        let leaf_soa = signed(
            vec![soa("secure.l.google.com.")],
            &island,
            "secure.l.google.com.",
            now,
        );

        MockAuth::start(move |query| {
            let question = query.queries.first()?;
            let qname = question.name.to_ascii().to_ascii_lowercase();
            let response = match (qname.as_str(), question.query_type) {
                (".", RecordType::DNSKEY) => answer(query, root_dnskey.clone()),
                ("com.", RecordType::DNSKEY) => answer(query, com_dnskey.clone()),
                ("com.", RecordType::DS) => answer(query, root_ds_com.clone()),
                ("com.", RecordType::NS) => referral(query, "com.", "ns.com."),
                ("google.com.", RecordType::NS) => referral(query, "google.com.", "ns.google.com."),
                ("google.com.", RecordType::DS) => {
                    let mut message = reply(query, ResponseCode::NoError);
                    message.add_authority(soa("com."));
                    for record in google_ds_denial.clone() {
                        message.add_authority(record);
                    }
                    message
                }
                ("www.google.com.", RecordType::A) => answer(
                    query,
                    vec![Record::from_rdata(
                        n("www.google.com."),
                        300,
                        RData::A(Ipv4Addr::new(198, 51, 100, 23).into()),
                    )],
                ),
                ("l.google.com.", RecordType::NS) => {
                    referral(query, "l.google.com.", "ns.l.google.com.")
                }
                ("secure.l.google.com.", RecordType::NS) => {
                    referral(query, "secure.l.google.com.", "ns.secure.l.google.com.")
                }
                ("secure.l.google.com.", RecordType::DNSKEY) => {
                    answer(query, island_dnskey.clone())
                }
                ("bad.secure.l.google.com.", RecordType::A) => {
                    answer(query, vec![unsigned_leaf.clone()])
                }
                ("bad.secure.l.google.com.", RecordType::DS) => {
                    let mut message = reply(query, ResponseCode::NoError);
                    for record in leaf_soa.clone() {
                        message.add_authority(record);
                    }
                    for record in leaf_ds_denial.clone() {
                        message.add_authority(record);
                    }
                    message
                }
                _ => reply(query, ResponseCode::ServFail),
            };
            Some(response)
        })
        .await
    };

    let config = signed_zone_config(server.addr, &root);
    config.trust_store.insert(TrustAnchor::from_keys(
        n("secure.l.google.com."),
        vec![island.record("secure.l.google.com.")],
    ));
    let resolver = IteratorResolver::with_config(config, None).expect("resolver");

    // Warm google.com as insecure through a name directly under it.
    let warm = resolver
        .resolve_with_options("www.google.com.", RecordType::A, ResolveOptions::default())
        .await
        .expect("resolution completes");
    assert_eq!(warm.security, Security::Insecure);

    let resolved = resolver
        .resolve_with_options(
            "bad.secure.l.google.com.",
            RecordType::A,
            ResolveOptions::default(),
        )
        .await
        .expect("resolution completes");

    assert!(
        matches!(
            resolved.security,
            Security::Bogus(dns_dnssec::BogusReason::MissingSignature)
        ),
        "the anchored island must not inherit the parent's insecure status, got {:?}",
        resolved.security
    );
    assert!(!resolved.message.metadata.authentic_data);
}

/// Forwarded answers record no origin, so the validator probes DS directly at
/// the owner. The trust-anchor guard must still stop inheritance there:
/// otherwise a stripped signature inside an anchored island below a cached
/// insecure parent is downgraded to insecure.
#[tokio::test]
async fn forwarded_answer_does_not_inherit_insecurity_across_anchor() {
    let (root, com, _example, now) = build_hierarchy();
    let island = SigningKey::generate();
    let server = {
        let root_dnskey = signed(vec![root.record(".")], &root, ".", now);
        let com_dnskey = signed(vec![com.record("com.")], &com, "com.", now);
        let root_ds_com = ds_record(&com, "com.", &root, now);
        let google_ds_denial = nsec(
            "google.com.",
            "zzz.com.",
            &[RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
            &com,
            "com.",
            now,
        );
        let island_dnskey = signed(
            vec![island.record("secure.l.google.com.")],
            &island,
            "secure.l.google.com.",
            now,
        );
        let leaf_ds_denial = nsec(
            "bad.secure.l.google.com.",
            "zzz.secure.l.google.com.",
            &[RecordType::A, RecordType::RRSIG, RecordType::NSEC],
            &island,
            "secure.l.google.com.",
            now,
        );
        let leaf_soa = signed(
            vec![soa("secure.l.google.com.")],
            &island,
            "secure.l.google.com.",
            now,
        );

        MockAuth::start(move |query| {
            let question = query.queries.first()?;
            let qname = question.name.to_ascii().to_ascii_lowercase();
            let response = match (qname.as_str(), question.query_type) {
                (".", RecordType::DNSKEY) => answer(query, root_dnskey.clone()),
                ("com.", RecordType::DNSKEY) => answer(query, com_dnskey.clone()),
                ("com.", RecordType::DS) => answer(query, root_ds_com.clone()),
                ("google.com.", RecordType::DS) => {
                    let mut message = reply(query, ResponseCode::NoError);
                    message.add_authority(soa("com."));
                    for record in google_ds_denial.clone() {
                        message.add_authority(record);
                    }
                    message
                }
                ("www.google.com.", RecordType::DS) => {
                    // The enclosing zone is unsigned, so its denial is too.
                    let mut message = reply(query, ResponseCode::NoError);
                    message.add_authority(soa("google.com."));
                    message
                }
                ("www.google.com.", RecordType::A) => answer(
                    query,
                    vec![Record::from_rdata(
                        n("www.google.com."),
                        300,
                        RData::A(Ipv4Addr::new(198, 51, 100, 24).into()),
                    )],
                ),
                ("secure.l.google.com.", RecordType::DNSKEY) => {
                    answer(query, island_dnskey.clone())
                }
                ("bad.secure.l.google.com.", RecordType::DS) => {
                    let mut message = reply(query, ResponseCode::NoError);
                    for record in leaf_soa.clone() {
                        message.add_authority(record);
                    }
                    for record in leaf_ds_denial.clone() {
                        message.add_authority(record);
                    }
                    message
                }
                ("bad.secure.l.google.com.", RecordType::A) => answer(
                    query,
                    vec![Record::from_rdata(
                        n("bad.secure.l.google.com."),
                        300,
                        RData::A(Ipv4Addr::new(198, 51, 100, 25).into()),
                    )],
                ),
                _ => reply(query, ResponseCode::ServFail),
            };
            Some(response)
        })
        .await
    };

    let mut config = signed_zone_config(server.addr, &root);
    config.forward_zones = vec![ForwardZone {
        zone: Name::root(),
        servers: vec![server.addr.into()],
        forward_first: false,
        forward_fallback: false,
    }];
    config.trust_store.insert(TrustAnchor::from_keys(
        n("secure.l.google.com."),
        vec![island.record("secure.l.google.com.")],
    ));
    let resolver = IteratorResolver::with_config(config, None).expect("resolver");

    // Warm google.com as insecure through a name directly under it.
    let warm = resolver
        .resolve_with_options("www.google.com.", RecordType::A, ResolveOptions::default())
        .await
        .expect("resolution completes");
    assert_eq!(warm.security, Security::Insecure);

    let resolved = resolver
        .resolve_with_options(
            "bad.secure.l.google.com.",
            RecordType::A,
            ResolveOptions::default(),
        )
        .await
        .expect("resolution completes");

    assert!(
        matches!(
            resolved.security,
            Security::Bogus(dns_dnssec::BogusReason::MissingSignature)
        ),
        "an anchored island must stay validated for forwarded answers, got {:?}",
        resolved.security
    );
}

/// A DS query for an alias is answered with the alias's CNAME, not a DS denial
/// from the parent zone. The validator must follow the alias up to the zone
/// that owns it; otherwise the target's NSEC is checked against the alias name
/// and a legitimate unsigned CNAME is reported as bogus.
#[tokio::test]
async fn cname_in_unsigned_zone_is_insecure() {
    let (root, com, example, now) = build_hierarchy();
    let alias_ds_probe = Arc::new(AtomicBool::new(false));
    let server = {
        let alias_ds_probe = Arc::clone(&alias_ds_probe);
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
        let unsigned_ds_denial = nsec(
            "unsigned.com.",
            "zzz.com.",
            &[RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
            &com,
            "com.",
            now,
        );
        let www = signed(
            vec![Record::from_rdata(
                n("www.example.com."),
                300,
                RData::A(Ipv4Addr::new(192, 0, 2, 2).into()),
            )],
            &example,
            "example.com.",
            now,
        );
        let alias = Record::from_rdata(
            n("alias.unsigned.com."),
            60,
            RData::CNAME(CNAME(n("www.example.com."))),
        );
        let target_soa = signed(vec![soa("example.com.")], &example, "example.com.", now);
        let target_nsec = nsec(
            "www.example.com.",
            "zzz.example.com.",
            &[RecordType::A, RecordType::RRSIG, RecordType::NSEC],
            &example,
            "example.com.",
            now,
        );

        MockAuth::start(move |query| {
            let question = query.queries.first()?;
            let qname = question.name.to_ascii().to_ascii_lowercase();
            let response = match (qname.as_str(), question.query_type) {
                (".", RecordType::DNSKEY) => answer(query, root_dnskey.clone()),
                ("com.", RecordType::DNSKEY) => answer(query, com_dnskey.clone()),
                ("com.", RecordType::DS) => answer(query, root_ds_com.clone()),
                ("com.", RecordType::NS) => referral(query, "com.", "ns.com."),
                ("example.com.", RecordType::DNSKEY) => answer(query, example_dnskey.clone()),
                ("example.com.", RecordType::DS) => answer(query, com_ds_example.clone()),
                ("example.com.", RecordType::NS) => {
                    referral(query, "example.com.", "ns.example.com.")
                }
                ("www.example.com.", RecordType::A) => answer(query, www.clone()),
                ("www.example.com.", RecordType::DS) => {
                    let mut message = reply(query, ResponseCode::NoError);
                    for record in target_soa.clone() {
                        message.add_authority(record);
                    }
                    for record in target_nsec.clone() {
                        message.add_authority(record);
                    }
                    message
                }
                ("unsigned.com.", RecordType::NS) => {
                    referral(query, "unsigned.com.", "ns.unsigned.com.")
                }
                ("unsigned.com.", RecordType::DS) => {
                    let mut message = reply(query, ResponseCode::NoError);
                    message.add_authority(soa("com."));
                    for record in unsigned_ds_denial.clone() {
                        message.add_authority(record);
                    }
                    message
                }
                ("alias.unsigned.com.", RecordType::A) => answer(query, vec![alias.clone()]),
                ("alias.unsigned.com.", RecordType::DS) => {
                    alias_ds_probe.store(true, Ordering::SeqCst);
                    // Upstream followed the CNAME and returned a denial from
                    // the target's zone. The target's NSEC does not cover the
                    // alias name, so validating it against the alias is bogus.
                    let mut message = answer(query, vec![alias.clone()]);
                    for record in target_soa.clone() {
                        message.add_authority(record);
                    }
                    for record in target_nsec.clone() {
                        message.add_authority(record);
                    }
                    message
                }
                _ => reply(query, ResponseCode::ServFail),
            };
            Some(response)
        })
        .await
    };

    let resolver = IteratorResolver::with_config(signed_zone_config(server.addr, &root), None)
        .expect("resolver");
    let resolved = resolver
        .resolve_with_options(
            "alias.unsigned.com.",
            RecordType::A,
            ResolveOptions::default(),
        )
        .await
        .expect("resolution succeeds");

    assert_eq!(resolved.security, Security::Insecure);
    assert!(!resolved.message.metadata.authentic_data);
    assert!(
        !alias_ds_probe.load(Ordering::SeqCst),
        "the validator must use the authoritative zone from the walk, not probe DS at the alias"
    );
    assert!(
        resolved
            .message
            .answers
            .iter()
            .any(|record| record.record_type() == RecordType::A)
    );
}

/// An unsigned delegation whose own RRsets are queried must be insecure, not
/// bogus. The DS denial is signed by the parent, so the validator must inspect
/// the NSEC type bitmap instead of only looking for RRSIGs.
#[tokio::test]
async fn unsigned_delegation_apex_is_insecure() {
    let (root, com, _example, now) = build_hierarchy();
    let server = {
        let root_dnskey = signed(vec![root.record(".")], &root, ".", now);
        let com_dnskey = signed(vec![com.record("com.")], &com, "com.", now);
        let root_ds_com = ds_record(&com, "com.", &root, now);
        let unsigned_ds_denial = nsec(
            "unsigned2.com.",
            "zzz.com.",
            &[RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
            &com,
            "com.",
            now,
        );

        MockAuth::start(move |query| {
            let question = query.queries.first()?;
            let qname = question.name.to_ascii().to_ascii_lowercase();
            let response = match (qname.as_str(), question.query_type) {
                (".", RecordType::DNSKEY) => answer(query, root_dnskey.clone()),
                ("com.", RecordType::DNSKEY) => answer(query, com_dnskey.clone()),
                ("com.", RecordType::DS) => answer(query, root_ds_com.clone()),
                ("com.", RecordType::NS) => referral(query, "com.", "ns.com."),
                ("unsigned2.com.", RecordType::NS) => {
                    referral(query, "unsigned2.com.", "ns.unsigned2.com.")
                }
                ("unsigned2.com.", RecordType::DS) => {
                    let mut message = reply(query, ResponseCode::NoError);
                    message.add_authority(soa("com."));
                    for record in unsigned_ds_denial.clone() {
                        message.add_authority(record);
                    }
                    message
                }
                ("unsigned2.com.", RecordType::A) => answer(
                    query,
                    vec![Record::from_rdata(
                        n("unsigned2.com."),
                        300,
                        RData::A(Ipv4Addr::new(198, 51, 100, 8).into()),
                    )],
                ),
                _ => reply(query, ResponseCode::ServFail),
            };
            Some(response)
        })
        .await
    };

    let resolver = IteratorResolver::with_config(signed_zone_config(server.addr, &root), None)
        .expect("resolver");
    let resolved = resolver
        .resolve_with_options("unsigned2.com.", RecordType::A, ResolveOptions::default())
        .await
        .expect("resolution succeeds");

    assert_eq!(resolved.security, Security::Insecure);
    assert!(!resolved.message.metadata.authentic_data);
    assert_eq!(resolved.message.answers.len(), 1);
}

/// NSEC3 opt-out zones omit unsigned delegations from the chain. The DS denial
/// is a covering NSEC3 with the Opt-Out flag, which also makes the delegation
/// insecure rather than bogus.
#[tokio::test]
async fn nsec3_opt_out_delegation_apex_is_insecure() {
    let (root, com, _example, now) = build_hierarchy();
    let server = {
        let root_dnskey = signed(vec![root.record(".")], &root, ".", now);
        let com_dnskey = signed(vec![com.record("com.")], &com, "com.", now);
        let root_ds_com = ds_record(&com, "com.", &root, now);

        // A single opt-out NSEC3 spanning the whole hash space covers every
        // name, including the unsigned delegation.
        let covering = Record::from_rdata(
            n(&format!(
                "{}.com.",
                data_encoding::BASE32HEX_NOPAD.encode(&[0u8; 20])
            )),
            60,
            RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                true,
                0,
                Vec::new(),
                vec![0xff; 20],
                [
                    RecordType::NS,
                    RecordType::DS,
                    RecordType::RRSIG,
                    RecordType::NSEC3,
                ],
            ))),
        );
        let unsigned_ds_denial = signed(vec![covering], &com, "com.", now);

        MockAuth::start(move |query| {
            let question = query.queries.first()?;
            let qname = question.name.to_ascii().to_ascii_lowercase();
            let response = match (qname.as_str(), question.query_type) {
                (".", RecordType::DNSKEY) => answer(query, root_dnskey.clone()),
                ("com.", RecordType::DNSKEY) => answer(query, com_dnskey.clone()),
                ("com.", RecordType::DS) => answer(query, root_ds_com.clone()),
                ("com.", RecordType::NS) => referral(query, "com.", "ns.com."),
                ("unsigned3.com.", RecordType::NS) => {
                    referral(query, "unsigned3.com.", "ns.unsigned3.com.")
                }
                ("unsigned3.com.", RecordType::DS) => {
                    let mut message = reply(query, ResponseCode::NoError);
                    message.add_authority(soa("com."));
                    for record in unsigned_ds_denial.clone() {
                        message.add_authority(record);
                    }
                    message
                }
                ("unsigned3.com.", RecordType::A) => answer(
                    query,
                    vec![Record::from_rdata(
                        n("unsigned3.com."),
                        300,
                        RData::A(Ipv4Addr::new(198, 51, 100, 9).into()),
                    )],
                ),
                _ => reply(query, ResponseCode::ServFail),
            };
            Some(response)
        })
        .await
    };

    let resolver = IteratorResolver::with_config(signed_zone_config(server.addr, &root), None)
        .expect("resolver");
    let resolved = resolver
        .resolve_with_options("unsigned3.com.", RecordType::A, ResolveOptions::default())
        .await
        .expect("resolution succeeds");

    assert_eq!(resolved.security, Security::Insecure);
    assert!(!resolved.message.metadata.authentic_data);
    assert_eq!(resolved.message.answers.len(), 1);
}

/// An NSEC3 proof claiming more iterations than the configured limit must be
/// rejected as bogus before any hashing, so a hostile zone cannot spin the
/// validator's CPU (RFC 9276 section 3.2).
#[tokio::test]
async fn nsec3_proof_with_excessive_iterations_is_bogus() {
    let (root, com, _example, now) = build_hierarchy();
    let server = {
        let root_dnskey = signed(vec![root.record(".")], &root, ".", now);
        let com_dnskey = signed(vec![com.record("com.")], &com, "com.", now);
        let root_ds_com = ds_record(&com, "com.", &root, now);

        // Same shape as the opt-out fixture, but with one iteration above the
        // limit. The chain to `com.` still validates, so the only reason to
        // reject the DS denial is the iteration count.
        let covering = Record::from_rdata(
            n(&format!(
                "{}.com.",
                data_encoding::BASE32HEX_NOPAD.encode(&[0u8; 20])
            )),
            60,
            RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                true,
                151,
                Vec::new(),
                vec![0xff; 20],
                [
                    RecordType::NS,
                    RecordType::DS,
                    RecordType::RRSIG,
                    RecordType::NSEC3,
                ],
            ))),
        );
        let unsigned_ds_denial = signed(vec![covering], &com, "com.", now);

        MockAuth::start(move |query| {
            let question = query.queries.first()?;
            let qname = question.name.to_ascii().to_ascii_lowercase();
            let response = match (qname.as_str(), question.query_type) {
                (".", RecordType::DNSKEY) => answer(query, root_dnskey.clone()),
                ("com.", RecordType::DNSKEY) => answer(query, com_dnskey.clone()),
                ("com.", RecordType::DS) => answer(query, root_ds_com.clone()),
                ("com.", RecordType::NS) => referral(query, "com.", "ns.com."),
                ("unsigned4.com.", RecordType::NS) => {
                    referral(query, "unsigned4.com.", "ns.unsigned4.com.")
                }
                ("unsigned4.com.", RecordType::DS) => {
                    let mut message = reply(query, ResponseCode::NoError);
                    message.add_authority(soa("com."));
                    for record in unsigned_ds_denial.clone() {
                        message.add_authority(record);
                    }
                    message
                }
                ("unsigned4.com.", RecordType::A) => answer(
                    query,
                    vec![Record::from_rdata(
                        n("unsigned4.com."),
                        300,
                        RData::A(Ipv4Addr::new(198, 51, 100, 10).into()),
                    )],
                ),
                _ => reply(query, ResponseCode::ServFail),
            };
            Some(response)
        })
        .await
    };

    let mut config = signed_zone_config(server.addr, &root);
    // Pin the limit so the test pins the contract, not just the default.
    config.nsec3_max_iterations = 150;
    let resolver = IteratorResolver::with_config(config, None).expect("resolver");
    let resolved = resolver
        .resolve_with_options("unsigned4.com.", RecordType::A, ResolveOptions::default())
        .await
        .expect("resolution completes");

    assert!(matches!(
        resolved.security,
        Security::Bogus(dns_dnssec::BogusReason::IterationLimit)
    ));
    assert!(!resolved.message.metadata.authentic_data);
}

/// A signed `example.com` zone holding an unsigned A record, with the DS and
/// DNSKEY records needed to prove that the zone is signed.
async fn stripped_signature_fixture() -> (SocketAddr, SigningKey, SigningKey) {
    let (root, com, example, now) = build_hierarchy();
    let server = {
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
        let stripped_denial = nsec(
            "stripped.example.com.",
            "zzz.example.com.",
            &[RecordType::A, RecordType::RRSIG, RecordType::NSEC],
            &example,
            "example.com.",
            now,
        );

        MockAuth::start(move |query| {
            let question = query.queries.first()?;
            let qname = question.name.to_ascii().to_ascii_lowercase();
            let response = match (qname.as_str(), question.query_type) {
                (".", RecordType::DNSKEY) => answer(query, root_dnskey.clone()),
                ("com.", RecordType::DNSKEY) => answer(query, com_dnskey.clone()),
                ("com.", RecordType::DS) => answer(query, root_ds_com.clone()),
                ("com.", RecordType::NS) => referral(query, "com.", "ns.com."),
                ("example.com.", RecordType::DNSKEY) => answer(query, example_dnskey.clone()),
                ("example.com.", RecordType::DS) => answer(query, com_ds_example.clone()),
                ("example.com.", RecordType::NS) => {
                    referral(query, "example.com.", "ns.example.com.")
                }
                ("stripped.example.com.", RecordType::A) => answer(
                    query,
                    vec![Record::from_rdata(
                        n("stripped.example.com."),
                        300,
                        RData::A(Ipv4Addr::new(192, 0, 2, 44).into()),
                    )],
                ),
                ("stripped.example.com.", RecordType::DS) => {
                    let mut message = reply(query, ResponseCode::NoError);
                    message.add_authority(soa("example.com."));
                    for record in stripped_denial.clone() {
                        message.add_authority(record);
                    }
                    message
                }
                _ => reply(query, ResponseCode::ServFail),
            };
            Some(response)
        })
        .await
    };
    (server.addr, root, example)
}

#[tokio::test]
async fn stripped_signature_in_signed_zone_is_bogus() {
    let (addr, root, _example) = stripped_signature_fixture().await;
    let resolver =
        IteratorResolver::with_config(signed_zone_config(addr, &root), None).expect("resolver");
    let resolved = resolver
        .resolve_with_options(
            "stripped.example.com.",
            RecordType::A,
            ResolveOptions::default(),
        )
        .await
        .expect("resolution completes");

    assert!(matches!(
        resolved.security,
        Security::Bogus(dns_dnssec::BogusReason::MissingSignature)
    ));
}

/// A configured exclusion makes the whole subtree insecure without weakening
/// validation for other zones.
#[tokio::test]
async fn domain_insecure_skips_validation_for_excluded_subtree() {
    let (addr, root, _example) = stripped_signature_fixture().await;
    let mut config = signed_zone_config(addr, &root);
    config.domain_insecure = vec![n("example.com.")];
    let resolver = IteratorResolver::with_config(config, None).expect("resolver");
    let resolved = resolver
        .resolve_with_options(
            "stripped.example.com.",
            RecordType::A,
            ResolveOptions::default(),
        )
        .await
        .expect("resolution completes");

    assert_eq!(resolved.security, Security::Insecure);
    assert!(!resolved.message.metadata.authentic_data);
    assert_eq!(resolved.message.answers.len(), 1);
}

/// `domain-insecure` applies to names below the entry even when the entry is
/// not a zone cut; the enclosing zone stays signed.
#[tokio::test]
async fn domain_insecure_applies_below_a_non_zone_name() {
    let (addr, root, _example) = stripped_signature_fixture().await;
    let mut config = signed_zone_config(addr, &root);
    config.domain_insecure = vec![n("stripped.example.com.")];
    let resolver = IteratorResolver::with_config(config, None).expect("resolver");
    let resolved = resolver
        .resolve_with_options(
            "stripped.example.com.",
            RecordType::A,
            ResolveOptions::default(),
        )
        .await
        .expect("resolution completes");

    assert_eq!(resolved.security, Security::Insecure);
    assert!(!resolved.message.metadata.authentic_data);
}

/// An explicit trust anchor at or below an excluded domain overrides the
/// exclusion, matching Unbound's `domain-insecure` behaviour.
#[tokio::test]
async fn trust_anchor_overrides_domain_insecure() {
    let (addr, root, example) = stripped_signature_fixture().await;
    let mut config = signed_zone_config(addr, &root);
    config.domain_insecure = vec![n("example.com.")];
    config.trust_store.insert(TrustAnchor::from_keys(
        n("example.com."),
        vec![example.record("example.com.")],
    ));
    let resolver = IteratorResolver::with_config(config, None).expect("resolver");
    let resolved = resolver
        .resolve_with_options(
            "stripped.example.com.",
            RecordType::A,
            ResolveOptions::default(),
        )
        .await
        .expect("resolution completes");

    assert!(matches!(
        resolved.security,
        Security::Bogus(dns_dnssec::BogusReason::MissingSignature)
    ));
}

/// DS evidence that cannot be obtained (upstream SERVFAIL on every probe)
/// must fail closed instead of downgrading the zone to insecure. Otherwise an
/// attacker able to blackhole only the DS exchange could serve forged,
/// unsigned data for a genuinely signed zone.
#[tokio::test]
async fn jammed_ds_answers_fail_closed() {
    let (root, com, _example, now) = build_hierarchy();
    let server = {
        let root_dnskey = signed(vec![root.record(".")], &root, ".", now);
        let com_dnskey = signed(vec![com.record("com.")], &com, "com.", now);
        let unsigned_www = Record::from_rdata(
            n("www.unsigned.com."),
            300,
            RData::A(Ipv4Addr::new(198, 51, 100, 7).into()),
        );

        MockAuth::start(move |query| {
            let question = query.queries.first()?;
            let qname = question.name.to_ascii().to_ascii_lowercase();
            let response = match (qname.as_str(), question.query_type) {
                (".", RecordType::DNSKEY) => answer(query, root_dnskey.clone()),
                ("com.", RecordType::DNSKEY) => answer(query, com_dnskey.clone()),
                ("com.", RecordType::NS) => referral(query, "com.", "ns.com."),
                // Every DS probe is jammed: SERVFAIL for the delegation proof,
                // the zone's own status chain, and rarely-reachable parents.
                (_, RecordType::DS) => reply(query, ResponseCode::ServFail),
                ("unsigned.com.", RecordType::NS) => {
                    referral(query, "unsigned.com.", "ns.unsigned.com.")
                }
                ("www.unsigned.com.", RecordType::A) => answer(query, vec![unsigned_www.clone()]),
                _ => reply(query, ResponseCode::ServFail),
            };
            Some(response)
        })
        .await
    };

    let resolver = IteratorResolver::with_config(signed_zone_config(server.addr, &root), None)
        .expect("resolver");
    let resolved = resolver
        .resolve_with_options(
            "www.unsigned.com.",
            RecordType::A,
            ResolveOptions::default(),
        )
        .await
        .expect("resolution completes");

    // Without DS proof the unsigned data cannot be classified Insecure; the
    // validator must fail closed (bogus) rather than serve it.
    assert!(
        matches!(resolved.security, Security::Bogus(_)),
        "jammed DS probes must not downgrade the answer to insecure, got {:?}",
        resolved.security
    );
    assert!(!resolved.message.metadata.authentic_data);
}

/// A negative proof that cites a zone which does not contain the queried name
/// must never validate. The RRSIG signer fallback lets an upstream attach
/// denial material from one of its own signed zones; the bailiwick check
/// relegates such answers to insecure instead of letting the foreign zone's
/// signature vouch for a name it does not own.
#[tokio::test]
async fn negative_proof_from_foreign_zone_is_not_secure() {
    let (root, com, example, now) = build_hierarchy();
    let attacker = SigningKey::generate();
    let server = {
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
        // A second, genuinely signed zone under com: the attacker's zone.
        let attacker_zone = "attacker.com.";
        let com_ds_attacker = ds_record(&attacker, attacker_zone, &com, now);
        let attacker_dnskey = signed(
            vec![attacker.record(attacker_zone)],
            &attacker,
            attacker_zone,
            now,
        );
        // Denial material signed by the attacker for its own zone: NSEC with
        // an RRSIG whose signer_name is attacker.com. Attached to an
        // NXDOMAIN for www.example.com — a name in a different, signed zone.
        let attacker_nsec = nsec(
            "aaa.attacker.com.",
            "zzz.attacker.com.",
            &[RecordType::NSEC, RecordType::RRSIG],
            &attacker,
            attacker_zone,
            now,
        );

        MockAuth::start(move |query| {
            let question = query.queries.first()?;
            let qname = question.name.to_ascii().to_ascii_lowercase();
            let response = match (qname.as_str(), question.query_type) {
                (".", RecordType::DNSKEY) => answer(query, root_dnskey.clone()),
                ("com.", RecordType::DNSKEY) => answer(query, com_dnskey.clone()),
                ("com.", RecordType::DS) => {
                    let mut message = answer(query, root_ds_com.clone());
                    for record in com_ds_attacker.clone() {
                        message.add_answers([record]);
                    }
                    message
                }
                ("com.", RecordType::NS) => referral(query, "com.", "ns.com."),
                ("attacker.com.", RecordType::DNSKEY) => answer(query, attacker_dnskey.clone()),
                // The attacker's zone must validate cleanly: the attack only
                // matters when the foreign zone IS a trusted, signed chain.
                ("attacker.com.", RecordType::DS) => answer(query, com_ds_attacker.clone()),
                ("example.com.", RecordType::DNSKEY) => answer(query, example_dnskey.clone()),
                ("example.com.", RecordType::DS) => answer(query, com_ds_example.clone()),
                ("example.com.", RecordType::NS) => {
                    referral(query, "example.com.", "ns.example.com.")
                }
                ("www.example.com.", RecordType::A) => {
                    // Forged NXDOMAIN: the SOA from example.com is missing;
                    // only attacker-zone denial records remain in authority.
                    let mut message = reply(query, ResponseCode::NXDomain);
                    for record in attacker_nsec.clone() {
                        message.add_authority(record);
                    }
                    message
                }
                _ => reply(query, ResponseCode::ServFail),
            };
            Some(response)
        })
        .await
    };

    let resolver = IteratorResolver::with_config(signed_zone_config(server.addr, &root), None)
        .expect("resolver");
    let resolved = resolver
        .resolve_with_options("www.example.com.", RecordType::A, ResolveOptions::default())
        .await
        .expect("resolution completes");

    // attacker.com does not contain www.example.com, so its signatures can
    // never vouch for the name's nonexistence. The gate must classify the
    // answer insecure (never Secure; and never bogus — the answer itself is
    // merely unvalidated, not provably wrong).
    assert_eq!(resolved.security, Security::Insecure);
    assert!(!resolved.message.metadata.authentic_data);
}
