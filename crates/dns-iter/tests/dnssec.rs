//! Deterministic DNSSEC tests against signed fake zones.
//!
//! The fake hierarchy is root -> com -> example.com. Every zone is signed with
//! a fresh ED25519 key, and the resolver is given the fake root DNSKEY as its
//! trust anchor. This exercises DS/DNSKEY chaining, positive RRset validation,
//! NSEC denial proofs, insecure delegations, and bogus data.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use dns_dnssec::{AutoTrustAnchor, Security, TrustAnchor, TrustStore};
use dns_iter::{IteratorConfig, IteratorResolver, ResolveOptions};
use dns_proto::{
    Algorithm, DNSClass, DNSKEY, DNSSECRData, DS, DigestType, Message, MessageType, NS, NSEC,
    NSEC3, Name, Nsec3HashAlgorithm, OpCode, PublicKeyBuf, RData, RRSIG, Record, RecordType,
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

#[tokio::test]
async fn stripped_signature_in_signed_zone_is_bogus() {
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

    let resolver = IteratorResolver::with_config(signed_zone_config(server.addr, &root), None)
        .expect("resolver");
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
