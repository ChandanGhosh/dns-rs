//! Signed authoritative mock for the DNSSEC benchmark scenario.
//!
//! Generates an Ed25519 key at startup, writes the matching DNSKEY record in
//! zone-file syntax (the trust anchor the resolver is configured with), and
//! answers A and DNSKEY queries for one signed zone. A answers carry the TTL
//! passed on the command line, so a TTL of 0 forces the resolver to revalidate
//! every query instead of serving it from the message cache.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dns_proto::{
    Algorithm, DNSClass, DNSKEY, DNSSECRData, Message, MessageType, Name, OpCode, PublicKeyBuf,
    Query, RData, RRSIG, Record, RecordType, SerialNumber, SigInput, TBS, encode,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

const DNSKEY_TTL: u32 = 3600;
/// Validity window of every generated signature.
///
/// Sized for benchmark runs (minutes, not hours). A run that keeps the same
/// mock process alive longer than this starts receiving SERVFAIL once the
/// signatures expire, so restart the mock for long soaks.
const SIGNATURE_LIFETIME: u32 = 3600;

/// One encoded response plus the length of its question section.
///
/// Keeping the question in the template lets the responder replace it with the
/// client's exact bytes, preserving the random capitalization the resolver uses
/// for spoofing resistance.
struct Template {
    wire: Vec<u8>,
    question_len: usize,
}

struct Signer {
    pair: Ed25519KeyPair,
    dnskey: DNSKEY,
    zone: Name,
    key_tag: u16,
    now: u32,
}

impl Signer {
    fn new(zone: &str) -> Self {
        let random = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).expect("generate Ed25519 key");
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse generated key");
        let dnskey = DNSKEY::with_flags(
            257,
            PublicKeyBuf::new(pair.public_key().as_ref().to_vec(), Algorithm::ED25519),
        );
        let key_tag = dnskey.calculate_key_tag().expect("DNSKEY key tag");
        let zone = Name::from_ascii(zone).expect("valid zone name");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before the Unix epoch")
            .as_secs() as u32;
        Self {
            pair,
            dnskey,
            zone,
            key_tag,
            now,
        }
    }

    fn dnskey_record(&self) -> Record {
        Record::from_rdata(
            self.zone.clone(),
            DNSKEY_TTL,
            RData::DNSSEC(DNSSECRData::DNSKEY(self.dnskey.clone())),
        )
    }

    fn anchor_line(&self) -> String {
        format!(
            "{} {DNSKEY_TTL} IN DNSKEY {}",
            self.zone.to_ascii(),
            self.dnskey
        )
    }

    fn sign_rrset(&self, rrset: &[Record]) -> Record {
        let owner = &rrset[0].name;
        let input = SigInput {
            type_covered: rrset[0].record_type(),
            algorithm: Algorithm::ED25519,
            num_labels: owner.num_labels(),
            original_ttl: rrset[0].ttl,
            sig_expiration: SerialNumber::from(self.now.saturating_add(SIGNATURE_LIFETIME)),
            sig_inception: SerialNumber::from(self.now.saturating_sub(60)),
            key_tag: self.key_tag,
            signer_name: self.zone.clone(),
        };
        let tbs =
            TBS::from_input(owner, DNSClass::IN, &input, rrset.iter()).expect("build signed data");
        let signature = self.pair.sign(tbs.as_ref());
        Record::from_rdata(
            owner.clone(),
            rrset[0].ttl,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(
                input,
                signature.as_ref().to_vec(),
            ))),
        )
    }

    fn signed(&self, mut rrset: Vec<Record>) -> Vec<Record> {
        let signature = self.sign_rrset(&rrset);
        rrset.push(signature);
        rrset
    }

    fn a_records(&self, qname: &Name, ttl: u32) -> Vec<Record> {
        self.signed(vec![Record::from_rdata(
            qname.clone(),
            ttl,
            RData::A(Ipv4Addr::new(192, 0, 2, 1).into()),
        )])
    }

    fn template(&self, qname: &Name, qtype: RecordType, records: Vec<Record>) -> Template {
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message.metadata.authoritative = true;
        message.add_query(Query::query(qname.clone(), qtype));
        message.add_answers(records);
        let wire = encode(&message).expect("encode mock response");
        let question_len = question_end(&wire).expect("encoded response has a question") - 12;
        Template { wire, question_len }
    }
}

/// Parse a query's question into a lowercase owner name, query type, and the
/// offset just past the question section.
fn parse_question(message: &[u8]) -> Option<(String, RecordType, usize)> {
    if message.len() < 12 {
        return None;
    }
    let mut offset = 12;
    let mut name = String::new();
    loop {
        let length = *message.get(offset)? as usize;
        offset += 1;
        if length == 0 {
            break;
        }
        if length & 0xC0 != 0 {
            return None;
        }
        let end = offset.checked_add(length)?;
        let label = message.get(offset..end)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        offset = end;
    }
    let record_type = u16::from_be_bytes([*message.get(offset)?, *message.get(offset + 1)?]);
    Some((
        format!("{name}."),
        RecordType::from(record_type),
        offset.checked_add(4)?,
    ))
}

fn question_end(message: &[u8]) -> Option<usize> {
    parse_question(message).map(|(_, _, end)| end)
}

fn refused(query: &[u8], question_end: usize) -> Vec<u8> {
    let mut response = Vec::with_capacity(question_end);
    response.extend_from_slice(&query[..question_end]);
    response[2] = 0x84 | (query[2] & 0x01);
    response[3] = 0x05;
    response[6..12].fill(0);
    response
}

fn serve(addr: SocketAddr, zone: &str, ttl: u32, names: usize, anchor_path: &str) -> ! {
    let signer = Signer::new(zone);
    if let Err(error) = fs::write(anchor_path, format!("{}\n", signer.anchor_line())) {
        eprintln!("dnssec-mock: write trust anchor {anchor_path}: {error}");
        process::exit(1);
    }

    let mut templates: HashMap<(String, RecordType), Template> =
        HashMap::with_capacity(names.max(1) * 2);
    let zone_text = signer.zone.to_ascii();
    for index in 0..names.max(1) {
        let name = format!("n{index:05}.{zone_text}");
        let qname = Name::from_ascii(&name).expect("valid benchmark name");
        let key = (name.to_ascii_lowercase(), RecordType::A);
        let records = signer.a_records(&qname, ttl);
        templates.insert(key, signer.template(&qname, RecordType::A, records));
    }
    let dnskey_records = signer.signed(vec![signer.dnskey_record()]);
    templates.insert(
        (zone_text.to_ascii_lowercase(), RecordType::DNSKEY),
        signer.template(&signer.zone, RecordType::DNSKEY, dnskey_records),
    );

    let socket = UdpSocket::bind(addr).unwrap_or_else(|error| {
        eprintln!("dnssec-mock: bind {addr}: {error}");
        process::exit(1);
    });
    eprintln!("dnssec-mock: listening on {addr} zone={zone_text} ttl={ttl}");

    let answered = Arc::new(AtomicU64::new(0));
    let reporter = Arc::clone(&answered);
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_millis(250));
            println!(
                "stats upstream_queries={}",
                reporter.load(Ordering::Relaxed)
            );
        }
    });

    let mut buffer = vec![0u8; 1500];
    let mut response = Vec::with_capacity(1500);
    loop {
        let (length, peer) = match socket.recv_from(&mut buffer) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("dnssec-mock: recv: {error}");
                continue;
            }
        };
        let query = &buffer[..length];
        let Some((qname, qtype, question_end)) = parse_question(query) else {
            continue;
        };
        match templates.get(&(qname.clone(), qtype)) {
            Some(template) => {
                send_template(&socket, &mut response, query, question_end, template, peer)
            }
            None => {
                let generated;
                let template = if qtype == RecordType::A
                    && Name::from_ascii(&qname).is_ok_and(|name| signer.zone.zone_of(&name))
                {
                    let name = Name::from_ascii(&qname).expect("name was just validated");
                    let records = signer.a_records(&name, ttl);
                    generated = signer.template(&name, RecordType::A, records);
                    &generated
                } else {
                    send_bytes(&socket, &refused(query, question_end), peer);
                    answered.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                send_template(&socket, &mut response, query, question_end, template, peer);
            }
        }
        answered.fetch_add(1, Ordering::Relaxed);
    }
}

/// Write one templated response, replacing the template question with the
/// client's bytes so the case echo is exact and echoing the RD bit.
fn send_template(
    socket: &UdpSocket,
    response: &mut Vec<u8>,
    query: &[u8],
    question_end: usize,
    template: &Template,
    peer: SocketAddr,
) {
    build_response(response, query, question_end, template);
    send_bytes(socket, response, peer);
}

fn build_response(response: &mut Vec<u8>, query: &[u8], question_end: usize, template: &Template) {
    response.clear();
    response.extend_from_slice(&template.wire);
    let length = question_end - 12;
    if length == template.question_len {
        response[12..question_end].copy_from_slice(&query[12..question_end]);
    }
    response[0..2].copy_from_slice(&query[0..2]);
    response[2] = (response[2] & !0x01) | (query[2] & 0x01);
}

fn send_bytes(socket: &UdpSocket, response: &[u8], peer: SocketAddr) {
    let _ = socket.send_to(response, peer);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 7 || args[1] != "serve" {
        eprintln!("usage: dnssec-mock serve ADDR ZONE TTL NAMES ANCHOR_FILE");
        process::exit(2);
    }
    let addr: SocketAddr = args[2].parse().expect("mock address");
    let zone = &args[3];
    let ttl: u32 = args[4].parse().expect("answer ttl");
    let names: usize = args[5].parse().expect("name count");
    let anchor_path = &args[6];
    serve(addr, zone, ttl, names, anchor_path);
}

#[cfg(test)]
mod tests {
    use dns_proto::decode;

    use super::*;

    fn encoded_query(name: &str, qtype: RecordType) -> Vec<u8> {
        let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(
            Name::from_ascii(name).expect("test name"),
            qtype,
        ));
        encode(&message).expect("encode query")
    }

    #[test]
    fn parse_question_reads_the_owner_and_type() {
        let wire = encoded_query("www.bench.test.", RecordType::AAAA);
        let (name, qtype, end) = parse_question(&wire).expect("question parses");
        assert_eq!(name, "www.bench.test.");
        assert_eq!(qtype, RecordType::AAAA);
        assert_eq!(end, wire.len());
    }

    #[test]
    fn parse_question_rejects_a_compressed_owner() {
        let mut wire = vec![0u8; 12];
        wire.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
        assert!(parse_question(&wire).is_none());
    }

    #[test]
    fn signed_answers_verify_with_the_generated_dnskey() {
        let signer = Signer::new("bench.test.");
        let qname = Name::from_ascii("n00000.bench.test.").expect("test name");
        let records = signer.a_records(&qname, 0);
        let rrset: Vec<Record> = records
            .iter()
            .filter(|record| record.record_type() == RecordType::A)
            .cloned()
            .collect();
        let signatures: Vec<Record> = records
            .iter()
            .filter(|record| record.record_type() == RecordType::RRSIG)
            .cloned()
            .collect();
        dns_dnssec::verify_rrset(
            &rrset,
            &signatures,
            &[signer.dnskey_record()],
            u64::from(signer.now),
        )
        .expect("generated signature verifies");
    }

    #[test]
    fn response_echoes_the_query_case_without_breaking_the_signature() {
        let signer = Signer::new("bench.test.");
        let qname = Name::from_ascii("n00000.bench.test.").expect("test name");
        let records = signer.a_records(&qname, 0);
        let template = signer.template(&qname, RecordType::A, records);
        let query = encoded_query("N00000.BENCH.TEST.", RecordType::A);
        let (_, _, question_end) = parse_question(&query).expect("query parses");

        let mut response = Vec::new();
        build_response(&mut response, &query, question_end, &template);
        let message = decode(&response).expect("response decodes");
        assert_eq!(message.queries[0].name.to_ascii(), "N00000.BENCH.TEST.");

        let rrset: Vec<Record> = message
            .answers
            .iter()
            .filter(|record| record.record_type() == RecordType::A)
            .cloned()
            .collect();
        let signatures: Vec<Record> = message
            .answers
            .iter()
            .filter(|record| record.record_type() == RecordType::RRSIG)
            .cloned()
            .collect();
        dns_dnssec::verify_rrset(
            &rrset,
            &signatures,
            &[signer.dnskey_record()],
            u64::from(signer.now),
        )
        .expect("case-patched response still verifies");
    }
}
