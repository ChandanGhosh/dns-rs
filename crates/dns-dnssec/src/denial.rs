//! NSEC and NSEC3 denial-of-existence proofs.

use data_encoding::BASE32HEX_NOPAD;
use dns_proto::{NSEC, NSEC3, Name, Nsec3HashAlgorithm, Record, RecordType};
use sha1::{Digest, Sha1};

use crate::DnssecError;

/// Default maximum NSEC3 iteration count accepted by a validator.
///
/// RFC 9276 section 3.2 recommends that validators treat responses with more
/// iterations as bogus. 150 matches Unbound's `nsec3-max-iterations` default.
pub const MAX_NSEC3_ITERATIONS: u16 = 150;

/// Whether `name` falls strictly between an NSEC owner and its next name.
pub fn nsec_covers(owner: &Name, next: &Name, name: &Name) -> bool {
    if owner == next {
        // A single NSEC in the zone covers every name except its owner.
        return name != owner;
    }
    if owner < next {
        owner < name && name < next
    } else {
        // The last NSEC wraps around to the apex.
        name > owner || name < next
    }
}

/// Whether an NSEC proves that `qtype` does not exist at its owner.
pub fn nsec_proves_nodata(nsec: &NSEC, qtype: RecordType) -> bool {
    let types: Vec<RecordType> = nsec.type_bit_maps().collect();
    if types.contains(&qtype) {
        return false;
    }
    // A CNAME at the owner would have been followed instead of returning
    // NODATA, unless the query was for CNAME itself.
    qtype == RecordType::CNAME || !types.contains(&RecordType::CNAME)
}

/// Compute the NSEC3 hash of a name (RFC 5155 §5).
///
/// Only SHA-1 is defined, so the caller should check the record's algorithm.
///
/// Returns [`DnssecError::IterationLimit`] when `iterations` exceeds
/// `max_iterations`. The check happens before any hashing so a hostile zone
/// cannot force unbounded CPU work.
pub fn nsec3_hash(
    name: &Name,
    iterations: u16,
    salt: &[u8],
    max_iterations: u16,
) -> Result<Vec<u8>, DnssecError> {
    if iterations > max_iterations {
        return Err(DnssecError::IterationLimit);
    }
    let wire = canonical_wire(name);
    let mut input = wire;
    input.extend_from_slice(salt);
    let mut digest = Sha1::digest(&input).to_vec();
    for _ in 0..iterations {
        let mut input = digest;
        input.extend_from_slice(salt);
        digest = Sha1::digest(&input).to_vec();
    }
    Ok(digest)
}

/// Decode the hashed owner name from an NSEC3 record's first label.
pub fn nsec3_owner_hash(record: &Record) -> Option<Vec<u8>> {
    let label = record.name.iter().next()?;
    BASE32HEX_NOPAD.decode(&label.to_ascii_uppercase()).ok()
}

/// Whether a hash falls strictly between an NSEC3 owner hash and its next hash.
pub fn nsec3_covers(owner_hash: &[u8], next_hash: &[u8], hash: &[u8]) -> bool {
    if owner_hash == next_hash {
        return hash != owner_hash;
    }
    if owner_hash < next_hash {
        owner_hash < hash && hash < next_hash
    } else {
        hash > owner_hash || hash < next_hash
    }
}

/// Whether an NSEC3 proves that `qtype` does not exist at its owner.
pub fn nsec3_proves_nodata(nsec3: &NSEC3, qtype: RecordType) -> bool {
    let types: Vec<RecordType> = nsec3.type_bit_maps().collect();
    if types.contains(&qtype) {
        return false;
    }
    qtype == RecordType::CNAME || !types.contains(&RecordType::CNAME)
}

/// Build the wildcard name for a closest encloser.
pub fn wildcard_name(closest_encloser: &Name) -> Option<Name> {
    Name::from_ascii(format!("*.{}", closest_encloser.to_ascii())).ok()
}

/// Whether an NSEC3 record's hash algorithm is one we implement.
pub fn nsec3_algorithm_supported(nsec3: &NSEC3) -> bool {
    matches!(nsec3.hash_algorithm(), Nsec3HashAlgorithm::SHA1)
}

/// Canonical, uncompressed, lowercase wire form of a name.
fn canonical_wire(name: &Name) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.iter() {
        out.push(label.len() as u8);
        out.extend(label.iter().map(u8::to_ascii_lowercase));
    }
    out.push(0);
    out
}

#[cfg(test)]
mod tests {
    use dns_proto::{NSEC, NSEC3, Name, Record, RecordType};

    use super::{
        MAX_NSEC3_ITERATIONS, nsec_covers, nsec_proves_nodata, nsec3_covers, nsec3_hash,
        nsec3_owner_hash, nsec3_proves_nodata, wildcard_name,
    };

    fn name(text: &str) -> Name {
        Name::from_ascii(text).expect("valid name")
    }

    fn nsec(_owner: &str, next: &str, types: &[RecordType]) -> NSEC {
        NSEC::new(name(next), types.to_vec())
    }

    #[test]
    fn nsec_covering_handles_wraparound() {
        assert!(nsec_covers(
            &name("a.example."),
            &name("c.example."),
            &name("b.example.")
        ));
        assert!(!nsec_covers(
            &name("a.example."),
            &name("c.example."),
            &name("d.example.")
        ));
        // Last NSEC in the zone wraps back to the apex.
        assert!(nsec_covers(
            &name("z.example."),
            &name("example."),
            &name("zz.example.")
        ));
        // Names between the apex and the last owner are not covered by the
        // wraparound NSEC.
        assert!(!nsec_covers(
            &name("z.example."),
            &name("example."),
            &name("a.example.")
        ));
        assert!(!nsec_covers(
            &name("z.example."),
            &name("example."),
            &name("example.")
        ));
    }

    #[test]
    fn nsec_nodata_respects_type_bitmap() {
        let record = nsec("www.example.", "zzz.example.", &[RecordType::A]);
        assert!(nsec_proves_nodata(&record, RecordType::AAAA));
        assert!(!nsec_proves_nodata(&record, RecordType::A));

        let cname = nsec("www.example.", "zzz.example.", &[RecordType::CNAME]);
        // A CNAME owner answers A/AAAA by chasing, so it is not NODATA.
        assert!(!nsec_proves_nodata(&cname, RecordType::AAAA));
        assert!(!nsec_proves_nodata(&cname, RecordType::A));
    }

    #[test]
    fn nsec3_hash_matches_rfc5155_vectors() {
        let salt = [0xaa, 0xbb, 0xcc, 0xdd];
        let expected = [
            ("example.", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"),
            ("a.example.", "35mthgpgcu1qg68fab165klnsnk3dpvl"),
            ("ai.example.", "gjeqe526plbf1g8mklp59enfd789njgi"),
            ("ns1.example.", "2t7b4g4vsa5smi47k61mv5bv1a22bojr"),
            ("*.example.", "jhsv97rodsnhc4f1ke4jh23egaa5agvp"),
        ];
        for (input, encoded) in expected {
            let hash = nsec3_hash(&name(input), 12, &salt, MAX_NSEC3_ITERATIONS)
                .expect("hash within limit");
            assert_eq!(
                data_encoding::BASE32HEX_NOPAD
                    .encode(&hash)
                    .to_ascii_lowercase(),
                encoded,
                "hash for {input}"
            );
        }
    }

    #[test]
    fn nsec3_hash_rejects_excessive_iterations_before_hashing() {
        let name = name("a.example.");
        // One above the limit must fail; the limit itself must succeed.
        assert_eq!(
            nsec3_hash(
                &name,
                MAX_NSEC3_ITERATIONS + 1,
                &[0xaa],
                MAX_NSEC3_ITERATIONS
            ),
            Err(crate::DnssecError::IterationLimit)
        );
        assert!(nsec3_hash(&name, MAX_NSEC3_ITERATIONS, &[0xaa], MAX_NSEC3_ITERATIONS).is_ok());
        // The u16 maximum is rejected outright.
        assert_eq!(
            nsec3_hash(&name, u16::MAX, &[0xaa], MAX_NSEC3_ITERATIONS),
            Err(crate::DnssecError::IterationLimit)
        );
    }

    #[test]
    fn nsec3_covering_handles_wraparound() {
        assert!(nsec3_covers(&[0x10], &[0x20], &[0x18]));
        assert!(!nsec3_covers(&[0x10], &[0x20], &[0x30]));
        assert!(nsec3_covers(&[0xF0], &[0x10], &[0x05]));
        assert!(nsec3_covers(&[0xF0], &[0x10], &[0xF5]));
    }

    #[test]
    fn nsec3_owner_hash_decodes_first_label() {
        let hash = nsec3_hash(
            &name("a.example."),
            12,
            &[0xaa, 0xbb, 0xcc, 0xdd],
            MAX_NSEC3_ITERATIONS,
        )
        .expect("hash within limit");
        let encoded = data_encoding::BASE32HEX_NOPAD.encode(&hash);
        let record = Record::from_rdata(
            name(&format!("{encoded}.example.")),
            300,
            dns_proto::RData::DNSSEC(dns_proto::DNSSECRData::NSEC3(NSEC3::new(
                dns_proto::Nsec3HashAlgorithm::SHA1,
                false,
                12,
                vec![0xaa, 0xbb, 0xcc, 0xdd],
                vec![0x01],
                vec![RecordType::A],
            ))),
        );
        assert_eq!(nsec3_owner_hash(&record).expect("decodes"), hash);
    }

    #[test]
    fn nsec3_nodata_respects_type_bitmap() {
        let record = NSEC3::new(
            dns_proto::Nsec3HashAlgorithm::SHA1,
            false,
            0,
            Vec::new(),
            vec![0x01],
            vec![RecordType::A],
        );
        assert!(nsec3_proves_nodata(&record, RecordType::AAAA));
        assert!(!nsec3_proves_nodata(&record, RecordType::A));
    }

    #[test]
    fn wildcard_name_prefixes_a_label() {
        assert_eq!(
            wildcard_name(&name("example.")).expect("wildcard"),
            name("*.example.")
        );
    }
}
