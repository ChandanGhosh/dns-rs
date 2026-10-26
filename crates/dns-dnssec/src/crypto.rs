//! DNSSEC cryptographic primitives and RRset verification.
//!
//! Wire parsing and the canonical "to be signed" serialization come from
//! `hickory-proto` through the `dns-proto` facade. Signature and digest
//! verification use `ring` directly so the supported algorithm set and the
//! failure classification stay under our control.

use dns_proto::{
    Algorithm, DNSKEY, DNSSECRData, DS, DigestType, NSEC, NSEC3, Name, PublicKey, RData, RRSIG,
    Record, RecordType, TBS,
};
use ring::signature::{
    self, RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY, RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
    RsaPublicKeyComponents, UnparsedPublicKey,
};

use crate::DnssecError;

/// Extract the DNSKEY rdata from a record.
pub fn dnskey_of(record: &Record) -> Option<&DNSKEY> {
    match &record.data {
        RData::DNSSEC(DNSSECRData::DNSKEY(key)) => Some(key),
        _ => None,
    }
}

/// Extract the DS rdata from a record.
pub fn ds_of(record: &Record) -> Option<&DS> {
    match &record.data {
        RData::DNSSEC(DNSSECRData::DS(ds)) => Some(ds),
        _ => None,
    }
}

/// Extract the RRSIG rdata from a record.
pub fn rrsig_of(record: &Record) -> Option<&RRSIG> {
    match &record.data {
        RData::DNSSEC(DNSSECRData::RRSIG(sig)) => Some(sig),
        _ => None,
    }
}

/// Extract the NSEC rdata from a record.
pub fn nsec_of(record: &Record) -> Option<&NSEC> {
    match &record.data {
        RData::DNSSEC(DNSSECRData::NSEC(nsec)) => Some(nsec),
        _ => None,
    }
}

/// Extract the NSEC3 rdata from a record.
pub fn nsec3_of(record: &Record) -> Option<&NSEC3> {
    match &record.data {
        RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) => Some(nsec3),
        _ => None,
    }
}

/// Whether two DNSKEY rdata values are the same key.
pub fn same_key(left: &DNSKEY, right: &DNSKEY) -> bool {
    left.flags() == right.flags()
        && left.public_key().algorithm() == right.public_key().algorithm()
        && left.public_key().public_bytes() == right.public_key().public_bytes()
}

/// Whether a DS record covers a DNSKEY at `zone`.
pub fn ds_matches_key(ds: &DS, zone: &Name, key: &DNSKEY) -> bool {
    if !key.zone_key() {
        return false;
    }
    if ds.algorithm() != key.public_key().algorithm() {
        return false;
    }
    if key.calculate_key_tag().ok() != Some(ds.key_tag()) {
        return false;
    }
    let Ok(digest) = key.to_digest(zone, ds.digest_type()) else {
        return false;
    };
    digest.as_ref() == ds.digest()
}

/// Verify one RRSIG over an RRset using a DNSKEY record.
///
/// `rrset` must contain only records with the same owner name, type and class.
/// `now` is Unix time in seconds.
pub fn verify_rrsig(
    rrset: &[Record],
    rrsig_record: &Record,
    dnskey_record: &Record,
    now: u64,
) -> Result<(), DnssecError> {
    let Some(rrsig) = rrsig_of(rrsig_record) else {
        return Err(DnssecError::Malformed);
    };
    let Some(key) = dnskey_of(dnskey_record) else {
        return Err(DnssecError::Malformed);
    };
    let Some(first) = rrset.first() else {
        return Err(DnssecError::Malformed);
    };
    if rrset
        .iter()
        .any(|record| record.name != first.name || record.record_type() != first.record_type())
    {
        return Err(DnssecError::Malformed);
    }

    // The RRSIG owner is the RRset owner; the signer name is the zone apex and
    // must also be the DNSKEY owner.
    if rrsig_record.name != first.name || dnskey_record.name != rrsig.input().signer_name {
        return Err(DnssecError::Malformed);
    }
    if !rrsig.input().signer_name.zone_of(&first.name) {
        return Err(DnssecError::Malformed);
    }
    if rrsig.input().type_covered != first.record_type() {
        return Err(DnssecError::Malformed);
    }
    if !key.zone_key() {
        return Err(DnssecError::InvalidKey);
    }
    if key.public_key().algorithm() != rrsig.input().algorithm {
        return Err(DnssecError::KeyTagMismatch);
    }
    if key.calculate_key_tag().ok() != Some(rrsig.input().key_tag) {
        return Err(DnssecError::KeyTagMismatch);
    }

    check_validity(
        rrsig.input().sig_inception.get(),
        rrsig.input().sig_expiration.get(),
        now,
    )?;

    let tbs = TBS::from_input(&first.name, first.dns_class, rrsig.input(), rrset.iter())
        .map_err(|_| DnssecError::Malformed)?;

    verify_signature(
        key.public_key().algorithm(),
        key.public_key().public_bytes(),
        tbs.as_ref(),
        rrsig.sig(),
    )
}

/// Verify that at least one RRSIG over `rrset` validates with one of `keys`.
pub fn verify_rrset(
    rrset: &[Record],
    rrsigs: &[Record],
    keys: &[Record],
    now: u64,
) -> Result<(), DnssecError> {
    let Some(first) = rrset.first() else {
        return Err(DnssecError::Malformed);
    };
    let qtype = first.record_type();
    let mut saw_signature = false;
    let mut last_error = DnssecError::MissingKey;

    for signature_record in rrsigs {
        let Some(signature) = rrsig_of(signature_record) else {
            continue;
        };
        if signature.input().type_covered != qtype {
            continue;
        }
        saw_signature = true;

        for key_record in keys {
            let Some(key) = dnskey_of(key_record) else {
                continue;
            };
            if key_record.name != signature.input().signer_name {
                continue;
            }
            if key.public_key().algorithm() != signature.input().algorithm {
                continue;
            }
            if key.calculate_key_tag().ok() != Some(signature.input().key_tag) {
                continue;
            }
            match verify_rrsig(rrset, signature_record, key_record, now) {
                Ok(()) => return Ok(()),
                Err(error) => last_error = error,
            }
        }
    }

    if saw_signature {
        Err(last_error)
    } else {
        Err(DnssecError::MissingSignature)
    }
}

/// Validate a DNSKEY RRset against a DS set from the parent zone.
///
/// A DS must match one of the DNSKEYs, and that key must sign the DNSKEY RRset.
pub fn verify_dnskey_with_ds(
    zone: &Name,
    keys: &[Record],
    rrsigs: &[Record],
    ds_records: &[Record],
    now: u64,
) -> Result<(), DnssecError> {
    let mut saw_ds = false;
    let mut last_error = DnssecError::MissingKey;
    for ds_record in ds_records {
        let Some(ds) = ds_of(ds_record) else {
            continue;
        };
        saw_ds = true;
        for key_record in keys {
            let Some(key) = dnskey_of(key_record) else {
                continue;
            };
            if key_record.name != *zone || !ds_matches_key(ds, zone, key) {
                continue;
            }
            match verify_rrset(keys, rrsigs, std::slice::from_ref(key_record), now) {
                Ok(()) => return Ok(()),
                Err(error) => last_error = error,
            }
        }
    }

    if saw_ds {
        Err(last_error)
    } else {
        Err(DnssecError::MissingKey)
    }
}

/// Validate a DNSKEY RRset against configured DNSKEY trust anchors.
pub fn verify_dnskey_with_anchor(
    zone: &Name,
    keys: &[Record],
    rrsigs: &[Record],
    anchors: &[Record],
    now: u64,
) -> Result<(), DnssecError> {
    let mut last_error = DnssecError::MissingKey;
    for anchor_record in anchors {
        let Some(anchor) = dnskey_of(anchor_record) else {
            continue;
        };
        if anchor_record.name != *zone {
            continue;
        }
        for key_record in keys {
            let Some(key) = dnskey_of(key_record) else {
                continue;
            };
            if !same_key(anchor, key) {
                continue;
            }
            match verify_rrset(keys, rrsigs, std::slice::from_ref(key_record), now) {
                Ok(()) => return Ok(()),
                Err(error) => last_error = error,
            }
        }
    }

    Err(last_error)
}

/// Check RRSIG inception/expiration using RFC 1982 serial arithmetic.
pub fn check_validity(inception: u32, expiration: u32, now: u64) -> Result<(), DnssecError> {
    let now = now as u32;
    if !serial_le(inception, now) {
        return Err(DnssecError::NotYetValid);
    }
    if !serial_le(now, expiration) {
        return Err(DnssecError::Expired);
    }
    Ok(())
}

fn serial_le(left: u32, right: u32) -> bool {
    right.wrapping_sub(left) < 0x8000_0000
}

/// Verify a signature with a raw DNSKEY public key.
pub fn verify_signature(
    algorithm: Algorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), DnssecError> {
    match algorithm {
        Algorithm::ED25519 => {
            let key = UnparsedPublicKey::new(&signature::ED25519, public_key);
            key.verify(message, signature)
                .map_err(|_| DnssecError::BadSignature)
        }
        Algorithm::ECDSAP256SHA256 => verify_ecdsa(
            &signature::ECDSA_P256_SHA256_FIXED,
            public_key,
            message,
            signature,
        ),
        Algorithm::ECDSAP384SHA384 => verify_ecdsa(
            &signature::ECDSA_P384_SHA384_FIXED,
            public_key,
            message,
            signature,
        ),
        Algorithm::RSASHA256 => verify_rsa(
            &RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
            public_key,
            message,
            signature,
        ),
        Algorithm::RSASHA512 => verify_rsa(
            &RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
            public_key,
            message,
            signature,
        ),
        // SHA-1 verification is retained for interoperability with legacy
        // signed zones. New deployments should not use these algorithms.
        #[allow(deprecated)]
        Algorithm::RSASHA1 | Algorithm::RSASHA1NSEC3SHA1 => verify_rsa(
            &RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
            public_key,
            message,
            signature,
        ),
        _ => Err(DnssecError::UnsupportedAlgorithm),
    }
}

/// Whether we can verify signatures made with `algorithm`.
pub fn algorithm_supported(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::ED25519
            | Algorithm::ECDSAP256SHA256
            | Algorithm::ECDSAP384SHA384
            | Algorithm::RSASHA256
            | Algorithm::RSASHA512
    ) || {
        #[allow(deprecated)]
        {
            matches!(algorithm, Algorithm::RSASHA1 | Algorithm::RSASHA1NSEC3SHA1)
        }
    }
}

fn verify_ecdsa(
    parameters: &'static signature::EcdsaVerificationAlgorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), DnssecError> {
    // DNSKEY stores the raw X || Y coordinates; ring wants the SEC1
    // uncompressed point prefix.
    let mut encoded = Vec::with_capacity(public_key.len() + 1);
    encoded.push(0x04);
    encoded.extend_from_slice(public_key);
    UnparsedPublicKey::new(parameters, encoded)
        .verify(message, signature)
        .map_err(|_| DnssecError::BadSignature)
}

fn verify_rsa(
    parameters: &'static signature::RsaParameters,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), DnssecError> {
    let (modulus, exponent) = rsa_components(public_key)?;
    let components = RsaPublicKeyComponents {
        n: modulus,
        e: exponent,
    };
    components
        .verify(parameters, message, signature)
        .map_err(|_| DnssecError::BadSignature)
}

/// Split a DNSKEY RSA public key into `(modulus, exponent)` (RFC 3110).
pub fn rsa_components(public_key: &[u8]) -> Result<(&[u8], &[u8]), DnssecError> {
    let Some(&first) = public_key.first() else {
        return Err(DnssecError::InvalidKey);
    };
    let (exponent_len, offset) = if first == 0 {
        if public_key.len() < 3 {
            return Err(DnssecError::InvalidKey);
        }
        let length = usize::from(u16::from_be_bytes([public_key[1], public_key[2]]));
        (length, 3)
    } else {
        (usize::from(first), 1)
    };
    if exponent_len == 0 || public_key.len() <= offset + exponent_len {
        return Err(DnssecError::InvalidKey);
    }
    let exponent = &public_key[offset..offset + exponent_len];
    let modulus = &public_key[offset + exponent_len..];
    if modulus.is_empty() {
        return Err(DnssecError::InvalidKey);
    }
    Ok((modulus, exponent))
}

/// Whether a record type is DNSSEC metadata that should not be cached as data.
pub fn is_dnssec_type(record_type: RecordType) -> bool {
    record_type.is_dnssec()
}

/// Digest types we can compute.
pub fn digest_supported(digest: DigestType) -> bool {
    matches!(
        digest,
        DigestType::SHA1 | DigestType::SHA256 | DigestType::SHA384
    )
}

#[cfg(test)]
mod tests {
    use dns_proto::{
        Algorithm, DNSKEY, DNSSECRData, DigestType, Name, PublicKeyBuf, RData, RRSIG, Record,
        RecordType, SerialNumber, SigInput, TBS,
    };
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair};

    use super::{
        algorithm_supported, check_validity, ds_matches_key, verify_rrset, verify_rrsig,
        verify_signature,
    };
    use crate::DnssecError;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).expect("valid name")
    }

    fn dnskey_record(owner: &str, key: &DNSKEY) -> Record {
        Record::from_rdata(
            name(owner),
            3600,
            RData::DNSSEC(DNSSECRData::DNSKEY(key.clone())),
        )
    }

    fn a_record(owner: &str, address: [u8; 4]) -> Record {
        Record::from_rdata(
            name(owner),
            300,
            RData::A(std::net::Ipv4Addr::from(address).into()),
        )
    }

    fn sig_input(
        type_covered: RecordType,
        algorithm: Algorithm,
        key_tag: u16,
        signer: &str,
        now: u32,
    ) -> SigInput {
        SigInput {
            type_covered,
            algorithm,
            num_labels: 3,
            original_ttl: 300,
            sig_expiration: SerialNumber::from(now + 3600),
            sig_inception: SerialNumber::from(now - 60),
            key_tag,
            signer_name: name(signer),
        }
    }

    #[test]
    fn ed25519_rrsig_round_trip() {
        let random = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).expect("generate key");
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse key");

        let key = DNSKEY::with_flags(
            257,
            PublicKeyBuf::new(pair.public_key().as_ref().to_vec(), Algorithm::ED25519),
        );
        let key_record = dnskey_record("example.com.", &key);
        let tag = key.calculate_key_tag().expect("key tag");

        let rrset = vec![a_record("www.example.com.", [192, 0, 2, 1])];
        let input = sig_input(
            RecordType::A,
            Algorithm::ED25519,
            tag,
            "example.com.",
            1_700_000_000,
        );
        let tbs = TBS::from_input(
            &name("www.example.com."),
            dns_proto::DNSClass::IN,
            &input,
            rrset.iter(),
        )
        .expect("tbs");
        let signature = pair.sign(tbs.as_ref());
        let rrsig = RRSIG::from_sig(input, signature.as_ref().to_vec());
        let sig_record = Record::from_rdata(
            name("www.example.com."),
            300,
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
        );

        verify_rrsig(&rrset, &sig_record, &key_record, 1_700_000_000).expect("signature verifies");
        verify_rrset(
            &rrset,
            std::slice::from_ref(&sig_record),
            std::slice::from_ref(&key_record),
            1_700_000_000,
        )
        .expect("rrset verifies");

        let mut modified = rrset.clone();
        modified[0] = a_record("www.example.com.", [192, 0, 2, 2]);
        assert!(verify_rrsig(&modified, &sig_record, &key_record, 1_700_000_000).is_err());
    }

    #[test]
    fn ecdsa_p256_rrsig_round_trip() {
        let random = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random)
            .expect("generate key");
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &random)
                .expect("parse key");
        // DNSKEY stores X || Y without the 0x04 SEC1 prefix.
        let public = &pair.public_key().as_ref()[1..];

        let key = DNSKEY::with_flags(
            257,
            PublicKeyBuf::new(public.to_vec(), Algorithm::ECDSAP256SHA256),
        );
        let key_record = dnskey_record("example.com.", &key);
        let tag = key.calculate_key_tag().expect("key tag");

        let rrset = vec![a_record("www.example.com.", [192, 0, 2, 1])];
        let input = sig_input(
            RecordType::A,
            Algorithm::ECDSAP256SHA256,
            tag,
            "example.com.",
            1_700_000_000,
        );
        let tbs = TBS::from_input(
            &name("www.example.com."),
            dns_proto::DNSClass::IN,
            &input,
            rrset.iter(),
        )
        .expect("tbs");
        let signature = pair.sign(&random, tbs.as_ref()).expect("sign");
        let rrsig = RRSIG::from_sig(input, signature.as_ref().to_vec());
        let sig_record = Record::from_rdata(
            name("www.example.com."),
            300,
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
        );

        verify_rrsig(&rrset, &sig_record, &key_record, 1_700_000_000).expect("signature verifies");
    }

    #[test]
    fn rejects_expired_and_future_signatures() {
        assert!(matches!(
            check_validity(100, 200, 250),
            Err(DnssecError::Expired)
        ));
        assert!(matches!(
            check_validity(300, 400, 250),
            Err(DnssecError::NotYetValid)
        ));
        check_validity(100, 200, 150).expect("valid");
    }

    #[test]
    fn serial_arithmetic_wraps() {
        // A signature that expires just after the 32-bit wrap.
        check_validity(u32::MAX - 100, 100, 50).expect("valid across wrap");
        check_validity(u32::MAX - 100, 100, 200).expect_err("expired after wrap");
    }

    #[test]
    fn ds_covers_matching_key() {
        let random = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).expect("generate key");
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse key");
        let key = DNSKEY::with_flags(
            257,
            PublicKeyBuf::new(pair.public_key().as_ref().to_vec(), Algorithm::ED25519),
        );
        let zone = name("example.com.");
        let ds = dns_proto::DS::new(
            key.calculate_key_tag().expect("tag"),
            Algorithm::ED25519,
            DigestType::SHA256,
            key.to_digest(&zone, DigestType::SHA256)
                .expect("digest")
                .as_ref()
                .to_vec(),
        );
        assert!(ds_matches_key(&ds, &zone, &key));

        let other = name("other.example.");
        assert!(!ds_matches_key(&ds, &other, &key));
    }

    #[test]
    fn unsupported_algorithms_are_reported() {
        assert!(algorithm_supported(Algorithm::RSASHA256));
        assert!(algorithm_supported(Algorithm::ECDSAP384SHA384));
        assert!(!algorithm_supported(Algorithm::Unknown(253)));
        assert!(matches!(
            verify_signature(Algorithm::Unknown(253), &[], b"", &[]),
            Err(DnssecError::UnsupportedAlgorithm)
        ));
    }

    #[test]
    fn rsa_sha256_signature_verifies() {
        // Deterministic 2048-bit RSA/SHA-256 PKCS#1 v1.5 vector.
        let modulus = data_encoding::HEXLOWER
            .decode(
                b"bca35dd8b81f02ab772dcb86effc8cde8a93ac5fb9625f5576f626dd1491c6658fa932b6a7f599bbc6a1c98ad72c933ff8ead10117ef0ea9f7ce6af1827e0202689efd24e5ceb923b5c3ff3e0d302655d78bbe342697e844353c189df9701988ac8f3d587ca5e201b6b6b9f798cddbdf66ffa6ca079a4433fa815f996eeec82b93055e5d43ab38996e9f405599d1b6f28103d58c8ffc46b8f9ab779db9ccb62648f700ab62ec9e0fcc1a79453d02f665d55c7b0b598c8809250e43d8fd261fe4f6a978f901cf7bfbfe7fb005d930fc2e770776f569b66dcafd679ac4f6257dc88b8f2024e24de8c14bddc73b351a64ee26178a58db2e049ca97289fed0277327",
            )
            .expect("modulus hex");
        let signature = data_encoding::HEXLOWER
            .decode(
                b"6e481c60a65546c64a5d96e0a26d99a313d40ad267de4c84383869a5064dc460cc821d4d188015eed4b8a4e8ae5d4905559bf482fa56d116463e4c96abbd9d5128ddd66c88830a3eab05bc1bd5e629ee9fd11af3874d492795c0acebff1f31a68b8098e5e72e836a093afe04824894efdd6852a11250cf56e85c10cc9c1e951e0d7a4d4a36fe60a1f426b3caa5691a8b4891d55a2875d947c15766ea3fddc28f24ae3e16b1777ef627c7bd3fb95e727e4d0d1854533ed68b1f18de433237a3ec6ce16ed1666db72b88c18aaf40890d42a5824947b735025f77567171552e51b40e93ae40a6996a93256da23e7652885995c0b317feb6273791597eb0ff44b95f",
            )
            .expect("signature hex");

        // RFC 3110 form: one-byte exponent length followed by 65537.
        let mut public_key = vec![3, 1, 0, 1];
        public_key.extend_from_slice(&modulus);

        verify_signature(
            Algorithm::RSASHA256,
            &public_key,
            b"dns-rs rsa test vector",
            &signature,
        )
        .expect("RSA signature verifies");

        assert!(
            verify_signature(
                Algorithm::RSASHA256,
                &public_key,
                b"dns-rs rsa test vectoR",
                &signature,
            )
            .is_err()
        );
    }

    #[test]
    fn rsa_components_parses_both_length_forms() {
        let short = [3u8, 1, 0, 1, 0xAA, 0xBB];
        let (modulus, exponent) = super::rsa_components(&short).expect("short exponent");
        assert_eq!(exponent, &[1, 0, 1]);
        assert_eq!(modulus, &[0xAA, 0xBB]);

        let long = [0u8, 0, 3, 1, 0, 1, 0xCC];
        let (modulus, exponent) = super::rsa_components(&long).expect("long exponent");
        assert_eq!(exponent, &[1, 0, 1]);
        assert_eq!(modulus, &[0xCC]);
    }
}
