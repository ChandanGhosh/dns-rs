//! High-level RRset and delegation validation.

use dns_proto::{DNSKEY, DS, Name, RData, Record};

use crate::crypto::{
    algorithm_supported, digest_supported, dnskey_of, ds_of, verify_dnskey_with_anchor,
    verify_dnskey_with_ds, verify_rrset,
};
use crate::{BogusReason, Security};

/// Outcome of validating one RRset or delegation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationOutcome {
    /// Signed and chained to a trust anchor.
    Secure,
    /// Unsigned, or below an unsigned delegation.
    Insecure,
    /// Signed but invalid.
    Bogus(BogusReason),
}

impl From<ValidationOutcome> for Security {
    fn from(outcome: ValidationOutcome) -> Self {
        match outcome {
            ValidationOutcome::Secure => Self::Secure,
            ValidationOutcome::Insecure => Self::Insecure,
            ValidationOutcome::Bogus(reason) => Self::Bogus(reason),
        }
    }
}

/// Validates RRsets against a set of DNSKEY records at a fixed time.
#[derive(Debug, Clone, Copy)]
pub struct RrsetValidator {
    now: u64,
}

impl RrsetValidator {
    /// Create a validator for the given Unix time in seconds.
    pub fn new(now: u64) -> Self {
        Self { now }
    }

    /// Current validation time.
    pub fn now(&self) -> u64 {
        self.now
    }

    /// Verify a signed RRset with the zone's DNSKEY set.
    ///
    /// An RRset without any RRSIG is classified as insecure; callers that know
    /// the zone is signed should treat that as bogus themselves.
    pub fn verify_signed_rrset(
        &self,
        rrset: &[Record],
        rrsigs: &[Record],
        keys: &[Record],
    ) -> ValidationOutcome {
        if rrsigs.is_empty() {
            return ValidationOutcome::Insecure;
        }
        match verify_rrset(rrset, rrsigs, keys, self.now) {
            Ok(()) => ValidationOutcome::Secure,
            Err(error) => ValidationOutcome::Bogus(error.into()),
        }
    }

    /// Verify a DNSKEY RRset against a DS set from the parent.
    ///
    /// An empty DS set means the delegation is unsigned, so the child zone is
    /// insecure. If the DS set only names unsupported algorithms or digests,
    /// the zone is also treated as insecure, matching RFC 4035 §5.2.
    pub fn verify_dnskey_with_ds(
        &self,
        zone: &Name,
        keys: &[Record],
        rrsigs: &[Record],
        ds_records: &[Record],
    ) -> ValidationOutcome {
        let ds: Vec<&DS> = ds_records.iter().filter_map(ds_of).collect();
        if ds.is_empty() {
            return ValidationOutcome::Insecure;
        }
        if !ds
            .iter()
            .any(|ds| algorithm_supported(ds.algorithm()) && digest_supported(ds.digest_type()))
        {
            return ValidationOutcome::Insecure;
        }
        match verify_dnskey_with_ds(zone, keys, rrsigs, ds_records, self.now) {
            Ok(()) => ValidationOutcome::Secure,
            Err(error) => ValidationOutcome::Bogus(error.into()),
        }
    }

    /// Verify a DNSKEY RRset against configured DNSKEY trust anchors.
    pub fn verify_dnskey_with_anchor(
        &self,
        zone: &Name,
        keys: &[Record],
        rrsigs: &[Record],
        anchors: &[Record],
    ) -> ValidationOutcome {
        match verify_dnskey_with_anchor(zone, keys, rrsigs, anchors, self.now) {
            Ok(()) => ValidationOutcome::Secure,
            Err(error) => ValidationOutcome::Bogus(error.into()),
        }
    }

    /// Whether a DNSKEY RRset contains a key covered by any DS.
    pub fn dnskey_matches_ds(&self, zone: &Name, keys: &[Record], ds_records: &[Record]) -> bool {
        let ds: Vec<&DS> = ds_records.iter().filter_map(ds_of).collect();
        keys.iter().filter_map(dnskey_of).any(|key| {
            ds.iter()
                .any(|ds| crate::crypto::ds_matches_key(ds, zone, key))
        })
    }
}

/// Extract DNSKEY rdata from records.
pub fn dnskey_records(records: &[Record]) -> Vec<&DNSKEY> {
    records.iter().filter_map(dnskey_of).collect()
}

/// Extract DS rdata from records.
pub fn ds_records(records: &[Record]) -> Vec<&DS> {
    records.iter().filter_map(ds_of).collect()
}

/// Whether a record is a DNSKEY.
pub fn is_dnskey(record: &Record) -> bool {
    matches!(
        record.data,
        RData::DNSSEC(dns_proto::DNSSECRData::DNSKEY(_))
    )
}
