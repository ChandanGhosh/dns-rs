//! DNSSEC validation.
//!
//! This crate implements the validation half of DNSSEC: trust anchors,
//! DNSKEY/DS chain checks, RRSIG verification, and NSEC/NSEC3 denial proofs.
//! Wire parsing and canonical RRset serialization come from `dns-proto`;
//! cryptographic verification uses `ring`.
//!
//! The resolver owns fetching DNSKEY and DS records. The functions here are
//! deliberately synchronous and side-effect free so they can be tested against
//! hand-built signed zones.

mod autotrust;
mod crypto;
mod denial;
mod trust;
mod validator;

pub use autotrust::{
    ADD_HOLD_DOWN, AutoKey, AutoTrustAnchor, AutoTrustError, DEFAULT_PROBE_INTERVAL,
    DEFAULT_RETRY_TIME, KeyState, REMOVE_HOLD_DOWN, same_key_ignoring_revoke, unix_now,
};
pub use crypto::{
    algorithm_supported, check_validity, digest_supported, dnskey_of, ds_matches_key, ds_of,
    is_dnssec_type, nsec_of, nsec3_of, rrsig_of, rsa_components, same_key,
    verify_dnskey_with_anchor, verify_dnskey_with_ds, verify_rrset, verify_rrsig, verify_signature,
};
pub use denial::{
    nsec_covers, nsec_proves_nodata, nsec3_algorithm_supported, nsec3_covers, nsec3_hash,
    nsec3_owner_hash, nsec3_proves_nodata, wildcard_name,
};
pub use trust::{
    TrustAnchor, TrustAnchorError, TrustStore, load_trust_anchors, parse_trust_anchors,
    root_trust_anchor, root_trust_anchor_keys,
};
pub use validator::{RrsetValidator, ValidationOutcome, dnskey_records, ds_records, is_dnskey};

/// Result of validating a response or RRset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Security {
    /// The data is signed and the chain of trust validates.
    Secure,
    /// The data is unsigned or below an unsigned delegation.
    Insecure,
    /// The data is signed but validation failed.
    Bogus(BogusReason),
}

impl Security {
    /// Whether the data may be returned to a client.
    pub fn is_acceptable(&self) -> bool {
        !matches!(self, Self::Bogus(_))
    }
}

/// Why a response was classified as bogus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BogusReason {
    /// A signature did not verify.
    Signature,
    /// A required DNSKEY or DS record was missing.
    MissingKey,
    /// A required signature was missing.
    MissingSignature,
    /// The DS set did not match any DNSKEY.
    MissingDs,
    /// The signature validity period has passed.
    Expired,
    /// The signature is not valid yet.
    NotYetValid,
    /// The response used an unsupported algorithm or digest.
    UnsupportedAlgorithm,
    /// The denial-of-existence proof was invalid.
    DenialOfExistence,
    /// The record data was malformed.
    Malformed,
    /// The RRSIG key tag did not match the DNSKEY.
    KeyTagMismatch,
}

impl From<DnssecError> for BogusReason {
    fn from(error: DnssecError) -> Self {
        match error {
            DnssecError::BadSignature => Self::Signature,
            DnssecError::MissingKey => Self::MissingKey,
            DnssecError::MissingSignature => Self::MissingSignature,
            DnssecError::Expired => Self::Expired,
            DnssecError::NotYetValid => Self::NotYetValid,
            DnssecError::UnsupportedAlgorithm => Self::UnsupportedAlgorithm,
            DnssecError::DenialOfExistence => Self::DenialOfExistence,
            DnssecError::KeyTagMismatch => Self::KeyTagMismatch,
            DnssecError::InvalidKey | DnssecError::Malformed => Self::Malformed,
        }
    }
}

/// DNSSEC-related failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DnssecError {
    /// The public key is malformed.
    #[error("invalid public key")]
    InvalidKey,

    /// The signature is malformed or does not verify.
    #[error("signature verification failed")]
    BadSignature,

    /// The signature has expired.
    #[error("signature has expired")]
    Expired,

    /// The signature is not valid yet.
    #[error("signature is not yet valid")]
    NotYetValid,

    /// The algorithm or digest is not supported.
    #[error("unsupported DNSSEC algorithm")]
    UnsupportedAlgorithm,

    /// The RRSIG key tag does not match the key.
    #[error("RRSIG key tag does not match the DNSKEY")]
    KeyTagMismatch,

    /// No usable key was found.
    #[error("no matching DNSKEY")]
    MissingKey,

    /// The RRset had no signature.
    #[error("RRset is not signed")]
    MissingSignature,

    /// The record data was malformed.
    #[error("malformed DNSSEC record")]
    Malformed,

    /// A denial-of-existence proof was invalid.
    #[error("invalid denial-of-existence proof")]
    DenialOfExistence,
}

/// Verify an Ed25519 signature.
pub fn verify_ed25519(
    public_key: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), DnssecError> {
    verify_signature(
        dns_proto::Algorithm::ED25519,
        public_key,
        message,
        signature_bytes,
    )
}

#[cfg(test)]
mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::{DnssecError, verify_ed25519};

    #[test]
    fn verifies_ed25519_signatures() {
        let random = SystemRandom::new();
        let key_pair_pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).expect("generate key pair");
        let key_pair = Ed25519KeyPair::from_pkcs8(key_pair_pkcs8.as_ref()).expect("parse key pair");

        let message = b"dns-rs dnssec spike";
        let signature = key_pair.sign(message);

        verify_ed25519(key_pair.public_key().as_ref(), message, signature.as_ref())
            .expect("signature verifies");
    }

    #[test]
    fn rejects_modified_messages() {
        let random = SystemRandom::new();
        let key_pair_pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).expect("generate key pair");
        let key_pair = Ed25519KeyPair::from_pkcs8(key_pair_pkcs8.as_ref()).expect("parse key pair");

        let signature = key_pair.sign(b"original");
        let error = verify_ed25519(
            key_pair.public_key().as_ref(),
            b"modified",
            signature.as_ref(),
        )
        .expect_err("signature must not verify");
        assert!(matches!(error, DnssecError::BadSignature));
    }
}
