//! DNSSEC validation on top of the iterative walk.
//!
//! The validator fetches DNSKEY and DS records through the same iterator. The
//! fetches set DO and are marked `validating`, so they never recurse back into
//! validation. Positive answers are validated RRset by RRset; negative answers
//! are checked against NSEC or NSEC3 denial proofs.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dns_dnssec::{
    BogusReason, DnssecError, Security, TrustAnchor, nsec_covers, nsec_proves_nodata,
    nsec3_algorithm_supported, nsec3_covers, nsec3_hash, nsec3_owner_hash, nsec3_proves_nodata,
    rrsig_of, same_key_ignoring_revoke, verify_dnskey_with_anchor, verify_dnskey_with_ds,
    verify_rrset, wildcard_name,
};
use dns_proto::{Message, Name, RData, Record, RecordType, ResponseCode};

use crate::ResolveError;
use crate::iterator::{Budget, IteratorResolver, WalkContext};

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_QUERY_BUDGET: u32 = 64;

/// Flags that affect one client-facing resolution.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResolveOptions {
    /// Return DNSSEC records to the client (EDNS DO bit).
    pub dnssec_ok: bool,
    /// The client asked us to skip validation (CD bit).
    pub checking_disabled: bool,
}

/// A resolved message together with its validation status.
#[derive(Clone, Debug)]
pub struct Resolved {
    /// The response to return to the client.
    pub message: Message,
    /// Whether the response is secure, insecure, or bogus.
    pub security: Security,
}

/// The result of an RFC 5011 DNSKEY probe.
#[derive(Clone, Debug)]
pub struct ProbedDnskeys {
    /// Every DNSKEY in the authenticated RRset.
    pub keys: Vec<Record>,
    /// Keys carrying the REVOKE bit whose own signature covered the RRset.
    pub revoked: Vec<Record>,
}

#[derive(Clone, Debug)]
pub(crate) struct ZoneStatus {
    pub(crate) security: Security,
    pub(crate) keys: Vec<Record>,
}

impl ZoneStatus {
    fn secure(keys: Vec<Record>) -> Self {
        Self {
            security: Security::Secure,
            keys,
        }
    }

    fn insecure() -> Self {
        Self {
            security: Security::Insecure,
            keys: Vec::new(),
        }
    }

    fn bogus(reason: BogusReason) -> Self {
        Self {
            security: Security::Bogus(reason),
            keys: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
struct CachedZone {
    status: ZoneStatus,
    expires: Instant,
}

/// Cache of validated zone keys, keyed by zone apex.
#[derive(Default)]
pub(crate) struct ZoneCache {
    entries: HashMap<String, CachedZone>,
    signed: HashMap<String, CachedZone>,
}

impl ZoneCache {
    fn get(&mut self, zone: &Name) -> Option<ZoneStatus> {
        let key = zone.to_ascii().to_ascii_lowercase();
        let entry = self.entries.get(&key)?;
        if entry.expires <= Instant::now() {
            self.entries.remove(&key);
            return None;
        }
        Some(entry.status.clone())
    }

    fn insert(&mut self, zone: &Name, status: ZoneStatus, ttl: Duration) {
        let ttl = ttl.clamp(Duration::from_secs(30), Duration::from_secs(3600));
        self.entries.insert(
            zone.to_ascii().to_ascii_lowercase(),
            CachedZone {
                status,
                expires: Instant::now() + ttl,
            },
        );
    }

    fn get_signed(&mut self, name: &Name) -> Option<Security> {
        let key = name.to_ascii().to_ascii_lowercase();
        let entry = self.signed.get(&key)?;
        if entry.expires <= Instant::now() {
            self.signed.remove(&key);
            return None;
        }
        Some(entry.status.security.clone())
    }

    fn insert_signed(&mut self, name: &Name, security: Security, ttl: Duration) {
        self.signed.insert(
            name.to_ascii().to_ascii_lowercase(),
            CachedZone {
                status: ZoneStatus {
                    security,
                    keys: Vec::new(),
                },
                expires: Instant::now() + ttl,
            },
        );
    }
}

impl IteratorResolver {
    /// Validate a response and classify it as secure, insecure, or bogus.
    pub(crate) async fn validate_message<'a>(
        &'a self,
        message: &Message,
        qtype: RecordType,
        context: &'a WalkContext<'a>,
    ) -> Security {
        match message.metadata.response_code {
            ResponseCode::NoError | ResponseCode::NXDomain => {}
            _ => return Security::Insecure,
        }

        if message.answers.is_empty() || crate::scrub::is_negative(message) {
            return self
                .validate_negative(message, qtype, context.clone())
                .await;
        }

        self.validate_positive(message, context.clone()).await
    }

    /// Fetch a zone's DNSKEY RRset and authenticate it against the current
    /// trust anchor.
    ///
    /// This is used by RFC 5011 maintenance. The returned records are the raw
    /// DNSKEY RRset; the caller runs the autotrust state machine over them.
    pub async fn probe_dnskey(&self, zone: &Name) -> Result<ProbedDnskeys, ResolveError> {
        let deadline = Instant::now() + PROBE_TIMEOUT;
        let ancestors = HashSet::new();
        let context = WalkContext {
            depth: 0,
            ancestors: &ancestors,
            deadline,
            budget: std::sync::Arc::new(Budget::new(PROBE_QUERY_BUDGET)),
            recursion_desired: false,
            dnssec_ok: true,
            validating: true,
            checking_disabled: true,
        };
        let response = self
            .fetch_internal(zone, RecordType::DNSKEY, &context)
            .await?;
        if response.metadata.response_code != ResponseCode::NoError {
            return Err(ResolveError::InvalidResponse(format!(
                "DNSKEY probe for {zone} returned {:?}",
                response.metadata.response_code
            )));
        }

        let keys = records_of(&response.answers, zone, RecordType::DNSKEY);
        let signatures = sigs_for(&response.answers, zone, RecordType::DNSKEY);
        if keys.is_empty() || signatures.is_empty() {
            return Err(ResolveError::InvalidResponse(format!(
                "DNSKEY probe for {zone} returned no signed keys"
            )));
        }

        let anchor =
            self.config.trust_store.anchor_for(zone).ok_or_else(|| {
                ResolveError::InvalidResponse(format!("no trust anchor for {zone}"))
            })?;
        let now = unix_now();
        if !dnskey_rrset_authentic(zone, &keys, &signatures, &anchor, now) {
            return Err(ResolveError::InvalidResponse(format!(
                "DNSKEY probe for {zone} was not signed by a trusted key"
            )));
        }

        // RFC 5011 only honors a revoke when the revoked key itself signed
        // the DNSKEY RRset, not merely when another trusted key did.
        let revoked = keys
            .iter()
            .filter(|record| {
                dns_dnssec::dnskey_of(record).is_some_and(|key| key.revoke())
                    && verify_rrset(&keys, &signatures, std::slice::from_ref(record), now).is_ok()
            })
            .cloned()
            .collect();
        Ok(ProbedDnskeys { keys, revoked })
    }

    async fn validate_positive(&self, message: &Message, context: WalkContext<'_>) -> Security {
        let now = unix_now();
        let mut result = Security::Secure;
        let mut validated = false;
        let mut seen: HashSet<(String, u16)> = HashSet::new();

        for record in &message.answers {
            if record.record_type() == RecordType::RRSIG {
                continue;
            }
            let key = (
                record.name.to_ascii().to_ascii_lowercase(),
                u16::from(record.record_type()),
            );
            if !seen.insert(key) {
                continue;
            }

            let rrset: Vec<Record> = message
                .answers
                .iter()
                .filter(|candidate| {
                    candidate.name == record.name && candidate.record_type() == record.record_type()
                })
                .cloned()
                .collect();
            let signatures: Vec<Record> =
                sigs_for(&message.answers, &record.name, record.record_type());

            let outcome = self
                .validate_rrset(
                    &rrset,
                    &signatures,
                    &record.name,
                    &message.authorities,
                    context.clone(),
                    now,
                )
                .await;
            result = combine(result, outcome);
            validated = true;
        }

        if validated {
            result
        } else {
            Security::Insecure
        }
    }

    async fn validate_rrset(
        &self,
        rrset: &[Record],
        signatures: &[Record],
        owner: &Name,
        authorities: &[Record],
        context: WalkContext<'_>,
        now: u64,
    ) -> Security {
        if signatures.is_empty() {
            let zone = self.zone_is_signed(owner, context).await;
            return match zone {
                Security::Secure if self.config.harden_dnssec_stripped => {
                    Security::Bogus(BogusReason::MissingSignature)
                }
                Security::Secure => Security::Insecure,
                other => other,
            };
        }

        let Some(signer) = signatures
            .iter()
            .find_map(|record| rrsig_of(record).map(|sig| sig.input().signer_name.clone()))
        else {
            return Security::Bogus(BogusReason::Malformed);
        };

        let zone = self.zone_status(signer, context.clone(), 0).await;
        if zone.security != Security::Secure {
            return zone.security;
        }

        match verify_rrset(rrset, signatures, &zone.keys, now) {
            Ok(()) => {
                if wildcard_labels(rrset, signatures).is_some() {
                    match wildcard_proof(owner, signatures, authorities) {
                        Ok(()) => Security::Secure,
                        Err(error) => Security::Bogus(error.into()),
                    }
                } else {
                    Security::Secure
                }
            }
            Err(error) => Security::Bogus(error.into()),
        }
    }

    async fn validate_negative(
        &self,
        message: &Message,
        qtype: RecordType,
        context: WalkContext<'_>,
    ) -> Security {
        let Some(qname) = effective_qname(message) else {
            return Security::Insecure;
        };
        let Some(zone_name) = negative_zone(message) else {
            return Security::Insecure;
        };

        let zone = self.zone_status(zone_name, context, 0).await;
        if zone.security != Security::Secure {
            return zone.security;
        }

        match verify_negative_proof(message, &qname, qtype, &zone.keys, unix_now()) {
            Ok(Proof::Secure) => Security::Secure,
            Ok(Proof::Insecure) => Security::Insecure,
            Err(error) => Security::Bogus(error.into()),
        }
    }

    /// Whether the zone containing `name` is signed.
    ///
    /// A DS query for a non-delegation name returns NODATA from its enclosing
    /// zone. The denial is validated against the parent: if it proves an
    /// unsigned delegation (including an NSEC3 opt-out span), everything below
    /// `name` is insecure. Otherwise the enclosing zone is signed, so an RRset
    /// without a signature is bogus.
    async fn zone_is_signed(&self, name: &Name, context: WalkContext<'_>) -> Security {
        if let Ok(mut cache) = self.zones.lock()
            && let Some(security) = cache.get_signed(name)
        {
            return security;
        }

        let response = match self.fetch_internal(name, RecordType::DS, &context).await {
            Ok(response) => response,
            Err(_) => return Security::Insecure,
        };

        let security = if !records_of(&response.answers, name, RecordType::DS).is_empty() {
            // The name is a delegation. It is only securely signed when the
            // parent chain is secure; an unsigned DS RRset means the parent is
            // insecure, so the child is an island of security.
            let signatures = sigs_for(&response.answers, name, RecordType::DS);
            match signatures
                .iter()
                .find_map(|record| rrsig_of(record).map(|sig| sig.input().signer_name.clone()))
            {
                Some(parent_name) => {
                    self.zone_status(parent_name, context.clone(), 0)
                        .await
                        .security
                }
                None => Security::Insecure,
            }
        } else {
            let Some(parent_name) = negative_zone(&response) else {
                return Security::Insecure;
            };
            let parent = self.zone_status(parent_name, context.clone(), 0).await;
            if parent.security != Security::Secure {
                parent.security
            } else {
                match verify_negative_proof(
                    &response,
                    name,
                    RecordType::DS,
                    &parent.keys,
                    unix_now(),
                ) {
                    Ok(Proof::Secure) => Security::Secure,
                    Ok(Proof::Insecure) => Security::Insecure,
                    Err(error) => Security::Bogus(error.into()),
                }
            }
        };

        if !matches!(security, Security::Bogus(_))
            && let Ok(mut cache) = self.zones.lock()
        {
            cache.insert_signed(name, security.clone(), Duration::from_secs(300));
        }
        security
    }

    fn zone_status<'a>(
        &'a self,
        zone: Name,
        context: WalkContext<'a>,
        depth: u32,
    ) -> Pin<Box<dyn Future<Output = ZoneStatus> + Send + 'a>> {
        Box::pin(async move {
            if depth > 24 {
                return ZoneStatus::bogus(BogusReason::Malformed);
            }
            if let Ok(mut cache) = self.zones.lock()
                && let Some(status) = cache.get(&zone)
            {
                return status;
            }

            if let Some(anchor) = self.config.trust_store.anchor_for(&zone) {
                let status = self.status_from_anchor(&zone, &anchor, &context).await;
                self.cache_zone(&zone, &status);
                return status;
            }

            let ds_response = match self.fetch_internal(&zone, RecordType::DS, &context).await {
                Ok(response) => response,
                Err(_) => return ZoneStatus::insecure(),
            };

            let ds_records = records_of(&ds_response.answers, &zone, RecordType::DS);
            if !ds_records.is_empty() {
                let ds_signatures = sigs_for(&ds_response.answers, &zone, RecordType::DS);
                let Some(parent_name) = ds_signatures
                    .iter()
                    .find_map(|record| rrsig_of(record).map(|sig| sig.input().signer_name.clone()))
                else {
                    return ZoneStatus::bogus(BogusReason::MissingSignature);
                };
                let parent = self
                    .zone_status(parent_name, context.clone(), depth + 1)
                    .await;
                if parent.security != Security::Secure {
                    return parent;
                }
                if let Err(error) =
                    verify_rrset(&ds_records, &ds_signatures, &parent.keys, unix_now())
                {
                    return ZoneStatus::bogus(error.into());
                }

                let key_response = match self
                    .fetch_internal(&zone, RecordType::DNSKEY, &context)
                    .await
                {
                    Ok(response) => response,
                    Err(_) => return ZoneStatus::bogus(BogusReason::MissingKey),
                };
                let keys = records_of(&key_response.answers, &zone, RecordType::DNSKEY);
                let key_signatures = sigs_for(&key_response.answers, &zone, RecordType::DNSKEY);
                if keys.is_empty() {
                    return ZoneStatus::bogus(BogusReason::MissingKey);
                }
                match verify_dnskey_with_ds(&zone, &keys, &key_signatures, &ds_records, unix_now())
                {
                    Ok(()) => {
                        let status = ZoneStatus::secure(keys);
                        self.cache_zone(&zone, &status);
                        status
                    }
                    Err(error) => ZoneStatus::bogus(error.into()),
                }
            } else {
                // No DS: the parent must prove the delegation is unsigned.
                let Some(parent_name) = negative_zone(&ds_response) else {
                    return ZoneStatus::insecure();
                };
                let parent = self
                    .zone_status(parent_name, context.clone(), depth + 1)
                    .await;
                if parent.security != Security::Secure {
                    return parent;
                }
                let status = match verify_negative_proof(
                    &ds_response,
                    &zone,
                    RecordType::DS,
                    &parent.keys,
                    unix_now(),
                ) {
                    Ok(_) => ZoneStatus::insecure(),
                    Err(error) => ZoneStatus::bogus(error.into()),
                };
                self.cache_zone(&zone, &status);
                status
            }
        })
    }

    async fn status_from_anchor(
        &self,
        zone: &Name,
        anchor: &TrustAnchor,
        context: &WalkContext<'_>,
    ) -> ZoneStatus {
        let response = match self.fetch_internal(zone, RecordType::DNSKEY, context).await {
            Ok(response) => response,
            Err(_) => return ZoneStatus::bogus(BogusReason::MissingKey),
        };
        let keys = records_of(&response.answers, zone, RecordType::DNSKEY);
        let signatures = sigs_for(&response.answers, zone, RecordType::DNSKEY);
        if keys.is_empty() {
            return ZoneStatus::bogus(BogusReason::MissingKey);
        }

        let result = if !anchor.keys.is_empty() {
            verify_dnskey_with_anchor(zone, &keys, &signatures, &anchor.keys, unix_now())
        } else if !anchor.ds.is_empty() {
            verify_dnskey_with_ds(zone, &keys, &signatures, &anchor.ds, unix_now())
        } else {
            return ZoneStatus::bogus(BogusReason::MissingKey);
        };

        match result {
            Ok(()) => ZoneStatus::secure(keys),
            Err(error) => ZoneStatus::bogus(error.into()),
        }
    }

    async fn fetch_internal(
        &self,
        name: &Name,
        qtype: RecordType,
        context: &WalkContext<'_>,
    ) -> Result<Message, ResolveError> {
        let sub_context = WalkContext {
            depth: context.depth + 1,
            ancestors: context.ancestors,
            deadline: context.deadline,
            budget: std::sync::Arc::clone(&context.budget),
            recursion_desired: context.recursion_desired,
            dnssec_ok: true,
            validating: true,
            checking_disabled: true,
        };
        self.resolve_inner(name.clone(), qtype, sub_context).await
    }

    fn cache_zone(&self, zone: &Name, status: &ZoneStatus) {
        let ttl = if status.keys.is_empty() {
            Duration::from_secs(300)
        } else {
            let seconds = status
                .keys
                .iter()
                .map(|record| record.ttl)
                .min()
                .unwrap_or(300);
            Duration::from_secs(u64::from(seconds))
        };
        if let Ok(mut cache) = self.zones.lock() {
            cache.insert(zone, status.clone(), ttl);
        }
    }
}

/// Whether an NSEC or NSEC3 proof was secure or only proves an insecure
/// (opt-out) delegation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Proof {
    Secure,
    Insecure,
}

/// Whether a DNSKEY RRset is signed by one of the anchor's keys.
///
/// The comparison ignores the REVOKE bit so a key that is being retired can
/// still authenticate the RRset that carries its revoked form.
fn dnskey_rrset_authentic(
    zone: &Name,
    keys: &[Record],
    signatures: &[Record],
    anchor: &TrustAnchor,
    now: u64,
) -> bool {
    for anchor_key in &anchor.keys {
        for fetched in keys {
            if same_key_ignoring_revoke(anchor_key, fetched)
                && verify_rrset(keys, signatures, std::slice::from_ref(fetched), now).is_ok()
            {
                return true;
            }
        }
    }
    if !anchor.ds.is_empty()
        && verify_dnskey_with_ds(zone, keys, signatures, &anchor.ds, now).is_ok()
    {
        return true;
    }
    !anchor.keys.is_empty()
        && verify_dnskey_with_anchor(zone, keys, signatures, &anchor.keys, now).is_ok()
}

fn verify_negative_proof(
    message: &Message,
    qname: &Name,
    qtype: RecordType,
    keys: &[Record],
    now: u64,
) -> Result<Proof, DnssecError> {
    let nsecs: Vec<(&Record, &dns_proto::NSEC)> = message
        .authorities
        .iter()
        .filter_map(|record| dns_dnssec::nsec_of(record).map(|nsec| (record, nsec)))
        .collect();
    let nsec3s: Vec<(&Record, &dns_proto::NSEC3)> = message
        .authorities
        .iter()
        .filter_map(|record| dns_dnssec::nsec3_of(record).map(|nsec3| (record, nsec3)))
        .collect();

    if nsecs.is_empty() && nsec3s.is_empty() {
        return Err(DnssecError::DenialOfExistence);
    }

    verify_denial_signatures(&message.authorities, &nsecs, &nsec3s, keys, now)?;

    if !nsecs.is_empty() {
        return nsec_proof(&nsecs, qname, qtype, message.metadata.response_code);
    }
    nsec3_proof(&nsec3s, qname, qtype, message.metadata.response_code)
}

fn verify_denial_signatures(
    authorities: &[Record],
    nsecs: &[(&Record, &dns_proto::NSEC)],
    nsec3s: &[(&Record, &dns_proto::NSEC3)],
    keys: &[Record],
    now: u64,
) -> Result<(), DnssecError> {
    let mut seen = HashSet::new();
    for (record, _) in nsecs {
        if !seen.insert(record.name.to_ascii().to_ascii_lowercase()) {
            continue;
        }
        let rrset: Vec<Record> = nsecs
            .iter()
            .filter(|(candidate, _)| candidate.name == record.name)
            .map(|(candidate, _)| (*candidate).clone())
            .collect();
        let signatures = sigs_for(authorities, &record.name, RecordType::NSEC);
        if signatures.is_empty() {
            return Err(DnssecError::MissingSignature);
        }
        verify_rrset(&rrset, &signatures, keys, now)?;
    }

    let mut seen = HashSet::new();
    for (record, _) in nsec3s {
        if !seen.insert(record.name.to_ascii().to_ascii_lowercase()) {
            continue;
        }
        let rrset: Vec<Record> = nsec3s
            .iter()
            .filter(|(candidate, _)| candidate.name == record.name)
            .map(|(candidate, _)| (*candidate).clone())
            .collect();
        let signatures = sigs_for(authorities, &record.name, RecordType::NSEC3);
        if signatures.is_empty() {
            return Err(DnssecError::MissingSignature);
        }
        verify_rrset(&rrset, &signatures, keys, now)?;
    }
    Ok(())
}

fn nsec_proof(
    nsecs: &[(&Record, &dns_proto::NSEC)],
    qname: &Name,
    qtype: RecordType,
    rcode: ResponseCode,
) -> Result<Proof, DnssecError> {
    if rcode == ResponseCode::NoError {
        let Some((_, nsec)) = nsecs
            .iter()
            .find(|(record, nsec)| record.name == *qname && nsec_proves_nodata(nsec, qtype))
        else {
            return Err(DnssecError::DenialOfExistence);
        };
        // A DS NODATA whose NSEC has NS but no DS is an unsigned delegation.
        if qtype == RecordType::DS {
            let types: Vec<RecordType> = nsec.type_bit_maps().collect();
            if types.contains(&RecordType::NS) && !types.contains(&RecordType::DS) {
                return Ok(Proof::Insecure);
            }
        }
        return Ok(Proof::Secure);
    }

    let covering = nsecs
        .iter()
        .find(|(record, nsec)| nsec_covers(&record.name, nsec.next_domain_name(), qname));
    if covering.is_none() {
        return Err(DnssecError::DenialOfExistence);
    }

    let Some(closest) = nsec_closest_encloser(qname, nsecs) else {
        return Err(DnssecError::DenialOfExistence);
    };
    let Some(wildcard) = wildcard_name(&closest) else {
        return Err(DnssecError::DenialOfExistence);
    };
    let wildcard_covered = nsecs
        .iter()
        .any(|(record, nsec)| nsec_covers(&record.name, nsec.next_domain_name(), &wildcard));
    if wildcard_covered {
        Ok(Proof::Secure)
    } else {
        Err(DnssecError::DenialOfExistence)
    }
}

fn nsec3_proof(
    nsec3s: &[(&Record, &dns_proto::NSEC3)],
    qname: &Name,
    qtype: RecordType,
    rcode: ResponseCode,
) -> Result<Proof, DnssecError> {
    let (_, first) = nsec3s[0];
    if !nsec3_algorithm_supported(first) {
        return Err(DnssecError::UnsupportedAlgorithm);
    }
    let iterations = first.iterations();
    let salt = first.salt();

    let hash = nsec3_hash(qname, iterations, salt);
    if rcode == ResponseCode::NoError {
        if let Some((_, nsec3)) = nsec3s
            .iter()
            .find(|(record, _)| nsec3_owner_hash(record).as_deref() == Some(hash.as_slice()))
        {
            if !nsec3_proves_nodata(nsec3, qtype) {
                return Err(DnssecError::DenialOfExistence);
            }
            // A DS NODATA whose NSEC3 has NS but no DS is an unsigned
            // delegation.
            if qtype == RecordType::DS {
                let types: Vec<RecordType> = nsec3.type_bit_maps().collect();
                if types.contains(&RecordType::NS) && !types.contains(&RecordType::DS) {
                    return Ok(Proof::Insecure);
                }
            }
            return Ok(Proof::Secure);
        }
        // An opt-out NSEC3 span covering an existing delegation proves that
        // the delegation is unsigned (RFC 5155 section 7.2.4).
        if qtype == RecordType::DS
            && nsec3s.iter().any(|(record, nsec3)| {
                nsec3.opt_out()
                    && nsec3_covers(
                        &nsec3_owner_hash(record).unwrap_or_default(),
                        nsec3.next_hashed_owner_name(),
                        &hash,
                    )
            })
        {
            return Ok(Proof::Insecure);
        }
        return Err(DnssecError::DenialOfExistence);
    }

    let Some((closest, _)) = ancestors(qname).into_iter().skip(1).find_map(|ancestor| {
        let ancestor_hash = nsec3_hash(&ancestor, iterations, salt);
        nsec3s
            .iter()
            .find(|(record, _)| {
                nsec3_owner_hash(record).as_deref() == Some(ancestor_hash.as_slice())
            })
            .map(|(_, nsec3)| (ancestor, nsec3))
    }) else {
        return Err(DnssecError::DenialOfExistence);
    };

    let Some(next_closer) = next_closer(qname, &closest) else {
        return Err(DnssecError::DenialOfExistence);
    };
    let next_hash = nsec3_hash(&next_closer, iterations, salt);
    let Some((_, next_record)) = nsec3s.iter().find(|(record, nsec3)| {
        let owner = nsec3_owner_hash(record).unwrap_or_default();
        nsec3_covers(&owner, nsec3.next_hashed_owner_name(), &next_hash)
    }) else {
        return Err(DnssecError::DenialOfExistence);
    };

    let Some(wildcard) = wildcard_name(&closest) else {
        return Err(DnssecError::DenialOfExistence);
    };
    let wildcard_hash = nsec3_hash(&wildcard, iterations, salt);
    let wildcard_covered = nsec3s.iter().any(|(record, nsec3)| {
        let owner = nsec3_owner_hash(record).unwrap_or_default();
        nsec3_covers(&owner, nsec3.next_hashed_owner_name(), &wildcard_hash)
    });
    if !wildcard_covered {
        return Err(DnssecError::DenialOfExistence);
    }

    if next_record.opt_out() {
        Ok(Proof::Insecure)
    } else {
        Ok(Proof::Secure)
    }
}

fn nsec_closest_encloser(qname: &Name, nsecs: &[(&Record, &dns_proto::NSEC)]) -> Option<Name> {
    let mut best = Name::root();
    for (record, nsec) in nsecs {
        for candidate in [&record.name, nsec.next_domain_name()] {
            let common = common_suffix(qname, candidate);
            if common.num_labels() > best.num_labels() {
                best = common;
            }
        }
    }
    if best.num_labels() == 0 {
        None
    } else {
        Some(best)
    }
}

fn common_suffix(left: &Name, right: &Name) -> Name {
    let mut suffix = left.clone();
    loop {
        if suffix.zone_of(right) {
            return suffix;
        }
        if suffix.num_labels() == 0 {
            return Name::root();
        }
        suffix = suffix.base_name();
    }
}

fn ancestors(name: &Name) -> Vec<Name> {
    let mut result = Vec::new();
    let mut current = name.clone();
    loop {
        result.push(current.clone());
        if current.num_labels() == 0 {
            break;
        }
        current = current.base_name();
    }
    result
}

fn next_closer(qname: &Name, closest: &Name) -> Option<Name> {
    let mut current = qname.clone();
    while current.num_labels() > closest.num_labels() + 1 {
        current = current.base_name();
    }
    if current.num_labels() == closest.num_labels() + 1 {
        Some(current)
    } else {
        None
    }
}

/// Follow CNAMEs in the answer section to the name the negative proof covers.
fn effective_qname(message: &Message) -> Option<Name> {
    let mut name = message.queries.first()?.name.clone();
    for _ in 0..8 {
        let target = message.answers.iter().find_map(|record| {
            if record.name == name
                && let RData::CNAME(target) = &record.data
            {
                Some(target.0.clone())
            } else {
                None
            }
        });
        match target {
            Some(target) => name = target,
            None => break,
        }
    }
    Some(name)
}

fn negative_zone(message: &Message) -> Option<Name> {
    message
        .authorities
        .iter()
        .find(|record| record.record_type() == RecordType::SOA)
        .map(|record| record.name.clone())
        .or_else(|| {
            message
                .authorities
                .iter()
                .find_map(|record| rrsig_of(record).map(|sig| sig.input().signer_name.clone()))
        })
}

fn records_of(records: &[Record], owner: &Name, rtype: RecordType) -> Vec<Record> {
    records
        .iter()
        .filter(|record| &record.name == owner && record.record_type() == rtype)
        .cloned()
        .collect()
}

fn sigs_for(records: &[Record], owner: &Name, covered: RecordType) -> Vec<Record> {
    records
        .iter()
        .filter(|record| {
            &record.name == owner
                && record.record_type() == RecordType::RRSIG
                && rrsig_of(record).is_some_and(|sig| sig.input().type_covered == covered)
        })
        .cloned()
        .collect()
}

fn wildcard_labels(rrset: &[Record], signatures: &[Record]) -> Option<u8> {
    let owner_labels = rrset.first()?.name.num_labels();
    signatures.iter().find_map(|record| {
        let sig = rrsig_of(record)?;
        (sig.input().num_labels < owner_labels).then_some(sig.input().num_labels)
    })
}

fn wildcard_proof(
    owner: &Name,
    signatures: &[Record],
    authorities: &[Record],
) -> Result<(), DnssecError> {
    let Some(labels) = signatures.iter().find_map(|record| {
        let sig = rrsig_of(record)?;
        (sig.input().num_labels < owner.num_labels()).then_some(sig.input().num_labels)
    }) else {
        return Ok(());
    };

    let mut closest = owner.clone();
    while closest.num_labels() > labels {
        closest = closest.base_name();
    }
    let Some(next_closer) = next_closer(owner, &closest) else {
        return Err(DnssecError::DenialOfExistence);
    };

    let nsecs: Vec<(&Record, &dns_proto::NSEC)> = authorities
        .iter()
        .filter_map(|record| dns_dnssec::nsec_of(record).map(|nsec| (record, nsec)))
        .collect();
    if !nsecs.is_empty() {
        let covered = nsecs
            .iter()
            .any(|(record, nsec)| nsec_covers(&record.name, nsec.next_domain_name(), &next_closer));
        return if covered {
            Ok(())
        } else {
            Err(DnssecError::DenialOfExistence)
        };
    }

    let nsec3s: Vec<(&Record, &dns_proto::NSEC3)> = authorities
        .iter()
        .filter_map(|record| dns_dnssec::nsec3_of(record).map(|nsec3| (record, nsec3)))
        .collect();
    let Some((_, first)) = nsec3s.first() else {
        return Err(DnssecError::DenialOfExistence);
    };
    let iterations = first.iterations();
    let salt = first.salt();
    let closest_hash = nsec3_hash(&closest, iterations, salt);
    let closest_match = nsec3s
        .iter()
        .any(|(record, _)| nsec3_owner_hash(record).as_deref() == Some(closest_hash.as_slice()));
    let next_hash = nsec3_hash(&next_closer, iterations, salt);
    let next_covered = nsec3s.iter().any(|(record, nsec3)| {
        let owner = nsec3_owner_hash(record).unwrap_or_default();
        nsec3_covers(&owner, nsec3.next_hashed_owner_name(), &next_hash)
    });
    if closest_match && next_covered {
        Ok(())
    } else {
        Err(DnssecError::DenialOfExistence)
    }
}

fn combine(left: Security, right: Security) -> Security {
    match (left, right) {
        (Security::Bogus(reason), _) | (_, Security::Bogus(reason)) => Security::Bogus(reason),
        (Security::Insecure, _) | (_, Security::Insecure) => Security::Insecure,
        (Security::Secure, Security::Secure) => Security::Secure,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::{common_suffix, next_closer};
    use dns_proto::Name;

    fn n(text: &str) -> Name {
        Name::from_ascii(text).expect("name")
    }

    #[test]
    fn common_suffix_finds_longest_shared_ancestor() {
        assert_eq!(
            common_suffix(&n("a.b.example.com."), &n("x.example.com.")),
            n("example.com.")
        );
        assert_eq!(
            common_suffix(&n("a.b.example.com."), &n("b.example.com.")),
            n("b.example.com.")
        );
        assert_eq!(common_suffix(&n("a.example."), &n("other.")), Name::root());
    }

    #[test]
    fn next_closer_is_one_label_below_the_closest_encloser() {
        assert_eq!(
            next_closer(&n("a.b.example.com."), &n("example.com.")),
            Some(n("b.example.com."))
        );
        assert_eq!(
            next_closer(&n("a.example.com."), &n("example.com.")),
            Some(n("a.example.com."))
        );
    }
}
