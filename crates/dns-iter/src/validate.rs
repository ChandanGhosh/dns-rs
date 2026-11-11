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

/// Maximum depth of the DS/DNSKEY chain walk before giving up as malformed.
const MAX_CHAIN_DEPTH: u32 = 24;

/// How long a validated zone status is cached when no DNSKEY TTL is known.
///
/// Insecure status is inherited by descendants, so this is also the longest
/// time a newly signed zone can remain treated as unsigned. Bounded to five
/// minutes so a delegation or signing change is picked up promptly. Secure and
/// Bogus statuses always stop inheritance, and an explicit trust anchor below
/// the cached zone bypasses this path entirely.
const ZONE_STATUS_TTL_SECS: u32 = 300;
const ZONE_STATUS_TTL: Duration = Duration::from_secs(ZONE_STATUS_TTL_SECS as u64);
const MIN_ZONE_STATUS_TTL: Duration = Duration::from_secs(30);
const MAX_ZONE_STATUS_TTL: Duration = Duration::from_secs(3600);

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

/// Response-level data shared by every RRset in one answer.
struct AnswerContext<'a> {
    /// Authority records, used to prove wildcard expansion.
    authorities: &'a [Record],
    /// Authoritative zone that supplied each answer owner.
    origins: &'a HashMap<Name, Name>,
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
///
/// `Name` hashes and compares case-insensitively, so it is used directly as the
/// map key. This mirrors the message cache and avoids formatting and
/// lowercasing (two `String` allocations) on every validation lookup.
#[derive(Default)]
pub(crate) struct ZoneCache {
    entries: HashMap<Name, CachedZone>,
    signed: HashMap<Name, CachedZone>,
}

impl ZoneCache {
    fn get(&mut self, zone: &Name) -> Option<ZoneStatus> {
        {
            let entry = self.entries.get(zone)?;
            if entry.expires > Instant::now() {
                return Some(entry.status.clone());
            }
        }
        self.entries.remove(zone);
        None
    }

    fn insert(&mut self, zone: &Name, status: ZoneStatus, ttl: Duration) {
        let ttl = ttl.clamp(MIN_ZONE_STATUS_TTL, MAX_ZONE_STATUS_TTL);
        self.entries.insert(
            zone.clone(),
            CachedZone {
                status,
                expires: Instant::now() + ttl,
            },
        );
    }

    fn get_signed(&mut self, name: &Name) -> Option<Security> {
        {
            let entry = self.signed.get(name)?;
            if entry.expires > Instant::now() {
                return Some(entry.status.security.clone());
            }
        }
        self.signed.remove(name);
        None
    }

    fn insert_signed(&mut self, name: &Name, security: Security, ttl: Duration) {
        self.signed.insert(
            name.clone(),
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
    /// Whether `name` falls under a configured `domain-insecure` entry.
    ///
    /// The entry is a static negative trust anchor (RFC 7646): it marks the
    /// named domain and everything below it as insecure. The longest matching
    /// entry wins, and an explicit trust anchor at or below it re-enables
    /// validation for the subtree it covers, matching Unbound's semantics.
    fn is_domain_insecure(&self, name: &Name) -> bool {
        let Some(domain) = self
            .config
            .domain_insecure
            .iter()
            .filter(|domain| domain.zone_of(name))
            .max_by_key(|domain| domain.num_labels())
        else {
            return false;
        };
        !self.config.trust_store.anchor_within(domain, name)
    }

    /// Whether `name` is covered by a cached zone that is already unsigned.
    ///
    /// Everything below a delegation without a DS RRset is insecure, so a
    /// zone's probe result applies to all of its descendants (RFC 4035
    /// section 5.2). The search starts at `name` and walks strict ancestors,
    /// stopping at the first cached zone status: a `Secure` ancestor says
    /// nothing about a delegation below it, and a bogus ancestor must not mask
    /// the name's own status. A trust anchor inside the covered subtree
    /// re-enables validation, so the walk also stops before crossing one.
    fn cached_insecure_cover(&self, name: &Name) -> bool {
        // Hold the cache lock for the whole ancestor walk: the status is a
        // single consistent snapshot, and a deep name no longer locks once per
        // label on the validation hot path.
        let Ok(mut cache) = self.zones.lock() else {
            return false;
        };
        let mut candidate = name.clone();
        loop {
            if self.config.trust_store.anchor_within(&candidate, name) {
                return false;
            }
            if let Some(status) = cache.get(&candidate) {
                return status.security == Security::Insecure;
            }
            if candidate.num_labels() == 0 {
                return false;
            }
            let parent = candidate.base_name();
            if parent == candidate {
                return false;
            }
            candidate = parent;
        }
    }

    /// Validate a response and classify it as secure, insecure, or bogus.
    ///
    /// `origins` maps each answer owner to the authoritative zone that supplied
    /// it. Unsigned RRsets use it to start the chain of trust at a real zone
    /// apex instead of probing DS at the owner name.
    pub(crate) async fn validate_message<'a>(
        &'a self,
        message: &Message,
        qtype: RecordType,
        origins: &HashMap<Name, Name>,
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

        self.validate_positive(message, origins, context.clone())
            .await
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
            forward_only: false,
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

    async fn validate_positive(
        &self,
        message: &Message,
        origins: &HashMap<Name, Name>,
        context: WalkContext<'_>,
    ) -> Security {
        let now = unix_now();
        let answer = AnswerContext {
            authorities: &message.authorities,
            origins,
        };
        let mut result = Security::Secure;
        let mut validated = false;
        // Group the answer section in one pass. This replaces a re-scan of
        // every answer for each RRset and each signature lookup.
        let mut rrsets: HashMap<(&Name, u16), Vec<Record>> = HashMap::new();
        let mut signatures: HashMap<(&Name, u16), Vec<Record>> = HashMap::new();
        let mut order: Vec<(&Name, u16)> = Vec::new();
        for record in &message.answers {
            if record.record_type() == RecordType::RRSIG {
                if let Some(sig) = rrsig_of(record) {
                    signatures
                        .entry((&record.name, u16::from(sig.input().type_covered)))
                        .or_default()
                        .push(record.clone());
                }
                continue;
            }
            let key = (&record.name, u16::from(record.record_type()));
            let rrset = rrsets.entry(key).or_default();
            if rrset.is_empty() {
                order.push(key);
            }
            rrset.push(record.clone());
        }

        for key in order {
            let rrset = rrsets.get(&key).map(Vec::as_slice).unwrap_or(&[]);
            let signatures = signatures.get(&key).map(Vec::as_slice).unwrap_or(&[]);
            let outcome = self
                .validate_rrset(rrset, signatures, key.0, &answer, context.clone(), now)
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
        answer: &AnswerContext<'_>,
        context: WalkContext<'_>,
        now: u64,
    ) -> Security {
        if self.is_domain_insecure(owner) {
            return Security::Insecure;
        }
        if signatures.is_empty() {
            let zone = match answer.origins.get(owner) {
                // The walk recorded the zone that owns this name. Start the
                // chain of trust there instead of probing DS at an alias.
                Some(origin) => {
                    let origin_security = self
                        .zone_status(origin.clone(), context.clone(), 0)
                        .await
                        .security;
                    if origin_security != Security::Secure || origin == owner {
                        origin_security
                    } else {
                        // The answer came from an ancestor zone. The owner may
                        // still be a delegation the walk did not have to
                        // follow, so probe the owner's own zone before treating
                        // the ancestor's status as final.
                        self.zone_is_signed(owner, context).await
                    }
                }
                // Forwarded answers do not reveal the authoritative zone;
                // fall back to probing DS at the owner.
                None => self.zone_is_signed(owner, context).await,
            };
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
                    match wildcard_proof(
                        owner,
                        signatures,
                        answer.authorities,
                        self.config.nsec3_max_iterations,
                    ) {
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
        if message
            .queries
            .first()
            .is_some_and(|query| self.is_domain_insecure(&query.name))
        {
            return Security::Insecure;
        }
        let Some(qname) = effective_qname(message) else {
            return Security::Insecure;
        };
        if self.is_domain_insecure(&qname) {
            return Security::Insecure;
        }
        let Some(zone_name) = negative_zone(message) else {
            return Security::Insecure;
        };
        // The denial must come from a zone that actually contains the queried
        // name. Without this bailiwick check an upstream can attach NSEC
        // records from one of its own signed zones (whose RRSIG signer names
        // resolve the zone for us) and manufacture a "Secure" NXDOMAIN or
        // NODATA answer for a name it has no authority over.
        if !zone_name.zone_of(&qname) {
            return Security::Insecure;
        }

        let zone = self.zone_status(zone_name, context, 0).await;
        if zone.security != Security::Secure {
            return zone.security;
        }

        match verify_negative_proof(
            message,
            &qname,
            qtype,
            &zone.keys,
            unix_now(),
            self.config.nsec3_max_iterations,
        ) {
            Ok(Proof::Secure) => Security::Secure,
            Ok(Proof::Insecure) => Security::Insecure,
            Err(error) => Security::Bogus(error.into()),
        }
    }

    /// Probe whether the zone containing `name` is signed.
    ///
    /// Used when the walk did not record a distinct authoritative zone for an
    /// unsigned RRset: either the answer was forwarded, or the owner may be a
    /// delegation below the zone that answered. A DS query for a non-delegation
    /// name returns NODATA from its enclosing zone. The denial is validated
    /// against the parent: if it proves an unsigned delegation (including an
    /// NSEC3 opt-out span), everything below `name` is insecure. Otherwise the
    /// enclosing zone is signed, so an RRset without a signature is bogus.
    ///
    /// A DS query for an alias is answered with a CNAME, so the probe follows
    /// the alias up to the zone that owns it.
    async fn zone_is_signed(&self, name: &Name, context: WalkContext<'_>) -> Security {
        let original = name.clone();
        let mut name = name.clone();
        loop {
            if self.is_domain_insecure(&name) {
                return Security::Insecure;
            }
            if let Ok(mut cache) = self.zones.lock()
                && let Some(security) = cache.get_signed(&name)
            {
                return security;
            }
            if self.cached_insecure_cover(&name) {
                return Security::Insecure;
            }

            let response = match self.fetch_internal(&name, RecordType::DS, &context).await {
                Ok(response) => response,
                // Transient resolution failure (upstream SERVFAIL/refusal,
                // network error): probe the parent instead of failing open.
                // Letting this path return Insecure would let an attacker
                // downgrade a signed zone by jamming one DS probe; returning
                // Bogus instead would break genuinely unsigned names whose
                // proof lives at the delegation level, not the qname.
                Err(_) => {
                    if name.num_labels() == 0 {
                        return Security::Bogus(BogusReason::MissingKey);
                    }
                    name = name.base_name();
                    continue;
                }
            };

            // A DS query for an alias is answered with a CNAME instead of a
            // denial from the parent zone. The alias is not a delegation, and
            // the target's denial does not cover the alias name. The alias
            // itself lives in the parent zone, so determine that zone's
            // signing status instead.
            if crate::scrub::cname_target(&response, &name).is_some() {
                if name.num_labels() == 0 {
                    return Security::Insecure;
                }
                name = name.base_name();
                continue;
            }

            let security = if !records_of(&response.answers, &name, RecordType::DS).is_empty() {
                // The name is a delegation. It is only securely signed when the
                // parent chain is secure; an unsigned DS RRset means the parent
                // is insecure, so the child is an island of security.
                let signatures = sigs_for(&response.answers, &name, RecordType::DS);
                match signatures
                    .iter()
                    .find_map(|record| rrsig_of(record).map(|sig| sig.input().signer_name.clone()))
                {
                    Some(parent_name) => {
                        // A DS RRset is signed by the parent zone. Following a
                        // signer at or below the child would recurse into the
                        // same status lookup, so treat it as malformed.
                        if parent_name == name || !parent_name.zone_of(&name) {
                            return Security::Bogus(BogusReason::Malformed);
                        }
                        self.zone_status(parent_name, context.clone(), 0)
                            .await
                            .security
                    }
                    None => Security::Insecure,
                }
            } else {
                let Some(parent_name) = negative_zone(&response)
                    .and_then(|candidate| ds_probe_parent(&name, candidate))
                else {
                    return Security::Insecure;
                };
                // Same bailiwick requirement: the denial of the DS record must
                // come from a zone containing the name, not from an unrelated
                // signed zone a hostile upstream supplies. A child-served SOA
                // falls back to the immediate parent (see `ds_probe_parent`).
                let parent = self.zone_status(parent_name, context.clone(), 0).await;
                if parent.security != Security::Secure {
                    parent.security
                } else {
                    match verify_negative_proof(
                        &response,
                        &name,
                        RecordType::DS,
                        &parent.keys,
                        unix_now(),
                        self.config.nsec3_max_iterations,
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
                cache.insert_signed(&original, security.clone(), ZONE_STATUS_TTL);
                cache.insert_signed(&name, security.clone(), ZONE_STATUS_TTL);
            }
            return security;
        }
    }

    fn zone_status<'a>(
        &'a self,
        zone: Name,
        context: WalkContext<'a>,
        depth: u32,
    ) -> Pin<Box<dyn Future<Output = ZoneStatus> + Send + 'a>> {
        Box::pin(async move {
            if depth > MAX_CHAIN_DEPTH {
                return ZoneStatus::bogus(BogusReason::Malformed);
            }
            if self.is_domain_insecure(&zone) {
                return ZoneStatus::insecure();
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
            if self.cached_insecure_cover(&zone) {
                return ZoneStatus::insecure();
            }

            // A configured stub zone is trusted by appointment: the operator
            // selected its servers directly, so the public chain of trust does
            // not reach it (like Unbound, stub zones validate only through an
            // explicit trust anchor, handled above). Probing DS here would
            // walk the delegation the stub replaces, which cannot succeed for
            // private zones and errors out. Forward zones are deliberately
            // excluded: their upstream is a recursive resolver and DS probes
            // sent through it are legitimate, so those keep the full chain
            // below.
            if self
                .config
                .stub_zones
                .iter()
                .any(|stub| stub.zone.zone_of(&zone))
            {
                return ZoneStatus::insecure();
            }

            let ds_response = match self.fetch_internal(&zone, RecordType::DS, &context).await {
                Ok(response) => response,
                // Failing closed: without proof of signing status the data
                // cannot be vouched for, and an attacker able to jam the DS
                // exchange must not downgrade the zone to Insecure. Not
                // cached, so recovery after the outage is immediate.
                Err(_) => return ZoneStatus::bogus(BogusReason::MissingKey),
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
                // A DS RRset is signed by the parent zone. Following a signer
                // at or below this zone would recurse without making progress.
                if parent_name == zone || !parent_name.zone_of(&zone) {
                    return ZoneStatus::bogus(BogusReason::Malformed);
                }
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
                // No DS: the parent must prove the delegation is unsigned, and
                // the proof must come from a zone containing the child.
                let Some(parent_name) = negative_zone(&ds_response)
                    .and_then(|candidate| ds_probe_parent(&zone, candidate))
                else {
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
                    self.config.nsec3_max_iterations,
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
            forward_only: false,
        };
        self.resolve_inner(name.clone(), qtype, sub_context)
            .await
            .map(|answer| answer.message)
    }

    fn cache_zone(&self, zone: &Name, status: &ZoneStatus) {
        let ttl = if status.keys.is_empty() {
            ZONE_STATUS_TTL
        } else {
            let seconds = status
                .keys
                .iter()
                .map(|record| record.ttl)
                .min()
                .unwrap_or(ZONE_STATUS_TTL_SECS);
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
    max_iterations: u16,
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
    nsec3_proof(
        &nsec3s,
        qname,
        qtype,
        message.metadata.response_code,
        max_iterations,
    )
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
        if !seen.insert(&record.name) {
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
        if !seen.insert(&record.name) {
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
    max_iterations: u16,
) -> Result<Proof, DnssecError> {
    let (_, first) = nsec3s[0];
    if !nsec3_algorithm_supported(first) {
        return Err(DnssecError::UnsupportedAlgorithm);
    }
    let iterations = first.iterations();
    let salt = first.salt();

    let hash = nsec3_hash(qname, iterations, salt, max_iterations)?;
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

    // The closest encloser is the first ancestor with a matching NSEC3 owner.
    // Hash each ancestor with the same checked helper so the iteration limit
    // applies to every hash in the proof.
    let mut closest = None;
    for ancestor in ancestors(qname).into_iter().skip(1) {
        let ancestor_hash = nsec3_hash(&ancestor, iterations, salt, max_iterations)?;
        if nsec3s.iter().any(|(record, _)| {
            nsec3_owner_hash(record).as_deref() == Some(ancestor_hash.as_slice())
        }) {
            closest = Some(ancestor);
            break;
        }
    }
    let Some(closest) = closest else {
        return Err(DnssecError::DenialOfExistence);
    };

    let Some(next_closer) = next_closer(qname, &closest) else {
        return Err(DnssecError::DenialOfExistence);
    };
    let next_hash = nsec3_hash(&next_closer, iterations, salt, max_iterations)?;
    let Some((_, next_record)) = nsec3s.iter().find(|(record, nsec3)| {
        let owner = nsec3_owner_hash(record).unwrap_or_default();
        nsec3_covers(&owner, nsec3.next_hashed_owner_name(), &next_hash)
    }) else {
        return Err(DnssecError::DenialOfExistence);
    };

    let Some(wildcard) = wildcard_name(&closest) else {
        return Err(DnssecError::DenialOfExistence);
    };
    let wildcard_hash = nsec3_hash(&wildcard, iterations, salt, max_iterations)?;
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

/// Pick the parent zone named by a DS probe's negative answer.
///
/// Normally the SOA or RRSIG in the denial names the zone holding the DS
/// RRset. A server authoritative for both a zone and its parent may instead
/// answer a DS query at the child apex from the child zone, putting the
/// child's own SOA in the authority section. Treating that owner as the parent
/// would recurse into the same zone until the depth cap and report the zone as
/// bogus, so fall back to the immediate parent name. The returned name is
/// always a strict ancestor (or `None` at the root), guaranteeing progress.
fn ds_probe_parent(probed: &Name, candidate: Name) -> Option<Name> {
    if candidate != *probed && candidate.zone_of(probed) {
        Some(candidate)
    } else if probed.num_labels() > 0 {
        Some(probed.base_name())
    } else {
        None
    }
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
    max_iterations: u16,
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
    let closest_hash = nsec3_hash(&closest, iterations, salt, max_iterations)?;
    let closest_match = nsec3s
        .iter()
        .any(|(record, _)| nsec3_owner_hash(record).as_deref() == Some(closest_hash.as_slice()));
    let next_hash = nsec3_hash(&next_closer, iterations, salt, max_iterations)?;
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
    use dns_dnssec::{TrustAnchor, TrustStore};
    use dns_proto::{Algorithm, DNSKEY, DNSSECRData, Name, PublicKeyBuf, RData, Record};

    use super::{IteratorResolver, ZONE_STATUS_TTL, ZoneStatus, common_suffix, next_closer};
    use crate::IteratorConfig;

    fn n(text: &str) -> Name {
        Name::from_ascii(text).expect("name")
    }

    fn resolver_with_anchor(anchor: Option<&str>) -> IteratorResolver {
        let store = TrustStore::builtin();
        if let Some(name) = anchor {
            let key = Record::from_rdata(
                n(name),
                3600,
                RData::DNSSEC(DNSSECRData::DNSKEY(DNSKEY::with_flags(
                    257,
                    PublicKeyBuf::new(vec![7; 32], Algorithm::ED25519),
                ))),
            );
            store.insert(TrustAnchor::from_keys(n(name), vec![key]));
        }
        let config = IteratorConfig {
            trust_store: store,
            ..IteratorConfig::default()
        };
        IteratorResolver::with_config(config, None).expect("resolver")
    }

    fn cache_status(resolver: &IteratorResolver, zone: &str, status: ZoneStatus) {
        resolver
            .zones
            .lock()
            .expect("zone cache")
            .insert(&n(zone), status, ZONE_STATUS_TTL);
    }

    #[test]
    fn cached_insecure_cover_applies_to_descendants() {
        let resolver = resolver_with_anchor(None);
        cache_status(&resolver, "google.com.", ZoneStatus::insecure());

        assert!(resolver.cached_insecure_cover(&n("www.l.google.com.")));
        assert!(resolver.cached_insecure_cover(&n("google.com.")));
        assert!(!resolver.cached_insecure_cover(&n("www.example.net.")));
    }

    #[test]
    fn cached_insecure_cover_stops_at_a_trust_anchor() {
        let resolver = resolver_with_anchor(Some("secure.l.google.com."));
        cache_status(&resolver, "google.com.", ZoneStatus::insecure());

        assert!(!resolver.cached_insecure_cover(&n("www.secure.l.google.com.")));
        assert!(!resolver.cached_insecure_cover(&n("secure.l.google.com.")));
        assert!(resolver.cached_insecure_cover(&n("www.l.google.com.")));
    }

    #[test]
    fn cached_secure_status_stops_the_walk() {
        let resolver = resolver_with_anchor(None);
        cache_status(&resolver, "google.com.", ZoneStatus::insecure());
        cache_status(
            &resolver,
            "secure.l.google.com.",
            ZoneStatus::secure(Vec::new()),
        );

        assert!(!resolver.cached_insecure_cover(&n("www.secure.l.google.com.")));
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
