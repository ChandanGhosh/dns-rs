//! RFC 5011 automatic trust-anchor maintenance.
//!
//! A [`AutoTrustAnchor`] tracks the DNSKEY records that are candidates to be
//! trust anchors for one zone. New keys stay in [`KeyState::AddPend`] for the
//! add hold-down time, revoked keys stay in [`KeyState::Revoked`] for the
//! remove hold-down time, and only [`KeyState::Valid`] keys are used to seed
//! the resolver's trust store.
//!
//! The state is persisted in a file format that mirrors Unbound's
//! `auto-trust-anchor-file`: a small `;;key: value` header, then one DNSKEY
//! record per key followed by a `;;state=N [ add ] [ remove ]` line. All
//! timestamps are Unix seconds.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE64;
use dns_proto::{Name, PublicKey, Record};

use crate::crypto::dnskey_of;
use crate::trust::{TrustAnchor, parse_anchor_record};

/// How long a new key must be continuously present before it is trusted.
pub const ADD_HOLD_DOWN: u64 = 30 * 24 * 60 * 60;

/// How long a revoked or missing key is retained before it is dropped.
pub const REMOVE_HOLD_DOWN: u64 = 30 * 24 * 60 * 60;

/// Default interval between successful probes (12 hours).
pub const DEFAULT_PROBE_INTERVAL: u64 = 12 * 60 * 60;

/// Default retry delay after a failed probe (1 hour).
pub const DEFAULT_RETRY_TIME: u64 = 60 * 60;

/// The lifecycle state of one candidate trust anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyState {
    /// The key is present but has not completed the add hold-down.
    AddPend,
    /// The key is trusted and may validate the zone's DNSKEY RRset.
    Valid,
    /// The key carried the REVOKE bit and is waiting for the remove hold-down.
    Revoked,
}

impl KeyState {
    /// The numeric state used by Unbound's file format.
    pub fn as_unbound(self) -> u8 {
        match self {
            Self::AddPend => 1,
            Self::Valid => 2,
            Self::Revoked => 4,
        }
    }

    fn from_unbound(value: u8) -> Self {
        match value {
            1 => Self::AddPend,
            4 | 5 => Self::Revoked,
            // 0 (initial), 2 (valid) and 3 (missing) all mean "trusted".
            _ => Self::Valid,
        }
    }
}

/// One tracked DNSKEY.
#[derive(Clone, Debug)]
pub struct AutoKey {
    /// The DNSKEY record exactly as last observed.
    pub record: Record,
    /// Current lifecycle state.
    pub state: KeyState,
    /// When the key first appeared (Unix seconds).
    pub first_seen: u64,
    /// When the key was last present in the DNSKEY RRset.
    pub last_seen: u64,
    /// When the key was observed with the REVOKE bit set.
    pub revoked_at: Option<u64>,
}

impl AutoKey {
    fn new(record: Record, state: KeyState, first_seen: u64, last_seen: u64) -> Self {
        Self {
            record,
            state,
            first_seen,
            last_seen,
            revoked_at: (state == KeyState::Revoked).then_some(first_seen),
        }
    }

    /// The key tag of the tracked record.
    pub fn key_tag(&self) -> Option<u16> {
        dnskey_of(&self.record)?.calculate_key_tag().ok()
    }
}

/// RFC 5011 state for one zone.
#[derive(Clone, Debug)]
pub struct AutoTrustAnchor {
    /// Zone apex these keys belong to.
    pub zone: Name,
    /// Tracked keys.
    pub keys: Vec<AutoKey>,
    /// When the DNSKEY RRset last validated.
    pub last_success: Option<u64>,
    /// When the next probe is due.
    pub next_probe: Option<u64>,
    /// Consecutive failed probes.
    pub query_failed: u32,
    /// Interval between successful probes.
    pub probe_interval: u64,
    /// Delay before retrying a failed probe.
    pub retry_time: u64,
}

impl AutoTrustAnchor {
    /// Create an empty tracker for `zone`.
    pub fn new(zone: Name) -> Self {
        Self {
            zone,
            keys: Vec::new(),
            last_success: None,
            next_probe: None,
            query_failed: 0,
            probe_interval: DEFAULT_PROBE_INTERVAL,
            retry_time: DEFAULT_RETRY_TIME,
        }
    }

    /// Seed a tracker from already-trusted keys.
    pub fn from_trust_anchor(anchor: &TrustAnchor, now: u64) -> Self {
        let mut tracker = Self::new(anchor.name.clone());
        for record in &anchor.keys {
            if dnskey_of(record).is_some_and(|key| key.secure_entry_point()) {
                tracker
                    .keys
                    .push(AutoKey::new(record.clone(), KeyState::Valid, now, now));
            }
        }
        tracker.last_success = Some(now);
        tracker.next_probe = Some(now + tracker.probe_interval);
        tracker
    }

    /// Load a tracker from an Unbound-style auto-trust-anchor file.
    pub fn load(path: &Path) -> Result<Self, AutoTrustError> {
        let text = std::fs::read_to_string(path).map_err(|source| AutoTrustError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&text)
    }

    /// Parse a tracker from Unbound-style text.
    pub fn parse(text: &str) -> Result<Self, AutoTrustError> {
        let mut zone: Option<Name> = None;
        let mut keys: Vec<AutoKey> = Vec::new();
        let mut last_success = None;
        let mut next_probe = None;
        let mut query_failed = 0;
        let mut probe_interval = DEFAULT_PROBE_INTERVAL;
        let mut retry_time = DEFAULT_RETRY_TIME;

        for (index, raw_line) in text.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix(";;state=") {
                let Some(key) = keys.last_mut() else {
                    continue;
                };
                let (state, first, revoked) = parse_state(rest);
                key.state = state;
                if let Some(first) = first {
                    key.first_seen = first;
                }
                if let Some(revoked) = revoked {
                    key.revoked_at = Some(revoked);
                }
                continue;
            }
            if let Some(rest) = line.strip_prefix(";;") {
                let (name, value) = rest.split_once(':').unwrap_or((rest, ""));
                let value = value.trim();
                match name.trim() {
                    "id" => {
                        if let Some(first) = value.split_whitespace().next()
                            && let Ok(parsed) = Name::from_ascii(first)
                        {
                            zone = Some(parsed);
                        }
                    }
                    "last_success" => last_success = value.parse().ok(),
                    "next_probe_time" => next_probe = value.parse().ok(),
                    "query_failed" => query_failed = value.parse().unwrap_or(0),
                    "query_interval" => {
                        probe_interval = value.parse().unwrap_or(DEFAULT_PROBE_INTERVAL);
                    }
                    "retry_time" => retry_time = value.parse().unwrap_or(DEFAULT_RETRY_TIME),
                    _ => {}
                }
                continue;
            }
            if line.starts_with(';') {
                continue;
            }

            let record = parse_anchor_record(line).map_err(|message| {
                AutoTrustError::Parse(format!("line {}: {message}", index + 1))
            })?;
            let Some(key) = dnskey_of(&record) else {
                return Err(AutoTrustError::Parse(format!(
                    "line {}: auto-trust-anchor-file only supports DNSKEY records",
                    index + 1
                )));
            };
            if !key.secure_entry_point() {
                continue;
            }
            if zone.is_none() {
                zone = Some(record.name.clone());
            }
            // A key without state metadata is treated as an explicit anchor.
            keys.push(AutoKey::new(record, KeyState::Valid, 0, 0));
        }

        let zone = zone.ok_or_else(|| {
            AutoTrustError::Parse("no zone or DNSKEY records in auto-trust-anchor file".to_owned())
        })?;
        // The file does not store a per-key last-seen timestamp. The last
        // successful probe is the best available lower bound, and it keeps a
        // long-standing key from being purged before its remove hold-down.
        let last_seen_default = last_success.unwrap_or(0);
        for key in &mut keys {
            if key.last_seen == 0 {
                key.last_seen = last_seen_default.max(key.first_seen);
            }
        }
        Ok(Self {
            zone,
            keys,
            last_success,
            next_probe,
            query_failed,
            probe_interval,
            retry_time,
        })
    }

    /// Serialize the tracker in Unbound-style text.
    pub fn render(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, ";;id: {} 1", self.zone);
        if let Some(value) = self.last_success {
            let _ = writeln!(output, ";;last_success: {value}");
        }
        if let Some(value) = self.next_probe {
            let _ = writeln!(output, ";;next_probe_time: {value}");
        }
        let _ = writeln!(output, ";;query_failed: {}", self.query_failed);
        let _ = writeln!(output, ";;query_interval: {}", self.probe_interval);
        let _ = writeln!(output, ";;retry_time: {}", self.retry_time);
        for key in &self.keys {
            let Some(dnskey) = dnskey_of(&key.record) else {
                continue;
            };
            let _ = writeln!(
                output,
                "{}\t{}\tIN\tDNSKEY\t{} 3 {} {}",
                key.record.name,
                key.record.ttl,
                dnskey.flags(),
                u8::from(dnskey.public_key().algorithm()),
                BASE64.encode(dnskey.public_key().public_bytes())
            );
            let _ = writeln!(
                output,
                ";;state={} [ {} ] [ {} ]",
                key.state.as_unbound(),
                format_utc(key.first_seen),
                format_utc(key.revoked_at.unwrap_or(0))
            );
        }
        output
    }

    /// Write the tracker to `path`.
    pub fn save(&self, path: &Path) -> Result<(), AutoTrustError> {
        if let Some(parent) = path.parent()
            && !parent.is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|source| AutoTrustError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        }
        std::fs::write(path, self.render()).map_err(|source| AutoTrustError::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Records that are currently trusted.
    pub fn trusted_keys(&self) -> Vec<Record> {
        self.keys
            .iter()
            .filter(|key| key.state == KeyState::Valid)
            .map(|key| key.record.clone())
            .collect()
    }

    /// A [`TrustAnchor`] containing the currently valid keys.
    pub fn trust_anchor(&self) -> TrustAnchor {
        TrustAnchor::from_keys(self.zone.clone(), self.trusted_keys())
    }

    /// Whether the tracker has at least one valid key.
    pub fn has_valid_key(&self) -> bool {
        self.keys.iter().any(|key| key.state == KeyState::Valid)
    }

    /// Whether a probe is due at `now`.
    pub fn is_due(&self, now: u64) -> bool {
        self.next_probe.is_none_or(|next| now >= next)
    }

    /// Record a successful probe that returned a validated DNSKEY RRset.
    pub fn record_success(&mut self, now: u64) {
        self.last_success = Some(now);
        self.query_failed = 0;
        self.next_probe = Some(now + self.probe_interval);
    }

    /// Record a failed probe, scheduling a retry.
    pub fn record_failure(&mut self, now: u64) {
        self.query_failed = self.query_failed.saturating_add(1);
        let shift = self.query_failed.min(4);
        let delay = self
            .retry_time
            .saturating_mul(1u64 << shift)
            .min(self.probe_interval);
        self.next_probe = Some(now + delay);
    }

    /// Apply a validated DNSKEY RRset to the state machine.
    ///
    /// `records` must have already been authenticated against a currently
    /// valid key. Keys that are new enter the add hold-down; keys with the
    /// REVOKE bit move to [`KeyState::Revoked`]; keys that disappear are
    /// removed after the remove hold-down.
    pub fn update(&mut self, records: &[Record], now: u64) {
        // Without a verified signature, treat every REVOKE-bit record as
        // revoked. Callers that have authenticated the self-signature should
        // use [`Self::update_with_revocations`].
        let revoked: Vec<Record> = records
            .iter()
            .filter(|record| dnskey_of(record).is_some_and(|key| key.revoke()))
            .cloned()
            .collect();
        self.update_with_revocations(records, &revoked, now);
    }

    /// Apply a validated DNSKEY RRset, honoring only the listed revocations.
    ///
    /// `revoked` must contain the keys whose own signature covered the
    /// DNSKEY RRset, as required by RFC 5011 section 4.1.
    pub fn update_with_revocations(
        &mut self,
        records: &[Record],
        revoked_records: &[Record],
        now: u64,
    ) {
        let candidates: Vec<Record> = records
            .iter()
            .filter(|record| {
                dnskey_of(record).is_some_and(|key| key.zone_key() && key.secure_entry_point())
            })
            .cloned()
            .collect();

        let mut seen = vec![false; candidates.len()];
        let mut index = 0;
        while index < self.keys.len() {
            let key = &mut self.keys[index];
            let Some(matched) = candidates
                .iter()
                .position(|record| same_key_ignoring_revoke(record, &key.record))
            else {
                match key.state {
                    KeyState::AddPend => {
                        // A pending key that vanished restarts its hold-down.
                        self.keys.remove(index);
                        continue;
                    }
                    KeyState::Valid => {
                        if now.saturating_sub(key.last_seen) >= REMOVE_HOLD_DOWN {
                            self.keys.remove(index);
                            continue;
                        }
                    }
                    KeyState::Revoked => {}
                }
                index += 1;
                continue;
            };

            seen[matched] = true;
            key.last_seen = now;
            let candidate = &candidates[matched];
            let revoked = revoked_records
                .iter()
                .any(|record| same_key_ignoring_revoke(record, candidate));
            match key.state {
                KeyState::AddPend => {
                    if revoked {
                        key.state = KeyState::Revoked;
                        key.revoked_at = Some(now);
                        key.record = candidate.clone();
                    }
                }
                KeyState::Valid => {
                    key.record = candidate.clone();
                    if revoked {
                        key.state = KeyState::Revoked;
                        key.revoked_at = Some(now);
                    }
                }
                KeyState::Revoked => {}
            }
            index += 1;
        }

        for (matched, record) in candidates.iter().enumerate() {
            if !seen[matched] {
                self.keys
                    .push(AutoKey::new(record.clone(), KeyState::AddPend, now, now));
            }
        }

        // Promote keys that have completed the add hold-down.
        for key in &mut self.keys {
            if key.state == KeyState::AddPend
                && key.last_seen == now
                && now.saturating_sub(key.first_seen) >= ADD_HOLD_DOWN
            {
                key.state = KeyState::Valid;
            }
        }

        // Drop revoked keys that have completed the remove hold-down.
        self.keys.retain(|key| {
            key.state != KeyState::Revoked
                || key
                    .revoked_at
                    .is_none_or(|revoked| now.saturating_sub(revoked) < REMOVE_HOLD_DOWN)
        });
    }
}

/// Whether two DNSKEY records are the same key, ignoring the REVOKE bit.
pub fn same_key_ignoring_revoke(left: &Record, right: &Record) -> bool {
    let (Some(left), Some(right)) = (dnskey_of(left), dnskey_of(right)) else {
        return false;
    };
    const REVOKE: u16 = 0b0000_0000_1000_0000;
    (left.flags() & !REVOKE) == (right.flags() & !REVOKE)
        && left.public_key().algorithm() == right.public_key().algorithm()
        && left.public_key().public_bytes() == right.public_key().public_bytes()
}

fn parse_state(text: &str) -> (KeyState, Option<u64>, Option<u64>) {
    let mut parts = text.split_whitespace();
    let state = parts
        .next()
        .and_then(|value| value.parse::<u8>().ok())
        .map(KeyState::from_unbound)
        .unwrap_or(KeyState::Valid);

    let mut timestamps = Vec::new();
    let tokens: Vec<&str> = parts.collect();
    let mut index = 0;
    while index < tokens.len() {
        if tokens[index] == "[" {
            let mut end = index + 1;
            let mut value = String::new();
            while end < tokens.len() && tokens[end] != "]" {
                value.push_str(tokens[end]);
                end += 1;
            }
            if let Some(parsed) = parse_timestamp(&value) {
                timestamps.push(parsed);
            }
            index = end + 1;
        } else {
            if let Some(parsed) = parse_timestamp(tokens[index]) {
                timestamps.push(parsed);
            }
            index += 1;
        }
    }

    let first = timestamps.first().copied().filter(|value| *value > 0);
    let revoked = timestamps.get(1).copied().filter(|value| *value > 0);
    (state, first, revoked)
}

/// Parse either Unix seconds or an `YYYY-MM-DDTHH:MM:SSZ` timestamp.
fn parse_timestamp(text: &str) -> Option<u64> {
    let text = text
        .trim()
        .trim_matches(|character| character == '[' || character == ']');
    if text.is_empty() {
        return None;
    }
    if let Ok(value) = text.parse::<u64>() {
        return Some(value);
    }
    let (date, time) = text.split_once('T')?;
    let time = time.trim_end_matches('Z');
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;
    if year <= 0 || month == 0 || day == 0 {
        return Some(0);
    }
    let mut time_parts = time.split(':');
    let hour: i64 = time_parts.next()?.parse().ok()?;
    let minute: i64 = time_parts.next()?.parse().ok()?;
    let second: i64 = time_parts.next()?.parse().ok()?;
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second;
    u64::try_from(seconds).ok()
}

/// Format Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
fn format_utc(seconds: u64) -> String {
    if seconds == 0 {
        return "0000-00-00T00:00:00Z".to_owned();
    }
    let days = (seconds / 86_400) as i64;
    let remainder = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        remainder / 3_600,
        (remainder % 3_600) / 60,
        remainder % 60
    )
}

/// Convert a Unix day count to a civil date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Convert a civil date to a Unix day count.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = (year - era * 400) as u64;
    let mp = if month > 2 { month - 3 } else { month + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + u64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

/// Unix time in seconds.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Errors while loading or saving an auto-trust-anchor file.
#[derive(Debug, thiserror::Error)]
pub enum AutoTrustError {
    /// The file could not be read or written.
    #[error("auto-trust-anchor file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// A line was not valid Unbound trust-anchor syntax.
    #[error("invalid auto-trust-anchor file: {0}")]
    Parse(String),
}

#[cfg(test)]
mod tests {
    use super::{
        ADD_HOLD_DOWN, AutoTrustAnchor, KeyState, REMOVE_HOLD_DOWN, same_key_ignoring_revoke,
        unix_now,
    };
    use dns_proto::{Algorithm, DNSKEY, DNSSECRData, Name, PublicKeyBuf, RData, Record};

    fn key(seed: u8, flags: u16) -> Record {
        let dnskey =
            DNSKEY::with_flags(flags, PublicKeyBuf::new(vec![seed; 32], Algorithm::ED25519));
        Record::from_rdata(
            Name::root(),
            3600,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        )
    }

    fn tracker() -> AutoTrustAnchor {
        let mut tracker = AutoTrustAnchor::new(Name::root());
        tracker.update(&[key(1, 257)], 0);
        // Complete the add hold-down for the initial key.
        tracker.update(&[key(1, 257)], ADD_HOLD_DOWN);
        tracker
    }

    #[test]
    fn new_keys_complete_add_hold_down() {
        let tracker = tracker();
        assert_eq!(tracker.keys.len(), 1);
        assert_eq!(tracker.keys[0].state, KeyState::Valid);
        assert_eq!(tracker.trusted_keys().len(), 1);
    }

    #[test]
    fn pending_key_is_not_trusted_before_hold_down() {
        let mut tracker = tracker();
        tracker.update(&[key(1, 257), key(2, 257)], ADD_HOLD_DOWN + 10);
        assert_eq!(tracker.keys.len(), 2);
        assert_eq!(tracker.trusted_keys().len(), 1);
        assert_eq!(tracker.keys[1].state, KeyState::AddPend);

        tracker.update(
            &[key(1, 257), key(2, 257)],
            ADD_HOLD_DOWN + 10 + ADD_HOLD_DOWN,
        );
        assert_eq!(tracker.trusted_keys().len(), 2);
    }

    #[test]
    fn missing_pending_key_restarts_hold_down() {
        let mut tracker = tracker();
        tracker.update(&[key(1, 257), key(2, 257)], ADD_HOLD_DOWN + 10);
        tracker.update(&[key(1, 257)], ADD_HOLD_DOWN + 20);
        assert_eq!(tracker.keys.len(), 1);

        tracker.update(&[key(1, 257), key(2, 257)], ADD_HOLD_DOWN + 30);
        assert_eq!(tracker.keys[1].state, KeyState::AddPend);
        assert_eq!(tracker.keys[1].first_seen, ADD_HOLD_DOWN + 30);
    }

    #[test]
    fn revoked_key_is_dropped_after_remove_hold_down() {
        let mut tracker = tracker();
        let revoked = key(1, 257 | 0x0080);
        tracker.update(std::slice::from_ref(&revoked), ADD_HOLD_DOWN + 100);
        assert_eq!(tracker.keys[0].state, KeyState::Revoked);
        assert!(tracker.trusted_keys().is_empty());

        tracker.update(&[revoked], ADD_HOLD_DOWN + 100 + REMOVE_HOLD_DOWN);
        assert!(tracker.keys.is_empty());
    }

    #[test]
    fn revoke_requires_a_verified_self_signature() {
        let mut tracker = tracker();
        let revoked = key(1, 257 | 0x0080);

        tracker.update_with_revocations(std::slice::from_ref(&revoked), &[], ADD_HOLD_DOWN + 100);
        assert_eq!(tracker.keys[0].state, KeyState::Valid);
        assert_eq!(tracker.trusted_keys().len(), 1);

        tracker.update_with_revocations(
            std::slice::from_ref(&revoked),
            std::slice::from_ref(&revoked),
            ADD_HOLD_DOWN + 200,
        );
        assert_eq!(tracker.keys[0].state, KeyState::Revoked);
    }

    #[test]
    fn valid_key_disappearing_is_removed_after_hold_down() {
        let mut tracker = tracker();
        tracker.update(&[], ADD_HOLD_DOWN + 100);
        assert_eq!(tracker.keys.len(), 1);
        tracker.update(&[], ADD_HOLD_DOWN + 100 + REMOVE_HOLD_DOWN);
        assert!(tracker.keys.is_empty());
    }

    #[test]
    fn state_file_round_trips() {
        let mut tracker = tracker();
        tracker.update(&[key(1, 257), key(2, 257)], ADD_HOLD_DOWN + 10);
        tracker.record_success(ADD_HOLD_DOWN + 10);
        let text = tracker.render();

        let parsed = AutoTrustAnchor::parse(&text).expect("parse");
        assert_eq!(parsed.zone, tracker.zone);
        assert_eq!(parsed.keys.len(), 2);
        assert_eq!(parsed.keys[0].state, KeyState::Valid);
        assert_eq!(parsed.keys[1].state, KeyState::AddPend);
        assert_eq!(parsed.keys[0].key_tag(), tracker.keys[0].key_tag());
        assert_eq!(parsed.last_success, tracker.last_success);
    }

    #[test]
    fn plain_dnskey_file_is_treated_as_valid() {
        let text = format!(
            "{} 3600 IN DNSKEY 257 3 15 {}",
            Name::root(),
            data_encoding::BASE64.encode(&[9u8; 32])
        );
        let tracker = AutoTrustAnchor::parse(&text).expect("parse");
        assert_eq!(tracker.keys.len(), 1);
        assert_eq!(tracker.keys[0].state, KeyState::Valid);
        assert!(tracker.has_valid_key());
    }

    #[test]
    fn revoke_bit_is_ignored_for_key_identity() {
        assert!(same_key_ignoring_revoke(
            &key(1, 257),
            &key(1, 257 | 0x0080)
        ));
        assert!(!same_key_ignoring_revoke(&key(1, 257), &key(2, 257)));
    }

    #[test]
    fn revoked_key_is_replaced_by_a_new_valid_key() {
        let mut tracker = tracker();
        tracker.update(&[key(1, 257), key(2, 257)], ADD_HOLD_DOWN + 10);
        tracker.update(
            &[key(1, 257), key(2, 257)],
            ADD_HOLD_DOWN + 10 + ADD_HOLD_DOWN,
        );
        assert_eq!(tracker.trusted_keys().len(), 2);

        let revoked = key(1, 257 | 0x0080);
        let revoked_at = ADD_HOLD_DOWN + 20 + ADD_HOLD_DOWN;
        tracker.update(&[revoked.clone(), key(2, 257)], revoked_at);
        assert_eq!(tracker.trusted_keys().len(), 1);
        assert_eq!(tracker.keys[0].state, KeyState::Revoked);

        tracker.update(&[revoked, key(2, 257)], revoked_at + REMOVE_HOLD_DOWN);
        assert_eq!(tracker.keys.len(), 1);
        assert_eq!(tracker.keys[0].state, KeyState::Valid);
        assert_eq!(tracker.trusted_keys().len(), 1);
    }

    #[test]
    fn failed_probes_back_off_towards_the_probe_interval() {
        let mut tracker = tracker();
        tracker.record_failure(100);
        assert_eq!(
            tracker.next_probe,
            Some(100 + 2 * super::DEFAULT_RETRY_TIME)
        );
        assert_eq!(tracker.query_failed, 1);

        for _ in 0..8 {
            tracker.record_failure(100);
        }
        assert_eq!(tracker.next_probe, Some(100 + tracker.probe_interval));
    }

    #[test]
    fn timestamps_round_trip_through_iso_format() {
        for value in [1u64, 1_700_000_000, 1_792_907_558] {
            let text = super::format_utc(value);
            assert_eq!(super::parse_timestamp(&text), Some(value), "{text}");
        }
        assert_eq!(super::format_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(super::parse_timestamp("0000-00-00T00:00:00Z"), Some(0));
    }

    #[test]
    fn saves_and_loads_from_disk() {
        let mut tracker = tracker();
        tracker.update(&[key(1, 257), key(2, 257)], ADD_HOLD_DOWN + 10);
        tracker.record_success(ADD_HOLD_DOWN + 10);

        let dir = std::env::temp_dir().join(format!(
            "dns-rs-autotrust-{}-{}",
            std::process::id(),
            unix_now()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("root.key");
        tracker.save(&path).expect("save");
        let loaded = AutoTrustAnchor::load(&path).expect("load");

        assert_eq!(loaded.zone, tracker.zone);
        assert_eq!(loaded.keys.len(), 2);
        assert_eq!(loaded.trusted_keys().len(), 1);
        assert_eq!(loaded.last_success, tracker.last_success);
        assert_eq!(loaded.next_probe, tracker.next_probe);

        std::fs::remove_dir_all(&dir).ok();
    }
}
