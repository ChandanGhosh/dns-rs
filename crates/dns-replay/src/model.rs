//! Data model for the supported subset of Unbound replay files.

use std::collections::HashMap;
use std::net::IpAddr;

use dns_proto::ResponseCode;

/// One parsed `.rpl` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayFile {
    /// Source name supplied when the file was parsed.
    pub source: String,
    /// Opaque configuration lines before `CONFIG_END`.
    pub config: ReplayConfig,
    /// Scenarios in file order.
    pub scenarios: Vec<Scenario>,
}

/// Configuration block of a replay file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplayConfig {
    /// Tokens following `COMMANDLINE`.
    pub commandline: Vec<String>,
    /// Unmodified configuration lines, used when reporting unsupported files.
    pub lines: Vec<String>,
    /// Lines inside `AUTOTRUST_FILE` blocks.
    pub autotrust: Vec<String>,
    /// Named temporary file contents.
    pub tempfiles: HashMap<String, String>,
}

/// One `SCENARIO_BEGIN` ... `SCENARIO_END` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scenario {
    /// Scenario name from the begin directive.
    pub name: String,
    /// Scripted fake-server responses.
    pub ranges: Vec<Range>,
    /// Clock-ordered test steps.
    pub steps: Vec<Step>,
}

/// One `RANGE_BEGIN` ... `RANGE_END` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Range {
    /// Inclusive first simulated time.
    pub start: u64,
    /// Inclusive last simulated time.
    pub end: u64,
    /// Server address this range serves, when specified.
    pub address: Option<IpAddr>,
    /// Scripted messages.
    pub entries: Vec<Entry>,
}

/// One `STEP` directive and its optional message block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// Simulated time from the step header.
    pub time: u64,
    /// Step action.
    pub kind: StepKind,
    /// Per-step address override.
    pub address: Option<IpAddr>,
    /// Message injected into or expected from the client side.
    pub entry: Option<Entry>,
    /// Filename used by `CHECK_TEMPFILE` and `CHECK_AUTOTRUST`.
    pub file: Option<String>,
}

/// Supported replay step actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepKind {
    /// Inject a client query.
    Query,
    /// Compare the client response with the following entry.
    CheckAnswer,
    /// Compare an upstream query with the following entry.
    CheckOutQuery,
    /// Advance simulated time by a number of seconds.
    TimePasses(u64),
    /// A fake-server reply injected outside a range.
    Reply,
    /// Advance to the next upstream timeout.
    Timeout,
    /// Run until upstream traffic stops.
    Traffic,
    /// Compare an RFC 5011 autotrust state file.
    CheckAutotrust,
    /// Compare a temporary file.
    CheckTempfile,
    /// Seed the infrastructure cache.
    InfraRtt,
    /// Remove an entry from the message cache.
    FlushMessage,
    /// Expire an entry from the message cache.
    ExpireMessage,
    /// Expect an error event.
    Error,
    /// A recognized event the harness cannot execute yet.
    Unsupported(String),
}

impl StepKind {
    /// Whether the first-pass runner can execute the step.
    pub fn is_supported(&self) -> bool {
        matches!(self, Self::Query | Self::CheckAnswer | Self::TimePasses(_))
    }

    /// Event name as written in a replay file.
    pub fn name(&self) -> String {
        match self {
            Self::Query => "QUERY".to_owned(),
            Self::CheckAnswer => "CHECK_ANSWER".to_owned(),
            Self::CheckOutQuery => "CHECK_OUT_QUERY".to_owned(),
            Self::TimePasses(_) => "TIME_PASSES".to_owned(),
            Self::Reply => "REPLY".to_owned(),
            Self::Timeout => "TIMEOUT".to_owned(),
            Self::Traffic => "TRAFFIC".to_owned(),
            Self::CheckAutotrust => "CHECK_AUTOTRUST".to_owned(),
            Self::CheckTempfile => "CHECK_TEMPFILE".to_owned(),
            Self::InfraRtt => "INFRA_RTT".to_owned(),
            Self::FlushMessage => "FLUSH_MESSAGE".to_owned(),
            Self::ExpireMessage => "EXPIRE_MESSAGE".to_owned(),
            Self::Error => "ERROR".to_owned(),
            Self::Unsupported(name) => name.clone(),
        }
    }
}

/// Header flags a replay entry may assert or set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EntryFlags {
    /// Query/response bit.
    pub qr: bool,
    /// Authoritative answer bit.
    pub aa: bool,
    /// Truncation bit.
    pub tc: bool,
    /// Recursion desired bit.
    pub rd: bool,
    /// Recursion available bit.
    pub ra: bool,
    /// Authentic data bit.
    pub ad: bool,
    /// Checking disabled bit.
    pub cd: bool,
}

/// A textual DNS message inside an `ENTRY_BEGIN` ... `ENTRY_END` block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    /// Tokens from the `MATCH` directive.
    pub matches: Vec<String>,
    /// Tokens from the `ADJUST` directive.
    pub adjusts: Vec<String>,
    /// Wire packets emitted by the entry, including `EXTRA_PACKET`s.
    pub replies: Vec<Reply>,
}

impl Entry {
    /// Return the first packet in the entry.
    pub fn first_reply(&self) -> Option<&Reply> {
        self.replies.first()
    }
}

/// One header and section set inside an entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reply {
    /// Response code from the `REPLY` directive.
    pub rcode: ResponseCode,
    /// Opcode token from the `REPLY` directive.
    pub op_code: String,
    /// Header flags from the `REPLY` directive.
    pub flags: EntryFlags,
    /// Question lines.
    pub question: Vec<RecordLine>,
    /// Answer-section records.
    pub answer: Vec<RecordLine>,
    /// Authority-section records.
    pub authority: Vec<RecordLine>,
    /// Additional-section records.
    pub additional: Vec<RecordLine>,
}

/// One record line in a replay entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordLine {
    /// Owner name.
    pub owner: String,
    /// Record TTL when the file specified one.
    pub ttl: Option<u32>,
    /// Class token, normally `IN`.
    pub class: String,
    /// Type token, for example `A` or `CNAME`.
    pub rtype: String,
    /// RDATA tokens.
    pub rdata: Vec<String>,
}

impl Default for RecordLine {
    fn default() -> Self {
        Self {
            owner: String::new(),
            ttl: None,
            class: "IN".to_owned(),
            rtype: String::new(),
            rdata: Vec::new(),
        }
    }
}
