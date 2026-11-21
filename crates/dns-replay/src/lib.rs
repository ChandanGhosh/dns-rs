//! Unbound `.rpl` replay conformance harness for `dns-rs`.
//!
//! The harness parses replay scenarios, serves their `RANGE` entries from
//! loopback authoritative servers, and drives the real iterative resolver
//! against them. It is a development-only crate; production crates do not
//! depend on it.

pub mod compare;
pub mod error;
pub mod fake;
pub mod model;
pub mod parser;
pub mod runner;

pub use error::ReplayError;
pub use model::{
    Entry, EntryFlags, Range, ReplayConfig, ReplayFile, Reply, Scenario, Step, StepKind,
};
pub use parser::{ParseError, parse};
pub use runner::{Report, ScenarioReport, run_file, run_parsed, run_scenario};
