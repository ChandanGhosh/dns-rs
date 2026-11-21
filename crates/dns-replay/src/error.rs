//! Errors produced while parsing or running replay scenarios.

use std::io;

use crate::parser::ParseError;

/// A replay harness failure.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// The replay file could not be parsed.
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// A scenario uses a step the first-pass runner cannot execute.
    #[error("{scenario}: step {time} uses unsupported event {event}")]
    UnsupportedStep {
        /// Scenario name.
        scenario: String,
        /// Simulated step time.
        time: u64,
        /// Event name from the replay file.
        event: String,
    },
    /// A scenario cannot be mapped onto the fake loopback network.
    #[error("{scenario}: {message}")]
    Scenario {
        /// Scenario name.
        scenario: String,
        /// Why the scenario cannot run.
        message: String,
    },
    /// A replay assertion failed.
    #[error("{scenario}: step {time}: {problems}", problems = problems.join("; "))]
    Assertion {
        /// Scenario name.
        scenario: String,
        /// Simulated step time.
        time: u64,
        /// Semantic differences from the expected message.
        problems: Vec<String>,
    },
    /// DNS encoding or decoding failed.
    #[error("DNS message error: {0}")]
    Message(String),
    /// A fake socket failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}
