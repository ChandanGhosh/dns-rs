//! Runner that drives `dns-iter` against loopback replay servers.

use std::str::FromStr;

use dns_iter::IteratorResolver;
use dns_proto::{Message, RecordType};

use crate::compare::compare_answer;
use crate::error::ReplayError;
use crate::fake::{FakeNetwork, resolver_config};
use crate::model::{ReplayFile, Scenario, Step, StepKind};
use crate::parser::parse;

/// Result of running every scenario in one replay file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// File source name.
    pub source: String,
    /// Per-scenario results in file order.
    pub scenarios: Vec<ScenarioReport>,
}

/// Result of running one replay scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioReport {
    /// Scenario name from the replay file.
    pub name: String,
    /// Number of steps executed.
    pub steps_run: usize,
}

/// Parse and run one replay file.
///
/// # Errors
///
/// Returns [`ReplayError`] for parse failures, unsupported steps, fake-network
/// setup failures, resolver failures, or failed assertions.
pub async fn run_file(source: &str, text: &str) -> Result<Report, ReplayError> {
    let file = parse(source, text)?;
    run_parsed(&file).await
}

/// Run every scenario in an already parsed replay file.
///
/// # Errors
///
/// Returns the first scenario failure; later scenarios are not run.
pub async fn run_parsed(file: &ReplayFile) -> Result<Report, ReplayError> {
    let mut scenarios = Vec::with_capacity(file.scenarios.len());
    for scenario in &file.scenarios {
        scenarios.push(run_scenario(scenario).await?);
    }
    Ok(Report {
        source: file.source.clone(),
        scenarios,
    })
}

/// Run one replay scenario.
///
/// # Errors
///
/// Returns [`ReplayError`] if the scenario uses an unsupported step, cannot be
/// bound to loopback, fails to resolve, or fails an answer assertion.
pub async fn run_scenario(scenario: &Scenario) -> Result<ScenarioReport, ReplayError> {
    validate_steps(scenario)?;
    let network = FakeNetwork::start(scenario).await?;
    let resolver = IteratorResolver::with_config(resolver_config(network.map()), None)?;
    let mut last_answer: Option<Message> = None;
    let mut steps_run = 0;
    let result: std::result::Result<(), ReplayError> = async {
        for step in &scenario.steps {
            network.state().set_time(step.time).await;
            execute_step(step, scenario, &resolver, &network, &mut last_answer).await?;
            steps_run += 1;
        }
        Ok(())
    }
    .await;
    network.stop().await;
    result?;
    Ok(ScenarioReport {
        name: scenario.name.clone(),
        steps_run,
    })
}

fn validate_steps(scenario: &Scenario) -> Result<(), ReplayError> {
    scenario
        .steps
        .iter()
        .find(|step| !step.kind.is_supported())
        .map_or(Ok(()), |step| {
            Err(ReplayError::UnsupportedStep {
                scenario: scenario.name.clone(),
                time: step.time,
                event: step.kind.name(),
            })
        })
}

async fn execute_step(
    step: &Step,
    scenario: &Scenario,
    resolver: &IteratorResolver,
    network: &FakeNetwork,
    last_answer: &mut Option<Message>,
) -> Result<(), ReplayError> {
    match &step.kind {
        StepKind::Query => {
            let entry = step.entry.as_ref().ok_or_else(|| ReplayError::Scenario {
                scenario: scenario.name.clone(),
                message: format!("step {} QUERY has no entry", step.time),
            })?;
            let question = entry
                .first_reply()
                .and_then(|reply| reply.question.first())
                .ok_or_else(|| ReplayError::Scenario {
                    scenario: scenario.name.clone(),
                    message: format!("step {} QUERY has no question", step.time),
                })?;
            if !question.class.eq_ignore_ascii_case("IN") {
                return Err(ReplayError::Scenario {
                    scenario: scenario.name.clone(),
                    message: format!("unsupported query class {}", question.class),
                });
            }
            let rtype =
                RecordType::from_str(&question.rtype.to_ascii_uppercase()).map_err(|error| {
                    ReplayError::Scenario {
                        scenario: scenario.name.clone(),
                        message: format!("invalid query type {:?}: {error}", question.rtype),
                    }
                })?;
            match resolver.resolve(&question.owner, rtype).await {
                Ok(answer) => {
                    *last_answer = Some(answer);
                    Ok(())
                }
                Err(error) => {
                    let queries = network.state().queries().await;
                    Err(ReplayError::Scenario {
                        scenario: scenario.name.clone(),
                        message: format!(
                            "step {} resolution failed: {error}; upstream queries: {queries:?}",
                            step.time
                        ),
                    })
                }
            }
        }
        StepKind::CheckAnswer => {
            let entry = step.entry.as_ref().ok_or_else(|| ReplayError::Scenario {
                scenario: scenario.name.clone(),
                message: format!("step {} CHECK_ANSWER has no entry", step.time),
            })?;
            let answer = last_answer.as_ref().ok_or_else(|| ReplayError::Scenario {
                scenario: scenario.name.clone(),
                message: format!("step {} CHECK_ANSWER has no prior QUERY", step.time),
            })?;
            let problems = compare_answer(entry, answer, network.map().reverse());
            if problems.is_empty() {
                Ok(())
            } else {
                Err(ReplayError::Assertion {
                    scenario: scenario.name.clone(),
                    time: step.time,
                    problems,
                })
            }
        }
        StepKind::TimePasses(seconds) => {
            let current = network.state().time().await;
            network
                .state()
                .set_time(current.saturating_add(*seconds))
                .await;
            Ok(())
        }
        other => Err(ReplayError::UnsupportedStep {
            scenario: scenario.name.clone(),
            time: step.time,
            event: other.name(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::run_file;

    const SCENARIO: &str = r#"
        CONFIG_END
        SCENARIO_BEGIN direct answer
        RANGE_BEGIN 0 100
            ADDRESS 193.0.14.129
            ENTRY_BEGIN
                MATCH opcode qtype qname
                REPLY QR AA NOERROR
                SECTION QUESTION
                example.com. IN A
                SECTION ANSWER
                example.com. 60 IN A 192.0.2.1
            ENTRY_END
        RANGE_END
        STEP 1 QUERY
        ENTRY_BEGIN
        SECTION QUESTION
        example.com. IN A
        ENTRY_END
        STEP 2 CHECK_ANSWER
        ENTRY_BEGIN
        MATCH all
        REPLY QR NOERROR
        SECTION QUESTION
        example.com. IN A
        SECTION ANSWER
        example.com. 60 IN A 192.0.2.1
        ENTRY_END
        SCENARIO_END
    "#;

    #[tokio::test]
    async fn runs_a_direct_answer_scenario() {
        let report = run_file("direct.rpl", SCENARIO).await.expect("run");
        assert_eq!(report.scenarios.len(), 1);
        assert_eq!(report.scenarios[0].name, "direct answer");
        assert_eq!(report.scenarios[0].steps_run, 2);
    }
}
