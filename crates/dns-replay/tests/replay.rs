//! Conformance suite over the frozen bundled replay manifest.

use std::fs;
use std::path::{Path, PathBuf};

use dns_replay::{ReplayError, run_file};

fn scenarios_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/scenarios")
}

fn manifest() -> Vec<String> {
    fs::read_to_string(scenarios_dir().join("MANIFEST"))
        .expect("read manifest")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

#[tokio::test]
async fn bundled_replay_scenarios_pass() {
    let names = manifest();
    assert!(names.len() >= 4, "the first-pass gate is four scenarios");
    for name in names {
        let path = scenarios_dir().join(&name);
        let text =
            fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let report = run_file(&name, &text)
            .await
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert!(!report.scenarios.is_empty(), "{name} has no scenarios");
        for scenario in report.scenarios {
            assert!(scenario.steps_run > 0, "{name}/{}: no steps", scenario.name);
        }
    }
}

#[test]
fn manifest_covers_every_bundled_scenario() {
    let listed = manifest();
    let mut on_disk = fs::read_dir(scenarios_dir())
        .expect("read scenarios directory")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".rpl"))
        .collect::<Vec<_>>();
    on_disk.sort_unstable();
    let mut sorted = listed.clone();
    sorted.sort_unstable();
    assert_eq!(on_disk, sorted, "add excluded scenarios to UNSUPPORTED.md");
}

#[tokio::test]
async fn unsupported_step_fails_loudly() {
    let text = r#"
CONFIG_END
SCENARIO_BEGIN Unsupported step
RANGE_BEGIN 0 100
    ADDRESS 193.0.14.129
    ENTRY_BEGIN
        MATCH opcode qtype qname
        REPLY QR NOERROR
        SECTION QUESTION
        example. IN NS
        SECTION ANSWER
        example. 3600 IN NS ns.example.
    ENTRY_END
RANGE_END
STEP 1 QUERY
ENTRY_BEGIN
SECTION QUESTION
example. IN NS
ENTRY_END
STEP 2 CHECK_OUT_QUERY
ENTRY_BEGIN
MATCH opcode qtype qname
SECTION QUESTION
example. IN NS
ENTRY_END
SCENARIO_END
"#;
    let error = run_file("unsupported.rpl", text)
        .await
        .expect_err("unsupported steps must not be skipped");
    assert!(
        matches!(error, ReplayError::UnsupportedStep { .. }),
        "unexpected error: {error}"
    );
}
