# Unbound replay harness design

**Status:** Design complete for M0; implementation starts in M1/M2.

## Purpose

Unbound ships 492 `.rpl` replay scenarios under `testdata/`, driven by
`testcode/testbound` and `testcode/replay.{c,h}`. They encode years of resolver
edge cases: referrals, lame servers, truncation, retries, cache expiry, CNAME and
DNAME chasing, QNAME minimisation, and DNSSEC validation.

The harness lets `dns-rs` run those scenarios deterministically against a virtual
clock and fake network. It is the primary behavioral conformance suite, complementing
RFC-derived unit tests, live interop tests, and fuzzing.

## Replay file format (summary)

A `.rpl` file has three parts:

1. **Configuration** (optional, before `CONFIG_END`)
   - `COMMANDLINE <args>`
   - `AUTOTRUST_FILE <id>` ... `AUTOTRUST_END`
   - `TEMPFILE_NAME` / `TEMPFILE_CONTENTS` / `$INCLUDE_TEMPFILE` / `TEMPFILE_END`
   - `CONFIG_END`
2. **Scenarios**
   - `SCENARIO_BEGIN <name>` ... `SCENARIO_END`
3. **Event ranges and steps**
   - `RANGE_BEGIN <start> <end>` ... `RANGE_END` describes fake server responses
     for a simulated time window, optionally with `ADDRESS <ip>`.
   - `STEP <time> <event> [ADDRESS <ip>]` advances the virtual clock and injects or
     checks an event.
   - `ENTRY_BEGIN` ... `ENTRY_END` contains a DNS message in a textual packet form
     (header fields, question, answer, authority, additional sections).

Event types that matter for `dns-rs`:

| Event | Meaning |
|---|---|
| `QUERY` | Inject a client query |
| `CHECK_ANSWER` | Assert the client response |
| `CHECK_OUT_QUERY` | Assert an upstream query (and optionally auto-reply) |
| `REPLY` | Deliver a response from a fake server |
| `TIMEOUT` | Advance to the next timeout |
| `TIME_PASSES ELAPSE <s>` | Advance the virtual clock |
| `TIME_PASSES EVAL <macro>` | Advance using a computed value |
| `TRAFFIC` | Run until traffic stops, then check |
| `CHECK_AUTOTRUST` | Compare autotrust state file |
| `CHECK_TEMPFILE` | Compare a temporary file |
| `INFRA_RTT` | Seed the infrastructure cache |
| `FLUSH_MESSAGE` / `EXPIRE_MESSAGE` | Manipulate the message cache |
| `ERROR` | Expect an error event |

Macros use `${...}` with `+ - * /`, `$var`, `${time}`, `${ctime v}`,
`${timeout}`, and `${range lo v hi}`. The implementation should support the
arithmetic and time macros first; file-comparison macros can follow.

## Required test seams

The resolver must not call `tokio::time`, `Instant::now`, `getrandom`, or real
sockets directly. Define narrow traits and inject them through a runtime context.

```rust
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
    fn sleep_until(&self, deadline: Instant) -> BoxFuture<'_, ()>;
}

pub trait Random: Send + Sync {
    fn fill(&self, buffer: &mut [u8]);
    fn u16(&self) -> u16;
}

#[async_trait]
pub trait UpstreamTransport: Send + Sync {
    async fn exchange(
        &self,
        server: SocketAddr,
        query: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, TransportError>;
}
```

Production implementations use Tokio, `getrandom`, and real sockets. The replay
implementation uses a deterministic clock, a seeded RNG, and a fake network backed
by the scenario's `RANGE`/`REPLY` entries.

The clock must distinguish the simulated wall clock from monotonic timers. Unbound
replay scenarios manipulate absolute times as well as elapsed durations.

## Fake network model

- A `FakeNetwork` holds a time-indexed set of server responses keyed by
  `(time range, server address, query name/type/class, maybe flags)`.
- On an upstream query, the fake transport records the outgoing message, then:
  - returns the matching response immediately, or
  - schedules it for delivery, or
  - returns a timeout when the scenario says so.
- `CHECK_OUT_QUERY` and `CHECK_ANSWER` compare semantic message fields, not raw
  bytes, so harmless compression or ordering differences do not fail tests.
- Truncated UDP responses trigger the real TCP fallback path, still through the
  fake transport.

## Harness architecture

```text
tests/replay/
├── mod.rs              # test entry point; discovers and runs .rpl files
├── parser.rs           # .rpl lexer/parser and macro expansion
├── scenario.rs         # ranges, steps, events, entries
├── fake_clock.rs       # virtual time and timer queue
├── fake_network.rs     # recorded queries and scripted responses
├── compare.rs          # semantic DNS message comparison
└── runner.rs           # drives the resolver and emits results
```

The harness is a dev-only crate/test target. The resolver itself must remain
independent of it.

## Scope for the first pass

Start with scenarios that exercise:

1. Basic recursion from root hints through referrals to an answer.
2. CNAME and DNAME chains.
3. NXDOMAIN and NODATA negative caching.
4. UDP truncation and TCP fallback.
5. Timeout, retry, and lame-server handling.
6. Cache TTL expiry and prefetch.
7. DNSSEC secure, insecure, and bogus outcomes.

Defer scenarios that depend on:

- `unbound-control`, `unbound-host`, or `unbound-anchor` CLI behavior
- Python/dynlib modules, DNSCrypt, dnstap, IPsec, or IPSet
- Full `unbound.conf` coverage outside the supported subset
- Autotrust file formatting, until RFC 5011 lands in M5

Maintain `tests/replay/UNSUPPORTED.md` with a scenario path and reason for every
excluded file. No silent skips.

## Pass-rate gates

- M2: at least 10 iterator scenarios pass.
- M3: at least 30 cache/retry scenarios pass.
- M5: at least 60 scenarios including DNSSEC pass.
- M9: agreed final subset passes, with no regressions.

The exact list is frozen when the harness first runs, so progress is measurable.

## Implementation order

1. Parser for config, scenario, range, step, and entry blocks.
2. Semantic message comparison and scenario discovery.
3. Virtual clock and fake network.
4. Runner that starts the resolver against the fake context.
5. Macro expansion.
6. Autotrust and tempfile comparisons.
7. CI job with a stable scenario manifest.

## Attribution

The `.rpl` format and test scenarios are from NLnet Labs' Unbound, BSD-3-Clause.
Reused scenario files retain their copyright notices and are referenced from the
repository rather than copied where practical.
