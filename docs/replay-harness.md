# Unbound replay harness

**Status:** First-pass conformance suite implemented. The harness runs a small
set of bundled `.rpl` scenarios, but it is not yet a full Unbound `testbound`
replacement. Unsupported features are listed below and in
[`UNSUPPORTED.md`](../crates/dns-replay/tests/scenarios/UNSUPPORTED.md).

## Purpose

Unbound ships hundreds of `.rpl` replay scenarios under `testdata/`, driven by
`testcode/testbound` and `testcode/replay.{c,h}`. They encode resolver edge cases
such as referrals, truncation, retries, cache expiry, CNAME and DNAME chains,
QNAME minimisation, and DNSSEC validation.

The `dns-replay` crate lets `dns-rs` run a growing, explicitly curated subset of
that style of scenario against the real iterative resolver. It complements
RFC-derived unit tests, live interop tests, and fuzzing. It is a dev-only crate;
production crates do not depend on it.

## Running the suite

```bash
cargo test -p dns-replay
```

The integration test in `crates/dns-replay/tests/replay.rs` reads the frozen
`MANIFEST` in `tests/scenarios/`, runs every listed file, and asserts that every
listed `.rpl` file on disk is present in the manifest. An unsupported step fails
the run instead of being silently skipped.

The bundled first-pass scenarios are:

| Scenario | Coverage |
| --- | --- |
| `basic_referral.rpl` | Pinned root referral through `com.` to an authoritative `A` answer. |
| `cname_chain.rpl` | CNAME chase from `com.` to `net.`. |
| `nxdomain.rpl` | Authoritative NXDOMAIN with an SOA in the authority section. |
| `truncation.rpl` | UDP truncation followed by a TCP retry. |

These are self-authored cases in Unbound's replay syntax. The upstream Unbound
corpus is not vendored yet; adding it is a later phase.

## Supported replay syntax

The parser accepts Unbound-style configuration and scenario blocks:

- `CONFIG_END`
- `SCENARIO_BEGIN <name>` ... `SCENARIO_END`
- `RANGE_BEGIN <start> <end>` ... `RANGE_END`, including `ADDRESS <ip>`
- `ENTRY_BEGIN` ... `ENTRY_END`
- `MATCH`, `ADJUST`, `REPLY`, and `EXTRA_PACKET`
- `SECTION QUESTION|ANSWER|AUTHORITY|ADDITIONAL`
- `STEP <time> QUERY|CHECK_ANSWER|TIME_PASSES ...`
- `TIME_PASSES ELAPSE <expression>` and computed `${...}` arithmetic with
  `+`, `-`, `*`, and `/`

Record lines may include or omit TTLs; omitted TTLs use 3600 seconds. Comments
start with `;`. Configuration lines before `CONFIG_END`, `AUTOTRUST_FILE`
blocks, and tempfile blocks are parsed but not applied.

`REPLY` tokens map QR, AA, TC, RD, RA, AD, and CD flags plus NOERROR, FORMERR,
SERVFAIL, NXDOMAIN, NOTIMPL/NOTIMP, REFUSED, and extended rcodes. `ADJUST
copy_query` makes a fake server echo the incoming question, which is what the
referral fixtures use.

## How the harness runs a scenario

1. `parser.rs` turns the file into scenarios, ranges, entries, and steps.
2. `fake.rs` binds one UDP socket and one TCP listener per replay server address,
   using aliases in `127.0.0.0/8` and a shared port. Each address serves only
   the ranges whose `ADDRESS` matches it.
3. `resolver_config` pins `IteratorConfig::root_servers` to the alias for the
   replay root server and disables case randomisation, QNAME minimisation,
   cookies, IPv6, and forwarders. The harness runs `IteratorResolver`, not a
   mock resolver.
4. `QUERY` steps call `IteratorResolver::resolve`. `time` selects the active
   `RANGE` entries; `TIME_PASSES` advances that simulated value.
5. `CHECK_ANSWER` compares the resolver response with the expected entry using
   `compare.rs`. Comparison is semantic: record order, TTLs, DNS compression,
   and the loopback address aliases do not affect the result. Header flags are
   checked only when the entry asserts them as true.

A truncated UDP reply is served first; the TCP listener serves the first
non-truncated `EXTRA_PACKET`, so the resolver's real TCP fallback path is
exercised.

## Current limits

The first pass deliberately does not provide full virtual time or a fully
deterministic socket/RNG seam:

- `TIME_PASSES` advances range selection and macro values only. It does not age
  cached records or advance retry timers.
- `CHECK_OUT_QUERY`, `REPLY`, `TIMEOUT`, `TRAFFIC`, `CHECK_AUTOTRUST`,
  `CHECK_TEMPFILE`, `INFRA_RTT`, `FLUSH_MESSAGE`, `EXPIRE_MESSAGE`, and `ERROR`
  steps are recognized but rejected as unsupported.
- Real file comparisons, DNSSEC trust anchors, cache seeding, and Unbound CLI
  behavior are not implemented.
- IPv6 replay addresses and non-IN query classes are not supported.

See `UNSUPPORTED.md` for the complete list. Unsupported scenarios must not be
added to `MANIFEST`.

## Roadmap

1. Add virtual clock and timer seams so TTL expiry, retries, and
   `TIME_PASSES` affect resolver behavior as they do in `testbound`.
2. Implement outbound-query assertions and scheduled replies.
3. Import upstream Unbound scenarios in small batches with reasons for exclusions.
4. Add cache manipulation and file comparison steps.
5. Add DNSSEC validation scenarios and raise the manifest gate with each batch.

The manifest is frozen at each expansion so progress is measurable and
regressions are visible.

## Attribution

The `.rpl` format is from NLnet Labs' Unbound, BSD-3-Clause. The bundled
fixtures are self-authored for this repository. If upstream scenarios are
imported later, retain their copyright notices and reference them from the
manifest with their source revision.
