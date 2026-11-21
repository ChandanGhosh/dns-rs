# Excluded replay coverage

Every bundled `.rpl` file is listed in `MANIFEST` and must pass. The following
features are not covered by the first-pass harness; a scenario that needs one
must not be added to the manifest until the feature is implemented.

- `CHECK_OUT_QUERY`: outbound query assertions are parsed but not executed.
- `REPLY`, `TIMEOUT`, and `TRAFFIC` steps: out-of-range injected packets and
  timeout scheduling are not implemented.
- `CHECK_AUTOTRUST` and `CHECK_TEMPFILE`: RFC 5011 state files and replay
  tempfiles are not compared.
- `INFRA_RTT`, `FLUSH_MESSAGE`, and `EXPIRE_MESSAGE`: the runner does not seed
  or mutate resolver caches directly.
- `ERROR` steps: expected error events are not modeled.
- `TIME_PASSES` with real TTL expiry: simulated time selects ranges but does
  not age cached records.
- DNSSEC validation scenarios: the runner disables validation and does not
  inject trust anchors.
- Non-IN query classes: the iterative resolver only resolves `IN` queries.
- IPv6 replay addresses: the fake network only binds IPv4 loopback aliases.
- Unbound-specific tooling and integrations: `unbound-control`,
  `unbound-host`, `unbound-anchor`, Python modules, DNSCrypt, dnstap, IPsec,
  and IPSet are outside the resolver core.
