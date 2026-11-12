# Security policy

dns-rs is a DNSSEC-validating recursive resolver. Security reports are welcome
and are handled before ordinary bug reports.

## Reporting a vulnerability

Please do **not** open a public issue for a security problem.

Use GitHub's private reporting flow on
[ChandanGhosh/dns-rs](https://github.com/ChandanGhosh/dns-rs/security/advisories/new).
If that is unavailable, open a minimal public issue asking for a private
channel without describing the flaw.

Include, when possible:

- the affected version or commit;
- whether the issue is remote or requires local configuration access;
- a minimal reproducer (configuration, query bytes, or a capture);
- the impact you believe it has, for example cache poisoning, validation
  bypass, denial of service, or information disclosure.

Never include credentials, private keys, or client data in a report.

## Scope

In scope:

- the resolver, listeners (UDP, TCP, DoT, DoH), and query pipeline;
- the optional Unix-domain control socket, including its peer authorization
  and command handling;
- DNS message parsing and encoding;
- DNSSEC validation, including trust anchors, denial proofs, and the zone
  status cache;
- configuration parsing and ACL, rate-limit, or rebinding policy bypass;
- the published container image and its default configuration.

Out of scope unless it leads to a concrete exploit in dns-rs:

- vulnerabilities in dependencies (report those upstream, and tell us if dns-rs
  is affected);
- benchmark and test utilities, including `dns-testutil` and `scripts/`;
- documentation errors and missing hardening features that are already listed
  as not implemented in the README.

## Supported versions

dns-rs is pre-1.0. Fixes are applied to the latest release and `main`; older
releases are not maintained separately.

## Disclosure

We aim to acknowledge a report within 7 days and to agree on a disclosure
timeline with the reporter. Please give us a reasonable window to ship a fix
before publishing details. Credit is given in the release notes unless you ask
to remain anonymous.
