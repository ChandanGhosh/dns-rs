# Fuzz targets

`cargo-fuzz` harnesses for the wire-format and configuration parsers.

## Requirements

- Rust nightly (`rustup toolchain install nightly`)
- `cargo install cargo-fuzz`

## Run

From this directory:

```sh
cargo fuzz run decode_message -- -runs=20000
```

CI runs a short smoke test (`-max_total_time=60`) on every push. Longer runs
are expected before a release.

## Targets

| Target | Input | Invariant |
|---|---|---|
| `decode_message` | arbitrary bytes | `dns_proto::decode` never panics; a successfully decoded message can be re-encoded without panicking |
