# Developing server-rs

## What this is, and what it ships with

server-rs is the HTTP backend the BlorgFS Windows filesystem driver
(github.com/Chuccle/BlorgFS) mounts. The two ship as one package: BlorgFS
pins this repository as `third_party/server-rs`, its CI builds this server
for Linux (musl) and Windows (x86_64-pc-windows-gnu) into one package with
the driver, and the Windows guest runtime tests run the pair together. Both compile the same FlatBuffers
schema from the Chuccle/schemas submodule (`schemas/` here,
`third_party/schemas` there); a schema change has to land in both pins
together.

Everything else the two sides agree on (routes, the path query key, status
codes, framing and behaviours B01-B11) is defined once in
`schemas/contract.json`. Routes and the query key compile from the generated
`schemas/generated/blorg_contract.rs`; `src/contract_tests.rs` and
`.github/workflows/contract.yml` check the rest. Change the contract in the
schemas repository, then bump `schemas` here and in BlorgFS together.

## Build and test (Linux)

```bash
tools/setup.sh                   # once per machine: flatc from the pinned submodule
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

- `build.rs` runs `flatc`, which must match the `flatbuffers` crate
  version, so it is built from `buildtools/flatbuffers` rather than taken
  from a package manager. `tools/setup.sh` does that and caches it; on a
  hosted Linux environment, make it the environment's setup script.
- CI (`.github/workflows/rust.yml`) runs tests for three feature sets: no
  default features, `logging`, and `stats` (the default).
- The Windows build cross-compiles from Linux, as CI's `windows` job does:
  `cargo build --release --locked --target x86_64-pc-windows-gnu` (needs
  mingw-w64). The packaged binary itself is built by BlorgFS's `build.yml`.
- Containers often run as root, which ignores file permissions.
  `test_permission_denied` detects that and reports it instead of failing.

## Testing with the driver

Everything that needs Windows (the MSVC build of the driver, loading the
driver, the runtime tests against this server) is driven from BlorgFS's
`tools/blorg`; see BlorgFS's DEVELOPING.md. With both repositories cloned
side by side, `blorg` uses this checkout as the server.
