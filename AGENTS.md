# AGENTS.md

Notes for coding agents (Claude Code, Codex, ...) working on server-rs,
especially from a Linux cloud session.

## What this is, and what it ships with

server-rs is the HTTP backend the BlorgFS Windows filesystem driver
(github.com/Chuccle/BlorgFS) mounts. The two ship as one package: BlorgFS
pins this repository as `third_party/server-rs`, CI builds `server-rs.exe`
for Windows next to the driver, and the Windows guest runtime tests run the
pair together. Both compile the same FlatBuffers schema from the
Chuccle/schemas submodule (`schemas/` here, `third_party/schemas` there);
a schema change has to land in both pins together.

The HTTP routes, query parameters and status codes are hand-written on both
sides (`src/lib.rs` here, `src/Client.c` in BlorgFS). Changing them breaks
the driver even when every test in this repository passes.

## Build and test (Linux)

```bash
bash tools/agent-setup.sh        # once per session: flatc from the pinned submodule
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

- `build.rs` runs `flatc`, which must match the `flatbuffers` crate
  version, so it is built from `buildtools/flatbuffers` rather than taken
  from a package manager. In Claude Code cloud sessions the SessionStart
  hook in `.claude/settings.json` runs the setup script; in other agent
  environments make it the environment's setup script.
- CI (`.github/workflows/rust.yml`) runs tests for three feature sets: no
  default features, `logging`, and `stats` (the default).
- Windows code paths type-check from Linux without a Windows SDK:
  `cargo clippy --locked --release --target x86_64-pc-windows-msvc --lib --bins -- -D warnings`.
  Leave out `--all-targets`: the benches pull in criterion, whose `alloca`
  dependency compiles C with MSVC's `lib.exe`.
- A Windows binary for iterating: `cargo build --release --target
  x86_64-pc-windows-gnu` (needs mingw-w64), or `cargo xwin build --release
  --target x86_64-pc-windows-msvc` where the session can reach Microsoft's
  download CDN. The package always ships the MSVC build from CI.
- Cloud sessions usually run as root, which ignores file permissions.
  `test_permission_denied` detects that and reports it instead of failing.

## Testing with the driver

Everything that needs Windows (the MSVC build of the package, loading the
driver, the runtime tests against this server) is driven from BlorgFS's
`tools/agent/blorg`; see "Remote agents" in BlorgFS's AGENTS.md. With both
repositories cloned side by side, `blorg` uses this checkout as the server.
