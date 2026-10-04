# server-rs

The HTTP backend that the [BlorgFS](https://github.com/Chuccle/BlorgFS) Windows filesystem driver mounts. It serves a directory tree read-only over plain HTTP. Metadata is encoded with the FlatBuffers schema from the `schemas` submodule ([Chuccle/schemas](https://github.com/Chuccle/schemas)).

BlorgFS is the package root. It pins this repository as `third_party/server-rs` and builds this server for Linux (`x86_64-unknown-linux-musl`) and Windows (`x86_64-pc-windows-gnu`) into one package with the driver. Its CI then runs the driver in a Windows guest against the packaged Linux server. A change to a route, query key or status code that the driver depends on fails there. Both repositories have to pin the same `schemas` commit; BlorgFS's CI checks that.

## Build and test (Linux)

```bash
tools/setup.sh                   # once per machine: flatc from the pinned submodule
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

- `build.rs` runs `flatc`, which must match the `flatbuffers` crate version. `tools/setup.sh` builds it from `buildtools/flatbuffers` and caches it. The script also works as the setup step of any hosted Linux environment.
- CI (`.github/workflows/rust.yml`) tests three feature sets: no default features, `logging`, and `stats` (the default).
- The Windows build cross-compiles from Linux, as CI's `windows` job does: `cargo build --release --locked --target x86_64-pc-windows-gnu`. This needs mingw-w64 (Debian/Ubuntu package `gcc-mingw-w64-x86-64`).
- Containers often run as root, which ignores file permissions. `test_permission_denied` detects that and skips instead of failing.

## Running

```bash
cargo run --release -- <directory to serve>    # listens on $PORT (default 8080)
```

Performance measurements are described in [BENCHMARKING.md](BENCHMARKING.md).
