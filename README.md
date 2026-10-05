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

## Change feed

`GET /get_changes?epoch=E&since=G` reports every path the filesystem watcher saw change after generation `G`, as a `ChangeBatch`, and holds the request for up to 20 s while nothing has. A client that follows it can keep metadata until it is told the path changed, instead of expiring it on a timer. Each path appears once: under `created` or `removed` if whether it exists changed, so a rename reports both of its paths, and otherwise under `modified`. A directory whose attributes changed is reported under `created`, since what it changed may be a descriptor everything beneath it inherits, and a client drops a created path's subtree. A batch with `reset` set means the client must drop everything: the server restarted, or the client fell further behind than the server retains. The route answers 503 while the watcher is not running or after it reported an error, because a feed that may have missed events cannot promise that nothing changed.

A metadata answer the feed cannot vouch for is marked `Cache-Control: no-store`. That covers a load that a batch of changes overtook, and any path that resolved through a symlink, since the watcher reports the target's path and not the one the client asked by. `src/utils/feed.rs` states the contract in full.

## Subtree listings

`GET /get_dir_info?path=P&subtree=N` answers with `P`'s listing plus, in its `descendants`, the listings of the directories beneath it, breadth first, until the next one would take the answer past `N` entries; each listing counts its entries plus one, and `N` is capped at 65536. A descendant names its directory by position: the `subdirectory`-th entry of listing `parent`, where 0 is `P` itself. Without `subtree` the answer is the plain listing, as before.

## Security descriptors

An entry may carry a Windows security descriptor, which the server stores without interpreting: a client's kernel does the access check. It is kept on the file itself, in the `user.blorgfs.sd` extended attribute on Unix or the `blorgfs.sd` stream on Windows, so it follows a rename and goes with a delete. An entry without one inherits from the directory it is in. A listing carries each distinct descriptor once, in its `security` vector, and an entry names its own by position plus one, 0 meaning it inherits. So that a client can resolve what an inheriting entry gets without asking about every directory above it, an answer also carries in `inherited` the nearest descriptor stored above, with `inherited_depth` saying how many levels up it is; on a listing, that describes the listed directory itself, at depth 0 when it has its own. A tree in which nothing has one is answered exactly as before.

`PUT /set_security?path=P` stores the request body as `P`'s descriptor, or with an empty body removes it, and answers 204. It is refused with 403 unless the server was started with `WRITABLE=1`: the server does not know who is asking, so anyone who can reach a writable server can change what it serves.

Performance measurements are described in [BENCHMARKING.md](BENCHMARKING.md).
