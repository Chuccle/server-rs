#!/usr/bin/env bash
# Prepares a Linux machine or container for `cargo build` / `cargo test`.
# Run it once on a fresh checkout; it is also suitable as the setup script
# of any hosted Linux environment. Never fails: it reports what is missing.
#
# build.rs shells out to `flatc`, and the generated code has to match the
# `flatbuffers` crate version - so flatc is built from the pinned
# buildtools/flatbuffers submodule, as CI and .devcontainer/post-create.sh
# do, and cached by that submodule's commit. Also adds the Windows Rust
# target so `cargo clippy --target x86_64-pc-windows-msvc --lib --bins`
# can type-check the Windows code paths without any Windows SDK.
set -uo pipefail

[[ "$(uname -s)" == "Linux" ]] || exit 0
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 0

git submodule update --init --recursive >/dev/null 2>&1 || echo "setup: submodule update failed"

rev="$(git rev-parse HEAD:buildtools/flatbuffers 2>/dev/null)"
cache="${XDG_CACHE_HOME:-$HOME/.cache}/server-rs/flatc-${rev:0:12}"
if [[ ! -x "$cache/flatc" ]] && command -v cmake >/dev/null; then
    echo "setup: building flatc from buildtools/flatbuffers"
    cmake -S buildtools/flatbuffers -B "$cache-build" -DCMAKE_BUILD_TYPE=Release \
        -DFLATBUFFERS_BUILD_TESTS=OFF -DFLATBUFFERS_BUILD_FLATLIB=OFF -DFLATBUFFERS_BUILD_FLATHASH=OFF >/dev/null &&
    cmake --build "$cache-build" --target flatc -j"$(nproc)" >/dev/null 2>&1 &&
    mkdir -p "$cache" && cp "$cache-build/flatc" "$cache/" && rm -rf "$cache-build"
fi

if [[ -x "$cache/flatc" ]]; then
    if [[ -w /usr/local/bin ]]; then
        ln -sf "$cache/flatc" /usr/local/bin/flatc
    else
        echo "setup: add flatc to PATH:  export PATH=\"$cache:\$PATH\""
    fi
    echo "setup: $("$cache/flatc" --version)"
else
    echo "setup: no flatc (is cmake installed?); cargo build will fail in build.rs"
fi

command -v rustup >/dev/null && rustup target add x86_64-pc-windows-msvc >/dev/null 2>&1
exit 0
