#!/usr/bin/env bash
# Prepare the container for `cargo build`.
#
# `build.rs` shells out to `flatc`, and the generated code has to match the
# `flatbuffers` crate version in Cargo.toml - so the compiler is built from the
# pinned submodule rather than installed from apt, exactly as CI does it.
set -euo pipefail

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    cmake \
    make \
    strace

git submodule update --init --recursive

if ! command -v flatc >/dev/null 2>&1; then
    echo "Building flatc from buildtools/flatbuffers ..."
    (
        cd buildtools/flatbuffers
        cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release -DFLATBUFFERS_BUILD_TESTS=OFF .
        make -j"$(nproc)"
        sudo make install
    )
fi

echo "flatc: $(flatc --version)"
echo "cargo: $(cargo --version)"
