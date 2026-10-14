#!/usr/bin/env bash
# Builds a static libuv prefix for local development.
# With no arguments, downloads the v1.53.0 tag archive. Pass a local tarball
# as the first argument to build from that file instead.
set -euo pipefail

TARBALL="${1:-}"
PREFIX="${2:-$(cd "$(dirname "$0")/.." && pwd)/.deps/libuv}"
LIBUV_URL="https://github.com/libuv/libuv/archive/refs/tags/v1.53.0.tar.gz"

if [ -f "${PREFIX}/include/uv.h" ]; then
    echo "libuv prefix already present at ${PREFIX}"
    exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

if [ -z "${TARBALL}" ]; then
    TARBALL="${WORK}/libuv-1.53.0.tar.gz"
    curl -fL --retry 3 -o "${TARBALL}" "${LIBUV_URL}"
fi

tar xzf "${TARBALL}" -C "${WORK}"
mapfile -t _lists < <(find "${WORK}" -mindepth 2 -maxdepth 2 -name CMakeLists.txt -type f)
if [ "${#_lists[@]}" -ne 1 ]; then
    echo "expected exactly one libuv source tree in ${TARBALL}" >&2
    exit 1
fi
SRC="$(dirname "${_lists[0]}")"

cmake -S "${SRC}" -B "${WORK}/build" \
    -DCMAKE_INSTALL_PREFIX="${PREFIX}" \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DLIBUV_BUILD_SHARED=OFF -DLIBUV_BUILD_TESTS=OFF -DLIBUV_BUILD_BENCH=OFF
cmake --build "${WORK}/build" -j"$(nproc)"
cmake --install "${WORK}/build"

echo "libuv prefix ready at ${PREFIX}"
