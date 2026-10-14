#!/usr/bin/env bash
# Builds a static Tongsuo/OpenSSL prefix for local development.
# yanterm-ssh itself only ever calls find_package(OpenSSL); this script exists
# because the dev machine has no system OpenSSL development package.
# With no arguments, downloads the Tongsuo 8.5.0 tag archive. Pass a local
# tarball as the first argument to build from that file instead.
set -euo pipefail

TARBALL="${1:-}"
PREFIX="${2:-$(cd "$(dirname "$0")/.." && pwd)/.deps/openssl}"
TONGSUO_URL="https://github.com/Tongsuo-Project/Tongsuo/archive/refs/tags/8.5.0.tar.gz"

if [ -f "${PREFIX}/include/openssl/configuration.h" ]; then
    echo "OpenSSL prefix already present at ${PREFIX}"
    exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

if [ -z "${TARBALL}" ]; then
    TARBALL="${WORK}/Tongsuo-8.5.0.tar.gz"
    curl -fL --retry 3 -o "${TARBALL}" "${TONGSUO_URL}"
fi

tar xzf "${TARBALL}" -C "${WORK}"
SRC="${WORK}"
if [ ! -f "${SRC}/Configure" ]; then
    mapfile -t _configs < <(find "${WORK}" -mindepth 2 -maxdepth 2 -name Configure -type f)
    if [ "${#_configs[@]}" -ne 1 ]; then
        echo "expected exactly one Tongsuo source tree in ${TARBALL}" >&2
        exit 1
    fi
    SRC="$(dirname "${_configs[0]}")"
fi
cd "${SRC}"
perl Configure linux-x86_64 no-shared no-tests \
    --prefix="${PREFIX}" --openssldir="${PREFIX}/ssl"
make -j"$(nproc)"
make install_sw install_ssldirs

# Tongsuo installs into lib64 on x86_64; find_package(OpenSSL) looks in lib too.
if [ -d "${PREFIX}/lib64" ] && [ ! -d "${PREFIX}/lib" ]; then
    ln -s lib64 "${PREFIX}/lib"
fi

echo "OpenSSL prefix ready at ${PREFIX}"
