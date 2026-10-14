# yanterm-ssh

[简体中文](README.md) | English

A C++20 **sans-I/O** SSH-2 protocol library for both clients and servers, usable either header-only or as a static library.

## Overview

yanterm-ssh implements the SSH-2 wire protocol and cryptographic negotiation, but **performs no I/O itself**: the caller feeds in received bytes, sends out the bytes the library produces, and learns about state changes through callbacks or coroutines. Networking and the event loop are entirely up to the caller.

On top of the sans-I/O core, the library also provides a coroutine facade (`session` / `channel`) built on [corral](https://github.com/hudson-trading/corral) structured concurrency, letting you write SSH clients or servers as if writing synchronous code.

The entire public API lives under `include/yanterm-ssh/`; see [`PUBLIC_API.md`](PUBLIC_API.md) for the full inventory.

## Features

- **Client and server**: a single state machine implementation, distinguished by `core::role`.
- **Authentication**: `none`, `password`, `publickey`, `keyboard-interactive`.
- **Channels**: `session` (pty / shell / exec / subsystem / env / window-change / signal / exit-status / exit-signal), `direct-tcpip`, `forwarded-tcpip`, `x11`, `direct-streamlocal`, `forwarded-streamlocal`.
- **Global requests**: `tcpip-forward`, `streamlocal-forward` and their cancellation, keepalive, custom global requests.
- **Transport layer**: rekey (by byte and packet count thresholds), `ext-info`, strict kex (Terrapin attack mitigation).
- **Keys and file formats**: parsing, generation and serialization of OpenSSH private keys (including bcrypt-pbkdf passphrase encryption), public keys, SHA-256 fingerprints, `known_hosts`, `authorized_keys`.
- **Pluggable crypto backend**: ships with an OpenSSL backend; applications can also implement their own backend, as long as it satisfies the `crypto::provider` constraints.
- **Chinese national (SM) algorithms**: SM2 / SM3 / SM4 algorithms are available when the backend supports them (e.g. Tongsuo).
- **Memory and security**: plaintext and ciphertext live in reference-counted page memory; sensitive data is carried by types such as `secure_bytes` and wiped on release.
- **Three delivery forms**: header-only, static library, C++20 modules (experimental).

### Not yet supported

The following capabilities are common in mainstream implementations such as OpenSSH, but are not yet supported by this library:

- **Authentication**: `gssapi-with-mic` (Kerberos), `hostbased`.
- **OpenSSH certificates**: `*-cert-v01@openssh.com` user and host certificates, and CA-based trust (`@cert-authority`).
- **Hardware keys**: FIDO/U2F security keys (`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`).
- **External signing**: ssh-agent and PKCS#11/smart-card signing; publickey authentication currently requires the private key material to be in-process.
- **Agent forwarding**: `auth-agent-req@openssh.com` and its channel.
- **Compression**: `zlib@openssh.com` / `zlib`; only `none` is negotiated.
- **Post-quantum key exchange**: `mlkem768x25519-sha256`, `sntrup761x25519-sha512@openssh.com`.
- **SFTP / SCP**: not built in; they can be carried over a `subsystem` channel, but the protocol must be implemented by the application.

## Supported algorithms

Algorithms are listed in default preference order. The "Enabled by default" column is what gets advertised to the peer with no configuration; algorithms in the "Supported only" column are not advertised by default and must be enabled explicitly via the `preferred_*` options. In either column, algorithms unsupported by the crypto backend are filtered out automatically.

| Category | Enabled by default | Supported only |
| --- | --- | --- |
| Key exchange | `curve25519-sha256`, `curve25519-sha256@libssh.org`, `ecdh-sha2-nistp256/384/521`, `sm2-sm3`, `ecgm-sm2-sm3`, `diffie-hellman-group16-sha512`, `diffie-hellman-group14-sha256` | `diffie-hellman-group14-sha1` |
| Host key | `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, `sm2`, `rsa-sha2-512`, `rsa-sha2-256` | `ssh-rsa` |
| Cipher | `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`, `aes256/192/128-ctr`, `sm4-ctr` | `sm4-cbc` |
| MAC | `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256`, `hmac-sha2-512`, `hmac-sm3` | `hmac-sha1` |

At runtime, use `kex::supported_*_algorithms(provider)` and `kex::default_*_algorithms(provider)` to query the lists actually available with the current backend.

## Architecture

The library is organized in layers (see section 0 of [`PUBLIC_API.md`](PUBLIC_API.md)):

- **Core protocol layer** (`core/`, `wire/`, `kex/`, `auth/`, `channels/`, `transport/`): pure sans-I/O state machines; the entry points are `core::connection` and the callback interface `core::handler`.
- **Crypto layer** (`crypto/`): the `crypto::provider` abstraction and the OpenSSL implementation `crypto::openssl_backend`.
- **Keys layer** (`keys/`): keys and the various file formats. `keys/io.hpp` is the only header that performs blocking file I/O and must be included explicitly.
- **Coroutine facade** (`session.hpp`, `channel.hpp`, `options.hpp`, `facade_types.hpp`): wraps the core layer in corral coroutines, with the underlying stream provided by `auv::stream`.

Corresponding CMake targets:

| Target | Contents | Extra dependencies |
| --- | --- | --- |
| `yanterm::ssh-core` | Header-only core protocol | None |
| `yanterm::ssh-static` | Separately compiled core + keys + blocking key I/O + bcrypt/Blowfish | None |
| `yanterm::ssh` | Header-only coroutine facade | corral and auv headers (consumer-supplied) |

The core target never depends on corral, auv, or any I/O library; this is a hard architectural constraint of the project.

## Building

### Dependencies

Building the library itself only requires a C++20 compiler (GCC or Clang), CMake 3.22+, and Ninja. The library targets do not depend on OpenSSL, Catch2, or libuv; OpenSSL is needed only when using the bundled OpenSSL backend.

Tests and tools are controlled by `YANTERM_SSH_BUILD_TESTS`, which is on by default when this repository is the top-level project.

At build time:

- **Catch2 3** (required, unit tests only). CMake looks for an installed Catch2 3 first, and otherwise downloads [v3.16.1](https://github.com/catchorg/Catch2/releases/tag/v3.16.1). For an offline build, place that version's source archive at `.deps/Catch2-3.16.1.tar.gz`.
- **OpenSSL 3.x/1.1.1** (required; a compatible implementation such as Tongsuo is fine). Without it, the unit tests and the tools that need a crypto backend are not built.
- **libuv** (optional). Used only by the benchmark tool `yanterm-ssh-bench`; the tool is skipped when libuv is missing.

At test time:

- **Python 3**. Used by the source-layout check in the default suite, and by the interop script.
- **OpenSSH** (`ssh`, `sshd`, `ssh-keygen`; optional). Interop tests are off by default. A few key round-trip cases are skipped when `ssh-keygen` is absent.
- **`Terrapin_Scanner`** (optional). When it is on `PATH`, the interop script also checks strict kex.

### Preparing dependencies

This repository does not require a system OpenSSL development package. Run the script below once to build a static Tongsuo/OpenSSL under `.deps/openssl`:

```bash
scripts/bootstrap-openssl.sh [source tarball path] [install prefix]
```

With no arguments, the script downloads and builds Tongsuo 8.5.0. The CMake presets already point `OPENSSL_ROOT_DIR` at `.deps/openssl`. An existing OpenSSL 3.x/1.1.1 development package on the system works as well.

Prepare libuv under `.deps/libuv` the same way; the presets already add that path to `CMAKE_PREFIX_PATH`:

```bash
scripts/bootstrap-libuv.sh [source tarball path] [install prefix]
```

With no arguments, the script downloads and builds libuv 1.53.0. A static libuv that already ships a CMake package is picked up directly.

Catch2 usually needs no separate install; configuring the tests fetches it.

### Build and test

```bash
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

Available presets:

| Preset | Purpose | Build directory |
| --- | --- | --- |
| `dev` | Debug, GCC toolchain, with tests | `build/dev` |
| `asan` | `dev` plus AddressSanitizer + UBSan | `build/asan` |
| `release` | Release, with tests and benchmark tool | `build/release` |
| `clang` | Debug, Clang 18, for C++20 module smoke tests | `build/clang` |

Common CMake options:

- `YANTERM_SSH_BUILD_TESTS`: build tests and tools; on by default when this is the top-level project.
- `YANTERM_SSH_INSTALL`: generate install rules; on by default when this is the top-level project.
- `YANTERM_SSH_INTEROP_TESTS`: enable OpenSSH interop tests; off by default.
- `YANTERM_SSH_ENABLE_ASAN`: enable ASan + UBSan.
- `YANTERM_SSH_STATIC_LIBSTDCXX`: statically link libgcc/libstdc++ into tests and tools; on by default.

## Using it in your project

### Choosing a target

```cmake
# Header-only core
target_link_libraries(app PRIVATE yanterm::ssh-core)

# Separately compiled static library
target_link_libraries(app PRIVATE yanterm::ssh-static)

# Coroutine facade (header-only; add corral / auv include paths yourself)
target_link_libraries(app PRIVATE yanterm::ssh)

# OpenSSL backend (header-only; only needed when including openssl.hpp)
find_package(OpenSSL 1.1.1 REQUIRED COMPONENTS Crypto)
target_link_libraries(app PRIVATE OpenSSL::Crypto)
```

### Integration options

1. **Build and install**: `cmake --install build/dev --prefix <prefix>`, then `find_package(yanterm-ssh CONFIG REQUIRED)` and link any of the targets above.
2. **Copy the headers**: add `include/` to your include path to use it header-only; you only need to link OpenSSL yourself if you use the OpenSSL backend.
3. **`add_subdirectory`**: add this repository as a subdirectory, then link the appropriate target.
4. **`FetchContent`**: declare this repository, then link the appropriate target.

### Caveats

- **The compilation mode is selected solely by the target you link.** Linking `yanterm::ssh-static` automatically propagates `YANTERM_SSH_SEPARATE_COMPILATION`; consumers must **not** define `YANTERM_SSH_HEADER_ONLY` or `YANTERM_SSH_SOURCE` manually, or compilation will fail.
- **Do not mix** header-only (or module) and static library modes within the same final program; doing so violates the ODR.
- **corral / auv include paths are supplied by the consumer.** The `yanterm::ssh` target does not propagate them; the in-repo tests use the `corral/` and `auv/` bundled under `tests/`.
- **C++20 modules are experimental**: after installation the `.cppm` sources are under `share/yanterm-ssh/modules` and must be compiled by the consumer; the library provides no BMI or CMake module target. The `yanterm.ssh` module unit contains lambda coroutines, which GCC (as of 16.2) cannot compile; Clang 18+ is required.

## Usage sketch

The code below only illustrates the call flow and omits error-handling details. For complete runnable examples, see `tools/bench/client.cpp` and the cases under `tests/`.

### Coroutine facade: running a remote command

```cpp
#include <yanterm-ssh/channel.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/session.hpp>

namespace ssh = yanterm::ssh;

// tcp is a connected auv::stream; provider comes from crypto::provider::wrap(openssl_backend)
corral::Task<void> run_uname(auv::stream tcp, ssh::crypto::provider provider,
                             const ssh::keys::private_key& identity) {
    ssh::client_session cs(std::move(tcp), provider, ssh::client_options{});

    co_await ssh::run_with(cs, [&]() -> corral::Task<void> {
        auto hs = co_await cs.handshake([](ssh::host_key_view key) -> corral::Task<bool> {
            // Verify the host key here, e.g. check key.fingerprint() against known_hosts
            co_return true;
        });
        if (hs) co_return;

        auto [aec, auth] = co_await cs.auth_publickey("user", identity);
        if (aec || !auth.success) co_return;

        auto opened = co_await cs.open_session_channel();
        if (opened.ec) co_return;
        if (co_await opened.ch.request_exec("uname -a")) co_return;

        auto stream = auv::stream::borrow(opened.ch);
        char buf[4096];
        for (;;) {
            auto [rec, n] = co_await stream.read([&] { return auv::buffer(buf, sizeof(buf)); });
            if (rec || n == 0) break;
            // Process buf[0, n)
        }
        co_await opened.ch.close();
    });
}
```

`run_with` starts the session's read/write loop in the background and disconnects once the user coroutine finishes. For finer lifetime control, you can `start(&client_session::run, &cs)` in your own nursery.

### Driving the sans-I/O core directly

If you don't want to pull in corral, use `core::connection` directly, implement the `core::handler` callbacks yourself, and shuttle the bytes:

```cpp
#include <yanterm-ssh/core/connection.hpp>

namespace core = yanterm::ssh::core;

struct my_handler : core::handler {
    // Override callbacks such as on_host_key, on_auth_result, on_open_result, on_readable as needed
};

my_handler h;
core::connection conn(core::role::client, provider, core::config{}, h);

// When network data arrives:
std::size_t accepted = 0;
if (auto ec = conn.feed(received_bytes, accepted)) { /* connection failed */ }
// The part of received_bytes after `accepted` still belongs to the caller; feed it again together with new data next time

// When there is data to send:
while (conn.pending_output_bytes() > 0) {
    auto seg = conn.pending_output0();
    std::size_t sent = send_to_socket(seg);
    conn.consume_output(sent);
}
```

Events that require an application decision, such as host key verification or server-side authentication verdicts, are handed to the handler as tickets; once the application decides, it submits the result via `connection::resolve`. Until then, `inbound_requests_stalled()` is true and `feed` will not consume any further complete packets.

## Testing

`ctest --preset dev` runs the following kinds of tests:

- `yanterm_ssh_tests`: the main unit tests, linked against the static library.
- `yanterm_ssh_header_only` / `yanterm_ssh_facade_header_only`: multiple translation units each include all public headers and are linked together, to catch ODR issues in header-only mode.
- `yanterm_ssh_header_self_contained`: checks that every header compiles on its own.
- `yanterm_ssh_source_layout`: checks that the source layout conforms to [`SOURCE_LAYOUT.md`](SOURCE_LAYOUT.md).
- `yanterm_ssh_replay_tests`: replays recorded OpenSSH handshake traces from `corpus/`.
- `yanterm_ssh_module_*`: C++20 module smoke tests; requires the `clang` preset and `clang-tools-18` (which provides `clang-scan-deps`), otherwise skipped automatically. Skipping under the GCC preset is expected.

After moving a definition between `.hpp` and `.ipp`, always run both `yanterm_ssh_header_only` and `yanterm_ssh_tests`; both compilation modes must be covered.

### OpenSSH interop tests

Requires `sshd` and `ssh` on the local machine. Enable `YANTERM_SSH_INTEROP_TESTS` and run:

```bash
cmake --preset dev -DYANTERM_SSH_INTEROP_TESTS=ON
cmake --build --preset dev
ctest --preset dev -L interop
```

The script `tools/run-openssh-interop.sh` starts a temporary sshd and covers the following scenarios:

- Handshake matrix: 3 key exchanges × 3 ciphers × 3 host keys.
- Authentication in both directions: publickey, password, keyboard-interactive.
- Channels: pty-shell, exec, direct-tcpip.

If `Terrapin_Scanner` is installed, strict kex is checked as well.

## Benchmarks

`yanterm-ssh-bench` measures handshake latency and one-way session throughput over real loopback TCP. The results are **end-to-end**, covering the protocol stack, the facade layer, and the pipe copy after the server `fork`s to execute the command. Throughput runs do not request a pty, because a pty may rewrite bytes (for example `ONLCR`).

### Results

On loopback on the same machine, yanterm client to yanterm server achieves the highest throughput: about 1.7 GiB/s with chacha20-poly1305 and about 3.4 GiB/s with aes256-gcm, clearly higher than the throughput measured when OpenSSH is the server (OpenSSL version differences partially affect this result).

**One-way throughput** (MiB/s, arithmetic mean of 3 runs per scenario. Bandwidth tests use a single TCP connection, a single channel, and a single thread)

| Client → Server | chacha20-poly1305 download | chacha20-poly1305 upload | aes256-gcm download | aes256-gcm upload |
| --- | ---: | ---: | ---: | ---: |
| yanterm → yanterm | 1762.4 | 1727.2 | 3494.5 | 3373.1 |
| yanterm → OpenSSH | 1124.6 | 1122.2 | 2570.0 | 2557.2 |
| OpenSSH → yanterm | 1403.8 | 1124.8 | 3487.8 | 2520.2 |
| OpenSSH → OpenSSH | 1021.7 | 1018.8 | 2327.8 | 2490.2 |

**Handshake latency** (yanterm → yanterm, `curve25519-sha256` + `aes256-gcm`)

| Min | Median | Mean |
| ---: | ---: | ---: |
| 0.526 ms | 0.534 ms | 0.595 ms |

Timing starts once the TCP connection is established and ends when user authentication succeeds. It includes version exchange, key exchange, and password authentication, but not TCP connection setup itself.

- TODO: consider switching to the number of completed handshake + authentication rounds per unit time.

### Test environment

| Item | Configuration |
| --- | --- |
| CPU | Intel Core i5-14600K with AES-NI, governor `performance`. 16 logical processors available inside the container (20 total), no CPU pinning |
| Memory | DDR4-3200, 16 GiB visible to the process |
| OS | Ubuntu 22.04.5 LTS, in a container on a Proxmox VE host, kernel 6.8.12-15-pve |
| Toolchain | GCC 16.2.0 (crosstool-NG 1.29.0), CMake 3.31.12, Ninja 1.12.1. `release` preset, `-O3 -DNDEBUG` |
| yanterm side | Statically linked Tongsuo 8.5.0 (based on OpenSSL 3.5.4), libuv 1.53.0 |
| OpenSSH side | OpenSSH 8.9p1 (Ubuntu-3ubuntu0.17), using the system OpenSSL 3.0.2 |

### Running it yourself

After preparing libuv as described above, the `release` preset builds `yanterm-ssh-bench`.

The default algorithm combination is `curve25519-sha256` + `chacha20-poly1305@openssh.com` + `ssh-ed25519`, which can be overridden with `--kex`, `--cipher`, and `--hostkey`; `--mac` is only needed when choosing a CTR-class cipher. `--workload` accepts `handshake`, `download`, `upload`, or `all`, and `--json` emits machine-readable results. See `yanterm-ssh-bench --help` for all options.

**yanterm client → yanterm server**

```bash
./build/release/yanterm-ssh-bench spawn-server
```

**yanterm client → OpenSSH server**

```bash
./build/release/yanterm-ssh-bench spawn-sshd
./build/release/yanterm-ssh-bench connect 127.0.0.1 --identity ~/.ssh/id_ed25519
```

**OpenSSH client → yanterm server**

```bash
ssh-keygen -q -t ed25519 -N '' -f /tmp/bench-user
./build/release/yanterm-ssh-bench server --port 22333 --user "$USER" \
    --authorized /tmp/bench-user.pub --host-key /tmp/bench-user
ssh -T -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -i /tmp/bench-user -p 22333 "$USER@127.0.0.1" \
    'dd if=/dev/zero bs=1M count=4096 status=none' >/dev/null
```

`connect` also supports `--jump [user@]host[:port]` (repeatable) to measure multi-hop jump-host chains.

## Usage constraints

- **Threading**: the protocol core is a single-threaded sans-I/O state machine. A single session must not be shared across threads, but each thread may create and use its own independent sessions.
- **ABI**: no cross-version C++ ABI stability is promised. Headers and the static library must come from the same version.
- **API stability**: the project is still at 0.x and the public API may change. Contents under `detail/` and `impl/` ship with the package but are not part of the public API.

## Documentation

- [`PUBLIC_API.md`](PUBLIC_API.md): public API inventory and module layering.
- [`SOURCE_LAYOUT.md`](SOURCE_LAYOUT.md): source layout conventions, plus implementation rules for the dual header-only / static library modes.

## License

[MIT](LICENSE)
