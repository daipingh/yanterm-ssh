# yanterm-ssh

简体中文 | [English](README.en.md)

一个基于 C++20 的 **sans-I/O** SSH-2 协议库，同时支持客户端与服务端，可按 header-only 或静态库两种方式使用。

## 简介

yanterm-ssh 实现了 SSH-2 的线上协议与密码学协商，但**自身不做任何 I/O**：调用方把收到的字节喂进去，再把库产出的字节发出去，并通过回调或协程得知状态变化。网络和事件循环全部由调用方决定。

在 sans-I/O 核心之上，库还提供一层基于 [corral](https://github.com/hudson-trading/corral) 结构化并发的协程门面（`session` / `channel`），可以像写同步代码一样写 SSH 客户端或服务端。

公开 API 全部位于 `include/yanterm-ssh/`，完整清单见 [`PUBLIC_API.md`](PUBLIC_API.md)。

## 特性

- **支持客户端与服务端**：同一套状态机实现，按 `core::role` 区分。
- **认证**：`none`、`password`、`publickey`、`keyboard-interactive`。
- **通道**：`session`（pty / shell / exec / subsystem / env / window-change / signal / exit-status / exit-signal）、`direct-tcpip`、`forwarded-tcpip`、`x11`、`direct-streamlocal`、`forwarded-streamlocal`。
- **全局请求**：`tcpip-forward`、`streamlocal-forward` 及其取消，keepalive，自定义全局请求。
- **传输层**：rekey（按字节数与包数阈值）、`ext-info`、strict kex（缓解 Terrapin 攻击）。
- **密钥与文件格式**：OpenSSH 私钥的解析、生成与序列化（含 bcrypt-pbkdf 口令加密）、公钥、SHA-256 指纹、`known_hosts`、`authorized_keys`。
- **可替换的加密后端**：自带 OpenSSL 后端；应用也可以自己实现加密后端，只需符合  `crypto::provider` 约束即可。
- **商密算法**：后端支持时（例如 Tongsuo）可使用 SM2 / SM3 / SM4 相关算法。
- **内存与安全**：明文和密文放在引用计数的页内存里；敏感数据用 `secure_bytes` 等类型承载，释放时擦除。
- **三种交付形态**：header-only、静态库、C++20 模块（实验性）。

### 暂未支持

以下能力在 OpenSSH 等主流实现中较为常见，本库目前尚未支持：

- **认证**：`gssapi-with-mic`（Kerberos）、`hostbased`。
- **OpenSSH 证书**：`*-cert-v01@openssh.com` 用户与主机证书，以及基于 CA 的信任（`@cert-authority`）。
- **硬件密钥**：FIDO/U2F 安全密钥（`sk-ssh-ed25519@openssh.com`、`sk-ecdsa-sha2-nistp256@openssh.com`）。
- **外部签名**：已提供外部签名接口，但未内置 ssh-agent 与 PKCS#11/智能卡客户端。
- **agent 转发**：`auth-agent-req@openssh.com` 及对应通道。
- **压缩**：`zlib@openssh.com` / `zlib`，目前只协商 `none`。
- **SFTP / SCP**：未内置；可通过 `subsystem` 通道承载，但协议需自行实现。

## 支持的算法

算法按下表顺序作为默认偏好。"默认启用"一列是不做任何配置时向对端通告的列表；"仅支持"一列的算法默认不通告，需要通过 `preferred_*` 选项显式开启。无论哪一列，加密后端不支持的算法都会被自动过滤掉。

| 类别 | 默认启用 | 仅支持 |
| --- | --- | --- |
| 密钥交换 | `mlkem768x25519-sha256`、`curve25519-sha256`、`curve25519-sha256@libssh.org`、`ecdh-sha2-nistp256/384/521`、`sm2-sm3`、`ecgm-sm2-sm3`、`diffie-hellman-group16-sha512`、`diffie-hellman-group14-sha256` | `diffie-hellman-group14-sha1` |
| 主机密钥 | `ssh-ed25519`、`ecdsa-sha2-nistp256/384/521`、`sm2`、`rsa-sha2-512`、`rsa-sha2-256` | `ssh-rsa` |
| 加密 | `chacha20-poly1305@openssh.com`、`aes256-gcm@openssh.com`、`aes128-gcm@openssh.com`、`aes256/192/128-ctr`、`sm4-ctr` | `sm4-cbc` |
| MAC | `hmac-sha2-256-etm@openssh.com`、`hmac-sha2-512-etm@openssh.com`、`hmac-sha2-256`、`hmac-sha2-512`、`hmac-sm3` | `hmac-sha1` |

运行期可以用 `kex::supported_*_algorithms(provider)` 和 `kex::default_*_algorithms(provider)` 查询当前后端实际可用的列表。

## 架构概览

库按层组织（详见 [`PUBLIC_API.md`](PUBLIC_API.md) 第 0 节）：

- **核心协议层**（`core/`、`wire/`、`kex/`、`auth/`、`channels/`、`transport/`）：纯 sans-I/O 状态机，入口是 `core::connection` 与回调接口 `core::handler`。
- **加密层**（`crypto/`）：`crypto::provider` 抽象与 OpenSSL 实现 `crypto::openssl_backend`。
- **密钥层**（`keys/`）：密钥与各类文件格式。其中 `keys/io.hpp` 是唯一做阻塞文件 I/O 的头文件，需要显式包含。
- **协程门面**（`session.hpp`、`channel.hpp`、`options.hpp`、`facade_types.hpp`）：把核心层包装成 corral 协程，底层流由 `auv::stream` 提供。

对应的 CMake 目标：

| 目标 | 内容 | 额外依赖 |
| --- | --- | --- |
| `yanterm::ssh-core` | header-only 的核心协议 | 无 |
| `yanterm::ssh-static` | 分离编译的核心 + 密钥 + 阻塞密钥 I/O + bcrypt/Blowfish | 无 |
| `yanterm::ssh` | header-only 的协程门面 | corral、auv 头文件（需自行提供） |

核心目标始终不依赖 corral、auv 或任何 I/O 库，这是本项目的硬性架构约束。

## 构建

### 依赖

构建库本身只需要支持 C++20 的编译器（GCC 或 Clang）、CMake 3.22+ 和 Ninja。库目标不依赖 OpenSSL、Catch2 或 libuv；只有使用自带的 OpenSSL 后端时才需要链接 OpenSSL。

测试和工具由 `YANTERM_SSH_BUILD_TESTS` 控制，作为顶层项目时默认开启。

构建测试时：

- **Catch2 3**（必选）。CMake 先查找已安装的 Catch2 3，找不到就自动下载 [v3.16.1](https://github.com/catchorg/Catch2/releases/tag/v3.16.1)。离线构建把该版本源码包放在 `.deps/Catch2-3.16.1.tar.gz`。
- **OpenSSL 3.x/1.1.1**（必选，兼容实现如 Tongsuo 亦可）。缺失时，单元测试以及依赖加密后端的工具都不会构建。
- **libuv**（可选）。只用于基准工具 `yanterm-ssh-bench`，缺失时跳过该工具。

运行测试时：

- **Python 3**。默认套件中的源码布局检查要用到，互操作脚本也要用。
- **OpenSSH**（`ssh`、`sshd`、`ssh-keygen`，可选）。互操作测试默认关闭。没有 `ssh-keygen` 时，个别密钥往返用例会跳过。
- **`Terrapin_Scanner`**（可选）。位于 `PATH` 时，互操作脚本会额外检查 strict kex。

### 准备依赖

本仓库不要求系统安装 OpenSSL 开发包。执行一次下面的脚本，会在 `.deps/openssl` 下构建一个静态的 Tongsuo/OpenSSL：

```bash
scripts/bootstrap-openssl.sh [源码压缩包路径] [安装前缀]
```

不传参数时，该脚本默认下载并构建 Tongsuo 8.5.0。CMake 预设已经把 `OPENSSL_ROOT_DIR` 指向 `.deps/openssl`。系统里已有的 OpenSSL 3.x/1.1.1 开发包同样可用。

libuv 用同样方式准备到 `.deps/libuv`，预设已将该路径加入 `CMAKE_PREFIX_PATH`：

```bash
scripts/bootstrap-libuv.sh [源码压缩包路径] [安装前缀]
```

不传参数时默认下载并构建 libuv 1.53.0。若本机已有带 CMake 配置的静态 libuv，也会被直接使用。

Catch2 通常不用单独安装，配置测试时会自动获取。

### 编译与测试

```bash
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

可用的预设：

| 预设 | 用途 | 构建目录 |
| --- | --- | --- |
| `dev` | Debug，GCC 工具链，含测试 | `build/dev` |
| `asan` | 在 `dev` 基础上开启 AddressSanitizer + UBSan | `build/asan` |
| `release` | Release，含测试与基准工具 | `build/release` |
| `clang` | Debug，Clang 18，用于 C++20 模块冒烟测试 | `build/clang` |

常用 CMake 选项：

- `YANTERM_SSH_BUILD_TESTS`：构建测试与工具，作为顶层项目时默认开启。
- `YANTERM_SSH_INSTALL`：生成安装规则，作为顶层项目时默认开启。
- `YANTERM_SSH_INTEROP_TESTS`：启用与 OpenSSH 的互操作测试，默认关闭。
- `YANTERM_SSH_ENABLE_ASAN`：开启 ASan + UBSan。
- `YANTERM_SSH_STATIC_LIBSTDCXX`：测试与工具静态链接 libgcc/libstdc++，默认开启。

## 在项目中使用

### 选择目标

```cmake
# header-only 核心
target_link_libraries(app PRIVATE yanterm::ssh-core)

# 分离编译的静态库
target_link_libraries(app PRIVATE yanterm::ssh-static)

# 协程门面（header-only，corral / auv 的头文件路径需自行添加）
target_link_libraries(app PRIVATE yanterm::ssh)

# OpenSSL 后端（header-only，仅在包含 openssl.hpp 时需要）
find_package(OpenSSL 1.1.1 REQUIRED COMPONENTS Crypto)
target_link_libraries(app PRIVATE OpenSSL::Crypto)
```

### 接入方式

1. **编译安装后使用**：`cmake --install build/dev --prefix <前缀>`，然后 `find_package(yanterm-ssh CONFIG REQUIRED)` 并链接上面任一目标。
2. **直接拷贝头文件**：把 `include/` 加入头文件搜索路径即可按 header-only 使用；只有用到 OpenSSL 后端时才需要自己链接 OpenSSL。
3. **`add_subdirectory`**：把本仓库作为子目录加入，再链接对应目标。
4. **`FetchContent`**：声明本仓库后链接对应目标。

### 注意事项

- **编译模式只靠选目标切换**。链接 `yanterm::ssh-static` 会自动传播 `YANTERM_SSH_SEPARATE_COMPILATION`；使用者**不要**手动定义 `YANTERM_SSH_HEADER_ONLY` 或 `YANTERM_SSH_SOURCE`，否则会在编译期报错。
- **同一个最终程序里不要混用** header-only（或模块）与静态库两种模式，否则会违反 ODR。
- **corral / auv 的头文件路径由使用者提供**。`yanterm::ssh` 目标不会传播它们；仓库内的测试使用 `tests/` 下随附的 `corral/` 与 `auv/`。
- **C++20 模块是实验性的**：安装后 `.cppm` 源文件位于 `share/yanterm-ssh/modules`，需要使用者自己编译，库不提供 BMI 或 CMake 模块目标。`yanterm.ssh` 模块单元包含 lambda 协程，GCC（截至 16.2）无法编译，需要 Clang 18+。

## 使用示意

以下代码只为说明调用流程，省略了错误处理细节。完整可运行的例子可以参考 `tools/bench/client.cpp` 和 `tests/` 下的用例。

### 协程门面：执行一条远程命令

```cpp
#include <yanterm-ssh/channel.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/session.hpp>

namespace ssh = yanterm::ssh;

// tcp 是一条已连接的 auv::stream，provider 由 crypto::provider::wrap(openssl_backend) 得到
corral::Task<void> run_uname(auv::stream tcp, ssh::crypto::provider provider,
                             const ssh::keys::private_key& identity) {
    ssh::client_session cs(std::move(tcp), provider, ssh::client_options{});

    co_await ssh::run_with(cs, [&]() -> corral::Task<void> {
        auto hs = co_await cs.handshake([](ssh::host_key_view key) -> corral::Task<bool> {
            // 在这里用 key.fingerprint() 对照 known_hosts 校验主机密钥
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
            // 处理 buf[0, n)
        }
        co_await opened.ch.close();
    });
}
```

`run_with` 会在后台启动会话的读写循环，等用户协程结束后主动断开连接。需要更精细地控制生命周期时，可以自己在 nursery 里 `start(&client_session::run, &cs)`。

### 直接驱动 sans-I/O 核心

不想引入 corral 时，可以直接使用 `core::connection`，自己实现 `core::handler` 回调并搬运字节：

```cpp
#include <yanterm-ssh/core/connection.hpp>

namespace core = yanterm::ssh::core;

struct my_handler : core::handler {
    // 按需覆写 on_host_key、on_auth_result、on_open_result、on_readable 等回调
};

my_handler h;
core::connection conn(core::role::client, provider, core::config{}, h);

// 收到网络数据时：
std::size_t accepted = 0;
if (auto ec = conn.feed(received_bytes, accepted)) { /* 连接失败 */ }
// received_bytes 中 accepted 之后的部分仍归调用方所有，下次需连同新数据一起再喂入

// 有待发送数据时：
while (conn.pending_output_bytes() > 0) {
    auto seg = conn.pending_output0();
    std::size_t sent = send_to_socket(seg);
    conn.consume_output(sent);
}
```

主机密钥校验、服务端认证裁决等需要应用决策的事件，会以 ticket 的形式交给 handler；应用决策后调用 `connection::resolve` 提交结果。在此之前，`inbound_requests_stalled()` 为真，`feed` 不会再消费新的完整报文。

## 测试

`ctest --preset dev` 会运行以下几类测试：

- `yanterm_ssh_tests`：主体单元测试，链接静态库。
- `yanterm_ssh_header_only` / `yanterm_ssh_facade_header_only`：多个翻译单元包含全部公开头文件后链接在一起，用于发现 header-only 模式下的 ODR 问题。
- `yanterm_ssh_header_self_contained`：逐个检查头文件能否单独编译。
- `yanterm_ssh_source_layout`：检查源码布局是否符合 [`SOURCE_LAYOUT.md`](SOURCE_LAYOUT.md)。
- `yanterm_ssh_replay_tests`：回放 `corpus/` 中录制的 OpenSSH 握手轨迹。
- `yanterm_ssh_module_*`：C++20 模块冒烟测试，需使用 `clang` 预设并安装 `clang-tools-18`（提供 `clang-scan-deps`），否则自动跳过。GCC 预设下跳过属于预期行为。

在 `.hpp` 与 `.ipp` 之间移动定义后，务必同时跑 `yanterm_ssh_header_only` 和 `yanterm_ssh_tests`，两种编译模式缺一不可。

### OpenSSH 互操作测试

需要本机有 `sshd` 和 `ssh`。开启 `YANTERM_SSH_INTEROP_TESTS` 后运行：

```bash
cmake --preset dev -DYANTERM_SSH_INTEROP_TESTS=ON
cmake --build --preset dev
ctest --preset dev -L interop
```

脚本 `tools/run-openssh-interop.sh` 会启动临时的 sshd，覆盖以下场景：

- 握手矩阵：3 种密钥交换 × 3 种加密 × 3 种主机密钥。
- 双向认证：publickey、password、keyboard-interactive。
- 通道：pty-shell、exec、direct-tcpip。

若安装了 `Terrapin_Scanner`，还会额外检查 strict kex。

## 基准测试

`yanterm-ssh-bench` 通过真实的回环 TCP 测量握手延迟和单向会话吞吐量。结果是**端到端**的，包含协议栈、门面层，以及服务端 `fork` 执行命令后的管道拷贝。测吞吐时不申请 pty，因为 pty 可能改写字节（例如 `ONLCR`）。

### 测量结果

在同一台机器的回环上，yanterm 客户端对 yanterm 服务端的吞吐最高：chacha20-poly1305 约 1.7 GiB/s，aes256-gcm 约 3.4 GiB/s，明显高于 OpenSSH 作为服务端时测出的吞吐（OpenSSL 版本差异对此结果有部分影响）。

**单向吞吐**（MiB/s，每个场景 3 次测量的算术平均。带宽测试为单条 TCP 连接、单个 channel、单线程）

| 客户端 → 服务端 | chacha20-poly1305 下载 | chacha20-poly1305 上传 | aes256-gcm 下载 | aes256-gcm 上传 |
| --- | ---: | ---: | ---: | ---: |
| yanterm → yanterm | 1762.4 | 1727.2 | 3494.5 | 3373.1 |
| yanterm → OpenSSH | 1124.6 | 1122.2 | 2570.0 | 2557.2 |
| OpenSSH → yanterm | 1403.8 | 1124.8 | 3487.8 | 2520.2 |
| OpenSSH → OpenSSH | 1021.7 | 1018.8 | 2327.8 | 2490.2 |

**握手延迟**（yanterm → yanterm，`curve25519-sha256` + `aes256-gcm`）

| 最小 | 中位 | 平均 |
| ---: | ---: | ---: |
| 0.526 ms | 0.534 ms | 0.595 ms |

计时从 TCP 连接建立后开始，到用户认证成功为止，包含版本交换、密钥交换和密码认证，不包含 TCP 建连本身。

- TODO：考虑调整为单位时间内握手认证完成次数。

### 测试环境

| 项目 | 配置 |
| --- | --- |
| CPU | Intel Core i5-14600K，支持 AES-NI，调速器 `performance`。容器内可用 16 个逻辑处理器（共 20 个），未绑核 |
| 内存 | DDR4-3200，进程可见 16 GiB |
| 系统 | Ubuntu 22.04.5 LTS，运行在 Proxmox VE 宿主的容器内，内核 6.8.12-15-pve |
| 工具链 | GCC 16.2.0（crosstool-NG 1.29.0），CMake 3.31.12，Ninja 1.12.1。`release` 预设，`-O3 -DNDEBUG` |
| yanterm 侧 | 静态链接 Tongsuo 8.5.0（基于 OpenSSL 3.5.4），libuv 1.53.0 |
| OpenSSH 侧 | OpenSSH 8.9p1（Ubuntu-3ubuntu0.17），使用系统 OpenSSL 3.0.2 |

### 自行运行

按上文准备好 libuv 后，用 `release` 预设构建即可得到 `yanterm-ssh-bench`。

默认算法组合是 `curve25519-sha256` + `chacha20-poly1305@openssh.com` + `ssh-ed25519`，可以用 `--kex`、`--cipher`、`--hostkey` 替换；`--mac` 只在选择 CTR 类加密时需要。`--workload` 可选 `handshake`、`download`、`upload` 或 `all`，`--json` 输出机器可读结果，完整选项见 `yanterm-ssh-bench --help`。

**yanterm 客户端 → yanterm 服务端**

```bash
./build/release/yanterm-ssh-bench spawn-server
```

**yanterm 客户端 → OpenSSH 服务端**

```bash
./build/release/yanterm-ssh-bench spawn-sshd
./build/release/yanterm-ssh-bench connect 127.0.0.1 --identity ~/.ssh/id_ed25519
```

**OpenSSH 客户端 → yanterm 服务端**

```bash
ssh-keygen -q -t ed25519 -N '' -f /tmp/bench-user
./build/release/yanterm-ssh-bench server --port 22333 --user "$USER" \
    --authorized /tmp/bench-user.pub --host-key /tmp/bench-user
ssh -T -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -i /tmp/bench-user -p 22333 "$USER@127.0.0.1" \
    'dd if=/dev/zero bs=1M count=4096 status=none' >/dev/null
```

`connect` 还支持 `--jump [user@]host[:port]`（可重复）来测量多跳跳板链路。

## 使用约束

- **线程**：协议核心是单线程的 sans-I/O 状态机。同一个会话不能被多个线程共享，但每个线程可以各自创建并使用独立的会话。
- **ABI**：不承诺跨版本的 C++ ABI 稳定。头文件和静态库必须来自同一版本。
- **API 稳定性**：项目仍处于 0.x 阶段，公开 API 可能调整。`detail/` 与 `impl/` 下的内容虽然随包发布，但不属于公开 API。

## 文档索引

- [`PUBLIC_API.md`](PUBLIC_API.md)：公开 API 清单与模块分层。
- [`SOURCE_LAYOUT.md`](SOURCE_LAYOUT.md)：源码布局规范，以及 header-only / 静态库双模式的实现规则。

## 许可证

[MIT](LICENSE)
