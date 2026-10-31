# yanterm-ssh 公共 API 清单

## 0. 模块与依赖

每层只能向下依赖。

| 层 | 内容 |
| --- | --- |
| L0 | `detail/config.hpp`、`error.hpp` |
| L1 词汇 | `wire/message_ids`、`transport/packet_mode`、`auth/types`、`channels/types`、`crypto/algorithms`、`sftp/types` |
| L2 | `wire/types` + `wire/detail/messages`、`crypto/provider`、`crypto/secure_buffer` |
| L3 | `crypto/openssl`、`keys/**`、`kex/algorithms` + `kex/detail/tables`、`channels/requests`、`memory/**`、`sftp/packets` |
| L4 | `core/**`（`types` / `config` / `handler` / `connection` 公开，`detail/**` 私有） |
| L5 门面 | `facade_types.hpp`、`options.hpp`、`session.hpp`、`channel.hpp`、`sftp.hpp`、`detail/session_impl.hpp` |

```mermaid
flowchart TB
  subgraph L5["L5 门面"]
    facade["session / channel / options / facade_types / sftp"]
  end
  subgraph L4["L4 core"]
    core_pub["types / config / handler / connection"]
    core_priv["core/detail/**"]
  end
  subgraph L3["L3"]
    openssl["crypto/openssl"]
    keys["keys/**"]
    kexalg["kex/algorithms + kex/detail/tables"]
    reqs["channels/requests"]
    memory["memory/**"]
    sftp_pkt["sftp/packets"]
  end
  subgraph L2["L2"]
    wtypes["wire/types"]
    wmsg["wire/detail/messages"]
    prov["crypto/provider"]
    secbuf["crypto/secure_buffer"]
  end
  subgraph L1["L1 词汇"]
    mid["wire/message_ids"]
    pm["transport/packet_mode"]
    at["auth/types"]
    ct["channels/types"]
    calg["crypto/algorithms"]
    sftp_ty["sftp/types"]
  end
  subgraph L0["L0"]
    cfg["detail/config.hpp"]
    err["error.hpp"]
  end
  L5 --> L4 --> L3 --> L2 --> L1 --> L0
```

## 1. 协程包装门面

- [yanterm-ssh/session.hpp](include/yanterm-ssh/session.hpp)
- [yanterm-ssh/channel.hpp](include/yanterm-ssh/channel.hpp)
- [yanterm-ssh/options.hpp](include/yanterm-ssh/options.hpp)
- [yanterm-ssh/facade_types.hpp](include/yanterm-ssh/facade_types.hpp)

### [yanterm-ssh/facade_types.hpp](include/yanterm-ssh/facade_types.hpp)

```
namespace yanterm::ssh

using disconnect_reason
using auth_result
using auth_verdict
using verdict_kind              // auth_verdict::kind
using kbdint_prompt
using publickey_sign_request
using channel_id
using channel_open_reason
using channel_type
using pty_spec
using x11_req_spec
using window_size
using exit_signal

struct disconnect_info          // 对端或本端 DISCONNECT
class host_key_view             // 握手时交给客户端校验的主机公钥
class auth_request              // 服务端 authenticate 回调入参

host_key_view::key
host_key_view::fingerprint

auth_request::user
auth_request::service
auth_request::method
auth_request::has_signature
auth_request::algorithm
auth_request::public_blob
auth_request::password
auth_request::challenge
```

### [yanterm-ssh/options.hpp](include/yanterm-ssh/options.hpp)

```
namespace yanterm::ssh

default_max_pending_requests   // max_pending_requests == 0 时的钳制值
struct session_options          // 握手与限流默认值
struct client_options           // 另含 on_banner
struct server_options           // 另含 host_keys、认证横幅与用户公钥认证算法列表
```

### [yanterm-ssh/session.hpp](include/yanterm-ssh/session.hpp)

```
namespace yanterm::ssh

class session                   // 会话基类：I/O 循环、开通道、全局请求
class client_session            // 客户端：handshake 与认证
class server_session            // 服务端：handshake 与 authenticate
run_with                        // 启动 session::run 并跑用户协程

session::run
session::disconnect
session::serve
session::open_session_channel
session::open_direct_tcpip
session::open_direct_streamlocal
session::open_forwarded_tcpip
session::open_x11
session::open_forwarded_streamlocal
session::request_tcpip_forward
session::cancel_tcpip_forward
session::request_streamlocal_forward
session::cancel_streamlocal_forward
session::send_global_request
session::rekey
session::send_keepalive
session::failure
session::failure_detail
session::disconnected
session::peer_identification
session::session_id
session::negotiated

client_session::handshake
client_session::auth_none
client_session::auth_password
client_session::auth_publickey_query  // 询问公钥是否可用（USERAUTH_PK_OK）
client_session::auth_publickey  // 两个重载：进程内私钥 / 公钥 + 外部 signer
client_session::auth_keyboard_interactive

server_session::handshake
server_session::authenticate
```

### [yanterm-ssh/channel.hpp](include/yanterm-ssh/channel.hpp)

```
namespace yanterm::ssh

class channel                   // 已打开通道；满足 auv stream_like
struct channel_open_result      // 出站开通道结果
class inbound_channel_open      // 入站 CHANNEL_OPEN；析构未结算则拒绝
class inbound_channel_request   // 入站 CHANNEL_REQUEST
class inbound_global_request    // 入站 GLOBAL_REQUEST；析构未结算则拒绝

channel::read
channel::write
channel::shutdown
channel::close
channel::read_stderr
channel::write_stderr
channel::request_pty
channel::request_shell
channel::request_exec
channel::request_subsystem
channel::request_env
channel::request_window_change
channel::request_signal
channel::send_exit_status
channel::send_exit_signal
channel::request_x11
channel::serve_requests

inbound_channel_open::type
inbound_channel_open::request_type
inbound_channel_open::host
inbound_channel_open::port
inbound_channel_open::originator_host
inbound_channel_open::originator_port
inbound_channel_open::socket_path
inbound_channel_open::payload
inbound_channel_open::accept
inbound_channel_open::reject

inbound_channel_request::type
inbound_channel_request::payload
inbound_channel_request::want_reply
inbound_channel_request::pty
inbound_channel_request::exec_command
inbound_channel_request::subsystem
inbound_channel_request::env
inbound_channel_request::window_change
inbound_channel_request::signal
inbound_channel_request::exit_status
inbound_channel_request::exit_signal
inbound_channel_request::x11

inbound_global_request::type
inbound_global_request::payload
inbound_global_request::want_reply
inbound_global_request::accept
inbound_global_request::reject
```

## 2. 核心协议（sans-I/O）

- [yanterm-ssh/core/types.hpp](include/yanterm-ssh/core/types.hpp)
- [yanterm-ssh/core/config.hpp](include/yanterm-ssh/core/config.hpp)
- [yanterm-ssh/core/handler.hpp](include/yanterm-ssh/core/handler.hpp)
- [yanterm-ssh/core/connection.hpp](include/yanterm-ssh/core/connection.hpp)
- [yanterm-ssh/wire/message_ids.hpp](include/yanterm-ssh/wire/message_ids.hpp)
- [yanterm-ssh/wire/types.hpp](include/yanterm-ssh/wire/types.hpp)
- [yanterm-ssh/kex/algorithms.hpp](include/yanterm-ssh/kex/algorithms.hpp)
- [yanterm-ssh/transport/packet_mode.hpp](include/yanterm-ssh/transport/packet_mode.hpp)
- [yanterm-ssh/auth/types.hpp](include/yanterm-ssh/auth/types.hpp)
- [yanterm-ssh/channels/types.hpp](include/yanterm-ssh/channels/types.hpp)
- [yanterm-ssh/channels/requests.hpp](include/yanterm-ssh/channels/requests.hpp)

### [yanterm-ssh/core/types.hpp](include/yanterm-ssh/core/types.hpp)

```
namespace yanterm::ssh::core

enum class role                 // client / server
enum class host_key_verdict     // 主机密钥裁决
struct publickey_sign_request   // 公钥认证待签请求：algorithm、crypto::sig_id 与公钥 blob
```

### [yanterm-ssh/core/config.hpp](include/yanterm-ssh/core/config.hpp)

```
namespace yanterm::ssh::core

struct config                   // sans-I/O 连接配置
```

### [yanterm-ssh/core/handler.hpp](include/yanterm-ssh/core/handler.hpp)

```
namespace yanterm::ssh::core

struct channel_ref              // 通道引用
class host_key_ticket           // 客户端主机密钥
class auth_ticket               // 服务端 USERAUTH_REQUEST
class kbdint_ticket             // 客户端 USERAUTH_INFO_REQUEST
class open_ticket               // 入站 CHANNEL_OPEN
class channel_request_ticket    // 入站 CHANNEL_REQUEST
class global_request_ticket     // 入站 GLOBAL_REQUEST
class handler                   // 虚函数回调；构造 connection 时传入

handler::on_peer_identification
handler::on_host_key
handler::on_handshake_done
handler::on_rekey_done
handler::on_debug
handler::on_ignore
handler::on_disconnect
handler::on_auth_banner
handler::on_auth_result
handler::on_kbdint_request
handler::on_auth_request
handler::on_kbdint_response
handler::on_open_request
handler::on_open_result
handler::on_channel_request
handler::on_channel_reply
handler::on_global_request
handler::on_global_reply
handler::on_readable
handler::on_writable
handler::on_eof
handler::on_closed
handler::on_released
```

### [yanterm-ssh/core/connection.hpp](include/yanterm-ssh/core/connection.hpp)

```
namespace yanterm::ssh::core

class connection                // sans-I/O 连接状态机
struct connection::host_key_spec

connection::set_host_key
connection::set_host_keys
connection::feed
connection::pending_output
connection::pending_output0
connection::pending_output_bytes
connection::consume_output

connection::inbound_requests_stalled
connection::resolve

connection::auth_none
connection::auth_password
connection::auth_publickey          // 用户公钥认证（进程内私钥）
connection::auth_publickey_sign_request
connection::auth_publickey_signed   // 用户公钥认证（外部私钥，如 auth agent）
connection::auth_publickey_query
connection::auth_keyboard_interactive
connection::send_auth_banner

connection::open_channel
connection::abandon_open
connection::channel_eof
connection::channel_close
connection::channel_write
connection::channel_write_extended
connection::channel_read
connection::channel_request
connection::request_pty
connection::request_shell
connection::request_exec
connection::request_subsystem
connection::request_env
connection::request_window_change
connection::request_signal
connection::send_exit_status
connection::send_exit_signal
connection::request_x11

connection::send_global_request
connection::request_tcpip_forward
connection::cancel_tcpip_forward
connection::request_streamlocal_forward
connection::cancel_streamlocal_forward

connection::send_ignore
connection::send_debug
connection::disconnect
connection::rekey

connection::peer_identification
connection::negotiated
connection::session_id
connection::outbound_sequence_number
connection::failure
connection::failure_detail
```

### [yanterm-ssh/wire/message_ids.hpp](include/yanterm-ssh/wire/message_ids.hpp)

```
namespace yanterm::ssh::wire

enum class msg                  // RFC 消息号
enum class disconnect_reason    // RFC 4253 断连原因
```

### [yanterm-ssh/wire/types.hpp](include/yanterm-ssh/wire/types.hpp)

```
namespace yanterm::ssh::wire

class name_list                 // RFC 4251 name-list 视图
class reader                    // 从 span 解包
class writer                    // 组包；take() 移出缓冲

name_list::raw
name_list::empty
name_list::begin
name_list::end
name_list::contains

reader::ok
reader::error
reader::offset
reader::remaining
reader::empty
reader::read_bytes
reader::read_byte
reader::read_bool
reader::read_uint32
reader::read_uint64
reader::read_string
reader::read_mpint
reader::read_name_list
reader::fail

writer::write_byte
writer::write_bool
writer::write_uint32
writer::write_uint64
writer::write_bytes
writer::write_string
writer::write_mpint
writer::write_name_list
writer::data
writer::size
writer::take
writer::clear
writer::reserve
```

### [yanterm-ssh/kex/algorithms.hpp](include/yanterm-ssh/kex/algorithms.hpp)

```
namespace yanterm::ssh::kex

struct negotiated               // 协商结果
default_kex_algorithms          // 逗号分隔 name-list
supported_kex_algorithms
default_host_key_algorithms
supported_host_key_algorithms
default_cipher_algorithms
supported_cipher_algorithms
default_mac_algorithms
supported_mac_algorithms
```

### [yanterm-ssh/transport/packet_mode.hpp](include/yanterm-ssh/transport/packet_mode.hpp)

```
namespace yanterm::ssh::transport

enum class packet_mode          // 明文 / CTR-MAC / CTR-ETM / CBC-MAC / CBC-ETM / GCM / ChaCha
```

### [yanterm-ssh/auth/types.hpp](include/yanterm-ssh/auth/types.hpp)

```
namespace yanterm::ssh::auth

enum class method
parse_method
method_name
struct kbdint_prompt            // keyboard-interactive 提示
struct auth_result              // 客户端认证回复
enum class verdict_kind         // success / failure / info
struct auth_verdict             // 服务端认证裁决

auth_verdict::success
auth_verdict::failure
auth_verdict::info
```

### [yanterm-ssh/channels/types.hpp](include/yanterm-ssh/channels/types.hpp)

```
namespace yanterm::ssh::channels

using channel_id
enum class channel_type
enum class channel_open_reason
type_name
parse_type
type_session
type_direct_tcpip
type_forwarded_tcpip
type_x11
type_direct_streamlocal
type_forwarded_streamlocal
max_channel_data_payload
extended_data_stderr
struct channel_open_spec        // 出站 / 入站开通道
channel_open_spec::extra
struct channel_open_verdict     // 入站开通道裁决
struct channel_request_spec     // 通道请求 type + payload
struct window_size
struct pty_spec
struct x11_req_spec
struct exit_signal

channel_open_verdict::accepted
channel_open_verdict::rejected
```

### [yanterm-ssh/channels/requests.hpp](include/yanterm-ssh/channels/requests.hpp)

```
namespace yanterm::ssh::channels

encode_pty_req / decode_pty_req
encode_exec / decode_exec
encode_subsystem / decode_subsystem
encode_env / decode_env
encode_window_change / decode_window_change
encode_signal / decode_signal
encode_exit_status / decode_exit_status
encode_exit_signal / decode_exit_signal
encode_direct_tcpip / decode_direct_tcpip
encode_x11 / decode_x11
encode_x11_req / decode_x11_req
encode_streamlocal / decode_streamlocal
encode_forwarded_streamlocal / decode_forwarded_streamlocal
encode_tcpip_forward / decode_tcpip_forward
encode_streamlocal_forward / decode_streamlocal_forward
```

## 3. 加密提供者

- [yanterm-ssh/crypto/algorithms.hpp](include/yanterm-ssh/crypto/algorithms.hpp)
- [yanterm-ssh/crypto/secure_buffer.hpp](include/yanterm-ssh/crypto/secure_buffer.hpp)
- [yanterm-ssh/crypto/provider.hpp](include/yanterm-ssh/crypto/provider.hpp)
- [yanterm-ssh/crypto/openssl.hpp](include/yanterm-ssh/crypto/openssl.hpp)
- [yanterm-ssh/crypto/openssl3.hpp](include/yanterm-ssh/crypto/openssl3.hpp)
- [yanterm-ssh/crypto/openssl11.hpp](include/yanterm-ssh/crypto/openssl11.hpp)

### [yanterm-ssh/crypto/algorithms.hpp](include/yanterm-ssh/crypto/algorithms.hpp)

```
namespace yanterm::ssh::crypto

enum class hash_id
enum class cipher_id
enum class mac_id
enum class kex_id
enum class kem_id
enum class sig_id
enum class primitive_kind
struct public_key_material      // 验签用公钥分量
struct signature_material
struct private_key_material     // 签名用私钥分量

hash_output_size
cipher_key_size
cipher_block_size
cipher_iv_size
is_rsa_sig
is_ecdsa_sig
is_sm2_sig
generated_key_storage_size
kex_public_size
kex_secret_size
kem_public_size
kem_ciphertext_size
kem_secret_size
secure_zero                     // span<std::byte>
```

### [yanterm-ssh/crypto/secure_buffer.hpp](include/yanterm-ssh/crypto/secure_buffer.hpp)

```
namespace yanterm::ssh::crypto

class secure_bytes
class secure_string
template <std::size_t N> class secure_array

secure_bytes::assign
secure_bytes::append
secure_bytes::reserve
secure_bytes::wipe
secure_bytes::data
secure_bytes::size
secure_bytes::span
secure_string::assign
secure_string::wipe
secure_string::view
secure_array::span
```

### [yanterm-ssh/crypto/provider.hpp](include/yanterm-ssh/crypto/provider.hpp)

```
namespace yanterm::ssh::crypto

struct provider_vtable          // 类型擦除槽；实现者走 wrap/decorate，不手写
class hash_ctx
class hmac_ctx
class cipher
class aead_cipher
class kex_agreement
class kem_keypair
class signing_key
class provider                  // 加密后端句柄

hash_ctx::update
hash_ctx::final_into
hmac_ctx::update
hmac_ctx::final_into
cipher::set_iv
cipher::update
aead_cipher::begin
aead_cipher::update
aead_cipher::final
kex_agreement::public_value
kex_agreement::agree
kem_keypair::public_key
kem_keypair::decapsulate
signing_key::sign

provider::wrap
provider::decorate
provider::supports
provider::random_bytes
provider::constant_time_eq
provider::new_hash
provider::new_hmac
provider::new_cipher
provider::new_aead
provider::new_kex
provider::new_kem
provider::encapsulate
provider::new_signing_key
provider::poly1305
provider::verify
provider::cbc_crypt
provider::generate_keypair
provider::hash
```

### [yanterm-ssh/crypto/openssl.hpp](include/yanterm-ssh/crypto/openssl.hpp)

```
namespace yanterm::ssh::crypto

using openssl_backend           // OpenSSL 后端；经 provider::wrap 接入；按编译时版本取 ossl3 或 ossl1_1 的实现
```

### [yanterm-ssh/crypto/openssl3.hpp](include/yanterm-ssh/crypto/openssl3.hpp)

```
namespace yanterm::ssh::crypto::ossl3

using openssl_backend           // 基于 OpenSSL 3.x API；需要 OpenSSL 3.0+
```

### [yanterm-ssh/crypto/openssl11.hpp](include/yanterm-ssh/crypto/openssl11.hpp)

```
namespace yanterm::ssh::crypto::ossl1_1

using openssl_backend           // 基于 OpenSSL 1.1.1 API；在 OpenSSL 3.x 下同样可用（有废弃告警）
```

## 4. 密钥与文件格式

- [yanterm-ssh/keys/public_key.hpp](include/yanterm-ssh/keys/public_key.hpp)
- [yanterm-ssh/keys/private_key.hpp](include/yanterm-ssh/keys/private_key.hpp)
- [yanterm-ssh/keys/fingerprint.hpp](include/yanterm-ssh/keys/fingerprint.hpp)
- [yanterm-ssh/keys/known_hosts.hpp](include/yanterm-ssh/keys/known_hosts.hpp)
- [yanterm-ssh/keys/authorized_keys.hpp](include/yanterm-ssh/keys/authorized_keys.hpp)
- [yanterm-ssh/keys/io.hpp](include/yanterm-ssh/keys/io.hpp)

### [yanterm-ssh/keys/public_key.hpp](include/yanterm-ssh/keys/public_key.hpp)

```
namespace yanterm::ssh::keys

class public_key                // SSH 公钥 blob / authorized_keys 行

public_key::parse_blob
public_key::from_material
public_key::parse_authorized_key_body
public_key::parse_line
public_key::to_line
public_key::blob
public_key::algorithm_name
public_key::algorithm
public_key::material
```

### [yanterm-ssh/keys/private_key.hpp](include/yanterm-ssh/keys/private_key.hpp)

```
namespace yanterm::ssh::keys

struct private_key_info         // 私钥文件探查（是否加密等）
class private_key               // OpenSSH 私钥

private_key::inspect
private_key::parse
private_key::serialize
private_key::generate
private_key::pub
private_key::material
private_key::comment
```

### [yanterm-ssh/keys/fingerprint.hpp](include/yanterm-ssh/keys/fingerprint.hpp)

```
namespace yanterm::ssh::keys

fingerprint_sha256
```

### [yanterm-ssh/keys/known_hosts.hpp](include/yanterm-ssh/keys/known_hosts.hpp)

```
namespace yanterm::ssh::keys

enum class host_marker
enum class host_key_match
struct known_host_line
class known_hosts               // known_hosts 解析与匹配

known_hosts::parse
known_hosts::serialize
known_hosts::match
known_hosts::append
known_hosts::erase_matching
known_hosts::lines
```

### [yanterm-ssh/keys/authorized_keys.hpp](include/yanterm-ssh/keys/authorized_keys.hpp)

```
namespace yanterm::ssh::keys

struct authorized_key_line
class authorized_keys           // authorized_keys 解析

authorized_keys::parse
authorized_keys::serialize
authorized_keys::lines
```

### [yanterm-ssh/keys/io.hpp](include/yanterm-ssh/keys/io.hpp)

阻塞文件 I/O，显式 include。

```
namespace yanterm::ssh::keys::io

read_file
check_private_key_permissions
atomic_write
load_private_key
```

## 5. 页内存

- [yanterm-ssh/memory/page_resource.hpp](include/yanterm-ssh/memory/page_resource.hpp)

### [yanterm-ssh/memory/page_resource.hpp](include/yanterm-ssh/memory/page_resource.hpp)

```
namespace yanterm::ssh::memory

default_page_size                 // 64 KiB
struct page_resource_options      // max_cached_blocks，默认 64
class page_resource               // 内部加锁；上游必须线程安全
class unsynchronized_page_resource // 不加锁，只给单线程用
default_page_resource()           // 进程级 page_resource 实例
```

## 6. 错误码与版本

- [yanterm-ssh/error.hpp](include/yanterm-ssh/error.hpp)
- [yanterm-ssh/version.hpp](include/yanterm-ssh/version.hpp)

### [yanterm-ssh/error.hpp](include/yanterm-ssh/error.hpp)

```
namespace yanterm::ssh

enum class errc                 // 失败域；std::error_condition，应用按 ec == errc::… 分支
condition_category              // name() 为 "yanterm-ssh.errc"
make_error_condition
error_category                  // 声明；库身份，非分支契约
```

SFTP 状态码不走上面的 `errc` 枚举。`sftp::status_code` 是 `std::error_code` 枚举，类别 `sftp::error_category()` 的 `name()` 为 `"yanterm-ssh.sftp"`。`default_error_condition` 把 `no_such_file` 映到 `std::errc::no_such_file_or_directory`，`permission_denied` 映到 `std::errc::permission_denied`，`op_unsupported` 映到 `std::errc::operation_not_supported`，`no_connection` / `connection_lost` 映到 `errc::session_closed`，`bad_message` 映到 `errc::protocol_violation`。`ok`、`eof`、`failure` 以及枚举外的数值留在该类别里，`error_code::value()` 仍是原始数值。

### [yanterm-ssh/version.hpp](include/yanterm-ssh/version.hpp)

```
namespace yanterm::ssh

YANTERM_SSH_VERSION_MAJOR
YANTERM_SSH_VERSION_MINOR
YANTERM_SSH_VERSION_PATCH
YANTERM_SSH_VERSION_STRING
version_string()
default_software()            // "yanterm_ssh_" + 版本号；RFC 4253 软件版本字段
```

## 7. SFTP

客户端只说 SFTP v3（draft-ietf-secsh-filexfer-02），外加对端在 `SSH_FXP_VERSION` 里通告、且版本字符串完全一致的 OpenSSH 扩展。没有 SFTP 服务端，也没有 SCP。`ATTR_EXTENDED` 解码时校验并跳过，编码时不发送。路径是不透明字节。

`open` 被取消时，服务端句柄可能一直留到通道关闭。`sftp_handle` 只保存句柄字节，析构不发送 `SSH_FXP_CLOSE`。

- [yanterm-ssh/sftp/types.hpp](include/yanterm-ssh/sftp/types.hpp)
- [yanterm-ssh/sftp/packets.hpp](include/yanterm-ssh/sftp/packets.hpp)
- [yanterm-ssh/sftp.hpp](include/yanterm-ssh/sftp.hpp)

### [yanterm-ssh/sftp/types.hpp](include/yanterm-ssh/sftp/types.hpp)

```
namespace yanterm::ssh::sftp

protocol_version                // 3
default_max_packet_length       // 262144
fallback_io_length              // 32768
max_handle_length               // 256
enum class msg                  // 1–20、101–105、200–201
enum class status_code          // 0–8；可与 error_code 比较
open_flags::*                   // read / write / append / creat / trunc / excl
attr_flags::*                   // size / uidgid / permissions / acmodtime / extended
struct attrs
struct name_entry
struct limits_info
struct statvfs_info
enum class extension            // 11 个 OpenSSH 扩展
class extension_set
error_category()                // name() 为 "yanterm-ssh.sftp"
make_error_code(status_code)
result<T> / result<void>        // ec、message、value
```

### [yanterm-ssh/sftp/packets.hpp](include/yanterm-ssh/sftp/packets.hpp)

帧与 v3 报文的 `encode_*` / `decode_*`。解码出的 `string_view` 和 `span` 借用输入。`SSH_FXP_SYMLINK` 按 OpenSSH 的顺序编码：先 `targetpath`，再 `linkpath`。`users-groups-by-id` 的请求和应答都是两段打包过的字符串，不是先写个数再写 `uint32`。扩展应答允许兼容的尾部。`advertised_extensions` 只接受下列名字和版本：

```
posix-rename@openssh.com            1
statvfs@openssh.com                 2
fstatvfs@openssh.com                2
hardlink@openssh.com                1
fsync@openssh.com                   1
lsetstat@openssh.com                1
limits@openssh.com                  1
expand-path@openssh.com             1
copy-data                           1
home-directory                      1
users-groups-by-id@openssh.com      1
```

### [yanterm-ssh/sftp.hpp](include/yanterm-ssh/sftp.hpp)

```
namespace yanterm::ssh

struct sftp_options               // max_packet_length、max_inflight、query_limits
class sftp_handle                 // 句柄字节；析构不 CLOSE
sftp::id_name_lists               // users、groups
basic_sftp_client<Stream>         // 要求 auv::stream_like<Stream>
sftp_client                       // basic_sftp_client<channel>
open_sftp(session&, sftp_options) // 打开 session 通道、请求 subsystem "sftp"、start()
```

`basic_sftp_client` 在 `start()` 里发送 `SSH_FXP_INIT` 3，不附带扩展。之后的操作共用一条写串行和中继读。取消进行中的请求会丢掉迟到的应答，不把客户端标成失败。`read_all` / `write_all` 按 `max_inflight` 流水线分片。对端没通告的扩展返回 `status_code::op_unsupported`，不会写到线上。`home_directory` 把用户名原样送出；空字符串在 OpenSSH 10 表示当前登录用户，更早的 OpenSSH 会按字面查找。

