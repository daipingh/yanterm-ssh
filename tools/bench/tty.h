#pragma once

#include <yanterm-ssh/crypto/secure_buffer.hpp>

#include <string_view>
#include <system_error>

namespace bench {

// 从控制终端读一行口令（POSIX `/dev/tty`，Windows `CONIN$`），关回显。
// 打不开控制终端时返回 passphrase_required；不读 stdin。
std::error_code read_controlling_tty_passphrase(std::string_view prompt,
                                                yanterm::ssh::crypto::secure_bytes& out);

}  // namespace bench
