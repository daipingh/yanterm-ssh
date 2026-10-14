#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/channels/types.hpp>
#include <yanterm-ssh/wire/types.hpp>

#include <cstdint>
#include <span>
#include <string_view>

namespace yanterm::ssh::channels {

void encode_pty_req(wire::writer& w, const pty_spec& s);
bool decode_pty_req(std::span<const std::byte> extra, std::string_view& term,
                     window_size& ws, std::span<const std::byte>& modes) noexcept;

void encode_exec(wire::writer& w, std::string_view command);
bool decode_exec(std::span<const std::byte> extra, std::string_view& command) noexcept;
void encode_subsystem(wire::writer& w, std::string_view name);
bool decode_subsystem(std::span<const std::byte> extra, std::string_view& name) noexcept;
void encode_env(wire::writer& w, std::string_view name, std::string_view value);
bool decode_env(std::span<const std::byte> extra, std::string_view& name,
                 std::string_view& value) noexcept;
void encode_window_change(wire::writer& w, const window_size& s);
bool decode_window_change(std::span<const std::byte> extra, window_size& s) noexcept;
void encode_signal(wire::writer& w, std::string_view name);
bool decode_signal(std::span<const std::byte> extra, std::string_view& name) noexcept;
void encode_exit_status(wire::writer& w, std::uint32_t status);
bool decode_exit_status(std::span<const std::byte> extra, std::uint32_t& status) noexcept;
void encode_exit_signal(wire::writer& w, const exit_signal& s);
bool decode_exit_signal(std::span<const std::byte> extra, std::string_view& name,
                         bool& core_dumped, std::string_view& message,
                         std::string_view& language) noexcept;
void encode_direct_tcpip(wire::writer& w, std::string_view host, std::uint32_t port,
                          std::string_view orig_host, std::uint32_t orig_port);
bool decode_direct_tcpip(std::span<const std::byte> extra, std::string_view& host,
                          std::uint32_t& port, std::string_view& orig_host,
                          std::uint32_t& orig_port) noexcept;
void encode_x11(wire::writer& w, std::string_view orig_host, std::uint32_t orig_port);
bool decode_x11(std::span<const std::byte> extra, std::string_view& orig_host,
                 std::uint32_t& orig_port) noexcept;
void encode_x11_req(wire::writer& w, const x11_req_spec& s);
bool decode_x11_req(std::span<const std::byte> extra, bool& single_connection,
                     std::string_view& protocol, std::string_view& cookie,
                     std::uint32_t& screen) noexcept;
void encode_streamlocal(wire::writer& w, std::string_view socket_path);
bool decode_streamlocal(std::span<const std::byte> extra, std::string_view& socket_path,
                         std::string_view& reserved) noexcept;
void encode_forwarded_streamlocal(wire::writer& w, std::string_view socket_path);
bool decode_forwarded_streamlocal(std::span<const std::byte> extra, std::string_view& socket_path,
                                   std::string_view& reserved) noexcept;
void encode_tcpip_forward(wire::writer& w, std::string_view addr, std::uint32_t port);
bool decode_tcpip_forward(std::span<const std::byte> extra, std::string_view& addr,
                         std::uint32_t& port) noexcept;
void encode_streamlocal_forward(wire::writer& w, std::string_view socket_path);
bool decode_streamlocal_forward(std::span<const std::byte> extra,
                                 std::string_view& socket_path) noexcept;

}  // namespace yanterm::ssh::channels

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/channels/impl/requests.ipp>
#endif
