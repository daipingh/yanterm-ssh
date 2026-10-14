#pragma once

#include <yanterm-ssh/channels/requests.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/channels/impl/requests.ipp is an implementation file, not a public header."
#endif

namespace yanterm::ssh::channels {

YANTERM_SSH_INLINE void encode_pty_req(wire::writer& w, const pty_spec& s) {
    w.write_string(s.term);
    w.write_uint32(s.width);
    w.write_uint32(s.height);
    w.write_uint32(s.pixel_width);
    w.write_uint32(s.pixel_height);
    if (s.modes.empty()) {
        const std::byte end{0};
        w.write_string(std::span<const std::byte>{&end, 1});
    } else {
        w.write_string(s.modes);
    }
}

YANTERM_SSH_INLINE bool decode_pty_req(std::span<const std::byte> extra, std::string_view& term,
                                        window_size& ws, std::span<const std::byte>& modes) noexcept {
    wire::reader r{extra};
    if (!r.read_string(term) || !r.read_uint32(ws.cols) || !r.read_uint32(ws.rows)
        || !r.read_uint32(ws.pixel_width) || !r.read_uint32(ws.pixel_height)
        || !r.read_string(modes)) {
        return false;
    }
    return r.empty();
}

YANTERM_SSH_INLINE void encode_exec(wire::writer& w, std::string_view command) { w.write_string(command); }
YANTERM_SSH_INLINE bool decode_exec(std::span<const std::byte> extra, std::string_view& command) noexcept {
    wire::reader r{extra};
    return r.read_string(command) && r.empty();
}
YANTERM_SSH_INLINE void encode_subsystem(wire::writer& w, std::string_view name) { w.write_string(name); }
YANTERM_SSH_INLINE bool decode_subsystem(std::span<const std::byte> extra, std::string_view& name) noexcept {
    wire::reader r{extra};
    return r.read_string(name) && r.empty();
}
YANTERM_SSH_INLINE void encode_env(wire::writer& w, std::string_view name, std::string_view value) {
    w.write_string(name);
    w.write_string(value);
}
YANTERM_SSH_INLINE bool decode_env(std::span<const std::byte> extra, std::string_view& name,
                                   std::string_view& value) noexcept {
    wire::reader r{extra};
    return r.read_string(name) && r.read_string(value) && r.empty();
}
YANTERM_SSH_INLINE void encode_window_change(wire::writer& w, const window_size& s) {
    w.write_uint32(s.cols);
    w.write_uint32(s.rows);
    w.write_uint32(s.pixel_width);
    w.write_uint32(s.pixel_height);
}
YANTERM_SSH_INLINE bool decode_window_change(std::span<const std::byte> extra, window_size& s) noexcept {
    wire::reader r{extra};
    return r.read_uint32(s.cols) && r.read_uint32(s.rows) && r.read_uint32(s.pixel_width)
        && r.read_uint32(s.pixel_height) && r.empty();
}
YANTERM_SSH_INLINE void encode_signal(wire::writer& w, std::string_view name) { w.write_string(name); }
YANTERM_SSH_INLINE bool decode_signal(std::span<const std::byte> extra, std::string_view& name) noexcept {
    wire::reader r{extra};
    return r.read_string(name) && r.empty();
}
YANTERM_SSH_INLINE void encode_exit_status(wire::writer& w, std::uint32_t status) { w.write_uint32(status); }
YANTERM_SSH_INLINE bool decode_exit_status(std::span<const std::byte> extra, std::uint32_t& status) noexcept {
    wire::reader r{extra};
    return r.read_uint32(status) && r.empty();
}
YANTERM_SSH_INLINE void encode_exit_signal(wire::writer& w, const exit_signal& s) {
    w.write_string(s.name);
    w.write_bool(s.core_dumped);
    w.write_string(s.message);
    w.write_string(s.language);
}
YANTERM_SSH_INLINE bool decode_exit_signal(std::span<const std::byte> extra, std::string_view& name,
                                            bool& core_dumped, std::string_view& message,
                                            std::string_view& language) noexcept {
    wire::reader r{extra};
    return r.read_string(name) && r.read_bool(core_dumped) && r.read_string(message)
        && r.read_string(language) && r.empty();
}
YANTERM_SSH_INLINE void encode_direct_tcpip(wire::writer& w, std::string_view host, std::uint32_t port,
                                             std::string_view orig_host, std::uint32_t orig_port) {
    w.write_string(host);
    w.write_uint32(port);
    w.write_string(orig_host);
    w.write_uint32(orig_port);
}
YANTERM_SSH_INLINE bool decode_direct_tcpip(std::span<const std::byte> extra, std::string_view& host,
                                             std::uint32_t& port, std::string_view& orig_host,
                                             std::uint32_t& orig_port) noexcept {
    wire::reader r{extra};
    return r.read_string(host) && r.read_uint32(port) && r.read_string(orig_host)
        && r.read_uint32(orig_port) && r.empty();
}
YANTERM_SSH_INLINE void encode_x11(wire::writer& w, std::string_view orig_host, std::uint32_t orig_port) {
    w.write_string(orig_host);
    w.write_uint32(orig_port);
}
YANTERM_SSH_INLINE bool decode_x11(std::span<const std::byte> extra, std::string_view& orig_host,
                                    std::uint32_t& orig_port) noexcept {
    wire::reader r{extra};
    return r.read_string(orig_host) && r.read_uint32(orig_port) && r.empty();
}
YANTERM_SSH_INLINE void encode_x11_req(wire::writer& w, const x11_req_spec& s) {
    w.write_bool(s.single_connection);
    w.write_string(s.protocol);
    w.write_string(s.cookie);
    w.write_uint32(s.screen);
}
YANTERM_SSH_INLINE bool decode_x11_req(std::span<const std::byte> extra, bool& single_connection,
                                        std::string_view& protocol, std::string_view& cookie,
                                        std::uint32_t& screen) noexcept {
    wire::reader r{extra};
    return r.read_bool(single_connection) && r.read_string(protocol) && r.read_string(cookie)
        && r.read_uint32(screen) && r.empty();
}
YANTERM_SSH_INLINE void encode_streamlocal(wire::writer& w, std::string_view socket_path) {
    w.write_string(socket_path);
    w.write_string(std::string_view{});
    w.write_uint32(0);
}
YANTERM_SSH_INLINE bool decode_streamlocal(std::span<const std::byte> extra, std::string_view& socket_path,
                                            std::string_view& reserved) noexcept {
    wire::reader r{extra};
    std::uint32_t reserved_u32 = 0;
    return r.read_string(socket_path) && r.read_string(reserved) && r.read_uint32(reserved_u32)
        && r.empty();
}
YANTERM_SSH_INLINE void encode_tcpip_forward(wire::writer& w, std::string_view addr, std::uint32_t port) {
    w.write_string(addr);
    w.write_uint32(port);
}
YANTERM_SSH_INLINE bool decode_tcpip_forward(std::span<const std::byte> extra, std::string_view& addr,
                                              std::uint32_t& port) noexcept {
    wire::reader r{extra};
    return r.read_string(addr) && r.read_uint32(port) && r.empty();
}
YANTERM_SSH_INLINE void encode_forwarded_streamlocal(wire::writer& w, std::string_view socket_path) {
    w.write_string(socket_path);
    w.write_string(std::string_view{});
}
YANTERM_SSH_INLINE bool decode_forwarded_streamlocal(std::span<const std::byte> extra,
                                                      std::string_view& socket_path,
                                                      std::string_view& reserved) noexcept {
    wire::reader r{extra};
    return r.read_string(socket_path) && r.read_string(reserved) && r.empty();
}
YANTERM_SSH_INLINE void encode_streamlocal_forward(wire::writer& w, std::string_view socket_path) {
    w.write_string(socket_path);
}
YANTERM_SSH_INLINE bool decode_streamlocal_forward(std::span<const std::byte> extra,
                                                    std::string_view& socket_path) noexcept {
    wire::reader r{extra};
    return r.read_string(socket_path) && r.empty();
}

}  // namespace yanterm::ssh::channels
