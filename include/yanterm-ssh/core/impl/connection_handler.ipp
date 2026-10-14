#include <yanterm-ssh/core/connection.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/core/impl/connection_handler.ipp is an implementation file, not a public header."
#endif

#include <vector>

namespace yanterm::ssh::core {

YANTERM_SSH_INLINE void handler::on_peer_identification(connection&, std::string_view) {}

YANTERM_SSH_INLINE void handler::on_host_key(connection& c, host_key_ticket ticket,
                                             std::span<const std::byte>) {
    (void)c.resolve(ticket, host_key_verdict::reject);
}

YANTERM_SSH_INLINE void handler::on_handshake_done(connection&) {}
YANTERM_SSH_INLINE void handler::on_rekey_done(connection&) {}

YANTERM_SSH_INLINE void handler::on_debug(connection&, bool, std::string_view,
                                          std::string_view) {}

YANTERM_SSH_INLINE void handler::on_ignore(connection&, std::span<const std::byte>) {}

YANTERM_SSH_INLINE void handler::on_disconnect(connection&, wire::disconnect_reason,
                                               std::string_view, std::string_view) {}

YANTERM_SSH_INLINE void handler::on_auth_banner(connection&, std::string_view,
                                                std::string_view) {}

YANTERM_SSH_INLINE void handler::on_auth_result(connection&, const auth::auth_result&) {}

YANTERM_SSH_INLINE void handler::on_kbdint_request(connection& c, kbdint_ticket ticket,
                                                  const auth::info_request_view& request) {
    std::vector<std::string_view> responses(request.prompts.size());
    (void)c.resolve(ticket, responses);
}

YANTERM_SSH_INLINE void handler::on_auth_request(connection& c, auth_ticket ticket,
                                                const auth::auth_request_view&) {
    (void)c.resolve(ticket, auth::auth_verdict::failure(""));
}

YANTERM_SSH_INLINE void handler::on_kbdint_response(
    connection&, auth_ticket, std::span<const std::string_view>) {}

YANTERM_SSH_INLINE void handler::on_open_request(
    connection& c, open_ticket ticket, const channels::open_request_view&) {
    (void)c.resolve(ticket, channels::channel_open_verdict::rejected(
                                channels::channel_open_reason::administratively_prohibited, {}));
}

YANTERM_SSH_INLINE void handler::on_open_result(
    connection&, channel_ref, void*, const channels::open_result_view&) {}

YANTERM_SSH_INLINE void handler::on_channel_request(
    connection& c, channel_request_ticket ticket, void*, const channels::request_view&) {
    (void)c.resolve(ticket, false);
}

YANTERM_SSH_INLINE void handler::on_channel_reply(connection&, channel_ref, void*, bool) {}

YANTERM_SSH_INLINE void handler::on_global_request(
    connection& c, global_request_ticket ticket, const channels::request_view&) {
    (void)c.resolve(ticket, false);
}

YANTERM_SSH_INLINE void handler::on_global_reply(
    connection&, bool, std::span<const std::byte>) {}

YANTERM_SSH_INLINE void handler::on_readable(connection&, channel_ref, void*, std::uint32_t) {}
YANTERM_SSH_INLINE void handler::on_writable(connection&, channel_ref, void*) {}
YANTERM_SSH_INLINE void handler::on_eof(connection&, channel_ref, void*) {}
YANTERM_SSH_INLINE void handler::on_closed(connection&, channel_ref, void*) {}
YANTERM_SSH_INLINE void handler::on_released(connection&, channel_ref, void*) {}

}  // namespace yanterm::ssh::core
