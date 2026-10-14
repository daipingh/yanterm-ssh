#pragma once

#include <yanterm-ssh/core/connection.hpp>
#include <yanterm-ssh/core/handler.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

namespace yanterm::ssh::testing {

class recording_handler : public core::handler {
public:
    struct peer_identification {
        std::string banner;
    };
    struct verify_host_key {
        core::host_key_ticket ticket;
        std::vector<std::byte> blob;
    };
    struct handshake_done {
        kex::negotiated algorithms;
        std::vector<std::byte> session_id;
        std::string server_sig_algs;
    };
    struct rekey_done {
        kex::negotiated algorithms;
        std::vector<std::byte> session_id;
        std::string server_sig_algs;
    };
    struct debug_message {
        bool always_display = false;
        std::string text;
        std::string language;
    };
    struct ignore_message {
        std::vector<std::byte> data;
    };
    struct disconnected {
        wire::disconnect_reason reason{};
        std::string description;
        std::string language;
    };
    struct auth_banner {
        std::string text;
        std::string language;
    };
    struct auth_response {
        bool success = false;
        bool partial_success = false;
        bool pk_ok = false;
        std::string methods;
    };
    struct auth_info_request {
        core::kbdint_ticket ticket;
        std::string name;
        std::string instruction;
        std::string language;
        std::vector<auth::kbdint_prompt> prompts;
    };
    struct auth_request {
        core::auth_ticket ticket;
        std::string user;
        std::string service;
        std::string method;
        bool has_signature = false;
        std::string algorithm;
        std::vector<std::byte> public_blob;
        std::string password;
        std::string submethods;
    };
    struct auth_info_response {
        core::auth_ticket ticket;
        std::vector<std::string> responses;
    };
    struct channel_open_request {
        core::open_ticket ticket;
        core::channel_ref ref{};
        channels::channel_type type = channels::channel_type::unknown;
        std::string type_name;
        std::uint32_t window = 0;
        std::uint32_t max_packet = 0;
        std::string host;
        std::uint32_t port = 0;
        std::string originator_host;
        std::uint32_t originator_port = 0;
        std::string socket_path;
        std::vector<std::byte> extra;
    };
    struct channel_opened {
        core::channel_ref ref;
        void* user = nullptr;
        std::uint32_t window = 0;
        std::uint32_t max_packet = 0;
    };
    struct channel_open_failed {
        core::channel_ref ref;
        void* user = nullptr;
        channels::channel_open_reason reason{};
        std::string description;
    };
    struct channel_request {
        core::channel_request_ticket ticket;
        std::uint64_t seq = 0;
        void* user = nullptr;
        std::string type;
        std::vector<std::byte> payload;
        bool want_reply = false;
    };
    struct channel_response {
        core::channel_ref ref;
        void* user = nullptr;
        bool success = false;
    };
    struct global_request {
        core::global_request_ticket ticket;
        std::uint64_t seq = 0;
        std::string type;
        std::vector<std::byte> payload;
        bool want_reply = false;
    };
    struct global_response {
        bool success = false;
        std::vector<std::byte> payload;
    };
    struct channel_readable {
        core::channel_ref ref;
        void* user = nullptr;
        std::uint32_t ext_type = 0;
    };
    struct channel_writable {
        core::channel_ref ref;
        void* user = nullptr;
    };
    struct channel_eof {
        core::channel_ref ref;
        void* user = nullptr;
    };
    struct channel_closed {
        core::channel_ref ref;
        void* user = nullptr;
    };
    struct channel_released {
        core::channel_ref ref;
        void* user = nullptr;
    };

    using recorded_event =
        std::variant<peer_identification, verify_host_key, handshake_done, rekey_done,
                     debug_message, ignore_message, disconnected, auth_banner, auth_response,
                     auth_info_request, auth_request, auth_info_response, channel_open_request,
                     channel_opened, channel_open_failed, channel_request, channel_response,
                     global_request, global_response, channel_readable, channel_writable,
                     channel_eof, channel_closed, channel_released>;

    std::vector<recorded_event> events;

    void on_peer_identification(core::connection&, std::string_view banner) override {
        events.emplace_back(peer_identification{std::string{banner}});
    }

    void on_host_key(core::connection&, core::host_key_ticket ticket,
                     std::span<const std::byte> blob) override {
        events.emplace_back(
            verify_host_key{ticket, std::vector<std::byte>{blob.begin(), blob.end()}});
    }

    void on_handshake_done(core::connection& c) override {
        const auto* algorithms = c.negotiated();
        events.emplace_back(handshake_done{
            algorithms ? *algorithms : kex::negotiated{},
            std::vector<std::byte>{c.session_id().begin(), c.session_id().end()},
            std::string{c.server_sig_algs()}});
    }

    void on_rekey_done(core::connection& c) override {
        const auto* algorithms = c.negotiated();
        events.emplace_back(rekey_done{
            algorithms ? *algorithms : kex::negotiated{},
            std::vector<std::byte>{c.session_id().begin(), c.session_id().end()},
            std::string{c.server_sig_algs()}});
    }

    void on_debug(core::connection&, bool always_display, std::string_view text,
                  std::string_view language) override {
        events.emplace_back(
            debug_message{always_display, std::string{text}, std::string{language}});
    }

    void on_ignore(core::connection&, std::span<const std::byte> data) override {
        events.emplace_back(ignore_message{{data.begin(), data.end()}});
    }

    void on_disconnect(core::connection&, wire::disconnect_reason reason,
                       std::string_view description, std::string_view language) override {
        events.emplace_back(
            disconnected{reason, std::string{description}, std::string{language}});
    }

    void on_auth_banner(core::connection&, std::string_view text,
                        std::string_view language) override {
        events.emplace_back(auth_banner{std::string{text}, std::string{language}});
    }

    void on_auth_result(core::connection&, const auth::auth_result& result) override {
        events.emplace_back(auth_response{result.success, result.partial_success, result.pk_ok,
                                          std::string{result.methods}});
    }

    void on_kbdint_request(core::connection&, core::kbdint_ticket ticket,
                           const auth::info_request_view& request) override {
        events.emplace_back(auth_info_request{
            ticket, std::string{request.name}, std::string{request.instruction},
            std::string{request.language},
            std::vector<auth::kbdint_prompt>{request.prompts.begin(), request.prompts.end()}});
    }

    void on_auth_request(core::connection&, core::auth_ticket ticket,
                         const auth::auth_request_view& request) override {
        events.emplace_back(auth_request{
            ticket, std::string{request.user}, std::string{request.service},
            std::string{request.method}, request.has_signature, std::string{request.algorithm},
            {request.public_blob.begin(), request.public_blob.end()}, std::string{request.password},
            std::string{request.submethods}});
    }

    void on_kbdint_response(core::connection&, core::auth_ticket ticket,
                            std::span<const std::string_view> responses) override {
        auth_info_response event{ticket, {}};
        for (auto response : responses) event.responses.emplace_back(response);
        events.emplace_back(std::move(event));
    }

    void on_open_request(core::connection&, core::open_ticket ticket,
                         const channels::open_request_view& request) override {
        events.emplace_back(channel_open_request{
            ticket,
            core::connection::channel_ref_of(ticket),
            request.type,
            std::string{request.type_name},
            request.window,
            request.max_packet,
            std::string{request.host},
            request.port,
            std::string{request.originator_host},
            request.originator_port,
            std::string{request.socket_path},
            {request.extra.begin(), request.extra.end()},
        });
    }

    void on_open_result(core::connection&, core::channel_ref ref, void* user,
                        const channels::open_result_view& result) override {
        if (result.success) {
            events.emplace_back(channel_opened{ref, user, result.window, result.max_packet});
        } else {
            events.emplace_back(
                channel_open_failed{ref, user, result.reason, std::string{result.description}});
        }
    }

    void on_channel_request(core::connection&, core::channel_request_ticket ticket, void* user,
                            const channels::request_view& request) override {
        events.emplace_back(channel_request{ticket, core::connection::seq_of(ticket), user,
                                            std::string{request.type},
                                            {request.payload.begin(), request.payload.end()},
                                            request.want_reply});
    }

    void on_channel_reply(core::connection&, core::channel_ref ref, void* user,
                          bool success) override {
        events.emplace_back(channel_response{ref, user, success});
    }

    void on_global_request(core::connection&, core::global_request_ticket ticket,
                           const channels::request_view& request) override {
        events.emplace_back(global_request{ticket, core::connection::seq_of(ticket),
                                           std::string{request.type},
                                           {request.payload.begin(), request.payload.end()},
                                           request.want_reply});
    }

    void on_global_reply(core::connection&, bool success,
                         std::span<const std::byte> payload) override {
        events.emplace_back(global_response{success, {payload.begin(), payload.end()}});
    }

    void on_readable(core::connection&, core::channel_ref ref, void* user,
                     std::uint32_t ext_type) override {
        events.emplace_back(channel_readable{ref, user, ext_type});
    }

    void on_writable(core::connection&, core::channel_ref ref, void* user) override {
        events.emplace_back(channel_writable{ref, user});
    }

    void on_eof(core::connection&, core::channel_ref ref, void* user) override {
        events.emplace_back(channel_eof{ref, user});
    }

    void on_closed(core::connection&, core::channel_ref ref, void* user) override {
        events.emplace_back(channel_closed{ref, user});
    }

    void on_released(core::connection&, core::channel_ref ref, void* user) override {
        events.emplace_back(channel_released{ref, user});
    }
};

class accepting_recording_handler : public recording_handler {
public:
    void on_host_key(core::connection& c, core::host_key_ticket ticket,
                     std::span<const std::byte> blob) override {
        recording_handler::on_host_key(c, ticket, blob);
        (void)c.resolve(ticket, core::host_key_verdict::accept);
    }
};

inline accepting_recording_handler& default_recording_handler() {
    static accepting_recording_handler handler;
    return handler;
}

inline std::string_view recorded_event_name(const recording_handler::recorded_event& ev) {
    return std::visit(
        [](const auto& value) -> std::string_view {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, recording_handler::peer_identification>) {
                return "peer_identification";
            }
            if constexpr (std::is_same_v<T, recording_handler::verify_host_key>) {
                return "verify_host_key";
            }
            if constexpr (std::is_same_v<T, recording_handler::handshake_done>) {
                return "handshake_done";
            }
            if constexpr (std::is_same_v<T, recording_handler::rekey_done>) return "rekey_done";
            if constexpr (std::is_same_v<T, recording_handler::debug_message>) {
                return "debug_message";
            }
            if constexpr (std::is_same_v<T, recording_handler::ignore_message>) {
                return "ignore_message";
            }
            if constexpr (std::is_same_v<T, recording_handler::disconnected>) return "disconnected";
            if constexpr (std::is_same_v<T, recording_handler::auth_banner>) return "auth_banner";
            if constexpr (std::is_same_v<T, recording_handler::auth_response>) {
                return "auth_response";
            }
            if constexpr (std::is_same_v<T, recording_handler::auth_info_request>) {
                return "auth_info_request";
            }
            if constexpr (std::is_same_v<T, recording_handler::auth_request>) return "auth_request";
            if constexpr (std::is_same_v<T, recording_handler::auth_info_response>) {
                return "auth_info_response";
            }
            if constexpr (std::is_same_v<T, recording_handler::channel_open_request>) {
                return "channel_open_request";
            }
            if constexpr (std::is_same_v<T, recording_handler::channel_opened>) {
                return "channel_opened";
            }
            if constexpr (std::is_same_v<T, recording_handler::channel_open_failed>) {
                return "channel_open_failed";
            }
            if constexpr (std::is_same_v<T, recording_handler::channel_request>) {
                return "channel_request";
            }
            if constexpr (std::is_same_v<T, recording_handler::channel_response>) {
                return "channel_response";
            }
            if constexpr (std::is_same_v<T, recording_handler::global_request>) {
                return "global_request";
            }
            if constexpr (std::is_same_v<T, recording_handler::global_response>) {
                return "global_response";
            }
            if constexpr (std::is_same_v<T, recording_handler::channel_readable>) {
                return "channel_readable";
            }
            if constexpr (std::is_same_v<T, recording_handler::channel_writable>) {
                return "channel_writable";
            }
            if constexpr (std::is_same_v<T, recording_handler::channel_eof>) return "channel_eof";
            if constexpr (std::is_same_v<T, recording_handler::channel_closed>) {
                return "channel_closed";
            }
            if constexpr (std::is_same_v<T, recording_handler::channel_released>) {
                return "channel_released";
            }
            return "unknown";
        },
        ev);
}

inline bool is_handler_transport_event(std::string_view name) {
    return name == "peer_identification" || name == "verify_host_key" || name == "handshake_done"
           || name == "rekey_done" || name == "debug_message" || name == "ignore_message"
           || name == "disconnected";
}

}  // namespace yanterm::ssh::testing
