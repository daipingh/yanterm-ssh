#include <yanterm-ssh/channels/requests.hpp>
#include <yanterm-ssh/channels/types.hpp>
#include <yanterm-ssh/wire/detail/messages.hpp>
#include <yanterm-ssh/wire/message_ids.hpp>
#include <yanterm-ssh/wire/types.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace yanterm::ssh::fuzz {
namespace {

void exercise_name_list(const wire::name_list& nl) noexcept {
    for (const std::string_view item : nl) {
        (void)item.size();
    }
    (void)nl.contains("ssh-ed25519");
}

}  // namespace

int fuzz_wire_one(std::span<const std::byte> input) {
    if (input.empty() || input.size() > 65536) {
        return 0;
    }

    const auto selector = std::to_integer<std::uint8_t>(input[0]) % 52u;
    const auto payload = input.subspan(1);
    wire::reader r{payload};

    switch (selector) {
        case 0: {
            for (unsigned step = 0; step < 64u && !r.empty() && r.ok(); ++step) {
                std::uint8_t op = 0;
                if (!r.read_byte(op)) break;
                switch (op % 9u) {
                    case 0: {
                        std::uint8_t b = 0;
                        (void)r.read_byte(b);
                        break;
                    }
                    case 1: {
                        bool v = false;
                        (void)r.read_bool(v);
                        break;
                    }
                    case 2: {
                        std::uint32_t v = 0;
                        (void)r.read_uint32(v);
                        break;
                    }
                    case 3: {
                        std::uint64_t v = 0;
                        (void)r.read_uint64(v);
                        break;
                    }
                    case 4: {
                        std::span<const std::byte> s;
                        (void)r.read_string(s);
                        break;
                    }
                    case 5: {
                        std::string_view sv;
                        (void)r.read_string(sv);
                        break;
                    }
                    case 6: {
                        std::span<const std::byte> mp;
                        (void)r.read_mpint(mp);
                        break;
                    }
                    case 7: {
                        wire::name_list nl;
                        if (r.read_name_list(nl)) {
                            exercise_name_list(nl);
                        }
                        break;
                    }
                    case 8: {
                        std::uint8_t len = 0;
                        if (!r.read_byte(len)) break;
                        std::span<const std::byte> bytes;
                        (void)r.read_bytes(bytes, len);
                        break;
                    }
                }
            }
            break;
        }
        case 1: {
            wire::detail::kexinit msg;
            if (msg.decode(r)) {
                exercise_name_list(msg.kex_algorithms);
                exercise_name_list(msg.server_host_key_algorithms);
                exercise_name_list(msg.encryption_c2s);
                exercise_name_list(msg.encryption_s2c);
                exercise_name_list(msg.mac_c2s);
                exercise_name_list(msg.mac_s2c);
                exercise_name_list(msg.compression_c2s);
                exercise_name_list(msg.compression_s2c);
                exercise_name_list(msg.languages_c2s);
                exercise_name_list(msg.languages_s2c);
            }
            break;
        }
        case 2: {
            wire::detail::disconnect_msg msg;
            (void)msg.decode(r);
            break;
        }
        case 3: {
            wire::detail::debug_msg msg;
            (void)msg.decode(r);
            break;
        }
        case 4: {
            wire::detail::ignore_msg msg;
            (void)msg.decode(r);
            break;
        }
        case 5: {
            wire::detail::unimplemented_msg msg;
            (void)msg.decode(r);
            break;
        }
        case 6: {
            wire::detail::service_msg msg;
            msg.id = wire::msg::service_request;
            (void)msg.decode(r);
            break;
        }
        case 7: {
            wire::detail::service_msg msg;
            msg.id = wire::msg::service_accept;
            (void)msg.decode(r);
            break;
        }
        case 8: {
            wire::detail::ext_info msg;
            if (msg.decode(r)) {
                std::string_view val;
                (void)msg.find("server-sig-algs", val);
            }
            break;
        }
        case 9: {
            wire::detail::kex_ecdh_init msg;
            (void)msg.decode(r);
            break;
        }
        case 10: {
            wire::detail::kex_ecdh_reply msg;
            (void)msg.decode(r);
            break;
        }
        case 11: {
            wire::detail::kexdh_init msg;
            (void)msg.decode(r);
            break;
        }
        case 12: {
            wire::detail::kexdh_reply msg;
            (void)msg.decode(r);
            break;
        }
        case 13: {
            wire::detail::userauth_request_none msg;
            (void)msg.decode(r);
            break;
        }
        case 14: {
            wire::detail::userauth_request_password msg;
            (void)msg.decode(r);
            break;
        }
        case 15: {
            wire::detail::userauth_request_publickey msg;
            (void)msg.decode(r);
            break;
        }
        case 16: {
            wire::detail::userauth_request_kbdint msg;
            if (msg.decode(r)) {
                exercise_name_list(msg.submethods);
            }
            break;
        }
        case 17: {
            wire::detail::userauth_failure msg;
            if (msg.decode(r)) {
                exercise_name_list(msg.methods);
            }
            break;
        }
        case 18: {
            wire::detail::userauth_success msg;
            (void)msg.decode(r);
            break;
        }
        case 19: {
            wire::detail::userauth_banner msg;
            (void)msg.decode(r);
            break;
        }
        case 20: {
            wire::detail::userauth_pk_ok msg;
            (void)msg.decode(r);
            break;
        }
        case 21: {
            wire::detail::userauth_info_request msg;
            if (msg.decode(r)) {
                const std::uint32_t limit = std::min<std::uint32_t>(msg.num_prompts, 16u);
                for (std::uint32_t i = 0; i < limit; ++i) {
                    std::string_view prompt;
                    bool echo = false;
                    if (!msg.prompt_at(i, prompt, echo)) break;
                }
            }
            break;
        }
        case 22: {
            wire::detail::userauth_info_response msg;
            if (msg.decode(r)) {
                const std::uint32_t limit = std::min<std::uint32_t>(msg.num_responses, 16u);
                for (std::uint32_t i = 0; i < limit; ++i) {
                    std::string_view resp;
                    if (!msg.response_at(i, resp)) break;
                }
            }
            break;
        }
        case 23: {
            wire::detail::channel_open msg;
            (void)msg.decode(r);
            break;
        }
        case 24: {
            wire::detail::channel_open_confirmation msg;
            (void)msg.decode(r);
            break;
        }
        case 25: {
            wire::detail::channel_open_failure msg;
            (void)msg.decode(r);
            break;
        }
        case 26: {
            wire::detail::channel_window_adjust msg;
            (void)msg.decode(r);
            break;
        }
        case 27: {
            wire::detail::channel_data msg;
            (void)msg.decode(r);
            break;
        }
        case 28: {
            wire::detail::channel_extended_data msg;
            (void)msg.decode(r);
            break;
        }
        case 29: {
            wire::detail::channel_eof_msg msg;
            (void)msg.decode(r);
            break;
        }
        case 30: {
            wire::detail::channel_close_msg msg;
            (void)msg.decode(r);
            break;
        }
        case 31: {
            wire::detail::channel_success_msg msg;
            (void)msg.decode(r);
            break;
        }
        case 32: {
            wire::detail::channel_failure_msg msg;
            (void)msg.decode(r);
            break;
        }
        case 33: {
            wire::detail::channel_request msg;
            (void)msg.decode(r);
            break;
        }
        case 34: {
            wire::detail::global_request msg;
            (void)msg.decode(r);
            break;
        }
        case 35: {
            wire::detail::request_success msg;
            (void)msg.decode(r);
            break;
        }
        case 36: {
            wire::detail::request_failure msg;
            (void)msg.decode(r);
            break;
        }
        case 37: {
            std::string_view term;
            channels::window_size ws{};
            std::span<const std::byte> modes;
            (void)channels::decode_pty_req(payload, term, ws, modes);
            break;
        }
        case 38: {
            std::string_view command;
            (void)channels::decode_exec(payload, command);
            break;
        }
        case 39: {
            std::string_view name;
            (void)channels::decode_subsystem(payload, name);
            break;
        }
        case 40: {
            std::string_view name;
            std::string_view value;
            (void)channels::decode_env(payload, name, value);
            break;
        }
        case 41: {
            channels::window_size ws{};
            (void)channels::decode_window_change(payload, ws);
            break;
        }
        case 42: {
            std::string_view name;
            (void)channels::decode_signal(payload, name);
            break;
        }
        case 43: {
            std::uint32_t status = 0;
            (void)channels::decode_exit_status(payload, status);
            break;
        }
        case 44: {
            std::string_view name;
            bool core_dumped = false;
            std::string_view message;
            std::string_view language;
            (void)channels::decode_exit_signal(payload, name, core_dumped, message, language);
            break;
        }
        case 45: {
            std::string_view host;
            std::uint32_t port = 0;
            std::string_view orig_host;
            std::uint32_t orig_port = 0;
            (void)channels::decode_direct_tcpip(payload, host, port, orig_host, orig_port);
            break;
        }
        case 46: {
            std::string_view orig_host;
            std::uint32_t orig_port = 0;
            (void)channels::decode_x11(payload, orig_host, orig_port);
            break;
        }
        case 47: {
            bool single_connection = false;
            std::string_view protocol;
            std::string_view cookie;
            std::uint32_t screen = 0;
            (void)channels::decode_x11_req(
                payload, single_connection, protocol, cookie, screen);
            break;
        }
        case 48: {
            std::string_view socket_path;
            std::string_view reserved;
            (void)channels::decode_streamlocal(payload, socket_path, reserved);
            break;
        }
        case 49: {
            std::string_view socket_path;
            std::string_view reserved;
            (void)channels::decode_forwarded_streamlocal(payload, socket_path, reserved);
            break;
        }
        case 50: {
            std::string_view addr;
            std::uint32_t port = 0;
            (void)channels::decode_tcpip_forward(payload, addr, port);
            break;
        }
        case 51: {
            std::string_view socket_path;
            (void)channels::decode_streamlocal_forward(payload, socket_path);
            break;
        }
    }

    return 0;
}

}  // namespace yanterm::ssh::fuzz

#if defined(YANTERM_SSH_FUZZER_STANDALONE)
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    return yanterm::ssh::fuzz::fuzz_wire_one(
        std::span<const std::byte>{reinterpret_cast<const std::byte*>(data), size});
}
#endif
