#include <yanterm-ssh/agent/packets.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yanterm::ssh::fuzz {
namespace {

volatile std::uint8_t sink;

void touch(std::span<const std::byte> bytes) noexcept {
    for (const std::byte b : bytes) {
        sink = static_cast<std::uint8_t>(sink + std::to_integer<std::uint8_t>(b));
    }
}

void touch(std::string_view text) noexcept {
    for (const char c : text) {
        sink = static_cast<std::uint8_t>(sink + static_cast<unsigned char>(c));
    }
}

void touch(const agent::key_constraints& constraints) noexcept {
    if (constraints.lifetime_seconds) {
        sink = static_cast<std::uint8_t>(sink + static_cast<std::uint8_t>(*constraints.lifetime_seconds));
    }
    sink = static_cast<std::uint8_t>(sink + static_cast<std::uint8_t>(constraints.confirm));
    for (const agent::constraint_extension& ext : constraints.extensions) {
        touch(ext.name);
        touch(std::span<const std::byte>{ext.details});
    }
}

void exercise(std::span<const std::byte> body) {
    switch (static_cast<std::uint8_t>(agent::message_type(body))) {
    case 5:
        (void)agent::decode_failure(body);
        break;
    case 6:
        (void)agent::decode_success(body);
        break;
    case 11:
        (void)agent::decode_request_identities(body);
        break;
    case 12: {
        std::vector<agent::identity_view> identities;
        if (agent::decode_identities_answer(body, identities)) {
            for (const agent::identity_view& id : identities) {
                touch(id.key_blob);
                touch(id.comment);
            }
        }
        break;
    }
    case 13: {
        std::span<const std::byte> key;
        std::span<const std::byte> data;
        std::uint32_t flags = 0;
        if (agent::decode_sign_request(body, key, data, flags)) {
            touch(key);
            touch(data);
            sink = static_cast<std::uint8_t>(sink + static_cast<std::uint8_t>(flags));
        }
        break;
    }
    case 14: {
        std::span<const std::byte> signature;
        if (agent::decode_sign_response(body, signature)) touch(signature);
        break;
    }
    case 17:
    case 25: {
        std::span<const std::byte> key;
        std::string_view comment;
        agent::key_constraints constraints;
        if (agent::decode_add_identity(body, key, comment, constraints)) {
            touch(key);
            touch(comment);
            touch(constraints);
        }
        break;
    }
    case 18: {
        std::span<const std::byte> key;
        if (agent::decode_remove_identity(body, key)) touch(key);
        break;
    }
    case 19:
        (void)agent::decode_remove_all_identities(body);
        break;
    case 20:
    case 26: {
        std::string_view token;
        std::string_view pin;
        agent::key_constraints constraints;
        if (agent::decode_add_smartcard_key(body, token, pin, constraints)) {
            touch(token);
            touch(pin);
            touch(constraints);
        }
        break;
    }
    case 21: {
        std::string_view token;
        std::string_view pin;
        if (agent::decode_remove_smartcard_key(body, token, pin)) {
            touch(token);
            touch(pin);
        }
        break;
    }
    case 22: {
        std::string_view passphrase;
        if (agent::decode_lock(body, passphrase)) touch(passphrase);
        break;
    }
    case 23: {
        std::string_view passphrase;
        if (agent::decode_unlock(body, passphrase)) touch(passphrase);
        break;
    }
    case 27: {
        std::string_view name;
        std::span<const std::byte> data;
        if (agent::decode_extension(body, name, data)) {
            touch(name);
            touch(data);
        }
        std::span<const std::byte> host;
        std::span<const std::byte> session_id;
        std::span<const std::byte> signature;
        bool forwarding = false;
        if (agent::decode_session_bind(body, host, session_id, signature, forwarding)) {
            touch(host);
            touch(session_id);
            touch(signature);
            sink = static_cast<std::uint8_t>(sink + static_cast<std::uint8_t>(forwarding));
        }
        break;
    }
    case 28:
        (void)agent::decode_extension_failure(body);
        break;
    case 29: {
        std::string_view name;
        std::span<const std::byte> data;
        if (agent::decode_extension_response(body, name, data)) {
            touch(name);
            touch(data);
        }
        std::vector<std::string> names;
        if (agent::decode_query_response(body, names)) {
            for (const std::string& ext : names) touch(ext);
        }
        break;
    }
    default:
        break;
    }
}

}  // namespace

int fuzz_agent_one(std::span<const std::byte> input) {
    if (input.empty() || input.size() > (1u << 20)) return 0;

    const auto mode = static_cast<unsigned>(std::to_integer<std::uint8_t>(input[0])) % 2u;
    const auto payload = input.subspan(1);
    if (mode == 0) {
        exercise(payload);
        return 0;
    }

    std::size_t off = 0;
    for (int frames = 0; frames < 16 && payload.size() - off >= 4; ++frames) {
        const auto len = agent::decode_frame_header(payload.subspan(off, 4));
        if (!agent::message_length_ok(len, agent::default_max_message_length)) break;
        if (payload.size() - off - 4 < len) break;
        exercise(payload.subspan(off + 4, len));
        off += 4u + static_cast<std::size_t>(len);
    }
    return 0;
}

}  // namespace yanterm::ssh::fuzz

#if defined(YANTERM_SSH_FUZZER_STANDALONE)
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    return yanterm::ssh::fuzz::fuzz_agent_one(
        std::span<const std::byte>{reinterpret_cast<const std::byte*>(data), size});
}
#endif
