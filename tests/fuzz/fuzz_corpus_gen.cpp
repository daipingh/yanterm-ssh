// Regenerates the recorded seeds under tests/fuzz/corpus. They go stale only
// when the pinned parameters in connection_prekex_setup.hpp, the target's use
// of randomness before NEWKEYS, or the key exchange message flow change:
//
//   yanterm-ssh-fuzz-corpus-gen tests/fuzz/corpus

#include "connection_prekex_setup.hpp"

#include <yanterm-ssh/core/connection.hpp>
#include <yanterm-ssh/core/handler.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/keys/private_key.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <span>
#include <string_view>
#include <vector>

namespace yanterm::ssh::fuzz {
namespace {

using bytes = std::vector<std::byte>;

constexpr std::uint64_t peer_random_seed = 0x0babe5eedULL;
constexpr std::uint64_t encrypted_key_random_seed = 0x0e17c0deULL;

class accepting_handler final : public core::handler {
public:
    void on_host_key(core::connection& c, core::host_key_ticket ticket,
                     std::span<const std::byte>) override {
        (void)c.resolve(ticket, core::host_key_verdict::accept);
    }
};

void append(bytes& out, std::span<const std::byte> in) {
    out.insert(out.end(), in.begin(), in.end());
}

void append(bytes& out, std::string_view s) {
    for (const char c : s) out.push_back(static_cast<std::byte>(c));
}

void append_u8(bytes& out, std::uint8_t v) { out.push_back(std::byte{v}); }

void append_u32(bytes& out, std::uint32_t v) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::byte>((v >> shift) & 0xffu));
    }
}

void append_string(bytes& out, std::string_view s) {
    append_u32(out, static_cast<std::uint32_t>(s.size()));
    append(out, s);
}

std::uint32_t read_u32(std::span<const std::byte> in, std::size_t off) {
    std::uint32_t v = 0;
    for (std::size_t i = 0; i < 4; ++i) v = (v << 8) | std::to_integer<std::uint32_t>(in[off + i]);
    return v;
}

// RFC 4253 section 6 binary packet with the initial "none" cipher.
bytes plaintext_packet(std::span<const std::byte> payload) {
    constexpr std::size_t block = 8;
    std::size_t padding = block - (5 + payload.size()) % block;
    if (padding < 4) padding += block;
    bytes out;
    append_u32(out, static_cast<std::uint32_t>(1 + payload.size() + padding));
    append_u8(out, static_cast<std::uint8_t>(padding));
    append(out, payload);
    out.insert(out.end(), padding, std::byte{0});
    return out;
}

// Identification line plus the first binary packet (the peer's KEXINIT).
bytes banner_and_kexinit(std::span<const std::byte> stream) {
    const auto lf = std::find(stream.begin(), stream.end(), std::byte{'\n'});
    const std::size_t line_end = static_cast<std::size_t>(lf - stream.begin()) + 1;
    const std::size_t packet_end = line_end + 4 + read_u32(stream, line_end);
    return bytes{stream.begin(), stream.begin() + static_cast<std::ptrdiff_t>(packet_end)};
}

bytes take_output(core::connection& c) {
    bytes out;
    while (c.pending_output_bytes() > 0) {
        const auto seg = c.pending_output0();
        if (seg.empty()) break;
        append(out, seg);
        c.consume_output(seg.size());
    }
    return out;
}

bool feed_all(core::connection& to, bytes& pending) {
    std::size_t accepted = 0;
    const auto ec = to.feed(pending, accepted);
    pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(accepted));
    return !ec && accepted > 0;
}

// Runs the harness's target against a real peer and records everything the
// peer sends until both sides go quiet.
bytes record_peer(std::uint8_t ctrl) {
    const prekex_params params = decode_ctrl(ctrl);
    const core::role peer_role =
        params.role == core::role::client ? core::role::server : core::role::client;

    testing::fixed_random_provider target_rng{base_provider(), target_random_seed};
    testing::fixed_random_provider peer_rng{base_provider(), peer_random_seed};
    accepting_handler target_handler;
    accepting_handler peer_handler;
    core::connection target{params.role, target_rng.get(), params.cfg, target_handler};
    core::connection peer{peer_role, peer_rng.get(), params.cfg, peer_handler};
    const auto& hk = server_host_key();
    auto& server = params.role == core::role::server ? target : peer;
    (void)server.set_host_key(hk.pub().blob(), hk.material());

    bytes transcript = take_output(peer);
    bytes to_target = transcript;
    bytes to_peer = take_output(target);

    for (int round = 0; round < 64; ++round) {
        bool progress = feed_all(target, to_target);
        const bytes from_target = take_output(target);
        append(to_peer, from_target);
        progress = feed_all(peer, to_peer) || progress;
        const bytes from_peer = take_output(peer);
        append(transcript, from_peer);
        append(to_target, from_peer);
        if (!progress && from_target.empty() && from_peer.empty()) break;
    }
    return transcript;
}

bytes frame(std::uint8_t ctrl, std::uint8_t chunk, std::span<const std::byte> stream) {
    bytes out;
    append_u8(out, ctrl);
    append_u8(out, chunk);
    append(out, stream);
    return out;
}

bytes with_inline_lengths(std::span<const std::byte> stream,
                          std::initializer_list<std::uint8_t> lengths) {
    bytes out;
    auto it = lengths.begin();
    while (!stream.empty()) {
        const std::uint8_t len = *it;
        if (++it == lengths.end()) it = lengths.begin();
        const std::size_t n = std::min<std::size_t>(std::max<std::size_t>(1, len % 65u), stream.size());
        append_u8(out, len);
        append(out, stream.first(n));
        stream = stream.subspan(n);
    }
    return out;
}

bytes prelude_ignore_debug_kexinit(std::span<const std::byte> stream) {
    const bytes head = banner_and_kexinit(stream);
    const auto lf = std::find(head.begin(), head.end(), std::byte{'\n'});
    const auto kexinit = std::span{head}.subspan(static_cast<std::size_t>(lf - head.begin()) + 1);

    bytes ignore_payload;
    append_u8(ignore_payload, 2);  // SSH_MSG_IGNORE
    append_string(ignore_payload, "");
    bytes debug_payload;
    append_u8(debug_payload, 4);  // SSH_MSG_DEBUG
    append_u8(debug_payload, 0);
    append_string(debug_payload, "pre-kex debug");
    append_string(debug_payload, "en");

    bytes out;
    append(out, std::string_view{"Welcome to SSH proxy\r\nAnother prelude line\r\n"});
    append(out, std::string_view{"SSH-2.0-OpenSSH_9.6\r\n"});
    append(out, plaintext_packet(ignore_payload));
    append(out, plaintext_packet(debug_payload));
    append(out, kexinit);
    return out;
}

bytes malformed_packet_length() {
    bytes out;
    append(out, std::string_view{"SSH-2.0-FuzzPeer\r\n"});
    append_u32(out, 0xffffffffu);
    append_u8(out, 4);
    append_u8(out, 20);  // SSH_MSG_KEXINIT
    out.insert(out.end(), 10, std::byte{0});
    return out;
}

// An encrypted key whose bcrypt rounds are low enough for fuzz_keys to parse.
// Rewriting the rounds makes the derived key wrong, so the seed reaches
// decryption and stops at the check integers.
bytes encrypted_private_key() {
    testing::fixed_random_provider rng{base_provider(), encrypted_key_random_seed};
    keys::private_key key;
    (void)keys::private_key::generate(rng.get(), crypto::sig_id::ed25519, 0, "fuzz-encrypted", key);
    constexpr std::array<std::byte, 4> pass{std::byte{'f'}, std::byte{'u'}, std::byte{'z'},
                                            std::byte{'z'}};
    bytes armored;
    (void)key.serialize(rng.get(), pass, "aes256-ctr", armored);

    bytes decoded;
    std::span<const std::byte> inner;
    (void)keys::detail::decode_openssh_file(armored, decoded, inner);
    bytes raw{inner.begin(), inner.end()};

    std::size_t off = keys::detail::openssh_key_v1_magic_size;
    off += 4 + read_u32(raw, off);  // cipher name
    off += 4 + read_u32(raw, off);  // kdf name
    off += 4;                       // kdfoptions length
    off += 4 + read_u32(raw, off);  // salt
    raw[off + 0] = std::byte{0};
    raw[off + 1] = std::byte{0};
    raw[off + 2] = std::byte{0};
    raw[off + 3] = std::byte{1};

    bytes out;
    append_u8(out, 2);  // fuzz_keys selector: private key
    append(out, raw);
    return out;
}

bool write_file(const std::filesystem::path& path, std::span<const std::byte> data) {
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    ofs.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!ofs) {
        std::fprintf(stderr, "fuzz_corpus_gen: failed to write %s\n", path.string().c_str());
        return false;
    }
    return true;
}

}  // namespace
}  // namespace yanterm::ssh::fuzz

int main(int argc, char** argv) {
    using namespace yanterm::ssh::fuzz;
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <corpus-dir>\n", argv[0]);
        return 2;
    }
    const std::filesystem::path root{argv[1]};
    const auto prekex = root / "connection_prekex";
    const auto keys_dir = root / "keys";
    std::filesystem::create_directories(prekex);
    std::filesystem::create_directories(keys_dir);

    // ctrl bits: 0x01 server, 0x02 strict kex, 0x04 ext-info, 0x08 fixed
    // chunks, 0x10 inline chunk lengths.
    const auto client = record_peer(0x06);
    const auto server = record_peer(0x07);
    const auto client_chunked = record_peer(0x0e);
    const auto server_chunked = record_peer(0x17);
    const auto client_plain = record_peer(0x00);

    const bool ok =
        write_file(prekex / "00_client_banner_and_kexinit.bin",
                   frame(0x06, 0, banner_and_kexinit(client)))
        && write_file(prekex / "01_server_banner_and_kexinit.bin",
                      frame(0x07, 0, banner_and_kexinit(server)))
        && write_file(prekex / "02_client_full_prekex_stream.bin", frame(0x06, 0, client))
        && write_file(prekex / "03_server_full_prekex_stream.bin", frame(0x07, 0, server))
        && write_file(prekex / "04_client_chunked_13b.bin", frame(0x0e, 13, client_chunked))
        && write_file(prekex / "05_server_var_chunks.bin",
                      frame(0x17, 0, with_inline_lengths(server_chunked, {7, 1, 64, 13, 32, 3})))
        && write_file(prekex / "06_banner_with_prelude_and_debug.bin",
                      frame(0x00, 0, prelude_ignore_debug_kexinit(client_plain)))
        && write_file(prekex / "07_malformed_packet_lengths.bin",
                      frame(0x06, 0, malformed_packet_length()))
        && write_file(keys_dir / "10_privkey_encrypted_ed25519_bcrypt1.bin", encrypted_private_key());
    return ok ? 0 : 1;
}
