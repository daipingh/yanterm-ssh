#include "../fixed_random_provider.hpp"

#include <yanterm-ssh/core/config.hpp>
#include <yanterm-ssh/core/connection.hpp>
#include <yanterm-ssh/core/handler.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/crypto/provider.hpp>
#include <yanterm-ssh/keys/private_key.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

namespace yanterm::ssh::fuzz {
namespace {

class fuzz_handler final : public core::handler {
public:
    void on_host_key(core::connection& c, core::host_key_ticket ticket,
                     std::span<const std::byte>) override {
        (void)c.resolve(ticket, core::host_key_verdict::accept);
    }
};

void drain_output(core::connection& conn) {
    while (conn.pending_output_bytes() > 0) {
        const auto seg = conn.pending_output0();
        if (seg.empty()) break;
        conn.consume_output(seg.size());
    }
}

}  // namespace

int fuzz_connection_prekex_one(std::span<const std::byte> input) {
    if (input.size() < 2 || input.size() > 65536) {
        return 0;
    }

    static crypto::openssl_backend backend;
    static const crypto::provider base_prov = crypto::provider::wrap(backend);
    static const keys::private_key host_key = [] {
        testing::fixed_random_provider key_rng{base_prov, 0x12345678ULL};
        keys::private_key hk;
        (void)keys::private_key::generate(
            key_rng.get(), crypto::sig_id::ed25519, 0, "fuzz-host", hk);
        return hk;
    }();

    testing::fixed_random_provider fixed_rng{base_prov, 0x5eed1234ULL};
    const crypto::provider prov = fixed_rng.get();

    const auto ctrl = std::to_integer<std::uint8_t>(input[0]);
    const auto chunk_param = std::to_integer<std::uint8_t>(input[1]);
    auto remaining = input.subspan(2);

    const core::role r = (ctrl & 0x01u) == 0 ? core::role::client : core::role::server;
    core::config cfg{};
    cfg.advertise_strict_kex = (ctrl & 0x02u) != 0;
    cfg.advertise_ext_info = (ctrl & 0x04u) != 0;
    const unsigned mode = (ctrl >> 3u) % 3u;

    fuzz_handler h;
    core::connection conn{r, prov, cfg, h};
    if (r == core::role::server) {
        (void)conn.set_host_key(host_key.pub().blob(), host_key.material());
    }
    drain_output(conn);

    while (!remaining.empty()) {
        std::span<const std::byte> chunk;
        if (mode == 0) {
            chunk = remaining;
        } else if (mode == 1) {
            const std::size_t max_chunk = std::max<std::size_t>(1, chunk_param % 65u);
            chunk = remaining.first(std::min(remaining.size(), max_chunk));
        } else {
            const auto len_byte = std::to_integer<std::uint8_t>(remaining[0]);
            remaining = remaining.subspan(1);
            if (remaining.empty()) break;
            const std::size_t max_chunk = std::max<std::size_t>(1, len_byte % 65u);
            chunk = remaining.first(std::min(remaining.size(), max_chunk));
        }

        std::size_t accepted = 0;
        const auto ec = conn.feed(chunk, accepted);
        drain_output(conn);

        if (ec || conn.failure() || conn.inbound_requests_stalled() || accepted == 0 ||
            accepted > chunk.size()) {
            break;
        }
        remaining = remaining.subspan(accepted);
    }

    return 0;
}

}  // namespace yanterm::ssh::fuzz

#if defined(YANTERM_SSH_FUZZER_STANDALONE)
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    return yanterm::ssh::fuzz::fuzz_connection_prekex_one(
        std::span<const std::byte>{reinterpret_cast<const std::byte*>(data), size});
}
#endif
