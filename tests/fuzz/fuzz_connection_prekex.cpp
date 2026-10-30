#include "connection_prekex_setup.hpp"

#include <yanterm-ssh/core/connection.hpp>
#include <yanterm-ssh/core/handler.hpp>
#include <yanterm-ssh/core/types.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

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

// Returns false once the input is exhausted.
bool append_next_chunk(chunk_mode mode, std::uint8_t chunk_param,
                       std::span<const std::byte>& remaining, std::vector<std::byte>& pending) {
    if (remaining.empty()) return false;
    std::size_t n = remaining.size();
    if (mode == chunk_mode::fixed) {
        n = std::max<std::size_t>(1, chunk_param % 65u);
    } else if (mode == chunk_mode::inline_lengths) {
        n = std::max<std::size_t>(1, std::to_integer<std::uint8_t>(remaining[0]) % 65u);
        remaining = remaining.subspan(1);
    }
    n = std::min(n, remaining.size());
    pending.insert(pending.end(), remaining.begin(), remaining.begin() + static_cast<std::ptrdiff_t>(n));
    remaining = remaining.subspan(n);
    return true;
}

}  // namespace

int fuzz_connection_prekex_one(std::span<const std::byte> input) {
    if (input.size() < 2 || input.size() > 65536) {
        return 0;
    }

    const prekex_params params = decode_ctrl(std::to_integer<std::uint8_t>(input[0]));
    const auto chunk_param = std::to_integer<std::uint8_t>(input[1]);
    auto remaining = input.subspan(2);

    testing::fixed_random_provider fixed_rng{base_provider(), target_random_seed};
    fuzz_handler h;
    core::connection conn{params.role, fixed_rng.get(), params.cfg, h};
    if (params.role == core::role::server) {
        const auto& hk = server_host_key();
        (void)conn.set_host_key(hk.pub().blob(), hk.material());
    }
    drain_output(conn);

    // feed() leaves unaccepted bytes with the caller, so a partial line or
    // packet has to be presented again together with the next chunk.
    std::vector<std::byte> pending;
    for (;;) {
        const bool appended = append_next_chunk(params.mode, chunk_param, remaining, pending);

        std::size_t accepted = 0;
        const auto ec = conn.feed(pending, accepted);
        drain_output(conn);

        if (ec || conn.failure() || conn.inbound_requests_stalled() || accepted > pending.size()) {
            break;
        }
        pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(accepted));
        if (!appended && (accepted == 0 || pending.empty())) {
            break;
        }
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
