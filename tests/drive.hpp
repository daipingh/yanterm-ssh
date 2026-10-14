#pragma once

#include <yanterm-ssh/core/connection.hpp>

#include <cstddef>
#include <span>
#include <system_error>
#include <vector>

namespace yanterm::ssh::testing {

// Gathers every pending output segment into one contiguous buffer. Tests that
// compare byte streams need contiguity; production callers use the vector-write
// form directly.
inline std::vector<std::byte> collect_output(const core::connection& c) {
    // pending_output fills from the front and returns how many segments it
    // wrote; a full array means there may be more, so grow and ask again.
    std::vector<std::span<const std::byte>> buf(16);
    std::size_t n = 0;
    for (;;) {
        n = c.pending_output(buf);
        if (n < buf.size()) break;
        buf.resize(buf.size() * 2);
    }

    std::vector<std::byte> out;
    out.reserve(c.pending_output_bytes());
    for (std::size_t i = 0; i < n; ++i) {
        out.insert(out.end(), buf[i].begin(), buf[i].end());
    }
    return out;
}

// Feeds `in` repeatedly until a call accepts nothing more or returns an error.
// Unconsumed suffix (incomplete unit) stays with the caller — here that means
// it remains in `in` past the returned offset. Returns total bytes accepted.
inline std::size_t feed_all(core::connection& c, std::span<const std::byte> in,
                            std::error_code& ec) {
    std::size_t total = 0;
    ec.clear();
    while (total < in.size()) {
        std::size_t accepted = 0;
        ec = c.feed(in.subspan(total), accepted);
        total += accepted;
        if (ec || accepted == 0) break;
    }
    return total;
}

}  // namespace yanterm::ssh::testing
