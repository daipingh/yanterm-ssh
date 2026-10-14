#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/channels/types.hpp>
#include <yanterm-ssh/memory/detail/pages.hpp>

#include <cstdint>
#include <deque>
#include <span>
#include <vector>

namespace yanterm::ssh::core::detail {

struct inbound_seq {
    std::uint64_t head_seq = 1;  // next want_reply request the app may resolve
    std::uint64_t next_seq = 1;
};

class channel {
public:
    channels::channel_id local = 0;
    channels::channel_id remote = 0;
    bool remote_known = false;
    bool inbound_open = false;
    bool abandoned = false;
    bool app_close = false;  // 应用调了 channel_close；abandon 也置位
    std::uint32_t seq = 0;
    void* user_data = nullptr;
    std::uint32_t outbound_outstanding = 0;
    inbound_seq inbound{};

    std::uint32_t local_window = 0;
    std::uint32_t remote_window = 0;
    std::uint32_t local_max_packet = 0;
    std::uint32_t remote_max_packet = 0;
    std::uint32_t advertised_window = 0;  // window we told the peer; WINDOW_ADJUST threshold
    std::uint32_t pending_adjust = 0;

    bool sent_eof = false;
    bool recv_eof = false;
    bool sent_close = false;
    bool recv_close = false;
    bool want_writable = false;

    std::deque<memory::detail::page_slice> rx_data;
    std::deque<memory::detail::page_slice> rx_ext;

    [[nodiscard]] bool fully_closed() const noexcept { return sent_close && recv_close; }
    [[nodiscard]] bool rx_empty() const noexcept { return rx_data.empty() && rx_ext.empty(); }
    [[nodiscard]] bool releasable() const noexcept {
        return fully_closed() && (app_close || rx_empty());
    }

    void note_sent_close() noexcept {
        sent_close = true;
        inbound.head_seq = inbound.next_seq;
    }
};

}  // namespace yanterm::ssh::core::detail
