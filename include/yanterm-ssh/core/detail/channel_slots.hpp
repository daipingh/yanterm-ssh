#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/core/detail/channel.hpp>
#include <yanterm-ssh/core/handler.hpp>
#include <yanterm-ssh/detail/error.hpp>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <system_error>
#include <vector>

namespace yanterm::ssh::core::detail {

struct outbound_data_window {
    channels::channel_id remote;
    std::uint32_t available;
    std::uint32_t max_packet;
};

[[nodiscard]] inline core::channel_ref ref_of(const channel& c) noexcept { return {c.local, c.seq}; }

class channel_slots {
public:
    explicit channel_slots(std::uint32_t max_channels) : max_channels_{max_channels} {}

    // 分配空槽并 emplace 一个 channel。local / seq 已填，并用参数设置
    // local_window、advertised_window、local_max_packet。满时返回 too_many_channels。
    // 调用方传入已经算好的有效值。slots 不保存窗口和包长配置。
    std::error_code allocate(std::uint32_t initial_window, std::uint32_t max_packet, channel*& out) {
        out = nullptr;
        if (in_use_ >= max_channels_) return code::too_many_channels;
        channels::channel_id id = 0;
        if (!free_.empty()) {
            id = free_.front();
            free_.erase(free_.begin());
        } else {
            id = static_cast<channels::channel_id>(slots_.size());
            slots_.emplace_back();
        }
        slots_[id].emplace();
        if (next_seq_ == 0) next_seq_ = 1;
        const std::uint32_t seq = next_seq_++;
        auto* c = find(id);
        c->local = id;
        c->seq = seq;
        c->local_window = initial_window;
        c->advertised_window = c->local_window;
        c->local_max_packet = max_packet;
        ++in_use_;
        out = c;
        return {};
    }

    [[nodiscard]] channel* find(channels::channel_id local) noexcept {
        if (local >= slots_.size() || !slots_[local]) return nullptr;
        return &*slots_[local];
    }

    [[nodiscard]] channel* find(core::channel_ref ref) noexcept {
        if (ref.seq == 0 || ref.index >= slots_.size() || !slots_[ref.index]) return nullptr;
        if (slots_[ref.index]->seq != ref.seq) return nullptr;
        return &*slots_[ref.index];
    }

    [[nodiscard]] std::size_t size() const noexcept { return slots_.size(); }

    [[nodiscard]] const channel* find(core::channel_ref ref) const noexcept {
        if (ref.seq == 0 || ref.index >= slots_.size() || !slots_[ref.index]) return nullptr;
        if (slots_[ref.index]->seq != ref.seq) return nullptr;
        return &*slots_[ref.index];
    }

    void erase(channels::channel_id local) noexcept {
        if (!find(local)) return;
        slots_[local].reset();
        free_.push_back(local);
        --in_use_;
    }

    // 按下标遍历现存通道。回调返回前不得把 channel& / channel* 留到回调之后。
    template <class Fn>
    void for_each(Fn&& fn) {
        for (std::size_t i = 0; i < slots_.size(); ++i) {
            if (!slots_[i]) continue;
            fn(*slots_[i]);
        }
    }

private:
    std::uint32_t max_channels_ = 0;
    std::uint32_t in_use_ = 0;
    std::deque<std::optional<channel>> slots_;
    std::vector<channels::channel_id> free_;
    std::uint32_t next_seq_ = 1;
};

}  // namespace yanterm::ssh::core::detail
