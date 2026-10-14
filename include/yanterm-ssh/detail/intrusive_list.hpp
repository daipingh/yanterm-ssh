#pragma once

#include <yanterm-ssh/detail/config.hpp>

#include <cstddef>
#include <cstdint>
#include <utility>

namespace yanterm::ssh::detail {

struct intrusive_hook {
    intrusive_hook* prev = nullptr;
    intrusive_hook* next = nullptr;
};

// Intrusive doubly-linked list. Hook points at a member of T. Nodes are not
// owned; unlink is a no-op when the node is already detached.
template <class T, intrusive_hook T::*Hook>
class intrusive_list {
public:
    intrusive_list() = default;
    intrusive_list(const intrusive_list&) = delete;
    intrusive_list& operator=(const intrusive_list&) = delete;

    [[nodiscard]] bool empty() const noexcept { return head_ == nullptr; }

    [[nodiscard]] T& front() noexcept { return *owner(head_); }
    [[nodiscard]] const T& front() const noexcept { return *owner(head_); }

    void push_back(T& node) noexcept {
        auto& h = node.*Hook;
        h.next = nullptr;
        h.prev = tail_;
        if (tail_ != nullptr) tail_->next = &h;
        else head_ = &h;
        tail_ = &h;
    }

    void pop_front() noexcept {
        if (head_ == nullptr) return;
        unlink(*owner(head_));
    }

    void unlink(T& node) noexcept {
        auto& h = node.*Hook;
        if (head_ != &h && h.prev == nullptr && h.next == nullptr) return;
        if (h.prev != nullptr) h.prev->next = h.next;
        else head_ = h.next;
        if (h.next != nullptr) h.next->prev = h.prev;
        else tail_ = h.prev;
        h.prev = nullptr;
        h.next = nullptr;
    }

    template <class Fn>
    void for_each(Fn&& fn) {
        for (intrusive_hook* h = head_; h != nullptr;) {
            intrusive_hook* next = h->next;
            fn(*owner(h));
            h = next;
        }
    }

    template <class Fn>
    void for_each(Fn&& fn) const {
        for (const intrusive_hook* h = head_; h != nullptr;) {
            const intrusive_hook* next = h->next;
            fn(*owner(const_cast<intrusive_hook*>(h)));
            h = next;
        }
    }

private:
    static T* owner(intrusive_hook* h) noexcept {
        const auto off = reinterpret_cast<std::uintptr_t>(
            std::addressof(static_cast<T*>(nullptr)->*Hook));
        return reinterpret_cast<T*>(reinterpret_cast<std::byte*>(h) - off);
    }

    intrusive_hook* head_ = nullptr;
    intrusive_hook* tail_ = nullptr;
};

}  // namespace yanterm::ssh::detail
