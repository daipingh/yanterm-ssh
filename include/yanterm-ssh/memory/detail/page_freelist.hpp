#pragma once

#include <cstddef>

#if defined(__SANITIZE_ADDRESS__)
#include <sanitizer/asan_interface.h>
#define YANTERM_SSH_PAGE_ASAN 1
#elif defined(__has_feature)
#  if __has_feature(address_sanitizer)
#include <sanitizer/asan_interface.h>
#define YANTERM_SSH_PAGE_ASAN 1
#  endif
#endif

namespace yanterm::ssh::memory::detail {

inline void poison_cached_page(void* p, std::size_t block_bytes) noexcept {
#if defined(YANTERM_SSH_PAGE_ASAN)
    ASAN_POISON_MEMORY_REGION(static_cast<char*>(p) + sizeof(void*), block_bytes - sizeof(void*));
#else
    (void)p;
    (void)block_bytes;
#endif
}

inline void unpoison_page(void* p, std::size_t block_bytes) noexcept {
#if defined(YANTERM_SSH_PAGE_ASAN)
    ASAN_UNPOISON_MEMORY_REGION(p, block_bytes);
#else
    (void)p;
    (void)block_bytes;
#endif
}

// 不加锁。调用方保证不同时访问。next 写在空闲块开头。
// 不向上游分配。block_bytes 只用于 ASan。
class page_freelist {
public:
    explicit page_freelist(std::size_t max_cached_blocks) noexcept : max_{max_cached_blocks} {}

    page_freelist(const page_freelist&) = delete;
    page_freelist& operator=(const page_freelist&) = delete;

    [[nodiscard]] std::size_t max_cached_blocks() const noexcept { return max_; }

    [[nodiscard]] static void* next_of(void* p) noexcept { return static_cast<node*>(p)->next; }

    [[nodiscard]] void* pop(std::size_t block_bytes) noexcept {
        if (head_ == nullptr) return nullptr;
        node* n = head_;
        head_ = n->next;
        --count_;
        unpoison_page(n, block_bytes);
        return n;
    }

    // 先写 next、再 poison、最后发布 head_。同步版本必须在持锁时调用。
    [[nodiscard]] bool try_push(void* p, std::size_t block_bytes) noexcept {
        if (count_ >= max_) return false;
        auto* n = static_cast<node*>(p);
        n->next = head_;
        poison_cached_page(p, block_bytes);
        head_ = n;
        ++count_;
        return true;
    }

    [[nodiscard]] void* take_all() noexcept {
        node* n = head_;
        head_ = nullptr;
        count_ = 0;
        return n;
    }

private:
    struct node {
        node* next = nullptr;
    };

    node* head_ = nullptr;
    std::size_t count_ = 0;
    std::size_t max_ = 0;
};

}  // namespace yanterm::ssh::memory::detail

#undef YANTERM_SSH_PAGE_ASAN
