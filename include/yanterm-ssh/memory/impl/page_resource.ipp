#pragma once

#include <yanterm-ssh/memory/page_resource.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/memory/impl/page_resource.ipp is an implementation file, not a public header."
#endif

namespace yanterm::ssh::memory::detail {

[[nodiscard]] YANTERM_SSH_INLINE bool is_page_block(std::size_t bytes, std::size_t alignment) noexcept {
    return bytes > default_page_size / 2 && bytes <= default_page_size
           && alignment <= alignof(std::max_align_t);
}

}  // namespace yanterm::ssh::memory::detail

namespace yanterm::ssh::memory {

YANTERM_SSH_INLINE page_resource::page_resource(page_resource_options opts, std::pmr::memory_resource* upstream)
    : upstream_{upstream != nullptr ? upstream : std::pmr::new_delete_resource()}
    , free_{opts.max_cached_blocks} {}

YANTERM_SSH_INLINE page_resource::page_resource(std::pmr::memory_resource* upstream)
    : page_resource(page_resource_options{}, upstream) {}

YANTERM_SSH_INLINE page_resource::~page_resource() { release(); }

YANTERM_SSH_INLINE void* page_resource::do_allocate(std::size_t bytes, std::size_t alignment) {
    if (!detail::is_page_block(bytes, alignment)) return upstream_->allocate(bytes, alignment);
    void* cached = nullptr;
    {
        std::lock_guard<std::mutex> lock(mu_);
        cached = free_.pop(default_page_size);
    }
    if (cached != nullptr) return cached;
    return upstream_->allocate(default_page_size, alignof(std::max_align_t));
}

YANTERM_SSH_INLINE void page_resource::do_deallocate(void* p, std::size_t bytes, std::size_t alignment) {
    if (!detail::is_page_block(bytes, alignment)) {
        upstream_->deallocate(p, bytes, alignment);
        return;
    }
    bool cached = false;
    {
        std::lock_guard<std::mutex> lock(mu_);
        cached = free_.try_push(p, default_page_size);
    }
    if (!cached) upstream_->deallocate(p, default_page_size, alignof(std::max_align_t));
}

YANTERM_SSH_INLINE bool page_resource::do_is_equal(const std::pmr::memory_resource& other) const noexcept {
    return this == &other;
}

YANTERM_SSH_INLINE void page_resource::release() {
    void* p = nullptr;
    {
        std::lock_guard<std::mutex> lock(mu_);
        p = free_.take_all();
    }
    while (p != nullptr) {
        void* next = detail::page_freelist::next_of(p);
        detail::unpoison_page(p, default_page_size);
        upstream_->deallocate(p, default_page_size, alignof(std::max_align_t));
        p = next;
    }
}

YANTERM_SSH_INLINE std::pmr::memory_resource* page_resource::upstream_resource() const noexcept { return upstream_; }

YANTERM_SSH_INLINE page_resource_options page_resource::options() const noexcept {
    return page_resource_options{free_.max_cached_blocks()};
}

YANTERM_SSH_INLINE page_resource* default_page_resource() noexcept {
    static page_resource instance;
    return &instance;
}

}  // namespace yanterm::ssh::memory

namespace yanterm::ssh::memory {

YANTERM_SSH_INLINE unsynchronized_page_resource::unsynchronized_page_resource(
    page_resource_options opts, std::pmr::memory_resource* upstream)
    : upstream_{upstream != nullptr ? upstream : std::pmr::new_delete_resource()}
    , free_{opts.max_cached_blocks} {}

YANTERM_SSH_INLINE unsynchronized_page_resource::unsynchronized_page_resource(std::pmr::memory_resource* upstream)
    : unsynchronized_page_resource(page_resource_options{}, upstream) {}

YANTERM_SSH_INLINE unsynchronized_page_resource::~unsynchronized_page_resource() { release(); }

YANTERM_SSH_INLINE void* unsynchronized_page_resource::do_allocate(std::size_t bytes, std::size_t alignment) {
    if (!detail::is_page_block(bytes, alignment)) return upstream_->allocate(bytes, alignment);
    if (void* cached = free_.pop(default_page_size)) return cached;
    return upstream_->allocate(default_page_size, alignof(std::max_align_t));
}

YANTERM_SSH_INLINE void unsynchronized_page_resource::do_deallocate(void* p, std::size_t bytes, std::size_t alignment) {
    if (!detail::is_page_block(bytes, alignment)) {
        upstream_->deallocate(p, bytes, alignment);
        return;
    }
    if (!free_.try_push(p, default_page_size)) upstream_->deallocate(p, default_page_size, alignof(std::max_align_t));
}

YANTERM_SSH_INLINE bool unsynchronized_page_resource::do_is_equal(
    const std::pmr::memory_resource& other) const noexcept {
    return this == &other;
}

YANTERM_SSH_INLINE void unsynchronized_page_resource::release() {
    void* p = free_.take_all();
    while (p != nullptr) {
        void* next = detail::page_freelist::next_of(p);
        detail::unpoison_page(p, default_page_size);
        upstream_->deallocate(p, default_page_size, alignof(std::max_align_t));
        p = next;
    }
}

YANTERM_SSH_INLINE std::pmr::memory_resource* unsynchronized_page_resource::upstream_resource() const noexcept {
    return upstream_;
}

YANTERM_SSH_INLINE page_resource_options unsynchronized_page_resource::options() const noexcept {
    return page_resource_options{free_.max_cached_blocks()};
}

}  // namespace yanterm::ssh::memory
