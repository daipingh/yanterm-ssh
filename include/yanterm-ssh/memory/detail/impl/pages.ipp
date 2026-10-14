#pragma once

#include <yanterm-ssh/memory/detail/pages.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/memory/detail/impl/pages.ipp is an implementation file, not a public header."
#endif

#include <cassert>
#include <new>

namespace yanterm::ssh::memory::detail {

YANTERM_SSH_INLINE page_ref::page_ref(const page_ref& other) noexcept : p_{other.p_} { retain(); }

YANTERM_SSH_INLINE page_ref::page_ref(page_ref&& other) noexcept : p_{other.p_} { other.p_ = nullptr; }

YANTERM_SSH_INLINE page_ref::page_ref(page* p) noexcept : p_{p} { retain(); }

YANTERM_SSH_INLINE page_ref& page_ref::operator=(const page_ref& other) noexcept {
    if (this != &other) {
        release();
        p_ = other.p_;
        retain();
    }
    return *this;
}

YANTERM_SSH_INLINE page_ref& page_ref::operator=(page_ref&& other) noexcept {
    if (this != &other) {
        release();
        p_ = other.p_;
        other.p_ = nullptr;
    }
    return *this;
}

YANTERM_SSH_INLINE page_ref::~page_ref() { release(); }

YANTERM_SSH_INLINE void page_ref::reset() noexcept {
    release();
    p_ = nullptr;
}

YANTERM_SSH_INLINE void page_ref::retain() noexcept {
    if (p_ != nullptr) ++p_->refs;
}

YANTERM_SSH_INLINE void page_ref::release() noexcept {
    if (p_ == nullptr) return;
    if (--p_->refs == 0) p_->owner->release_page(p_);
    p_ = nullptr;
}

YANTERM_SSH_INLINE std::byte* page::data() noexcept {
    return reinterpret_cast<std::byte*>(this) + page_header_size;
}
YANTERM_SSH_INLINE const std::byte* page::data() const noexcept {
    return reinterpret_cast<const std::byte*>(this) + page_header_size;
}

YANTERM_SSH_INLINE page_pool::page_pool(std::size_t page_size, std::pmr::memory_resource* mr)
    : page_size_{page_size <= page_header_size ? default_page_size : page_size}
    , mr_{mr != nullptr ? mr : default_page_resource()} {}

// Slices must not outlive the pool; every live page would otherwise be freed
// through a dangling owner.
YANTERM_SSH_INLINE page_pool::~page_pool() { assert(live_pages_ == 0); }

YANTERM_SSH_INLINE std::span<const std::byte> page_slice::bytes() const noexcept {
    if (!ref_.valid() || size_ == 0) return {};
    return {ref_.get()->data() + offset_, size_};
}

YANTERM_SSH_INLINE std::span<std::byte> page_slice::mutable_bytes() noexcept {
    if (!ref_.valid() || size_ == 0) return {};
    return {ref_.get()->data() + offset_, size_};
}

YANTERM_SSH_INLINE page_slice page_slice::subslice(std::size_t offset, std::size_t size) const {
    if (offset > size_ || size > size_ - offset) return {};
    page_slice s;
    s.ref_ = ref_;
    s.offset_ = offset_ + offset;
    s.size_ = size;
    return s;
}

YANTERM_SSH_INLINE void page_slice::reset() noexcept {
    ref_.reset();
    offset_ = 0;
    size_ = 0;
}

YANTERM_SSH_INLINE void page_slice::advance(std::size_t n) noexcept {
    const std::size_t step = (n > size_) ? size_ : n;
    offset_ += step;
    size_ -= step;
    if (size_ == 0) reset();
}

YANTERM_SSH_INLINE bool page_slice::try_merge(const page_slice& other) noexcept {
    if (!same_page_as(other) || page_offset() + size() != other.page_offset()) {
        return false;
    }
    extend(other.size());
    return true;
}

YANTERM_SSH_INLINE void page_slice::extend(std::size_t extra) noexcept {
    if (extra == 0) return;
    assert(ref_.valid());
    const std::size_t cap = ref_.get()->capacity;
    assert(offset_ <= cap && size_ <= cap - offset_);
    assert(extra <= cap - offset_ - size_);
    size_ += extra;
}

YANTERM_SSH_INLINE page_slice page_pool::allocate(std::size_t size) {
    if (size == 0 || size > page_capacity()) return {};
    if (current_ == nullptr || current_->capacity - current_->cursor < size) take_new_current();
    page_slice s;
    s.ref_ = page_ref{current_};
    s.offset_ = current_->cursor;
    s.size_ = size;
    current_->cursor += size;
    return s;
}

YANTERM_SSH_INLINE void page_pool::take_new_current() {
    void* block = mr_->allocate(page_size_, alignof(std::max_align_t));
    current_ = ::new (block) page{};
    current_->capacity = page_capacity();
    current_->owner = this;
    ++live_pages_;
}

YANTERM_SSH_INLINE void page_pool::release_page(page* p) noexcept {
    if (p == current_) current_ = nullptr;
    --live_pages_;
    p->~page();
    mr_->deallocate(p, page_size_, alignof(std::max_align_t));
}

}  // namespace yanterm::ssh::memory::detail
