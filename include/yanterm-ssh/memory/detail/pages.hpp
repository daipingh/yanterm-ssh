#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/memory/page_resource.hpp>

#include <cstddef>
#include <memory_resource>
#include <span>

namespace yanterm::ssh::memory::detail {

// Fixed-size reference-counted pages for decrypted plaintext (inbound) and
// assembled ciphertext (outbound).
//
// Each block is allocated from the memory_resource given to page_pool. The
// last live reference returns that block to the resource immediately.
//
// Invariant relied upon by the transport layer: usable capacity (block size
// minus header) is never smaller than one whole SSH binary packet, so a
// packet never straddles two pages and payloads stay contiguous.
//
// The refcount is NOT atomic: the protocol core is single-threaded sans-IO.
// Passing a page_slice to another thread is a usage error.

class page_pool;

struct page {
    std::size_t capacity = 0;  // usable bytes after the header
    std::size_t cursor = 0;
    std::size_t refs = 0;
    page_pool* owner = nullptr;

    [[nodiscard]] std::byte* data() noexcept;
    [[nodiscard]] const std::byte* data() const noexcept;
};

inline constexpr std::size_t page_header_size =
    (sizeof(page) + alignof(std::max_align_t) - 1) / alignof(std::max_align_t)
    * alignof(std::max_align_t);

class page_ref {
public:
    page_ref() = default;

    page_ref(const page_ref& other) noexcept;
    page_ref(page_ref&& other) noexcept;

    page_ref& operator=(const page_ref& other) noexcept;
    page_ref& operator=(page_ref&& other) noexcept;

    ~page_ref();

    void reset() noexcept;

    [[nodiscard]] bool valid() const noexcept { return p_ != nullptr; }
    [[nodiscard]] const page* get() const noexcept { return p_; }
    [[nodiscard]] page* get() noexcept { return p_; }

private:
    friend class page_pool;
    explicit page_ref(page* p) noexcept;

    void retain() noexcept;
    void release() noexcept;

    page* p_ = nullptr;
};

class page_slice {
public:
    page_slice() = default;

    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] std::size_t page_offset() const noexcept { return offset_; }

    [[nodiscard]] std::span<const std::byte> bytes() const noexcept;
    [[nodiscard]] std::span<std::byte> mutable_bytes() noexcept;

    // Sub-view sharing the same page (and therefore the same refcount).
    [[nodiscard]] page_slice subslice(std::size_t offset, std::size_t size) const;

    [[nodiscard]] bool same_page_as(const page_slice& other) const noexcept {
        return ref_.valid() && other.ref_.valid() && ref_.get() == other.ref_.get();
    }

    // 同页且 other 紧接本视图之后则合并并返回 true；否则两者都不变。
    [[nodiscard]] bool try_merge(const page_slice& other) noexcept;

    void reset() noexcept;

    // Shrinks the front of the view; used when output is partially consumed.
    void advance(std::size_t n) noexcept;

private:
    friend class page_pool;

    // Grows the view forward inside the same page. Outbound segment merging
    // calls this only for a slice the pool just handed out immediately after
    // this one. Overrunning the page is a programming error.
    void extend(std::size_t extra) noexcept;

    page_ref ref_;
    std::size_t offset_ = 0;
    std::size_t size_ = 0;
};

class page_pool {
public:
    explicit page_pool(std::size_t page_size = default_page_size,
                       std::pmr::memory_resource* mr = default_page_resource());
    ~page_pool();

    page_pool(const page_pool&) = delete;
    page_pool& operator=(const page_pool&) = delete;
    page_pool(page_pool&&) = delete;
    page_pool& operator=(page_pool&&) = delete;

    // Returns an empty slice when `size` is 0 or larger than page_capacity().
    [[nodiscard]] page_slice allocate(std::size_t size);

    [[nodiscard]] std::size_t page_size() const noexcept { return page_size_; }
    [[nodiscard]] std::size_t page_capacity() const noexcept { return page_size_ - page_header_size; }
    [[nodiscard]] std::size_t live_pages() const noexcept { return live_pages_; }

private:
    friend class page_ref;

    void take_new_current();
    void release_page(page* p) noexcept;

    std::size_t page_size_;
    std::pmr::memory_resource* mr_;
    page* current_ = nullptr;
    std::size_t live_pages_ = 0;
};

}  // namespace yanterm::ssh::memory::detail

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/memory/detail/impl/pages.ipp>
#endif
