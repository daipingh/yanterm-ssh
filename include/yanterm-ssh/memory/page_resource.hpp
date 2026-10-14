#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/memory/detail/page_freelist.hpp>

#include <cstddef>
#include <memory_resource>
#include <mutex>

namespace yanterm::ssh::memory {

inline constexpr std::size_t default_page_size = 64u * 1024u;

struct page_resource_options {
    std::size_t max_cached_blocks = 64;
};

class page_resource final : public std::pmr::memory_resource {
public:
    explicit page_resource(page_resource_options opts = {},
                           std::pmr::memory_resource* upstream = std::pmr::new_delete_resource());
    explicit page_resource(std::pmr::memory_resource* upstream);
    ~page_resource() override;
    page_resource(const page_resource&) = delete;
    page_resource& operator=(const page_resource&) = delete;
    void release();
    [[nodiscard]] std::pmr::memory_resource* upstream_resource() const noexcept;
    [[nodiscard]] page_resource_options options() const noexcept;

private:
    void* do_allocate(std::size_t bytes, std::size_t alignment) override;
    void do_deallocate(void* p, std::size_t bytes, std::size_t alignment) override;
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override;

    std::pmr::memory_resource* upstream_ = nullptr;
    detail::page_freelist free_;
    std::mutex mu_;
};

class unsynchronized_page_resource final : public std::pmr::memory_resource {
public:
    explicit unsynchronized_page_resource(
        page_resource_options opts = {},
        std::pmr::memory_resource* upstream = std::pmr::new_delete_resource());
    explicit unsynchronized_page_resource(std::pmr::memory_resource* upstream);
    ~unsynchronized_page_resource() override;
    unsynchronized_page_resource(const unsynchronized_page_resource&) = delete;
    unsynchronized_page_resource& operator=(const unsynchronized_page_resource&) = delete;
    void release();
    [[nodiscard]] std::pmr::memory_resource* upstream_resource() const noexcept;
    [[nodiscard]] page_resource_options options() const noexcept;

private:
    void* do_allocate(std::size_t bytes, std::size_t alignment) override;
    void do_deallocate(void* p, std::size_t bytes, std::size_t alignment) override;
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override;

    std::pmr::memory_resource* upstream_ = nullptr;
    detail::page_freelist free_;
};

[[nodiscard]] page_resource* default_page_resource() noexcept;

}  // namespace yanterm::ssh::memory

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/memory/impl/page_resource.ipp>
#endif
