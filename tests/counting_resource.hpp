#pragma once

#include <cstddef>
#include <memory_resource>

namespace yanterm::ssh::testing {

class counting_resource final : public std::pmr::memory_resource {
public:
    explicit counting_resource(std::pmr::memory_resource* upstream = std::pmr::new_delete_resource())
        : upstream_{upstream} {}

    [[nodiscard]] std::size_t outstanding_blocks() const noexcept { return blocks_; }
    [[nodiscard]] std::size_t outstanding_bytes() const noexcept { return bytes_; }
    [[nodiscard]] std::size_t total_allocations() const noexcept { return total_; }

private:
    void* do_allocate(std::size_t n, std::size_t align) override {
        void* p = upstream_->allocate(n, align);
        ++blocks_;
        ++total_;
        bytes_ += n;
        return p;
    }
    void do_deallocate(void* p, std::size_t n, std::size_t align) override {
        upstream_->deallocate(p, n, align);
        --blocks_;
        bytes_ -= n;
    }
    bool do_is_equal(const std::pmr::memory_resource& o) const noexcept override { return this == &o; }

    std::pmr::memory_resource* upstream_;
    std::size_t blocks_ = 0;
    std::size_t bytes_ = 0;
    std::size_t total_ = 0;
};

}  // namespace yanterm::ssh::testing
