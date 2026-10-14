#pragma once

#include <algorithm>
#include <cstddef>
#include <memory_resource>
#include <string>
#include <string_view>
#include <vector>

namespace yanterm::ssh::testing {

// 页块在最后一个 slice 释放时归还；归还前扫描整块，发现任一受监视秘密即记为泄漏。
class secret_scan_resource final : public std::pmr::memory_resource {
public:
    explicit secret_scan_resource(std::pmr::memory_resource* upstream = std::pmr::new_delete_resource())
        : upstream_{upstream} {}

    void watch(std::string_view secret) { secrets_.emplace_back(secret); }
    [[nodiscard]] bool leaked() const noexcept { return leaked_; }
    [[nodiscard]] std::size_t returned_blocks() const noexcept { return returned_; }

private:
    void* do_allocate(std::size_t n, std::size_t align) override { return upstream_->allocate(n, align); }

    void do_deallocate(void* p, std::size_t n, std::size_t align) override {
        const auto* b = static_cast<const char*>(p);
        for (const auto& s : secrets_) {
            if (std::search(b, b + n, s.begin(), s.end()) != b + n) leaked_ = true;
        }
        ++returned_;
        upstream_->deallocate(p, n, align);
    }

    bool do_is_equal(const std::pmr::memory_resource& o) const noexcept override { return this == &o; }

    std::pmr::memory_resource* upstream_;
    std::vector<std::string> secrets_;
    bool leaked_ = false;
    std::size_t returned_ = 0;
};

}  // namespace yanterm::ssh::testing
