#include <yanterm-ssh/memory/page_resource.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_template_test_macros.hpp>

#include <cstddef>
#include <new>
#include <vector>

using namespace yanterm::ssh;

namespace {

struct alloc_record {
    std::size_t bytes = 0;
    std::size_t align = 0;
    friend bool operator==(const alloc_record& a, const alloc_record& b) noexcept {
        return a.bytes == b.bytes && a.align == b.align;
    }
};

class tracing_resource final : public std::pmr::memory_resource {
public:
    std::vector<alloc_record> allocations;
    std::vector<alloc_record> deallocations;

private:
    void* do_allocate(std::size_t n, std::size_t align) override {
        allocations.push_back({n, align});
        if (align > alignof(std::max_align_t)) return ::operator new(n, std::align_val_t{align});
        return ::operator new(n);
    }
    void do_deallocate(void* p, std::size_t n, std::size_t align) override {
        deallocations.push_back({n, align});
        if (align > alignof(std::max_align_t)) ::operator delete(p, std::align_val_t{align});
        else ::operator delete(p);
    }
    bool do_is_equal(const std::pmr::memory_resource& o) const noexcept override { return this == &o; }
};

template <class Resource>
void check_page_class() {
    const std::size_t page = memory::default_page_size;
    const std::size_t align = alignof(std::max_align_t);
    struct probe {
        std::size_t bytes;
        std::size_t align;
        bool hit;
    };
    const probe probes[] = {
        {page / 2, align, false},
        {page / 2 + 1, align, true},
        {page, align, true},
        {page + 1, align, false},
        {64, align, false},
        {page, align * 2, false},
    };
    for (const auto& pr : probes) {
        tracing_resource up;
        {
            Resource r{&up};
            void* p = r.allocate(pr.bytes, pr.align);
            REQUIRE(up.allocations.size() == 1);
            if (pr.hit) {
                REQUIRE(up.allocations[0] == alloc_record{page, align});
                r.deallocate(p, pr.bytes, pr.align);
                REQUIRE(up.deallocations.empty());
            } else {
                REQUIRE(up.allocations[0] == alloc_record{pr.bytes, pr.align});
                r.deallocate(p, pr.bytes, pr.align);
                REQUIRE(up.deallocations.size() == 1);
                REQUIRE(up.deallocations[0] == alloc_record{pr.bytes, pr.align});
            }
        }
        REQUIRE(up.allocations.size() == up.deallocations.size());
    }
}

template <class Resource>
void check_reuse_and_cap() {
    const std::size_t page = memory::default_page_size;
    const std::size_t align = alignof(std::max_align_t);
    tracing_resource up;
    Resource r{&up};
    void* a = r.allocate(page, align);
    r.deallocate(a, page, align);
    void* b = r.allocate(page, align);
    REQUIRE(a == b);
    REQUIRE(up.allocations.size() == 1);
    r.deallocate(b, page, align);

    tracing_resource capped_up;
    {
        Resource capped{memory::page_resource_options{.max_cached_blocks = 2}, &capped_up};
        void* p[3];
        for (int i = 0; i < 3; ++i) p[i] = capped.allocate(page, align);
        REQUIRE(capped_up.allocations.size() == 3);
        for (int i = 0; i < 3; ++i) capped.deallocate(p[i], page, align);
        REQUIRE(capped_up.deallocations.size() == 1);
        capped.release();
        REQUIRE(capped_up.deallocations.size() == 3);
    }
    REQUIRE(capped_up.allocations.size() == capped_up.deallocations.size());

    tracing_resource dtor_up;
    {
        Resource held{&dtor_up};
        void* p = held.allocate(page, align);
        held.deallocate(p, page, align);
        REQUIRE(dtor_up.deallocations.empty());
    }
    REQUIRE(dtor_up.deallocations.size() == 1);
}

}  // namespace

TEMPLATE_TEST_CASE("page resource caches only the page size class", "[page_resource]",
                   memory::page_resource, memory::unsynchronized_page_resource) {
    check_page_class<TestType>();
    check_reuse_and_cap<TestType>();
}
