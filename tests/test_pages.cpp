#include <yanterm-ssh/memory/detail/pages.hpp>

#include "counting_resource.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

TEST_CASE("page_pool bump-allocates within one page", "[pages]") {
    memory::detail::page_pool pool{1024};
    REQUIRE(pool.page_size() == 1024);

    auto a = pool.allocate(100);
    auto b = pool.allocate(200);

    REQUIRE(a.size() == 100);
    REQUIRE(b.size() == 200);
    REQUIRE(a.same_page_as(b));
    REQUIRE(a.page_offset() == 0);
    REQUIRE(b.page_offset() == 100);
    REQUIRE(pool.live_pages() == 1);
}

TEST_CASE("page_pool takes a new page when the current one cannot fit", "[pages]") {
    memory::detail::page_pool pool{1024};
    auto a = pool.allocate(900);
    auto b = pool.allocate(200);

    REQUIRE_FALSE(a.same_page_as(b));
    REQUIRE(b.page_offset() == 0);
    REQUIRE(pool.live_pages() == 2);
}

TEST_CASE("a page goes back to the resource when its last slice dies", "[pages]") {
    counting_resource res;
    memory::detail::page_pool pool{1024, &res};
    {
        auto a = pool.allocate(100);
        auto b = a.subslice(10, 20);
        REQUIRE(res.outstanding_blocks() == 1);
        REQUIRE(res.outstanding_bytes() == 1024);

        a.reset();
        REQUIRE(pool.live_pages() == 1);
        REQUIRE(res.outstanding_blocks() == 1);
    }
    REQUIRE(pool.live_pages() == 0);
    REQUIRE(res.outstanding_blocks() == 0);
}

TEST_CASE("every page is one fixed-size block and usable capacity excludes the header",
          "[pages]") {
    counting_resource res;
    memory::detail::page_pool pool{1024, &res};
    REQUIRE(pool.page_size() == 1024);
    REQUIRE(pool.page_capacity() == 1024 - memory::detail::page_header_size);

    auto a = pool.allocate(pool.page_capacity());
    auto b = pool.allocate(1);
    REQUIRE_FALSE(a.same_page_as(b));
    REQUIRE(res.outstanding_blocks() == 2);
    REQUIRE(res.outstanding_bytes() == 2048);
}

TEST_CASE("slice contents survive independently of the pool cursor", "[pages]") {
    memory::detail::page_pool pool{1024};
    auto a = pool.allocate(4);
    auto w = a.mutable_bytes();
    w[0] = std::byte{0xde};
    w[1] = std::byte{0xad};
    w[2] = std::byte{0xbe};
    w[3] = std::byte{0xef};

    auto b = pool.allocate(4);
    auto bw = b.mutable_bytes();
    bw[0] = std::byte{0x00};

    REQUIRE(a.bytes()[0] == std::byte{0xde});
    REQUIRE(a.bytes()[3] == std::byte{0xef});
}

TEST_CASE("copying a slice keeps the page alive", "[pages]") {
    memory::detail::page_pool pool{1024};
    memory::detail::page_slice kept;
    {
        auto a = pool.allocate(8);
        kept = a;
    }
    REQUIRE(pool.live_pages() == 1);
    kept.reset();
    REQUIRE(pool.live_pages() == 0);
}

TEST_CASE("a default page_slice is empty and safe to reset", "[pages]") {
    memory::detail::page_slice s;
    REQUIRE(s.empty());
    REQUIRE(s.size() == 0);
    REQUIRE(s.bytes().empty());
    s.reset();
    REQUIRE(s.empty());
}

TEST_CASE("allocate returns an empty slice when the request cannot fit a page",
          "[pages]") {
    memory::detail::page_pool pool{1024};
    REQUIRE(pool.allocate(0).empty());
    REQUIRE(pool.allocate(pool.page_capacity() + 1).empty());
    REQUIRE(pool.live_pages() == 0);
}

TEST_CASE("advance shrinks the front of a slice", "[pages]") {
    memory::detail::page_pool pool{1024};
    auto a = pool.allocate(10);
    const auto* base = a.bytes().data();

    a.advance(3);
    REQUIRE(a.size() == 7);
    REQUIRE(a.bytes().data() == base + 3);
    REQUIRE(a.page_offset() == 3);

    a.advance(a.size());
    REQUIRE(a.empty());
}
