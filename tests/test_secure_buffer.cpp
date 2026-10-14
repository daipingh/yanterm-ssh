#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/crypto/secure_buffer.hpp>

#include <algorithm>
#include <cstddef>
#include <string_view>
#include <type_traits>
#include <vector>

using namespace yanterm::ssh;

namespace {

template <class T>
struct observing_allocator {
    using value_type = T;
    using is_always_equal = std::true_type;
    using propagate_on_container_move_assignment = std::true_type;

    observing_allocator() noexcept = default;

    template <class U>
    observing_allocator(const observing_allocator<U>&) noexcept {}

    [[nodiscard]] T* allocate(std::size_t n) { return std::allocator<T>{}.allocate(n); }

    void deallocate(T* p, std::size_t n) noexcept {
        crypto::wiping_allocator<T>::prepare_release(p, n);
        if (released != nullptr && p != nullptr && n != 0) {
            const auto* bytes = reinterpret_cast<const std::byte*>(p);
            released->emplace_back(bytes, bytes + static_cast<std::ptrdiff_t>(n * sizeof(T)));
        }
        std::allocator<T>{}.deallocate(p, n);
    }

    static std::vector<std::vector<std::byte>>* released;

    template <class U>
    friend bool operator==(const observing_allocator&, const observing_allocator<U>&) noexcept {
        return true;
    }
    template <class U>
    friend bool operator!=(const observing_allocator&, const observing_allocator<U>&) noexcept {
        return false;
    }
};

template <class T>
std::vector<std::vector<std::byte>>* observing_allocator<T>::released = nullptr;

bool contains_bytes(const void* obj, std::size_t n, std::string_view needle) {
    if (needle.empty() || n < needle.size()) return false;
    const auto* raw = static_cast<const char*>(obj);
    const std::string_view hay{raw, n};
    return hay.find(needle) != std::string_view::npos;
}

}  // namespace

TEST_CASE("secure_string move leaves no password in the source object", "[crypto][secure_buffer]") {
    crypto::secure_string src;
    src.assign("hunter2");
    crypto::secure_string dst = std::move(src);
    REQUIRE(dst == "hunter2");
    REQUIRE(src.empty());
    REQUIRE_FALSE(contains_bytes(&src, sizeof(src), "hunter2"));
    REQUIRE_FALSE(contains_bytes(&src, sizeof(src), "unter"));
}

TEST_CASE("secure_string wipe zeros in place and keeps the view", "[crypto][secure_buffer]") {
    crypto::secure_string secret;
    secret.assign("hunter2");
    const std::string_view view = secret.view();
    secret.wipe();
    REQUIRE(secret.empty());
    REQUIRE(view.size() == 7);
    REQUIRE(std::all_of(view.begin(), view.end(), [](char c) { return c == '\0'; }));
}

TEST_CASE("wiping allocator zeros a block before it is released", "[crypto][secure_buffer]") {
    crypto::wiping_allocator<std::byte> alloc;
    constexpr std::size_t n = 16;
    std::byte* block = alloc.allocate(n);
    std::fill_n(block, n, std::byte{0x11});
    crypto::wiping_allocator<std::byte>::prepare_release(block, n);
    REQUIRE(std::all_of(block, block + n, [](std::byte b) { return b == std::byte{0}; }));
    alloc.deallocate(block, n);

    std::vector<std::vector<std::byte>> released;
    observing_allocator<std::byte>::released = &released;
    {
        crypto::basic_secure_buffer<std::byte, observing_allocator<std::byte>> buf;
        const std::byte one[] = {std::byte{0x11}};
        buf.append(one);
        REQUIRE(released.empty());
        const std::vector<std::byte> chunk(1u << 20, std::byte{0x22});
        buf.append(chunk);
        REQUIRE_FALSE(released.empty());
    }
    observing_allocator<std::byte>::released = nullptr;

    REQUIRE_FALSE(released.empty());
    for (const auto& old : released) {
        REQUIRE(std::all_of(old.begin(), old.end(), [](std::byte b) { return b == std::byte{0}; }));
    }
}
