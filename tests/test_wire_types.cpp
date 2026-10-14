#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/detail/error.hpp>

#include <yanterm-ssh/wire/types.hpp>

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory_resource>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace yanterm::ssh;

using wire::name_list;
using wire::reader;
using wire::writer;

namespace {

std::vector<std::byte> bytes(std::initializer_list<int> vs) {
    std::vector<std::byte> out;
    out.reserve(vs.size());
    for (int v : vs) out.push_back(static_cast<std::byte>(v));
    return out;
}

std::string hex(std::span<const std::byte> in) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(in.size() * 2);
    for (std::byte b : in) {
        out.push_back(kDigits[std::to_integer<unsigned>(b) >> 4]);
        out.push_back(kDigits[std::to_integer<unsigned>(b) & 0x0Fu]);
    }
    return out;
}

}  // namespace

TEST_CASE("reader decodes scalars", "[wire]") {
    const auto buf = bytes({0x2a, 0x01, 0x00, 0x00, 0x01, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03});
    reader r{buf};

    std::uint8_t b = 0;
    bool flag = false;
    std::uint32_t u32 = 0;
    std::uint64_t u64 = 0;
    REQUIRE(r.read_byte(b));
    REQUIRE(r.read_bool(flag));
    REQUIRE(r.read_uint32(u32));
    REQUIRE(r.read_uint64(u64));

    REQUIRE(b == 0x2a);
    REQUIRE(flag);
    REQUIRE(u32 == 0x00000100u);
    REQUIRE(u64 == 0x0000000000000203ull);
    REQUIRE(r.empty());
    REQUIRE(r.ok());
}

TEST_CASE("reader treats any non-zero byte as boolean true", "[wire]") {
    const auto buf = bytes({0x05});
    reader r{buf};
    bool flag = false;
    REQUIRE(r.read_bool(flag));
    REQUIRE(flag);
}

TEST_CASE("reader borrows strings and accepts embedded NULs", "[wire]") {
    const auto buf = bytes({0x00, 0x00, 0x00, 0x03, 'a', 0x00, 'b'});
    reader r{buf};
    std::span<const std::byte> s;
    REQUIRE(r.read_string(s));
    REQUIRE(s.size() == 3);
    REQUIRE(s.data() == buf.data() + 4);  // borrowed, not copied
    REQUIRE(hex(s) == "610062");
}

TEST_CASE("reader decodes empty string", "[wire]") {
    const auto buf = bytes({0x00, 0x00, 0x00, 0x00});
    reader r{buf};
    std::string_view sv{"unset"};
    REQUIRE(r.read_string(sv));
    REQUIRE(sv.empty());
    REQUIRE(r.empty());
}

TEST_CASE("reader failure is sticky and reported once", "[wire]") {
    const auto buf = bytes({0x00, 0x00, 0x00, 0x08, 'a', 'b'});
    reader r{buf};
    std::span<const std::byte> s;
    REQUIRE_FALSE(r.read_string(s));
    REQUIRE_FALSE(r.ok());
    REQUIRE(r.error() == code::truncated_input);

    // Once failed, subsequent reads keep failing and do not overwrite the cause.
    std::uint8_t b = 0;
    REQUIRE_FALSE(r.read_byte(b));
    REQUIRE(r.error() == code::truncated_input);
}

TEST_CASE("reader rejects absurd string lengths without allocating", "[wire]") {
    const auto buf = bytes({0xff, 0xff, 0xff, 0xff, 'a'});
    reader r{buf};
    std::span<const std::byte> s;
    REQUIRE_FALSE(r.read_string(s));
    REQUIRE(r.error() == code::string_too_long);
}

// RFC 4251 section 5 mpint examples.
TEST_CASE("reader decodes canonical mpints", "[wire][mpint]") {
    SECTION("zero is the empty string") {
        const auto buf = bytes({0x00, 0x00, 0x00, 0x00});
        reader r{buf};
        std::span<const std::byte> m;
        REQUIRE(r.read_mpint(m));
        REQUIRE(m.empty());
    }
    SECTION("0x9a378f9b2e332a7 needs no padding") {
        const auto buf = bytes({0x00, 0x00, 0x00, 0x08,
                                0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7});
        reader r{buf};
        std::span<const std::byte> m;
        REQUIRE(r.read_mpint(m));
        REQUIRE(hex(m) == "09a378f9b2e332a7");
    }
    SECTION("0x80 carries a leading zero that is stripped from the magnitude") {
        const auto buf = bytes({0x00, 0x00, 0x00, 0x02, 0x00, 0x80});
        reader r{buf};
        std::span<const std::byte> m;
        REQUIRE(r.read_mpint(m));
        REQUIRE(hex(m) == "80");
    }
}

TEST_CASE("reader rejects negative mpints", "[wire][mpint]") {
    SECTION("-1234") {
        const auto buf = bytes({0x00, 0x00, 0x00, 0x02, 0xed, 0xcc});
        reader r{buf};
        std::span<const std::byte> m;
        REQUIRE_FALSE(r.read_mpint(m));
        REQUIRE(r.error() == code::invalid_mpint);
    }
    SECTION("-0xdeadbeef") {
        const auto buf = bytes({0x00, 0x00, 0x00, 0x05, 0xff, 0x21, 0x52, 0x41, 0x11});
        reader r{buf};
        std::span<const std::byte> m;
        REQUIRE_FALSE(r.read_mpint(m));
        REQUIRE(r.error() == code::invalid_mpint);
    }
}

TEST_CASE("reader rejects non-canonical mpints", "[wire][mpint]") {
    // 0x00 0x01 is non-canonical: the pad byte is only allowed when the next
    // byte has its high bit set.
    const auto buf = bytes({0x00, 0x00, 0x00, 0x02, 0x00, 0x01});
    reader r{buf};
    std::span<const std::byte> m;
    REQUIRE_FALSE(r.read_mpint(m));
    REQUIRE(r.error() == code::invalid_mpint);
}

TEST_CASE("name_list splits and searches", "[wire][namelist]") {
    const std::string raw = "zlib@openssh.com,none";
    const auto buf = bytes({0x00, 0x00, 0x00, 0x15});
    std::vector<std::byte> full = buf;
    for (char c : raw) full.push_back(static_cast<std::byte>(c));

    reader r{full};
    name_list nl;
    REQUIRE(r.read_name_list(nl));
    REQUIRE(nl.raw() == "zlib@openssh.com,none");

    std::vector<std::string_view> items;
    for (std::string_view n : nl) items.push_back(n);
    REQUIRE(items == std::vector<std::string_view>{"zlib@openssh.com", "none"});

    REQUIRE(nl.contains("none"));
    REQUIRE(nl.contains("zlib@openssh.com"));
    REQUIRE_FALSE(nl.contains("zlib"));
    REQUIRE_FALSE(nl.contains(""));
}

TEST_CASE("empty name_list has no elements", "[wire][namelist]") {
    const auto buf = bytes({0x00, 0x00, 0x00, 0x00});
    reader r{buf};
    name_list nl;
    REQUIRE(r.read_name_list(nl));
    REQUIRE(nl.begin() == nl.end());
    REQUIRE_FALSE(nl.contains("none"));
}

TEST_CASE("name_list rejects empty names and non-ASCII", "[wire][namelist]") {
    auto make = [](std::string_view raw) {
        std::vector<std::byte> out = bytes({0x00, 0x00, 0x00, 0x00});
        out[3] = static_cast<std::byte>(raw.size());
        for (char c : raw) out.push_back(static_cast<std::byte>(c));
        return out;
    };
    for (std::string_view bad : {",none", "none,", "a,,b", "no\x7fne", "no ne"}) {
        const auto buf = make(bad);
        reader r{buf};
        name_list nl;
        INFO("input: " << bad);
        REQUIRE_FALSE(r.read_name_list(nl));
        REQUIRE(r.error() == code::invalid_name_list);
    }
}

TEST_CASE("writer round-trips through reader", "[wire]") {
    writer w;
    w.write_byte(0x2a);
    w.write_bool(true);
    w.write_uint32(0x01020304u);
    w.write_uint64(0x0102030405060708ull);
    w.write_string(std::string_view{"hello"});
    w.write_name_list(std::vector<std::string_view>{"a", "b"});

    reader r{w.data()};
    std::uint8_t b = 0;
    bool flag = false;
    std::uint32_t u32 = 0;
    std::uint64_t u64 = 0;
    std::string_view s;
    name_list nl;
    REQUIRE(r.read_byte(b));
    REQUIRE(r.read_bool(flag));
    REQUIRE(r.read_uint32(u32));
    REQUIRE(r.read_uint64(u64));
    REQUIRE(r.read_string(s));
    REQUIRE(r.read_name_list(nl));
    REQUIRE(r.empty());

    REQUIRE(b == 0x2a);
    REQUIRE(flag);
    REQUIRE(u32 == 0x01020304u);
    REQUIRE(u64 == 0x0102030405060708ull);
    REQUIRE(s == "hello");
    REQUIRE(nl.raw() == "a,b");
}

TEST_CASE("writer emits RFC 4251 mpint encodings", "[wire][mpint]") {

    SECTION("zero") {
        writer w;
        w.write_mpint(std::span<const std::byte>{});
        REQUIRE(hex(w.data()) == "00000000");
    }
    SECTION("leading zeros in the magnitude are stripped") {
        const auto mag = bytes({0x00, 0x00, 0x09, 0xa3});
        writer w;
        w.write_mpint(mag);
        REQUIRE(hex(w.data()) == "0000000209a3");
    }
    SECTION("high bit forces a pad byte") {
        const auto mag = bytes({0x80});
        writer w;
        w.write_mpint(mag);
        REQUIRE(hex(w.data()) == "000000020080");
    }
    SECTION("an all-zero magnitude is still zero") {
        const auto mag = bytes({0x00, 0x00});
        writer w;
        w.write_mpint(mag);
        REQUIRE(hex(w.data()) == "00000000");
    }
}

TEST_CASE("writer name-list of zero names is the empty string", "[wire][namelist]") {
    writer w;
    w.write_name_list(std::span<const std::string_view>{});
    REQUIRE(hex(w.data()) == "00000000");
}

TEST_CASE("writer take moves buffer out and leaves writer empty", "[wire][wire_types]") {
    writer w;
    w.write_uint32(0x01020304u);
    w.write_string(std::string_view{"hi"});

    const std::vector<std::byte> expected(w.data().begin(), w.data().end());
    const std::vector<std::byte> taken = w.take();

    REQUIRE(taken == expected);
    REQUIRE(w.size() == 0);
    REQUIRE(w.data().empty());

    w.write_byte(0x42);
    REQUIRE(w.size() == 1);
    REQUIRE(std::to_integer<std::uint8_t>(w.data()[0]) == 0x42);
}
