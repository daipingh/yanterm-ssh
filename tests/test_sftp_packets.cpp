#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/sftp/packets.hpp>

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string_view>
#include <vector>

using namespace yanterm::ssh;

namespace {

std::vector<std::byte> bytes(std::initializer_list<int> vs) {
    std::vector<std::byte> out;
    out.reserve(vs.size());
    for (int v : vs) out.push_back(static_cast<std::byte>(v));
    return out;
}

std::span<const std::byte> bspan(std::string_view s) {
    return {reinterpret_cast<const std::byte*>(s.data()), s.size()};
}

std::vector<std::byte> take(wire::writer& w) {
    return w.take();
}

void append_u32(std::vector<std::byte>& out, std::uint32_t v) {
    out.push_back(static_cast<std::byte>(v >> 24));
    out.push_back(static_cast<std::byte>(v >> 16));
    out.push_back(static_cast<std::byte>(v >> 8));
    out.push_back(static_cast<std::byte>(v));
}

void append_u64(std::vector<std::byte>& out, std::uint64_t v) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::byte>(v >> shift));
    }
}

void append_str(std::vector<std::byte>& out, std::string_view s) {
    append_u32(out, static_cast<std::uint32_t>(s.size()));
    for (char c : s) out.push_back(static_cast<std::byte>(c));
}

}  // namespace

TEST_CASE("SFTP status codes map to standard and yanterm conditions", "[sftp][packets]") {
    CHECK(sftp::make_error_code(sftp::status_code::no_such_file)
          == std::errc::no_such_file_or_directory);
    CHECK(sftp::make_error_code(sftp::status_code::permission_denied)
          == std::errc::permission_denied);
    CHECK(sftp::make_error_code(sftp::status_code::op_unsupported)
          == std::errc::operation_not_supported);
    CHECK(sftp::make_error_code(sftp::status_code::bad_message)
          == errc::protocol_violation);
    CHECK(sftp::make_error_code(sftp::status_code::connection_lost)
          == errc::session_closed);

    const auto unknown = std::error_code{42, sftp::error_category()};
    CHECK(unknown.value() == 42);
    CHECK(unknown.category() == sftp::error_category());
    CHECK(unknown.default_error_condition().value() == 42);
    CHECK(unknown.default_error_condition().category() == sftp::error_category());
}

TEST_CASE("SFTP INIT and frame header match draft encoding", "[sftp][packets]") {
    wire::writer w;
    sftp::encode_frame_header(w, 5);
    sftp::encode_init(w);
    CHECK(take(w) == bytes({0, 0, 0, 5, 1, 0, 0, 0, 3}));

    const auto hdr = bytes({0, 4, 0, 0});
    CHECK(sftp::decode_frame_header(hdr) == 262144);
    CHECK(sftp::decode_frame_header(bytes({0, 1, 2})) == 0);
}

TEST_CASE("SFTP extension advertisement requires exact OpenSSH versions", "[sftp][packets]") {
    const sftp::extension_pair exts[] = {
        {"posix-rename@openssh.com", "1"},
        {"statvfs@openssh.com", "1"},
        {"limits@openssh.com", "1"},
        {"home-directory", "1"},
        {"unknown@example.com", "1"},
    };
    const auto set = sftp::advertised_extensions(exts);
    CHECK(set.contains(sftp::extension::posix_rename));
    CHECK_FALSE(set.contains(sftp::extension::statvfs));
    CHECK(set.contains(sftp::extension::limits));
    CHECK(set.contains(sftp::extension::home_directory));
}

TEST_CASE("SFTP VERSION decodes OpenSSH 10 extension vector", "[sftp][packets]") {
    const sftp::extension_pair exts[] = {
        {"posix-rename@openssh.com", "1"},
        {"statvfs@openssh.com", "2"},
        {"fstatvfs@openssh.com", "2"},
        {"hardlink@openssh.com", "1"},
        {"fsync@openssh.com", "1"},
        {"lsetstat@openssh.com", "1"},
        {"limits@openssh.com", "1"},
        {"expand-path@openssh.com", "1"},
        {"copy-data", "1"},
        {"home-directory", "1"},
        {"users-groups-by-id@openssh.com", "1"},
    };
    std::vector<std::byte> hand;
    hand.push_back(std::byte{2});
    append_u32(hand, 3);
    for (const auto& ext : exts) {
        append_str(hand, ext.name);
        append_str(hand, ext.version);
    }

    wire::writer w;
    sftp::encode_version(w, 3, exts);
    CHECK(take(w) == hand);

    sftp::version_reply vr;
    REQUIRE(sftp::decode_version(hand, vr));
    REQUIRE(vr.version == 3);
    REQUIRE(vr.extensions.size() == 11);
    CHECK(vr.extensions[1].name == "statvfs@openssh.com");
    CHECK(vr.extensions[1].version == "2");
    const auto set = sftp::advertised_extensions(vr.extensions);
    CHECK(set.contains(sftp::extension::posix_rename));
    CHECK(set.contains(sftp::extension::statvfs));
    CHECK(set.contains(sftp::extension::users_groups_by_id));

    auto truncated = hand;
    truncated.pop_back();
    CHECK_FALSE(sftp::decode_version(truncated, vr));
    const auto overrun = bytes({2, 0, 0, 0, 3, 0, 0, 0, 100});
    CHECK_FALSE(sftp::decode_version(overrun, vr));
}

TEST_CASE("SFTP OPEN encodes attributes without extended pairs", "[sftp][packets]") {
    wire::writer w;
    sftp::attrs a;
    a.flags = sftp::attr_flags::size | sftp::attr_flags::permissions | sftp::attr_flags::extended;
    a.size = 0x1020304050607080ull;
    a.permissions = 0644;
    sftp::encode_open(w, 7, "/tmp/a", sftp::open_flags::read | sftp::open_flags::write, a);

    const auto expected = bytes({
        3, 0, 0, 0, 7,
        0, 0, 0, 6, '/', 't', 'm', 'p', '/', 'a',
        0, 0, 0, 3,
        0, 0, 0, 5,
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0, 0, 1, 0xa4,
    });
    CHECK(take(w) == expected);
}

TEST_CASE("SFTP responses decode borrowed payloads", "[sftp][packets]") {
    wire::writer w;
    sftp::encode_status(w, 9, static_cast<sftp::status_code>(42), "detail", "en");
    auto buf = take(w);
    sftp::status_reply st;
    REQUIRE(sftp::decode_status(buf, st));
    CHECK(st.id == 9);
    CHECK(static_cast<std::uint32_t>(st.code) == 42);
    CHECK(st.message == "detail");

    w.clear();
    sftp::encode_handle(w, 10, bspan("abc"));
    buf = take(w);
    sftp::handle_reply h;
    REQUIRE(sftp::decode_handle(buf, h));
    CHECK(h.id == 10);
    CHECK(h.handle.data() == buf.data() + 9);
    CHECK(h.handle.size() == 3);
}

TEST_CASE("SFTP NAME rejects count mismatch and trailing bytes", "[sftp][packets]") {
    const auto too_short = bytes({104, 0, 0, 0, 1, 0, 0, 0, 2});
    sftp::name_reply_view names;
    CHECK_FALSE(sftp::decode_name(too_short, names));

    wire::writer w;
    const sftp::name_entry entries[] = {{"a", "long", {}}};
    sftp::encode_name(w, 1, entries);
    w.write_byte(0);
    CHECK_FALSE(sftp::decode_name(take(w), names));
}

TEST_CASE("SFTP ATTRS and NAME skip well-formed ATTR_EXTENDED pairs", "[sftp][packets]") {
    // ATTRS: type=105, id=5, flags=size|extended, size=0x1122334455667788,
    // extended count=2 with ("k1","v1") ("k2","v2")
    std::vector<std::byte> attrs_body;
    attrs_body.push_back(std::byte{105});
    append_u32(attrs_body, 5);
    append_u32(attrs_body, sftp::attr_flags::size | sftp::attr_flags::extended);
    append_u64(attrs_body, 0x1122334455667788ull);
    append_u32(attrs_body, 2);
    append_str(attrs_body, "k1");
    append_str(attrs_body, "v1");
    append_str(attrs_body, "k2");
    append_str(attrs_body, "v2");

    sftp::attrs_reply ar;
    REQUIRE(sftp::decode_attrs_reply(attrs_body, ar));
    CHECK(ar.id == 5);
    CHECK((ar.attributes.flags & sftp::attr_flags::size) != 0);
    CHECK((ar.attributes.flags & sftp::attr_flags::extended) != 0);
    CHECK(ar.attributes.size == 0x1122334455667788ull);

    // Build NAME manually so the extended pairs are present on the wire.
    std::vector<std::byte> name_body;
    name_body.push_back(std::byte{104});
    append_u32(name_body, 9);
    append_u32(name_body, 1);
    append_str(name_body, "f");
    append_str(name_body, "long");
    append_u32(name_body, sftp::attr_flags::permissions | sftp::attr_flags::extended);
    append_u32(name_body, 0755);
    append_u32(name_body, 1);
    append_str(name_body, "ext");
    append_str(name_body, "data");

    sftp::name_reply_view names;
    REQUIRE(sftp::decode_name(name_body, names));
    REQUIRE(names.entries.size() == 1);
    CHECK(names.entries[0].filename == "f");
    CHECK(names.entries[0].longname == "long");
    CHECK((names.entries[0].attributes.flags & sftp::attr_flags::permissions) != 0);
    CHECK((names.entries[0].attributes.flags & sftp::attr_flags::extended) != 0);
    CHECK(names.entries[0].attributes.permissions == 0755u);
}

TEST_CASE("SFTP malformed handles and attrs extended pairs are rejected safely", "[sftp][packets]") {
    wire::writer w;
    std::vector<std::byte> long_handle(sftp::max_handle_length + 1, std::byte{'x'});
    sftp::encode_handle(w, 4, long_handle);
    sftp::handle_reply h;
    CHECK_FALSE(sftp::decode_handle(take(w), h));

    const auto bad_attrs = bytes({
        105, 0, 0, 0, 5,
        0x80, 0, 0, 0,
        0, 0, 0, 1,
        0, 0, 0, 1, 'x',
    });
    sftp::attrs_reply ar;
    CHECK_FALSE(sftp::decode_attrs_reply(bad_attrs, ar));
}

TEST_CASE("SFTP limits reply matches a hand-built OpenSSH body", "[sftp][packets]") {
    std::vector<std::byte> hand;
    hand.push_back(std::byte{201});
    append_u32(hand, 9);
    append_u64(hand, 262144);
    append_u64(hand, 261120);
    append_u64(hand, 261120);
    append_u64(hand, 128);
    append_u32(hand, 0xdeadbeef);

    sftp::limits_info info;
    std::uint32_t id = 0;
    REQUIRE(sftp::decode_limits_reply(hand, id, info));
    CHECK(id == 9);
    CHECK(info.max_packet_length == 262144);
    CHECK(info.max_read_length == 261120);
    CHECK(info.max_write_length == 261120);
    CHECK(info.max_open_handles == 128);

    hand.resize(hand.size() - 4);
    hand.pop_back();
    CHECK_FALSE(sftp::decode_limits_reply(hand, id, info));
}

TEST_CASE("SFTP users-groups blob truncation is rejected", "[sftp][packets]") {
    const auto truncated = bytes({
        201, 0, 0, 0, 4,
        0, 0, 0, 8,
        1, 2, 3,
    });
    sftp::users_groups_reply_view view;
    CHECK_FALSE(sftp::decode_users_groups_by_id_reply(truncated, 1, 1, view));
}

TEST_CASE("SFTP extension replies decode limits and statvfs with compatible tails", "[sftp][packets]") {
    sftp::limits_info limits{262144, 261120, 261120, 128};
    wire::writer w;
    sftp::encode_limits_reply(w, 12, limits);
    w.write_uint32(0xdeadbeef);
    sftp::limits_info decoded;
    std::uint32_t id = 0;
    REQUIRE(sftp::decode_limits_reply(take(w), id, decoded));
    CHECK(id == 12);
    CHECK(decoded.max_read_length == 261120);

    sftp::statvfs_info sv;
    sv.bsize = 4096;
    sv.namemax = 255;
    w.clear();
    sftp::encode_statvfs_reply(w, 13, sv);
    sftp::statvfs_info got;
    REQUIRE(sftp::decode_statvfs_reply(take(w), id, got));
    CHECK(id == 13);
    CHECK(got.bsize == 4096);
    CHECK(got.namemax == 255);
}

TEST_CASE("SFTP users-groups-by-id enforces reply name counts", "[sftp][packets]") {
    wire::writer w;
    const std::string_view users[] = {"root"};
    const std::string_view groups[] = {"wheel", "staff"};
    sftp::encode_users_groups_by_id_reply(w, 4, users, groups);
    const auto buf = take(w);
    sftp::users_groups_reply_view reply;
    REQUIRE(sftp::decode_users_groups_by_id_reply(buf, 1, 2, reply));
    CHECK(reply.users[0] == "root");
    CHECK(reply.groups[1] == "staff");

    CHECK_FALSE(sftp::decode_users_groups_by_id_reply(buf, 2, 2, reply));
}
