#include <catch2/catch_test_macros.hpp>
#include <yanterm-ssh/channels/types.hpp>
#include <yanterm-ssh/channels/requests.hpp>
#include <yanterm-ssh/wire/types.hpp>

using namespace yanterm::ssh;

TEST_CASE("channel type names match RFC 4254 and OpenSSH", "[channel][types]") {
    REQUIRE(channels::type_name(channels::channel_type::session) == "session");
    REQUIRE(channels::type_name(channels::channel_type::direct_tcpip) == "direct-tcpip");
    REQUIRE(channels::type_name(channels::channel_type::forwarded_tcpip) == "forwarded-tcpip");
    REQUIRE(channels::type_name(channels::channel_type::x11) == "x11");
    REQUIRE(channels::type_name(channels::channel_type::direct_streamlocal)
            == "direct-streamlocal@openssh.com");
    REQUIRE(channels::type_name(channels::channel_type::forwarded_streamlocal)
            == "forwarded-streamlocal@openssh.com");
    REQUIRE(channels::parse_type("session") == channels::channel_type::session);
    REQUIRE(channels::parse_type("forwarded-streamlocal@openssh.com")
            == channels::channel_type::forwarded_streamlocal);
    REQUIRE(channels::parse_type("no-such") == channels::channel_type::unknown);
}

TEST_CASE("pty-req extra encodes term and size", "[channel][types]") {
    channels::pty_spec spec;
    spec.term = "xterm";
    spec.width = 80;
    spec.height = 24;
    wire::writer w;
    channels::encode_pty_req(w, spec);
    std::string_view term;
    channels::window_size ws{};
    std::span<const std::byte> modes;
    REQUIRE(channels::decode_pty_req(w.data(), term, ws, modes));
    REQUIRE(term == "xterm");
    REQUIRE(ws.cols == 80);
    REQUIRE(ws.rows == 24);
}

TEST_CASE("tcpip-forward extra round-trips", "[channel][types]") {
    wire::writer w;
    channels::encode_tcpip_forward(w, "127.0.0.1", 0);
    std::string_view addr;
    std::uint32_t port = 99;
    REQUIRE(channels::decode_tcpip_forward(w.data(), addr, port));
    REQUIRE(addr == "127.0.0.1");
    REQUIRE(port == 0);
}

TEST_CASE("direct-streamlocal extra is path, reserved string, reserved uint32",
          "[channel][types]") {
    wire::writer w;
    channels::encode_streamlocal(w, "/tmp/s.sock");
    // OpenSSH PROTOCOL 2.4: string socket path + string reserved + uint32 reserved.
    wire::reader r{w.data()};
    std::string_view path;
    std::string_view reserved;
    std::uint32_t reserved_u32 = 0xffffffffu;
    REQUIRE(r.read_string(path));
    REQUIRE(path == "/tmp/s.sock");
    REQUIRE(r.read_string(reserved));
    REQUIRE(reserved.empty());
    REQUIRE(r.read_uint32(reserved_u32));
    REQUIRE(reserved_u32 == 0);
    REQUIRE(r.empty());

    std::string_view decoded_path;
    std::string_view decoded_reserved;
    REQUIRE(channels::decode_streamlocal(w.data(), decoded_path, decoded_reserved));
    REQUIRE(decoded_path == "/tmp/s.sock");
    REQUIRE(decoded_reserved.empty());

    wire::writer forwarded;
    forwarded.write_string("/tmp/s.sock");
    forwarded.write_string(std::string_view{});
    std::string_view p2;
    std::string_view r2;
    REQUIRE_FALSE(channels::decode_streamlocal(forwarded.data(), p2, r2));
}

TEST_CASE("x11-req extra round-trips RFC 4254 fields", "[channel][types]") {
    channels::x11_req_spec spec;
    spec.single_connection = true;
    spec.protocol = "MIT-MAGIC-COOKIE-1";
    spec.cookie = "00112233445566778899aabbccddeeff";
    spec.screen = 1;
    wire::writer w;
    channels::encode_x11_req(w, spec);

    bool single = false;
    std::string_view protocol;
    std::string_view cookie;
    std::uint32_t screen = 0;
    REQUIRE(channels::decode_x11_req(w.data(), single, protocol, cookie, screen));
    REQUIRE(single);
    REQUIRE(protocol == "MIT-MAGIC-COOKIE-1");
    REQUIRE(cookie == spec.cookie);
    REQUIRE(screen == 1);

    REQUIRE_FALSE(channels::decode_x11_req({}, single, protocol, cookie, screen));
}

TEST_CASE("streamlocal-forward extra is a socket path", "[channel][types]") {
    wire::writer w;
    channels::encode_streamlocal_forward(w, "/tmp/agent.sock");
    std::string_view path;
    REQUIRE(channels::decode_streamlocal_forward(w.data(), path));
    REQUIRE(path == "/tmp/agent.sock");

    wire::writer trailing;
    channels::encode_streamlocal_forward(trailing, "/tmp/agent.sock");
    trailing.write_uint32(1);
    std::string_view p2;
    REQUIRE_FALSE(channels::decode_streamlocal_forward(trailing.data(), p2));
}

TEST_CASE("forwarded-streamlocal extra is path plus reserved string",
          "[channel][types]") {
    wire::writer w;
    channels::encode_forwarded_streamlocal(w, "/tmp/fwd.sock");
    std::string_view path;
    std::string_view reserved;
    REQUIRE(channels::decode_forwarded_streamlocal(w.data(), path, reserved));
    REQUIRE(path == "/tmp/fwd.sock");
    REQUIRE(reserved.empty());

    // direct-streamlocal carries an extra reserved uint32; forwarded does not.
    wire::writer direct;
    channels::encode_streamlocal(direct, "/tmp/fwd.sock");
    std::string_view p2;
    std::string_view r2;
    REQUIRE_FALSE(channels::decode_forwarded_streamlocal(direct.data(), p2, r2));
}
