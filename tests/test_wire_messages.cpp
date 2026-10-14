#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/wire/message_ids.hpp>
#include <yanterm-ssh/wire/detail/messages.hpp>
#include <yanterm-ssh/detail/error.hpp>

#include <array>
#include <cstddef>
#include <memory_resource>
#include <string_view>
#include <vector>

using namespace yanterm::ssh;

namespace {

std::span<const std::byte> as_bytes(std::string_view s) {
    return {reinterpret_cast<const std::byte*>(s.data()), s.size()};
}

}  // namespace

TEST_CASE("message ids match RFC 4253 and RFC 8308", "[wire][msg]") {
    REQUIRE(static_cast<int>(wire::msg::disconnect) == 1);
    REQUIRE(static_cast<int>(wire::msg::ignore) == 2);
    REQUIRE(static_cast<int>(wire::msg::unimplemented) == 3);
    REQUIRE(static_cast<int>(wire::msg::debug) == 4);
    REQUIRE(static_cast<int>(wire::msg::service_request) == 5);
    REQUIRE(static_cast<int>(wire::msg::service_accept) == 6);
    REQUIRE(static_cast<int>(wire::msg::ext_info) == 7);
    REQUIRE(static_cast<int>(wire::msg::kexinit) == 20);
    REQUIRE(static_cast<int>(wire::msg::newkeys) == 21);
    REQUIRE(static_cast<int>(wire::msg::kexdh_init) == 30);
    REQUIRE(static_cast<int>(wire::msg::kexdh_reply) == 31);
    REQUIRE(static_cast<int>(wire::msg::kex_ecdh_init) == 30);
    REQUIRE(static_cast<int>(wire::msg::kex_ecdh_reply) == 31);
}

TEST_CASE("kexinit round-trips", "[wire][msg]") {

    const std::array<std::string_view, 2> kex{"curve25519-sha256", "ext-info-c"};
    const std::array<std::string_view, 1> hostkey{"ssh-ed25519"};
    const std::array<std::string_view, 1> cipher{"chacha20-poly1305@openssh.com"};
    const std::array<std::string_view, 1> mac{"hmac-sha2-256-etm@openssh.com"};
    const std::array<std::string_view, 1> comp{"none"};
    const std::array<std::string_view, 0> langs{};

    wire::detail::kexinit out;
    for (std::size_t i = 0; i < out.cookie.size(); ++i) {
        out.cookie[i] = static_cast<std::byte>(i);
    }
    out.out_kex_algorithms = kex;
    out.out_server_host_key_algorithms = hostkey;
    out.out_encryption_c2s = cipher;
    out.out_encryption_s2c = cipher;
    out.out_mac_c2s = mac;
    out.out_mac_s2c = mac;
    out.out_compression_c2s = comp;
    out.out_compression_s2c = comp;
    out.out_languages_c2s = langs;
    out.out_languages_s2c = langs;
    out.first_kex_packet_follows = true;

    wire::writer w;
    out.encode(w);

    // The payload must start with the message id and the 16-byte cookie.
    REQUIRE(w.data()[0] == static_cast<std::byte>(wire::msg::kexinit));
    REQUIRE(w.size() > 17);

    wire::reader r{w.data()};
    wire::detail::kexinit in;
    REQUIRE(in.decode(r));
    REQUIRE(r.empty());

    REQUIRE(in.cookie == out.cookie);
    REQUIRE(in.kex_algorithms.raw() == "curve25519-sha256,ext-info-c");
    REQUIRE(in.kex_algorithms.contains("ext-info-c"));
    REQUIRE(in.server_host_key_algorithms.raw() == "ssh-ed25519");
    REQUIRE(in.encryption_c2s.raw() == "chacha20-poly1305@openssh.com");
    REQUIRE(in.mac_s2c.raw() == "hmac-sha2-256-etm@openssh.com");
    REQUIRE(in.compression_c2s.raw() == "none");
    REQUIRE(in.languages_c2s.raw().empty());
    REQUIRE(in.first_kex_packet_follows);
    REQUIRE(in.reserved == 0u);
}

TEST_CASE("kexinit decode rejects a wrong message id", "[wire][msg]") {
    wire::writer w;
    w.write_byte(static_cast<std::uint8_t>(wire::msg::newkeys));
    wire::reader r{w.data()};
    wire::detail::kexinit in;
    REQUIRE_FALSE(in.decode(r));
    REQUIRE_FALSE(r.ok());
    REQUIRE(r.error() == code::invalid_format);
}

TEST_CASE("disconnect round-trips and exposes the reason", "[wire][msg]") {
    wire::detail::disconnect_msg out;
    out.reason = wire::disconnect_reason::key_exchange_failed;
    out.description = "no matching key exchange method";
    out.language = "";

    wire::writer w;
    out.encode(w);

    wire::reader r{w.data()};
    wire::detail::disconnect_msg in;
    REQUIRE(in.decode(r));
    REQUIRE(r.empty());
    REQUIRE(in.reason == wire::disconnect_reason::key_exchange_failed);
    REQUIRE(static_cast<std::uint32_t>(in.reason) == 3u);
    REQUIRE(in.description == "no matching key exchange method");
    REQUIRE(in.language.empty());
}

TEST_CASE("debug, ignore and unimplemented round-trip", "[wire][msg]") {

    SECTION("debug") {
        wire::detail::debug_msg out{true, "hello", "en"};
        wire::writer w;
        out.encode(w);
        wire::reader r{w.data()};
        wire::detail::debug_msg in;
        REQUIRE(in.decode(r));
        REQUIRE(in.always_display);
        REQUIRE(in.message == "hello");
        REQUIRE(in.language == "en");
    }
    SECTION("ignore") {
        wire::detail::ignore_msg out;
        out.data = as_bytes("padding");
        wire::writer w;
        out.encode(w);
        wire::reader r{w.data()};
        wire::detail::ignore_msg in;
        REQUIRE(in.decode(r));
        REQUIRE(in.data.size() == 7);
    }
    SECTION("unimplemented") {
        wire::detail::unimplemented_msg out{0x01020304u};
        wire::writer w;
        out.encode(w);
        wire::reader r{w.data()};
        wire::detail::unimplemented_msg in;
        REQUIRE(in.decode(r));
        REQUIRE(in.sequence_number == 0x01020304u);
    }
}

TEST_CASE("service request and accept round-trip", "[wire][msg]") {
    wire::detail::service_msg out{wire::msg::service_request, "ssh-userauth"};
    wire::writer w;
    out.encode(w);

    wire::reader r{w.data()};
    wire::detail::service_msg in{wire::msg::service_request, {}};
    REQUIRE(in.decode(r));
    REQUIRE(in.service_name == "ssh-userauth");

    // Decoding the same bytes as a service_accept must fail on the id check.
    wire::reader r2{w.data()};
    wire::detail::service_msg wrong{wire::msg::service_accept, {}};
    REQUIRE_FALSE(wrong.decode(r2));
    REQUIRE_FALSE(r2.ok());
    REQUIRE(r2.error() == code::invalid_format);
}

TEST_CASE("ext_info round-trips and finds server-sig-algs", "[wire][msg]") {
    const std::array<wire::detail::ext_info::entry, 2> entries{
        wire::detail::ext_info::entry{"server-sig-algs", as_bytes("ssh-ed25519,rsa-sha2-256")},
        wire::detail::ext_info::entry{"delay-compression", as_bytes("")},
    };
    wire::detail::ext_info out;
    out.entries = entries;

    wire::writer w;
    out.encode(w);

    wire::reader r{w.data()};
    wire::detail::ext_info in;
    REQUIRE(in.decode(r));
    REQUIRE(r.empty());
    REQUIRE(in.count == 2u);

    std::string_view sig_algs;
    REQUIRE(in.find("server-sig-algs", sig_algs));
    REQUIRE(sig_algs == "ssh-ed25519,rsa-sha2-256");
    REQUIRE_FALSE(in.find("no-such-extension", sig_algs));
}

TEST_CASE("ecdh kex messages round-trip", "[wire][msg][kex]") {

    SECTION("init") {
        wire::detail::kex_ecdh_init out;
        out.client_public = as_bytes("0123456789abcdef0123456789abcdef");
        wire::writer w;
        out.encode(w);
        wire::reader r{w.data()};
        wire::detail::kex_ecdh_init in;
        REQUIRE(in.decode(r));
        REQUIRE(in.client_public.size() == 32);
    }
    SECTION("reply") {
        wire::detail::kex_ecdh_reply out;
        out.host_key = as_bytes("HOSTKEYBLOB");
        out.server_public = as_bytes("0123456789abcdef0123456789abcdef");
        out.signature = as_bytes("SIGBLOB");
        wire::writer w;
        out.encode(w);
        wire::reader r{w.data()};
        wire::detail::kex_ecdh_reply in;
        REQUIRE(in.decode(r));
        REQUIRE(r.empty());
        REQUIRE(in.host_key.size() == 11);
        REQUIRE(in.server_public.size() == 32);
        REQUIRE(in.signature.size() == 7);
    }
}

TEST_CASE("finite field dh kex messages round-trip", "[wire][msg][kex]") {
    const std::array<std::byte, 2> e_mag{std::byte{0x80}, std::byte{0x01}};

    SECTION("init") {
        wire::detail::kexdh_init out;
        out.e = e_mag;
        wire::writer w;
        out.encode(w);
        wire::reader r{w.data()};
        wire::detail::kexdh_init in;
        REQUIRE(in.decode(r));
        REQUIRE(in.e.size() == 2);
        REQUIRE(in.e[0] == std::byte{0x80});
    }
    SECTION("reply") {
        wire::detail::kexdh_reply out;
        out.host_key = as_bytes("HOSTKEYBLOB");
        out.f = e_mag;
        out.signature = as_bytes("SIGBLOB");
        wire::writer w;
        out.encode(w);
        wire::reader r{w.data()};
        wire::detail::kexdh_reply in;
        REQUIRE(in.decode(r));
        REQUIRE(r.empty());
        REQUIRE(in.f.size() == 2);
    }
}

TEST_CASE("userauth message ids match RFC 4252 and 4256", "[wire][msg][auth]") {
    REQUIRE(static_cast<int>(wire::msg::userauth_request) == 50);
    REQUIRE(static_cast<int>(wire::msg::userauth_failure) == 51);
    REQUIRE(static_cast<int>(wire::msg::userauth_success) == 52);
    REQUIRE(static_cast<int>(wire::msg::userauth_banner) == 53);
    REQUIRE(static_cast<int>(wire::msg::userauth_pk_ok) == 60);
    REQUIRE(static_cast<int>(wire::msg::userauth_passwd_changereq) == 60);
    REQUIRE(static_cast<int>(wire::msg::userauth_info_request) == 60);
    REQUIRE(static_cast<int>(wire::msg::userauth_info_response) == 61);
}

TEST_CASE("userauth_failure round-trips", "[wire][msg][auth]") {
    const std::array<std::string_view, 2> methods{"publickey", "password"};
    wire::detail::userauth_failure out;
    out.out_methods = methods;
    out.partial_success = true;
    wire::writer w;
    out.encode(w);
    REQUIRE(w.data()[0] == static_cast<std::byte>(wire::msg::userauth_failure));

    wire::reader r{w.data()};
    wire::detail::userauth_failure in;
    REQUIRE(in.decode(r));
    REQUIRE(r.empty());
    REQUIRE(in.methods.raw() == "publickey,password");
    REQUIRE(in.partial_success);
}

TEST_CASE("userauth_publickey request with signature round-trips", "[wire][msg][auth]") {
    const std::array<std::byte, 4> blob{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    const std::array<std::byte, 2> sig{std::byte{9}, std::byte{8}};
    wire::detail::userauth_request_publickey out;
    out.user = "alice";
    out.service = "ssh-connection";
    out.has_signature = true;
    out.algorithm = "ssh-ed25519";
    out.blob = blob;
    out.signature = sig;
    wire::writer w;
    out.encode(w);

    wire::reader r{w.data()};
    wire::detail::userauth_request_publickey in;
    REQUIRE(in.decode(r));
    REQUIRE(r.empty());
    REQUIRE(in.user == "alice");
    REQUIRE(in.service == "ssh-connection");
    REQUIRE(in.has_signature);
    REQUIRE(in.algorithm == "ssh-ed25519");
    REQUIRE(in.blob.size() == 4);
    REQUIRE(in.signature.size() == 2);
}

TEST_CASE("userauth_info_request round-trips two prompts", "[wire][msg][auth]") {
    const std::array<wire::detail::userauth_info_prompt, 2> prompts{{
        {"Password:", false},
        {"Token:", true},
    }};
    wire::detail::userauth_info_request out;
    out.name = "n";
    out.instruction = "i";
    out.language = "en";
    out.prompts = prompts;
    wire::writer w;
    out.encode(w);

    wire::reader r{w.data()};
    wire::detail::userauth_info_request in;
    REQUIRE(in.decode(r));
    REQUIRE(r.empty());
    REQUIRE(in.name == "n");
    REQUIRE(in.num_prompts == 2);
    std::string_view p0, p1;
    bool e0 = true, e1 = false;
    REQUIRE(in.prompt_at(0, p0, e0));
    REQUIRE(in.prompt_at(1, p1, e1));
    REQUIRE(p0 == "Password:");
    REQUIRE_FALSE(e0);
    REQUIRE(p1 == "Token:");
    REQUIRE(e1);
}

TEST_CASE("connection message ids match RFC 4254", "[wire][msg][channel]") {
    REQUIRE(static_cast<int>(wire::msg::global_request) == 80);
    REQUIRE(static_cast<int>(wire::msg::request_success) == 81);
    REQUIRE(static_cast<int>(wire::msg::request_failure) == 82);
    REQUIRE(static_cast<int>(wire::msg::channel_open) == 90);
    REQUIRE(static_cast<int>(wire::msg::channel_open_confirmation) == 91);
    REQUIRE(static_cast<int>(wire::msg::channel_open_failure) == 92);
    REQUIRE(static_cast<int>(wire::msg::channel_window_adjust) == 93);
    REQUIRE(static_cast<int>(wire::msg::channel_data) == 94);
    REQUIRE(static_cast<int>(wire::msg::channel_extended_data) == 95);
    REQUIRE(static_cast<int>(wire::msg::channel_eof) == 96);
    REQUIRE(static_cast<int>(wire::msg::channel_close) == 97);
    REQUIRE(static_cast<int>(wire::msg::channel_request) == 98);
    REQUIRE(static_cast<int>(wire::msg::channel_success) == 99);
    REQUIRE(static_cast<int>(wire::msg::channel_failure) == 100);
}

TEST_CASE("channel_open session round-trips", "[wire][msg][channel]") {
    wire::detail::channel_open out;
    out.type = "session";
    out.sender = 7;
    out.window = 1024;
    out.max_packet = 32768;
    wire::writer w;
    out.encode(w);
    REQUIRE(w.data()[0] == static_cast<std::byte>(wire::msg::channel_open));

    wire::reader r{w.data()};
    wire::detail::channel_open in;
    REQUIRE(in.decode(r));
    REQUIRE(r.empty());
    REQUIRE(in.type == "session");
    REQUIRE(in.sender == 7);
    REQUIRE(in.window == 1024);
    REQUIRE(in.max_packet == 32768);
    REQUIRE(in.extra.empty());
}

TEST_CASE("channel_data round-trips", "[wire][msg][channel]") {
    const std::array<std::byte, 3> payload{std::byte{'a'}, std::byte{'b'}, std::byte{'c'}};
    wire::detail::channel_data out;
    out.recipient = 3;
    out.data = payload;
    wire::writer w;
    out.encode(w);

    wire::reader r{w.data()};
    wire::detail::channel_data in;
    REQUIRE(in.decode(r));
    REQUIRE(r.empty());
    REQUIRE(in.recipient == 3);
    REQUIRE(in.data.size() == 3);
    REQUIRE(in.data[0] == std::byte{'a'});
}

TEST_CASE("channel_open_failure round-trips", "[wire][msg][channel]") {
    wire::detail::channel_open_failure out;
    out.recipient = 1;
    out.reason = 3;
    out.description = "nope";
    out.language = "en";
    wire::writer w;
    out.encode(w);

    wire::reader r{w.data()};
    wire::detail::channel_open_failure in;
    REQUIRE(in.decode(r));
    REQUIRE(r.empty());
    REQUIRE(in.recipient == 1);
    REQUIRE(in.reason == 3);
    REQUIRE(in.description == "nope");
}

TEST_CASE("global_request round-trips", "[wire][msg][channel]") {
    wire::detail::global_request out;
    out.type = "tcpip-forward";
    out.want_reply = true;
    const std::array<std::byte, 2> extra{std::byte{0}, std::byte{1}};
    out.extra = extra;
    wire::writer w;
    out.encode(w);

    wire::reader r{w.data()};
    wire::detail::global_request in;
    REQUIRE(in.decode(r));
    REQUIRE(r.empty());
    REQUIRE(in.type == "tcpip-forward");
    REQUIRE(in.want_reply);
    REQUIRE(in.extra.size() == 2);
}

TEST_CASE("channel_open_confirmation round-trips", "[wire][msg][channel]") {
    wire::detail::channel_open_confirmation out;
    out.recipient = 1;
    out.sender = 2;
    out.window = 4096;
    out.max_packet = 32768;
    wire::writer w;
    out.encode(w);
    wire::reader r{w.data()};
    wire::detail::channel_open_confirmation in;
    REQUIRE(in.decode(r));
    REQUIRE(r.empty());
    REQUIRE(in.recipient == 1);
    REQUIRE(in.sender == 2);
    REQUIRE(in.window == 4096);
    REQUIRE(in.max_packet == 32768);
}

TEST_CASE("channel_window_adjust round-trips", "[wire][msg][channel]") {
    wire::detail::channel_window_adjust out;
    out.recipient = 4;
    out.bytes = 128;
    wire::writer w;
    out.encode(w);
    wire::reader r{w.data()};
    wire::detail::channel_window_adjust in;
    REQUIRE(in.decode(r));
    REQUIRE(r.empty());
    REQUIRE(in.recipient == 4);
    REQUIRE(in.bytes == 128);
}

TEST_CASE("channel_extended_data round-trips", "[wire][msg][channel]") {
    const std::array<std::byte, 2> payload{std::byte{'e'}, std::byte{'r'}};
    wire::detail::channel_extended_data out;
    out.recipient = 1;
    out.data_type = 1;
    out.data = payload;
    wire::writer w;
    out.encode(w);
    wire::reader r{w.data()};
    wire::detail::channel_extended_data in;
    REQUIRE(in.decode(r));
    REQUIRE(r.empty());
    REQUIRE(in.recipient == 1);
    REQUIRE(in.data_type == 1);
    REQUIRE(in.data.size() == 2);
}

TEST_CASE("channel_eof and close round-trip", "[wire][msg][channel]") {
    wire::detail::channel_eof_msg eof_out;
    eof_out.recipient = 5;
    wire::writer w;
    eof_out.encode(w);
    wire::reader r{w.data()};
    wire::detail::channel_eof_msg eof_in;
    REQUIRE(eof_in.decode(r));
    REQUIRE(r.empty());
    REQUIRE(eof_in.recipient == 5);

    wire::detail::channel_close_msg cl_out;
    cl_out.recipient = 5;
    w.clear();
    cl_out.encode(w);
    wire::reader r2{w.data()};
    wire::detail::channel_close_msg cl_in;
    REQUIRE(cl_in.decode(r2));
    REQUIRE(r2.empty());
    REQUIRE(cl_in.recipient == 5);
}

TEST_CASE("channel_request round-trips extra", "[wire][msg][channel]") {
    const std::array<std::byte, 1> extra{std::byte{7}};
    wire::detail::channel_request out;
    out.recipient = 2;
    out.type = "pty-req";
    out.want_reply = true;
    out.extra = extra;
    wire::writer w;
    out.encode(w);
    wire::reader r{w.data()};
    wire::detail::channel_request in;
    REQUIRE(in.decode(r));
    REQUIRE(r.empty());
    REQUIRE(in.recipient == 2);
    REQUIRE(in.type == "pty-req");
    REQUIRE(in.want_reply);
    REQUIRE(in.extra.size() == 1);
}

TEST_CASE("channel_success and failure round-trip", "[wire][msg][channel]") {
    wire::detail::channel_success_msg ok;
    ok.recipient = 3;
    wire::writer w;
    ok.encode(w);
    wire::reader r{w.data()};
    wire::detail::channel_success_msg ok_in;
    REQUIRE(ok_in.decode(r));
    REQUIRE(ok_in.recipient == 3);

    wire::detail::channel_failure_msg bad;
    bad.recipient = 3;
    w.clear();
    bad.encode(w);
    wire::reader r2{w.data()};
    wire::detail::channel_failure_msg bad_in;
    REQUIRE(bad_in.decode(r2));
    REQUIRE(bad_in.recipient == 3);
}

TEST_CASE("request_success carries optional extra", "[wire][msg][channel]") {
    wire::detail::request_success empty;
    wire::writer w;
    empty.encode(w);
    wire::reader r{w.data()};
    wire::detail::request_success in;
    REQUIRE(in.decode(r));
    REQUIRE(r.empty());
    REQUIRE(in.extra.empty());

    std::uint32_t port = 0x01020304;
    std::array<std::byte, 4> be{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    (void)port;
    wire::detail::request_success with_port;
    with_port.extra = be;
    w.clear();
    with_port.encode(w);
    wire::reader r2{w.data()};
    wire::detail::request_success in2;
    REQUIRE(in2.decode(r2));
    REQUIRE(r2.empty());
    REQUIRE(in2.extra.size() == 4);
    REQUIRE(in2.extra[3] == std::byte{4});
}
