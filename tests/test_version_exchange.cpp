#include <catch2/catch_test_macros.hpp>

#include "hex_util.hpp"

#include <yanterm-ssh/core/detail/version_exchange.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/version.hpp>

#include <string>
#include <system_error>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

using core::role;
using core::detail::version_exchange;

namespace {

std::string sent(const version_exchange& vx) {
    const auto s = vx.outgoing();
    return std::string{reinterpret_cast<const char*>(s.data()), s.size()};
}

std::string fallback_identification() {
    return std::string("SSH-2.0-").append(default_software());
}

}  // namespace

TEST_CASE("local identification is well formed", "[version]") {
    version_exchange vx{role::client, "yanterm_ssh_0.1.0"};
    REQUIRE(sent(vx) == "SSH-2.0-yanterm_ssh_0.1.0\r\n");
    REQUIRE(vx.local_identification() == "SSH-2.0-yanterm_ssh_0.1.0");
}

TEST_CASE("software strings with a space or minus are replaced", "[version]") {
    for (std::string_view bad : {"has space", "has-minus", "tab\there"}) {
        version_exchange vx{role::client, bad};
        INFO("software: " << bad);
        REQUIRE(vx.local_identification() == fallback_identification());
    }
}

TEST_CASE("software that would overflow the 255-byte identification line is replaced",
          "[version]") {
    const std::string too_long(300, 'x');
    version_exchange vx{role::client, too_long};
    REQUIRE(vx.local_identification() == fallback_identification());
    REQUIRE(sent(vx).size() <= core::detail::max_identification_line);
}

TEST_CASE("peer identification is parsed without the line ending", "[version]") {
    version_exchange vx{role::client, "test"};
    std::size_t n = 0;
    const std::string in = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n";
    const std::error_code ec = vx.feed(bytes_of(in), n);
    REQUIRE_FALSE(ec);
    REQUIRE(n == in.size());
    REQUIRE(vx.done());
    REQUIRE(vx.peer_identification() == "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5");
}

TEST_CASE("a bare LF terminator is accepted", "[version]") {
    version_exchange vx{role::client, "test"};
    std::size_t accepted = 0;
    const std::error_code ec = vx.feed(bytes_of("SSH-2.0-Dropbear_2022.83\n"), accepted);
    REQUIRE_FALSE(ec);
    REQUIRE(vx.done());
    REQUIRE(vx.peer_identification() == "SSH-2.0-Dropbear_2022.83");
}

TEST_CASE("SSH-1.99 is accepted, other 1.x is not", "[version]") {
    SECTION("1.99 means 2.0 compatible") {
        version_exchange vx{role::client, "test"};
        std::size_t accepted = 0;
        const std::error_code ec = vx.feed(bytes_of("SSH-1.99-OldServer\r\n"), accepted);
        REQUIRE_FALSE(ec);
        REQUIRE(vx.done());
    }
    SECTION("1.5 is rejected") {
        version_exchange vx{role::client, "test"};
        std::size_t accepted = 0;
        const std::error_code ec = vx.feed(bytes_of("SSH-1.5-OldServer\r\n"), accepted);
        REQUIRE(ec == code::unsupported_protocol_version);
    }
}

TEST_CASE("a client tolerates server preamble lines", "[version]") {
    version_exchange vx{role::client, "test"};
    std::size_t n = 0;
    const std::string in = "This server is monitored.\r\n"
                           "Authorised users only.\r\n"
                           "SSH-2.0-OpenSSH_9.6p1\r\n";
    const std::error_code ec = vx.feed(bytes_of(in), n);
    REQUIRE_FALSE(ec);
    REQUIRE(n == in.size());
    REQUIRE(vx.done());
    REQUIRE(vx.peer_identification() == "SSH-2.0-OpenSSH_9.6p1");
}

TEST_CASE("a server rejects client preamble lines", "[version]") {
    version_exchange vx{role::server, "test"};
    std::size_t accepted = 0;
    const std::error_code ec =
        vx.feed(bytes_of("unexpected chatter\r\nSSH-2.0-OpenSSH_9.6p1\r\n"), accepted);
    REQUIRE(ec == code::missing_version_banner);
}

TEST_CASE("feed tolerates arbitrary fragmentation", "[version]") {
    const std::string in = "SSH-2.0-OpenSSH_9.6p1\r\n";
    for (std::size_t split = 1; split < in.size(); ++split) {
        version_exchange vx{role::client, "test"};
        std::size_t accepted = 0;
        INFO("split at " << split);
        const std::error_code ec1 = vx.feed(bytes_of(std::string_view{in}.substr(0, split)), accepted);
        REQUIRE_FALSE(ec1);
        if (!vx.done()) {
            REQUIRE(accepted == 0);
            std::size_t accepted2 = 0;
            const std::error_code ec2 = vx.feed(bytes_of(in), accepted2);
            REQUIRE_FALSE(ec2);
            REQUIRE(accepted2 == in.size());
        }
        REQUIRE(vx.done());
        REQUIRE(vx.peer_identification() == "SSH-2.0-OpenSSH_9.6p1");
    }
}

TEST_CASE("feed stops consuming once done so binary packets are not eaten", "[version]") {
    version_exchange vx{role::client, "test"};
    std::size_t n = 0;
    const std::string in = "SSH-2.0-OpenSSH_9.6p1\r\n\x00\x00\x01\x2c";
    const std::error_code ec = vx.feed({reinterpret_cast<const std::byte*>(in.data()), in.size()}, n);
    REQUIRE_FALSE(ec);
    REQUIRE(vx.done());
    REQUIRE(n == 23);  // exactly the identification line, CR LF included
}

TEST_CASE("an over-long line is rejected", "[version]") {
    version_exchange vx{role::client, "test"};
    std::size_t accepted = 0;
    std::string in = "SSH-2.0-";
    in.append(300, 'x');
    in += "\r\n";
    const std::error_code ec = vx.feed(bytes_of(in), accepted);
    REQUIRE(ec == code::version_line_too_long);
}

TEST_CASE("an over-long preamble line is rejected", "[version]") {
    version_exchange vx{role::client, "test"};
    std::size_t accepted = 0;
    std::string in(300, 'x');
    in += "\r\nSSH-2.0-OpenSSH_9.6p1\r\n";
    const std::error_code ec = vx.feed(bytes_of(in), accepted);
    REQUIRE(ec == code::version_line_too_long);
}

TEST_CASE("a non-SSH first line from a server is a protocol error", "[version]") {
    version_exchange vx{role::server, "test"};
    std::size_t accepted = 0;
    const std::error_code ec = vx.feed(bytes_of("GET / HTTP/1.1\r\n"), accepted);
    REQUIRE(ec == code::missing_version_banner);
}

// 修正E: 255 上限含结束符；253+CRLF 与 254+LF 合法，多一字节则非法。
TEST_CASE("identification line length boundary is inclusive of terminator", "[version]") {
    SECTION("253 content bytes plus CRLF is accepted") {
        version_exchange vx{role::client, "test"};
        std::size_t n = 0;
        std::string in = "SSH-2.0-";
        in.append(253 - in.size(), 'x');
        REQUIRE(in.size() == 253);
        in += "\r\n";
        REQUIRE(in.size() == 255);
        const std::error_code ec = vx.feed(bytes_of(in), n);
        REQUIRE_FALSE(ec);
        REQUIRE(n == in.size());
        REQUIRE(vx.done());
        REQUIRE(vx.peer_identification().size() == 253);
    }
    SECTION("254 content bytes plus bare LF is accepted") {
        version_exchange vx{role::client, "test"};
        std::size_t n = 0;
        std::string in = "SSH-2.0-";
        in.append(254 - in.size(), 'x');
        REQUIRE(in.size() == 254);
        in += '\n';
        REQUIRE(in.size() == 255);
        const std::error_code ec = vx.feed(bytes_of(in), n);
        REQUIRE_FALSE(ec);
        REQUIRE(n == in.size());
        REQUIRE(vx.done());
        REQUIRE(vx.peer_identification().size() == 254);
    }
    SECTION("254 content bytes plus CRLF is rejected") {
        version_exchange vx{role::client, "test"};
        std::size_t accepted = 0;
        std::string in = "SSH-2.0-";
        in.append(254 - in.size(), 'x');
        in += "\r\n";
        REQUIRE(in.size() == 256);
        const std::error_code ec = vx.feed(bytes_of(in), accepted);
        REQUIRE(ec == code::version_line_too_long);
        REQUIRE_FALSE(vx.done());
    }
    SECTION("255 content bytes plus bare LF is rejected") {
        version_exchange vx{role::client, "test"};
        std::size_t accepted = 0;
        std::string in = "SSH-2.0-";
        in.append(255 - in.size(), 'x');
        in += '\n';
        REQUIRE(in.size() == 256);
        const std::error_code ec = vx.feed(bytes_of(in), accepted);
        REQUIRE(ec == code::version_line_too_long);
        REQUIRE_FALSE(vx.done());
    }
}

TEST_CASE("a line without a terminator is not consumed", "[version]") {
    version_exchange vx{role::client, "yanterm_test"};
    std::size_t accepted = 0;
    const auto ec = vx.feed(bytes_of("SSH-2.0-OpenSSH_9.6"), accepted);
    REQUIRE_FALSE(ec);
    REQUIRE(accepted == 0);
    REQUIRE_FALSE(vx.done());
}

TEST_CASE("the caller re-presents the prefix until the line completes", "[version]") {
    version_exchange vx{role::client, "yanterm_test"};
    const std::string_view full = "SSH-2.0-OpenSSH_9.6p1\r\n";

    for (std::size_t split = 1; split < full.size(); ++split) {
        version_exchange one{role::client, "yanterm_test"};
        std::size_t accepted = 0;
        REQUIRE_FALSE(one.feed(bytes_of(full.substr(0, split)), accepted));
        REQUIRE(accepted == 0);            // no '\n' yet in any prefix but the last
        REQUIRE_FALSE(one.done());
    }

    std::size_t accepted = 0;
    REQUIRE_FALSE(vx.feed(bytes_of(full), accepted));
    REQUIRE(accepted == full.size());
    REQUIRE(vx.done());
    REQUIRE(vx.peer_identification() == "SSH-2.0-OpenSSH_9.6p1");
}

TEST_CASE("preamble lines are consumed line by line", "[version]") {
    version_exchange vx{role::client, "yanterm_test"};
    const std::string_view in = "hello\r\nSSH-2.0-Server\r\n";
    std::size_t accepted = 0;
    REQUIRE_FALSE(vx.feed(bytes_of(in), accepted));
    REQUIRE(accepted == in.size());
    REQUIRE(vx.done());
    REQUIRE(vx.peer_identification() == "SSH-2.0-Server");
}

TEST_CASE("bytes after the identification line are left to the caller", "[version]") {
    version_exchange vx{role::client, "yanterm_test"};
    const std::string_view in = "SSH-2.0-Server\r\nTRAILING";
    std::size_t accepted = 0;
    REQUIRE_FALSE(vx.feed(bytes_of(in), accepted));
    REQUIRE(vx.done());
    REQUIRE(accepted == std::string_view{"SSH-2.0-Server\r\n"}.size());
}

TEST_CASE("an over-long unterminated prefix is rejected without consuming", "[version]") {
    version_exchange vx{role::client, "yanterm_test"};
    std::string long_line(core::detail::max_identification_line + 1, 'x');
    std::size_t accepted = 0;
    const auto ec = vx.feed(bytes_of(long_line), accepted);
    REQUIRE(ec == code::version_line_too_long);
    REQUIRE(accepted == 0);
}
