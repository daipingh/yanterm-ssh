#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <string_view>

#include "memory_pipe.hpp"
#include "test_loop.hpp"

#include <auv/error.hpp>
#include <auv/stream.hpp>
#include <corral/corral.h>

using namespace yanterm::ssh::testing;

TEST_CASE("memory pipe echoes through corral::run", "[facade][pipe]") {
    TestLoop loop;
    auto [a, b] = memory_pipe::make(loop);
    auv::stream sa = auv::stream::own(std::move(a));
    auv::stream sb = auv::stream::own(std::move(b));

    corral::run(loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start([&](corral::TaskStarted<> started) -> corral::Task<void> {
                started();
                char buf[8];
                auto [ec, nread] = co_await sb.read([&] { return auv::buffer(buf, sizeof(buf)); });
                REQUIRE_FALSE(ec);
                REQUIRE(nread == 4);
                REQUIRE(std::memcmp(buf, "ping", 4) == 0);
                co_return;
            });
            const auto write_ec = co_await sa.write(std::string_view{"ping"});
            REQUIRE_FALSE(write_ec);
            co_return corral::join;
        };
    }());
}

TEST_CASE("shutdown then local write returns connection_shutdown", "[facade][pipe]") {
    TestLoop loop;
    auto [a, b] = memory_pipe::make(loop);
    auv::stream sa = auv::stream::own(std::move(a));
    auv::stream sb = auv::stream::own(std::move(b));
    (void)sb;

    corral::run(loop, [&]() -> corral::Task<void> {
        const auto sec = co_await sa.shutdown();
        REQUIRE_FALSE(sec);
        const auto wec = co_await sa.write(std::string_view{"x"});
        REQUIRE(wec == std::errc::not_connected);
    }());
}

TEST_CASE("shutdown then peer drains queued bytes then EOF; reverse still works",
          "[facade][pipe]") {
    TestLoop loop;
    auto [a, b] = memory_pipe::make(loop);
    auv::stream sa = auv::stream::own(std::move(a));
    auv::stream sb = auv::stream::own(std::move(b));

    corral::run(loop, [&]() -> corral::Task<void> {
        const auto wec1 = co_await sa.write(std::string_view{"ab"});
        REQUIRE_FALSE(wec1);
        const auto sec = co_await sa.shutdown();
        REQUIRE_FALSE(sec);

        char buf[8];
        auto [ec1, n1] = co_await sb.read([&] { return auv::buffer(buf, sizeof(buf)); });
        REQUIRE_FALSE(ec1);
        REQUIRE(n1 == 2);
        REQUIRE(std::memcmp(buf, "ab", 2) == 0);

        auto [ec2, n2] = co_await sb.read([&] { return auv::buffer(buf, sizeof(buf)); });
        REQUIRE(ec2 == auv::errc::eof);
        REQUIRE(n2 == 0);

        const auto wec2 = co_await sb.write(std::string_view{"xy"});
        REQUIRE_FALSE(wec2);
        auto [ec3, n3] = co_await sa.read([&] { return auv::buffer(buf, sizeof(buf)); });
        REQUIRE_FALSE(ec3);
        REQUIRE(n3 == 2);
        REQUIRE(std::memcmp(buf, "xy", 2) == 0);
    }());
}

TEST_CASE("destroying one end yields EOF on the peer", "[facade][pipe]") {
    TestLoop loop;
    auto [a, b] = memory_pipe::make(loop);
    auv::stream sa = auv::stream::own(std::move(a));
    auv::stream sb = auv::stream::own(std::move(b));

    corral::run(loop, [&]() -> corral::Task<void> {
        const auto wec = co_await sa.write(std::string_view{"z"});
        REQUIRE_FALSE(wec);
        sa.reset();

        char buf[8];
        auto [ec1, n1] = co_await sb.read([&] { return auv::buffer(buf, sizeof(buf)); });
        REQUIRE_FALSE(ec1);
        REQUIRE(n1 == 1);
        REQUIRE(buf[0] == 'z');

        auto [ec2, n2] = co_await sb.read([&] { return auv::buffer(buf, sizeof(buf)); });
        REQUIRE(ec2 == auv::errc::eof);
        REQUIRE(n2 == 0);
    }());
}

TEST_CASE("write after peer is destroyed returns broken_pipe", "[facade][pipe]") {
    TestLoop loop;
    auto [a, b] = memory_pipe::make(loop);
    auv::stream sa = auv::stream::own(std::move(a));
    auv::stream sb = auv::stream::own(std::move(b));

    corral::run(loop, [&]() -> corral::Task<void> {
        sb.reset();
        const auto wec = co_await sa.write(std::string_view{"x"});
        REQUIRE(wec == std::errc::broken_pipe);
    }());
}

TEST_CASE("parked peer read completes with EOF when local end is destroyed", "[facade][pipe]") {
    TestLoop loop;
    auto [a, b] = memory_pipe::make(loop);
    auv::stream sa = auv::stream::own(std::move(a));
    auv::stream sb = auv::stream::own(std::move(b));

    corral::run(loop, [&]() -> corral::Task<void> {
        co_await corral::allOf(
            [&]() -> corral::Task<void> {
                char buf[8];
                auto [ec, nread] = co_await sb.read([&] { return auv::buffer(buf, sizeof(buf)); });
                REQUIRE(ec == auv::errc::eof);
                REQUIRE(nread == 0);
            },
            [&]() -> corral::Task<void> {
                // Let the sibling reach sb.read() and park first.
                co_await corral::yield;
                co_await corral::yield;
                sa.reset();
            });
    }());
}
