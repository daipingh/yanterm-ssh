#include <catch2/catch_test_macros.hpp>
#include "handshake_fixture.hpp"
#include "legacy_loopback_event.hpp"
#include <yanterm-ssh/core/handler.hpp>
#include <yanterm-ssh/channels/types.hpp>
#include <type_traits>
#include <cstddef>
#include <span>

using namespace yanterm::ssh;
using namespace yanterm::ssh::core;
using namespace yanterm::ssh::testing;

static_assert(sizeof(channel_request_ticket) == 16);
static_assert(std::is_trivially_copyable_v<channel_request_ticket>);
static_assert(!std::is_convertible_v<open_ticket, channel_request_ticket>);
static_assert(!std::is_convertible_v<channel_ref, channel_request_ticket>);
static_assert(!std::is_convertible_v<std::uint64_t, auth_ticket>);

TEST_CASE("default tickets are equal to themselves", "[handle]") {
    CHECK(channel_ref{} == channel_ref{});
    CHECK(auth_ticket{} == auth_ticket{});
    CHECK(channel_ref{}.seq == 0);
}

TEST_CASE("stale channel_ref is invalid_state after slot reuse", "[handle]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    config cfg;
    cfg.max_channels = 1;
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);

    channel_ref first{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, first));
    REQUIRE(run_loopback_legacy(
        client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_open_request) {
                (void)server.conn.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
            }
        }));
    REQUIRE_FALSE(client.conn.channel_close(first));
    REQUIRE(run_loopback(client, server));

    channel_ref second{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, second));
    REQUIRE(second.index == first.index);
    REQUIRE(second.seq != first.seq);
    REQUIRE(client.conn.channel_close(first) == code::invalid_state);

    REQUIRE(run_loopback_legacy(
        client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_open_request) {
                (void)server.conn.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
            }
        }));
    const std::byte payload[] = {std::byte{'x'}};
    std::span<const std::byte> frags[] = {payload};
    std::size_t accepted = 0;
    REQUIRE_FALSE(client.conn.channel_write(second, frags, accepted));
    REQUIRE(accepted == 1);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}
