#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/session.hpp>

#include "counting_resource.hpp"
#include "facade_fixture.hpp"

#include <corral/corral.h>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

namespace {

corral::Task<void> drain_turns(TestLoop& loop, int n) {
    for (int i = 0; i < n; ++i) {
        corral::Event turn;
        loop.post([&] { turn.trigger(); });
        co_await turn;
    }
}

}  // namespace

TEST_CASE("an idle authenticated session holds no blocks from its memory resource",
          "[facade][memory]") {
    counting_resource client_res;
    counting_resource server_res;
    TestLoop loop;
    auto [a, b] = memory_pipe::make(loop);
    auto p = prov();
    server_options so;
    so.host_keys.push_back(parse_host_key_file(p, "id_ed25519"));
    client_session client{auv::stream::own(std::move(a)), p, {}, &client_res};
    server_session server{auv::stream::own(std::move(b)), p, std::move(so), &server_res};

    corral::run(loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &client);
            co_await n.start(&server_session::run, &server);
            auto [cec, sec] = co_await corral::allOf(
                client.handshake([](host_key_view) -> corral::Task<bool> { co_return true; }),
                server.handshake());
            REQUIRE_FALSE(cec);
            REQUIRE_FALSE(sec);
            auto [aec, auth] = co_await corral::allOf(
                client.auth_password("alice", "s3cret"),
                server.authenticate([](auth_request) -> corral::Task<auth_verdict> {
                    co_return auth_verdict::success();
                }));
            REQUIRE_FALSE(std::get<0>(aec));
            REQUIRE(std::get<1>(aec).success);
            REQUIRE_FALSE(auth);
            co_await drain_turns(loop, 8);

            CHECK(client_res.total_allocations() > 0);
            CHECK(client_res.outstanding_blocks() == 0);
            CHECK(server_res.outstanding_blocks() == 0);
            co_return corral::cancel;
        };
    });
}
