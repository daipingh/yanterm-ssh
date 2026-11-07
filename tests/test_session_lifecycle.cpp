#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/keys/private_key.hpp>
#include <yanterm-ssh/session.hpp>

#include "facade_fixture.hpp"
#include "handshake_fixture.hpp"
#include "memory_pipe.hpp"
#include "test_loop.hpp"

#include <auv/error.hpp>
#include <auv/stream.hpp>
#include <corral/corral.h>

#include <cerrno>
#include <memory_resource>
#include <utility>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

namespace {

// Counts overlapping write() calls on one pipe end. memory_pipe::write is
// otherwise synchronous unless the peer stalls reads.
struct concurrent_write_end {
    memory_pipe::end inner;
    int in_flight = 0;
    bool* concurrent = nullptr;

    concurrent_write_end(memory_pipe::end e, bool* flag)
        : inner(std::move(e)), concurrent(flag) {}

    corral::Task<auv::read_result> read(auv::read_allocator alloc_cb, void* alloc_arg) {
        co_return co_await inner.read(alloc_cb, alloc_arg);
    }

    corral::Task<std::error_code> write(const auv::buffer* bufs, std::size_t nbufs) {
        struct guard {
            concurrent_write_end* self;
            explicit guard(concurrent_write_end* s) : self(s) {
                ++self->in_flight;
                if (self->in_flight > 1 && self->concurrent) *self->concurrent = true;
            }
            ~guard() { --self->in_flight; }
        } g{this};
        co_return co_await inner.write(bufs, nbufs);
    }

    corral::Task<std::error_code> shutdown() { return inner.shutdown(); }

    corral::Task<void> close() { return inner.close(); }

    explicit operator auv::stream() && {
        auto owner = auv::detail::lifetime_owner::emplace<concurrent_write_end>(
            std::pmr::get_default_resource(), std::move(*this));
        concurrent_write_end* p = owner.get<concurrent_write_end>();
        return auv::stream::construct(p, auv::detail::stream_model<concurrent_write_end>::vtable(),
                                      std::move(owner));
    }
};

struct failing_io_end {
    std::error_code read_ec{};
    std::error_code write_ec{};

    corral::Task<auv::read_result> read(auv::read_allocator, void*) {
        if (!read_ec) co_await corral::suspendForever;
        co_return {read_ec, 0};
    }

    corral::Task<std::error_code> write(const auv::buffer*, std::size_t) { co_return write_ec; }

    corral::Task<std::error_code> shutdown() { return corral::just(std::error_code{}); }

    corral::Task<void> close() { return corral::noop(); }

    explicit operator auv::stream() && {
        auto owner = auv::detail::lifetime_owner::emplace<failing_io_end>(
            std::pmr::get_default_resource(), std::move(*this));
        failing_io_end* p = owner.get<failing_io_end>();
        return auv::stream::construct(p, auv::detail::stream_model<failing_io_end>::vtable(),
                                      std::move(owner));
    }
};

void require_transport_io(const client_session& cs, const std::error_code& io_ec) {
    REQUIRE(cs.failure().category() == io_ec.category());
    REQUIRE(cs.failure().value() == io_ec.value());
    REQUIRE(cs.failure() == errc::transport_failed);
    REQUIRE_FALSE(cs.failure_detail().empty());
}

}  // namespace

TEST_CASE("disconnect during serve shares the write pump", "[facade][serve]") {
    TestLoop loop;
    auto [a, b] = memory_pipe::make(loop);
    auto stall_server_reads = b.stall_reads();
    bool concurrent_writes = false;
    concurrent_write_end probed{std::move(a), &concurrent_writes};

    crypto::openssl_backend backend;
    auto p = crypto::provider::wrap(backend);
    server_options so;
    so.host_keys.push_back(parse_host_key_file(p, "id_ed25519"));

    client_session cs{auv::stream::own(std::move(probed)), p, client_options{}};
    server_session ss{auv::stream::own(std::move(b)), p, std::move(so)};

    corral::run(loop, [&]() -> corral::Task<void> {
        auto [cec, sec] = co_await corral::allOf(
            cs.handshake([](host_key_view) -> corral::Task<bool> { co_return true; }),
            ss.handshake());
        REQUIRE_FALSE(cec);
        REQUIRE_FALSE(sec);
        auto authed = co_await corral::allOf(
            cs.auth_password("alice", "s3cret"),
            ss.authenticate([](auth_request) -> corral::Task<auth_verdict> {
                co_return auth_verdict::success();
            }));
        auto [pec, result] = std::get<0>(authed);
        REQUIRE_FALSE(pec);
        REQUIRE(result.success);
        REQUIRE_FALSE(std::get<1>(authed));

        co_await corral::allOf(
            ss.serve(reject_inbound, reject_inbound),
            cs.serve(reject_inbound, reject_inbound, [&]() -> corral::Task<void> {
                stall_server_reads = true;
                CORRAL_WITH_NURSERY(n) {
                    n.start([&]() -> corral::Task<void> {
                        for (int i = 0; i < 4; ++i) {
                            corral::Event turn;
                            loop.post([&] { turn.trigger(); });
                            co_await turn;
                        }
                        stall_server_reads = false;
                    });
                    co_await cs.disconnect(disconnect_reason::by_application, "done");
                    co_return corral::join;
                };
            }));
    }());

    REQUIRE_FALSE(concurrent_writes);
    REQUIRE(ss.disconnected() != nullptr);
    REQUIRE(ss.disconnected()->reason == disconnect_reason::by_application);
    REQUIRE(ss.failure() == errc::peer_disconnected);
}

TEST_CASE("default construct then move-assign", "[facade][lifecycle]") {
    TestLoop loop;
    client_session empty;
    REQUIRE_FALSE(empty);
    REQUIRE(empty.failure() == errc::invalid_state);
    REQUIRE(empty.failure_detail().empty());

    auto [a, b] = memory_pipe::make(loop);
    crypto::openssl_backend backend;
    auto p = crypto::provider::wrap(backend);
    empty = client_session{auv::stream::own(std::move(a)), p, client_options{}};
    REQUIRE(empty);
    (void)b;

    client_session vacant;
    corral::run(loop, [&]() -> corral::Task<void> {
        auto ec = co_await vacant.handshake(
            [](host_key_view) -> corral::Task<bool> { co_return true; });
        REQUIRE(ec == errc::invalid_state);
        auto serve_ec = co_await vacant.serve(reject_inbound, reject_inbound);
        REQUIRE(serve_ec == errc::invalid_state);
    }());
}

TEST_CASE("read I/O failure latches transport_failed with detail", "[facade][lifecycle]") {
    TestLoop loop;
    crypto::openssl_backend backend;
    auto p = crypto::provider::wrap(backend);
    const auto io_ec = std::error_code(EIO, std::system_category());
    failing_io_end end;
    end.read_ec = io_ec;
    client_session cs{auv::stream::own(std::move(end)), p, client_options{}};

    corral::run(loop, [&]() -> corral::Task<void> {
        (void)co_await cs.handshake([](host_key_view) -> corral::Task<bool> {
            FAIL("host key verifier should not run");
            co_return true;
        });
        require_transport_io(cs, io_ec);
    }());
}

TEST_CASE("write I/O failure latches transport_failed with detail", "[facade][lifecycle]") {
    TestLoop loop;
    crypto::openssl_backend backend;
    auto p = crypto::provider::wrap(backend);
    const auto io_ec = std::error_code(EIO, std::system_category());
    failing_io_end end;
    end.write_ec = io_ec;
    client_session cs{auv::stream::own(std::move(end)), p, client_options{}};

    corral::run(loop, [&]() -> corral::Task<void> {
        (void)co_await cs.handshake([](host_key_view) -> corral::Task<bool> {
            FAIL("host key verifier should not run");
            co_return true;
        });
        require_transport_io(cs, io_ec);
    }());
}
