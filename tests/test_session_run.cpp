#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/keys/private_key.hpp>
#include <yanterm-ssh/session.hpp>

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
// otherwise synchronous unless the peer stalls reads, which hid the
// write_pump vs flush_pending race on real streams.
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
        co_return {read_ec ? read_ec : auv::make_error_code(auv::errc::eof), 0};
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

struct gated_write_end {
    memory_pipe::end inner;
    bool* fail = nullptr;
    std::error_code fail_ec{};

    gated_write_end(memory_pipe::end e, bool* flag, std::error_code ec)
        : inner(std::move(e)), fail(flag), fail_ec(ec) {}

    corral::Task<auv::read_result> read(auv::read_allocator alloc_cb, void* alloc_arg) {
        co_return co_await inner.read(alloc_cb, alloc_arg);
    }

    corral::Task<std::error_code> write(const auv::buffer* bufs, std::size_t nbufs) {
        if (fail && *fail) co_return fail_ec;
        co_return co_await inner.write(bufs, nbufs);
    }

    corral::Task<std::error_code> shutdown() { return inner.shutdown(); }

    corral::Task<void> close() { return inner.close(); }

    explicit operator auv::stream() && {
        auto owner = auv::detail::lifetime_owner::emplace<gated_write_end>(
            std::pmr::get_default_resource(), std::move(*this));
        gated_write_end* p = owner.get<gated_write_end>();
        return auv::stream::construct(p, auv::detail::stream_model<gated_write_end>::vtable(),
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

TEST_CASE("run pumps the identification banner", "[facade][run]") {
    TestLoop loop;
    auto [a, b] = memory_pipe::make(loop);
    crypto::openssl_backend backend;
    auto p = crypto::provider::wrap(backend);
    client_options co;
    server_options so;
    keys::private_key hk;
    REQUIRE_FALSE(keys::private_key::parse(load_fixture("id_ed25519"), p, {}, hk));
    so.host_keys.push_back(std::move(hk));

    client_session cs{auv::stream::own(std::move(a)), p, std::move(co)};
    server_session ss{auv::stream::own(std::move(b)), p, std::move(so)};

    corral::run(loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &cs);
            co_await n.start(&server_session::run, &ss);
            // Banner is "SSH-2.0-…\r\n". Drain one TestLoop turn so
            // memory_pipe wakeups (loop.post) run; corral::yield does not.
            corral::Event turn;
            loop.post([&] { turn.trigger(); });
            co_await turn;
            REQUIRE(cs.peer_identification().starts_with("SSH-2.0-"));
            REQUIRE(ss.peer_identification().starts_with("SSH-2.0-"));
            co_await cs.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("run FINALLY flushes DISCONNECT before close", "[facade][run]") {
    TestLoop loop;
    auto [a, b] = memory_pipe::make(loop);
    crypto::openssl_backend backend;
    auto p = crypto::provider::wrap(backend);
    client_options co;
    server_options so;
    keys::private_key hk;
    REQUIRE_FALSE(keys::private_key::parse(load_fixture("id_ed25519"), p, {}, hk));
    so.host_keys.push_back(std::move(hk));

    client_session cs{auv::stream::own(std::move(a)), p, std::move(co)};
    server_session ss{auv::stream::own(std::move(b)), p, std::move(so)};

    corral::run(loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&server_session::run, &ss);
            // Nest the client so cancel hits its run() FINALLY without a user
            // disconnect(), while the server stays alive to observe it.
            CORRAL_WITH_NURSERY(client_n) {
                co_await client_n.start(&client_session::run, &cs);
                for (int i = 0; i < 64; ++i) {
                    if (cs.peer_identification().starts_with("SSH-2.0-") &&
                        ss.peer_identification().starts_with("SSH-2.0-")) {
                        break;
                    }
                    corral::Event turn;
                    loop.post([&] { turn.trigger(); });
                    co_await turn;
                }
                co_return corral::cancel;
            };
            for (int i = 0; i < 64; ++i) {
                if (ss.disconnected() != nullptr) break;
                corral::Event turn;
                loop.post([&] { turn.trigger(); });
                co_await turn;
            }
            co_return corral::cancel;
        };
    }());

    REQUIRE(ss.disconnected() != nullptr);
    REQUIRE(ss.failure() == errc::peer_disconnected);
}

TEST_CASE("run FINALLY does not write concurrently with write_pump", "[facade][run]") {
    TestLoop loop;
    auto [a, b] = memory_pipe::make(loop);
    auto stall_server_reads = b.stall_reads();
    bool concurrent_writes = false;
    concurrent_write_end probed{std::move(a), &concurrent_writes};

    crypto::openssl_backend backend;
    auto p = crypto::provider::wrap(backend);
    client_options co;
    server_options so;
    keys::private_key hk;
    REQUIRE_FALSE(keys::private_key::parse(load_fixture("id_ed25519"), p, {}, hk));
    so.host_keys.push_back(std::move(hk));

    client_session cs{auv::stream::own(std::move(probed)), p, std::move(co)};
    server_session ss{auv::stream::own(std::move(b)), p, std::move(so)};

    corral::run(loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&server_session::run, &ss);
            CORRAL_WITH_NURSERY(client_n) {
                co_await client_n.start(&client_session::run, &cs);
                for (int i = 0; i < 64; ++i) {
                    if (cs.peer_identification().starts_with("SSH-2.0-") &&
                        ss.peer_identification().starts_with("SSH-2.0-")) {
                        break;
                    }
                    corral::Event turn;
                    loop.post([&] { turn.trigger(); });
                    co_await turn;
                }
                // Park the next client stream_.write so a racing flush_pending
                // would overlap in-flight writes instead of completing synchronously.
                stall_server_reads = true;
                n.start([&]() -> corral::Task<void> {
                    for (int i = 0; i < 8; ++i) {
                        corral::Event turn;
                        loop.post([&] { turn.trigger(); });
                        co_await turn;
                    }
                    stall_server_reads = false;
                    co_return;
                });
                co_return corral::cancel;
            };
            for (int i = 0; i < 64; ++i) {
                if (ss.disconnected() != nullptr) break;
                corral::Event turn;
                loop.post([&] { turn.trigger(); });
                co_await turn;
            }
            co_return corral::cancel;
        };
    }());

    REQUIRE_FALSE(concurrent_writes);
    REQUIRE(ss.disconnected() != nullptr);
    REQUIRE(ss.failure() == errc::peer_disconnected);
}

TEST_CASE("run cancellation makes handshake return", "[facade][run]") {
    TestLoop loop;
    auto [a, b] = memory_pipe::make(loop);
    crypto::openssl_backend backend;
    auto p = crypto::provider::wrap(backend);
    client_options co;
    client_session cs{auv::stream::own(std::move(a)), p, std::move(co)};
    auv::stream peer = auv::stream::own(std::move(b));

    corral::run(loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            corral::Event cancel_event;
            co_await n.start([&](corral::TaskStarted<> started) -> corral::Task<void> {
                co_await corral::anyOf(cs.run(std::move(started)), cancel_event.get());
            });

            co_await corral::allOf(
                [&]() -> corral::Task<void> {
                    auto ec = co_await cs.handshake([](host_key_view view) -> corral::Task<bool> {
                        FAIL("host key verifier should not run");
                        co_return true;
                    });
                    REQUIRE(ec.value() != 0);
                    REQUIRE(cancel_event.triggered());
                },
                [&]() -> corral::Task<void> {
                    co_await corral::yield;
                    co_await corral::yield;
                    cancel_event.trigger();
                }
            );
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("default construct then move-assign", "[facade][run]") {
    TestLoop loop;
    client_session empty;
    REQUIRE_FALSE(empty);
    REQUIRE(empty.failure() == errc::invalid_state);
    REQUIRE(empty.failure_detail().empty());

    auto [a, b] = memory_pipe::make(loop);
    crypto::openssl_backend backend;
    auto p = crypto::provider::wrap(backend);
    client_options co;
    empty = client_session{auv::stream::own(std::move(a)), p, std::move(co)};
    REQUIRE(empty);
    (void)b;

    client_session vacant;
    corral::run(loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &vacant);
            REQUIRE(vacant.failure() == errc::invalid_state);
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("read I/O failure latches transport_failed with detail", "[facade][run]") {
    TestLoop loop;
    crypto::openssl_backend backend;
    auto p = crypto::provider::wrap(backend);
    const auto io_ec = std::error_code(EIO, std::system_category());
    failing_io_end end;
    end.read_ec = io_ec;
    client_session cs{auv::stream::own(std::move(end)), p, client_options{}};

    corral::run(loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &cs);
            (void)co_await cs.handshake([](host_key_view) -> corral::Task<bool> {
                FAIL("host key verifier should not run");
                co_return true;
            });
            require_transport_io(cs, io_ec);
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("write I/O failure latches transport_failed with detail", "[facade][run]") {
    TestLoop loop;
    crypto::openssl_backend backend;
    auto p = crypto::provider::wrap(backend);
    const auto io_ec = std::error_code(EIO, std::system_category());
    failing_io_end end;
    end.write_ec = io_ec;
    client_session cs{auv::stream::own(std::move(end)), p, client_options{}};

    corral::run(loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &cs);
            (void)co_await cs.handshake([](host_key_view) -> corral::Task<bool> {
                FAIL("host key verifier should not run");
                co_return true;
            });
            require_transport_io(cs, io_ec);
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("flush I/O failure latches transport_failed with detail", "[facade][run]") {
    TestLoop loop;
    auto [a, b] = memory_pipe::make(loop);
    crypto::openssl_backend backend;
    auto p = crypto::provider::wrap(backend);
    const auto io_ec = std::error_code(EIO, std::system_category());
    bool fail_writes = false;
    gated_write_end gated{std::move(a), &fail_writes, io_ec};
    client_session cs{static_cast<auv::stream>(std::move(gated)), p, client_options{}};
    auv::stream peer = auv::stream::own(std::move(b));

    corral::run(loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            corral::Event cancel_event;
            co_await n.start([&](corral::TaskStarted<> started) -> corral::Task<void> {
                co_await corral::anyOf(cs.run(std::move(started)), cancel_event.get());
            });
            for (int i = 0; i < 8; ++i) {
                corral::Event turn;
                loop.post([&] { turn.trigger(); });
                co_await turn;
            }
            fail_writes = true;
            cancel_event.trigger();
            for (int i = 0; i < 8; ++i) {
                if (cs.failure() == errc::transport_failed) break;
                corral::Event turn;
                loop.post([&] { turn.trigger(); });
                co_await turn;
            }
            require_transport_io(cs, io_ec);
            (void)peer;
            co_return corral::cancel;
        };
    }());
}
