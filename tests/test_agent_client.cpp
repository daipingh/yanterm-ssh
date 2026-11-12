#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/agent.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/error.hpp>

#include "test_loop.hpp"

#include <corral/corral.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

namespace {

std::vector<std::byte> bytes_of(std::string_view s) {
    return {reinterpret_cast<const std::byte*>(s.data()),
            reinterpret_cast<const std::byte*>(s.data()) + s.size()};
}

std::span<const std::byte> as_bytes(std::string_view s) {
    return {reinterpret_cast<const std::byte*>(s.data()), s.size()};
}

void append_u32(std::vector<std::byte>& out, std::uint32_t v) {
    out.push_back(static_cast<std::byte>(v >> 24));
    out.push_back(static_cast<std::byte>(v >> 16));
    out.push_back(static_cast<std::byte>(v >> 8));
    out.push_back(static_cast<std::byte>(v));
}

std::vector<std::byte> frame_of(std::span<const std::byte> payload) {
    std::vector<std::byte> out;
    append_u32(out, static_cast<std::uint32_t>(payload.size()));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

std::vector<std::byte> message(void (*encode)(wire::writer&)) {
    wire::writer w;
    encode(w);
    return frame_of(w.data());
}

struct agent_io {
    struct state {
        std::vector<std::byte> inbound;
        std::size_t pos = 0;
        std::vector<std::byte> written;
        bool eof = false;
        std::size_t read_chunk = static_cast<std::size_t>(-1);
        std::size_t write_budget = static_cast<std::size_t>(-1);
        bool write_parked = false;
        corral::ParkingLot readable;
        corral::ParkingLot writable;
        corral::ParkingLot progress;
    };

    std::shared_ptr<state> st = std::make_shared<state>();

    void feed(std::span<const std::byte> bytes) {
        st->inbound.insert(st->inbound.end(), bytes.begin(), bytes.end());
        st->readable.unparkAll();
        st->progress.unparkAll();
    }

    void finish() {
        st->eof = true;
        st->readable.unparkAll();
        st->progress.unparkAll();
    }

    corral::Task<auv::read_result> read(auv::read_allocator alloc, void* arg) {
        for (;;) {
            if (st->pos < st->inbound.size()) {
                auv::buffer buf = alloc(arg);
                const std::size_t n = std::min(buf.size(), std::min(st->read_chunk, st->inbound.size() - st->pos));
                if (n == 0) co_return {std::make_error_code(std::errc::no_buffer_space), 0};
                std::memcpy(buf.data(), st->inbound.data() + st->pos, n);
                st->pos += n;
                st->progress.unparkAll();
                co_return {std::error_code{}, n};
            }
            if (st->eof) co_return {auv::make_error_code(auv::errc::eof), 0};
            co_await st->readable.park();
        }
    }

    corral::Task<std::error_code> write(const auv::buffer* bufs, std::size_t nbufs) {
        std::size_t total = 0;
        for (std::size_t i = 0; i < nbufs; ++i) total += bufs[i].size();
        std::size_t index = 0;
        std::size_t offset = 0;
        std::size_t accepted = 0;
        while (accepted < total) {
            if (st->write_budget == 0) {
                st->write_parked = true;
                st->progress.unparkAll();
                co_await st->writable.park();
                st->write_parked = false;
                continue;
            }
            while (index < nbufs && offset == bufs[index].size()) {
                ++index;
                offset = 0;
            }
            const std::size_t n = std::min(st->write_budget, bufs[index].size() - offset);
            const auto* p = reinterpret_cast<const std::byte*>(bufs[index].data()) + offset;
            st->written.insert(st->written.end(), p, p + n);
            offset += n;
            accepted += n;
            st->write_budget -= n;
            st->progress.unparkAll();
        }
        co_return std::error_code{};
    }

    corral::Task<std::error_code> shutdown() { co_return std::error_code{}; }
    corral::Task<void> close() { co_return; }
};

static_assert(auv::detail::stream_like<agent_io>);
static_assert(publickey_signer<basic_agent_client<agent_io>::signer_adapter>);

corral::Task<std::size_t> await_frame(agent_io& io, std::size_t from) {
    for (;;) {
        const auto& written = io.st->written;
        if (written.size() >= from + 4) {
            const auto len = agent::decode_frame_header(
                std::span<const std::byte>(written.data() + from, 4));
            if (len >= 1 && written.size() >= from + 4 + len) co_return from + 4 + len;
        }
        co_await io.st->progress.park();
    }
}

std::vector<std::byte> identities_answer() {
    wire::writer w;
    const agent::identity_view ids[] = {{as_bytes("key-a"), "alpha"}, {as_bytes("key-b"), "beta"}};
    agent::encode_identities_answer(w, ids);
    return frame_of(w.data());
}

}  // namespace

TEST_CASE("agent client reassembles a fragmented identities answer", "[agent][client]") {
    TestLoop loop;
    corral::run(loop, []() -> corral::Task<void> {
        agent_io io;
        io.st->read_chunk = 1;
        basic_agent_client<agent_io> client{io};
        std::vector<agent::identity> ids;
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto listed = co_await client.list_identities();
                std::error_code ec = listed.ec;
                ids = std::move(listed.identities);
                REQUIRE_FALSE(ec);
            });
            const auto end = co_await await_frame(io, 0);
            REQUIRE(io.st->written.size() == end);
            REQUIRE(io.st->written[4] == std::byte{11});
            io.feed(identities_answer());
            co_return corral::join;
        };
        REQUIRE(ids.size() == 2);
        REQUIRE(ids[0].comment == "alpha");
        REQUIRE(ids[1].key_blob == bytes_of("key-b"));

        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                const auto end = co_await await_frame(io, io.st->written.size());
                (void)end;
                io.feed(message([](wire::writer& w) { agent::encode_failure(w); }));
            });
            auto [ec, signature] = co_await client.sign(as_bytes("key-a"), as_bytes("data"), 0);
            REQUIRE(ec == agent::refusal::failure);
            REQUIRE(signature.empty());
            co_return corral::join;
        };
        REQUIRE(ids[0].comment == "alpha");
        REQUIRE(ids[1].key_blob == bytes_of("key-b"));
        REQUIRE_FALSE(client.failure());
    }());
}

TEST_CASE("agent client sends the sign request in key, data, flags order", "[agent][client]") {
    TestLoop loop;
    corral::run(loop, []() -> corral::Task<void> {
        agent_io io;
        basic_agent_client<agent_io> client{io};
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                const auto end = co_await await_frame(io, 0);
                std::span<const std::byte> body(io.st->written.data() + 4, end - 4);
                std::span<const std::byte> key;
                std::span<const std::byte> data;
                std::uint32_t flags = 0;
                REQUIRE(agent::decode_sign_request(body, key, data, flags));
                REQUIRE(flags == agent::sign_flags::rsa_sha2_512);
                REQUIRE(std::string_view{reinterpret_cast<const char*>(key.data()), key.size()} == "key");
                REQUIRE(std::string_view{reinterpret_cast<const char*>(data.data()), data.size()} == "data");
                io.feed(message([](wire::writer& w) { agent::encode_sign_response(w, as_bytes("ssh-sig")); }));
            });
            auto [ec, signature] = co_await client.sign(as_bytes("key"), as_bytes("data"),
                                                       agent::sign_flags::rsa_sha2_512);
            REQUIRE_FALSE(ec);
            REQUIRE(signature == bytes_of("ssh-sig"));
            co_return corral::join;
        };
        REQUIRE_FALSE(client.failure());
    }());
}

TEST_CASE("agent client keeps a second request behind the first reply", "[agent][client]") {
    TestLoop loop;
    corral::run(loop, []() -> corral::Task<void> {
        agent_io io;
        io.st->read_chunk = 1;
        basic_agent_client<agent_io> client{io};
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto [ec, ids] = co_await client.list_identities();
                REQUIRE_FALSE(ec);
                REQUIRE(ids.size() == 2);
            });
            n.start([&]() -> corral::Task<void> {
                auto [ec, signature] = co_await client.sign(as_bytes("k"), as_bytes("d"), 0);
                REQUIRE_FALSE(ec);
                REQUIRE(signature == bytes_of("sig"));
            });
            const auto first = co_await await_frame(io, 0);
            REQUIRE(io.st->written.size() == first);
            REQUIRE(io.st->written[4] == std::byte{11});
            io.feed(identities_answer());
            const auto second = co_await await_frame(io, first);
            REQUIRE(io.st->written[first + 4] == std::byte{13});
            io.feed(message([](wire::writer& w) { agent::encode_sign_response(w, as_bytes("sig")); }));
            (void)second;
            co_return corral::join;
        };
        REQUIRE_FALSE(client.failure());
    }());
}

TEST_CASE("agent business refusals stay distinct from a latched client", "[agent][client]") {
    struct row {
        const char* name;
        int reply;
        bool forwarding;
    };
    const row rows[] = {
        {"success", 6, false},
        {"failure", 5, false},
        {"extension failure", 28, true},
    };
    for (const auto& row : rows) {
        INFO(row.name);
        TestLoop loop;
        corral::run(loop, [&]() -> corral::Task<void> {
            agent_io io;
            basic_agent_client<agent_io> client{io};
            CORRAL_WITH_NURSERY(n) {
                n.start([&]() -> corral::Task<void> {
                    const auto end = co_await await_frame(io, 0);
                    std::span<const std::byte> body(io.st->written.data() + 4, end - 4);
                    std::span<const std::byte> host;
                    std::span<const std::byte> session_id;
                    std::span<const std::byte> signature;
                    bool forwarding = !row.forwarding;
                    REQUIRE(agent::decode_session_bind(body, host, session_id, signature, forwarding));
                    REQUIRE(forwarding == row.forwarding);
                    io.feed(frame_of(std::vector<std::byte>{static_cast<std::byte>(row.reply)}));
                });
                auto ec = co_await client.bind_session(as_bytes("host"), as_bytes("sess"),
                                                      as_bytes("kex"), row.forwarding);
                if (row.reply == 6) REQUIRE_FALSE(ec);
                if (row.reply == 5) REQUIRE(ec == agent::refusal::failure);
                if (row.reply == 28) REQUIRE(ec == agent::refusal::extension_failure);
                co_return corral::join;
            };
            REQUIRE_FALSE(client.failure());
            CORRAL_WITH_NURSERY(n) {
                n.start([&]() -> corral::Task<void> {
                    const auto from = io.st->written.size();
                    co_await await_frame(io, from);
                    io.feed(message([](wire::writer& w) { agent::encode_success(w); }));
                });
                auto again = co_await client.bind_session(as_bytes("host"), as_bytes("sess"),
                                                          as_bytes("kex"), false);
                REQUIRE_FALSE(again);
                co_return corral::join;
            };
            REQUIRE_FALSE(client.failure());
        }());
    }
}

TEST_CASE("agent client distinguishes cancellation from a business refusal", "[agent][client]") {
    enum class phase { queued, after_write, mid_read, business };
    struct row {
        const char* name;
        phase which;
        bool usable;
    };
    const row rows[] = {
        {"queued cancel writes nothing and stays usable", phase::queued, true},
        {"cancel after the write starts latches the client", phase::after_write, false},
        {"cancel during a partial read latches the client", phase::mid_read, false},
        {"a complete failure stays usable", phase::business, true},
    };

    for (const auto& row : rows) {
        INFO(row.name);
        TestLoop loop;
        corral::run(loop, [&]() -> corral::Task<void> {
            agent_io io;
            basic_agent_client<agent_io> client{io};
            const auto before = io.st->written.size();

            if (row.which == phase::queued) {
                CORRAL_WITH_NURSERY(outer) {
                    outer.start([&]() -> corral::Task<void> {
                        auto [ec, ids] = co_await client.list_identities();
                        REQUIRE_FALSE(ec);
                        REQUIRE(ids.size() == 2);
                    });
                    const auto first = co_await await_frame(io, before);
                    REQUIRE(io.st->written.size() == first);
                    CORRAL_WITH_NURSERY(queued) {
                        queued.start([&]() -> corral::Task<void> {
                            co_await client.sign(as_bytes("k"), as_bytes("d"), 0);
                        });
                        co_await corral::yield;
                        co_await corral::yield;
                        REQUIRE(io.st->written.size() == first);
                        co_return corral::cancel;
                    };
                    REQUIRE(io.st->written.size() == first);
                    REQUIRE_FALSE(client.failure());
                    io.feed(identities_answer());
                    co_return corral::join;
                };
            } else if (row.which == phase::after_write) {
                io.st->write_budget = 0;
                CORRAL_WITH_NURSERY(outer) {
                    outer.start([&]() -> corral::Task<void> {
                        while (!io.st->write_parked) co_await io.st->progress.park();
                        io.st->write_budget = static_cast<std::size_t>(-1);
                        io.st->writable.unparkAll();
                    });
                    CORRAL_WITH_NURSERY(op) {
                        op.start([&]() -> corral::Task<void> {
                            co_await client.list_identities();
                        });
                        while (!io.st->write_parked) co_await io.st->progress.park();
                        co_return corral::cancel;
                    };
                    co_return corral::join;
                };
                const auto end = co_await await_frame(io, before);
                REQUIRE(io.st->written.size() == end);
                REQUIRE(client.failure() == std::errc::operation_canceled);
            } else if (row.which == phase::mid_read) {
                CORRAL_WITH_NURSERY(outer) {
                    outer.start([&]() -> corral::Task<void> {
                        const auto end = co_await await_frame(io, before);
                        auto reply = identities_answer();
                        io.feed(std::span<const std::byte>(reply.data(), 2));
                        while (io.st->pos < 2) co_await io.st->progress.park();
                        (void)end;
                    });
                    CORRAL_WITH_NURSERY(op) {
                        op.start([&]() -> corral::Task<void> {
                            // Same discarded await as the write-cancel row above.
                            co_await client.list_identities();
                        });
                        while (io.st->pos < 2) co_await io.st->progress.park();
                        co_return corral::cancel;
                    };
                    co_return corral::join;
                };
                REQUIRE(client.failure() == std::errc::operation_canceled);
            } else {
                CORRAL_WITH_NURSERY(n) {
                    n.start([&]() -> corral::Task<void> {
                        co_await await_frame(io, before);
                        io.feed(message([](wire::writer& w) { agent::encode_failure(w); }));
                    });
                    auto [ec, ids] = co_await client.list_identities();
                    REQUIRE(ec == agent::refusal::failure);
                    REQUIRE(ids.empty());
                    co_return corral::join;
                };
                REQUIRE_FALSE(client.failure());
            }

            const auto written = io.st->written.size();
            if (!row.usable) {
                auto [ec, ids] = co_await client.list_identities();
                REQUIRE(ec == client.failure());
                REQUIRE(ids.empty());
                REQUIRE(io.st->written.size() == written);
            } else {
                CORRAL_WITH_NURSERY(n) {
                    n.start([&]() -> corral::Task<void> {
                        co_await await_frame(io, written);
                        io.feed(identities_answer());
                    });
                    auto [ec, ids] = co_await client.list_identities();
                    REQUIRE_FALSE(ec);
                    REQUIRE(ids.size() == 2);
                    co_return corral::join;
                };
                REQUIRE_FALSE(client.failure());
            }
        }());
    }
}

TEST_CASE("agent transport errors latch the client and a refusal does not", "[agent][client]") {
    struct row {
        const char* name;
        bool eof;
        bool bad_length;
        bool wrong_type;
        bool malformed;
    };
    const row rows[] = {
        {"eof", true, false, false, false},
        {"illegal length", false, true, false, false},
        {"unexpected type", false, false, true, false},
        {"malformed identities", false, false, false, true},
        {"failure with a trailing byte", false, false, false, false},
    };
    for (const auto& row : rows) {
        INFO(row.name);
        TestLoop loop;
        corral::run(loop, [&]() -> corral::Task<void> {
            agent_io io;
            basic_agent_client<agent_io> client{io};
            CORRAL_WITH_NURSERY(n) {
                n.start([&]() -> corral::Task<void> {
                    co_await await_frame(io, 0);
                    if (row.eof) {
                        io.finish();
                    } else if (row.bad_length) {
                        io.feed(std::vector<std::byte>{std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}});
                    } else if (row.wrong_type) {
                        io.feed(message([](wire::writer& w) { agent::encode_success(w); }));
                    } else if (row.malformed) {
                        auto body = identities_answer();
                        body.push_back(std::byte{0});
                        body[3] = static_cast<std::byte>(static_cast<unsigned>(body[3]) + 1);
                        io.feed(body);
                    } else {
                        auto body = message([](wire::writer& w) { agent::encode_failure(w); });
                        body.push_back(std::byte{0});
                        body[3] = static_cast<std::byte>(static_cast<unsigned>(body[3]) + 1);
                        io.feed(body);
                    }
                });
                auto [ec, ids] = co_await client.list_identities();
                REQUIRE(ec);
                REQUIRE(ec == client.failure());
                REQUIRE(ec != agent::refusal::failure);
                REQUIRE(ids.empty());
                co_return corral::join;
            };
            const auto written = io.st->written.size();
            auto [again, ids] = co_await client.list_identities();
            REQUIRE(again == client.failure());
            REQUIRE(io.st->written.size() == written);
            (void)ids;
        }());
    }
}

std::vector<std::byte> typed_frame(agent::msg type, std::initializer_list<std::byte> rest) {
    std::vector<std::byte> body;
    body.push_back(static_cast<std::byte>(type));
    body.insert(body.end(), rest.begin(), rest.end());
    return frame_of(body);
}

TEST_CASE("a malformed agent reply latches before a queued request writes", "[agent][client]") {
    enum class which { identities, signature };
    struct row {
        const char* name;
        which reply;
    };
    const row rows[] = {
        {"identities answer names one key and omits it", which::identities},
        {"sign response cuts the signature string short", which::signature},
    };
    for (const auto& row : rows) {
        INFO(row.name);
        TestLoop loop;
        corral::run(loop, [&]() -> corral::Task<void> {
            agent_io io;
            basic_agent_client<agent_io> client{io};
            std::size_t first_end = 0;
            std::error_code first_ec;
            std::error_code second_ec;
            bool first_done = false;
            bool second_done = false;
            CORRAL_WITH_NURSERY(n) {
                n.start([&]() -> corral::Task<void> {
                    if (row.reply == which::identities) {
                        auto [ec, ids] = co_await client.list_identities();
                        first_ec = ec;
                        first_done = true;
                        REQUIRE(ids.empty());
                    } else {
                        auto [ec, signature] = co_await client.sign(as_bytes("k"), as_bytes("d"), 0);
                        first_ec = ec;
                        first_done = true;
                        REQUIRE(signature.empty());
                    }
                });
                n.start([&]() -> corral::Task<void> {
                    if (row.reply == which::identities) {
                        auto [ec, signature] = co_await client.sign(as_bytes("k"), as_bytes("d"), 0);
                        second_ec = ec;
                        second_done = true;
                        REQUIRE(signature.empty());
                    } else {
                        auto [ec, ids] = co_await client.list_identities();
                        second_ec = ec;
                        second_done = true;
                        REQUIRE(ids.empty());
                    }
                });
                first_end = co_await await_frame(io, 0);
                REQUIRE(io.st->written.size() == first_end);
                if (row.reply == which::identities) {
                    io.feed(typed_frame(agent::msg::identities_answer,
                                        {std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}}));
                } else {
                    io.feed(typed_frame(agent::msg::sign_response,
                                        {std::byte{0}, std::byte{0}, std::byte{0}, std::byte{4}}));
                }
                int spins = 0;
                while (!(first_done && second_done) && io.st->written.size() == first_end && spins < 64) {
                    co_await corral::yield;
                    ++spins;
                }
                REQUIRE(io.st->written.size() == first_end);
                REQUIRE(first_done);
                REQUIRE(second_done);
                co_return corral::join;
            };
            REQUIRE(first_ec == code::invalid_format);
            REQUIRE(first_ec == client.failure());
            REQUIRE(second_ec == client.failure());
            REQUIRE(io.st->written.size() == first_end);
            auto [again, ids] = co_await client.list_identities();
            REQUIRE(again == client.failure());
            REQUIRE(ids.empty());
            REQUIRE(io.st->written.size() == first_end);
        }());
    }
}

TEST_CASE("a complete failure still lets a queued agent request write", "[agent][client]") {
    TestLoop loop;
    corral::run(loop, []() -> corral::Task<void> {
        agent_io io;
        basic_agent_client<agent_io> client{io};
        std::error_code first_ec;
        std::error_code second_ec;
        std::vector<std::byte> signature;
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto [ec, ids] = co_await client.list_identities();
                first_ec = ec;
                REQUIRE(ids.empty());
            });
            n.start([&]() -> corral::Task<void> {
                auto signed_data = co_await client.sign(as_bytes("k"), as_bytes("d"), 0);
                second_ec = signed_data.ec;
                signature = std::move(signed_data.signature);
            });
            const auto first = co_await await_frame(io, 0);
            REQUIRE(io.st->written.size() == first);
            io.feed(message([](wire::writer& w) { agent::encode_failure(w); }));
            const auto second = co_await await_frame(io, first);
            REQUIRE(io.st->written[first + 4] == std::byte{static_cast<unsigned>(agent::msg::sign_request)});
            io.feed(message([](wire::writer& w) { agent::encode_sign_response(w, as_bytes("sig")); }));
            (void)second;
            co_return corral::join;
        };
        REQUIRE(first_ec == agent::refusal::failure);
        REQUIRE_FALSE(second_ec);
        REQUIRE(signature == bytes_of("sig"));
        REQUIRE_FALSE(client.failure());
    }());
}

TEST_CASE("agent client rejects an oversized request without latching", "[agent][client]") {
    TestLoop loop;
    corral::run(loop, []() -> corral::Task<void> {
        agent_io io;
        agent_options opts;
        opts.max_message_length = 8;
        basic_agent_client<agent_io> client{io, opts};
        auto [ec, signature] = co_await client.sign(as_bytes("this-key-is-too-long"), as_bytes("data"), 0);
        REQUIRE(ec == code::invalid_argument);
        REQUIRE(signature.empty());
        REQUIRE(io.st->written.empty());
        REQUIRE_FALSE(client.failure());

        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                co_await await_frame(io, 0);
                wire::writer w;
                agent::encode_identities_answer(w, {});
                io.feed(frame_of(w.data()));
            });
            auto [listed, ids] = co_await client.list_identities();
        REQUIRE_FALSE(listed);
        REQUIRE(ids.empty());
        co_return corral::join;
        };
        REQUIRE_FALSE(client.failure());
    }());
}

TEST_CASE("agent client add identity matches the ed25519 layout", "[agent][client]") {
    crypto::openssl_backend backend;
    auto p = crypto::provider::wrap(backend);
    keys::private_key key;
    REQUIRE_FALSE(keys::private_key::generate(p, crypto::sig_id::ed25519, 0, "ed", key));
    const auto m = key.material();

    TestLoop loop;
    corral::run(loop, [&]() -> corral::Task<void> {
        agent_io io;
        basic_agent_client<agent_io> client{io};
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                const auto end = co_await await_frame(io, 0);
                std::span<const std::byte> body(io.st->written.data() + 4, end - 4);
                wire::writer hand;
                hand.write_byte(17);
                hand.write_string("ssh-ed25519");
                hand.write_string(m.public_key);
                hand.write_uint32(64);
                hand.write_bytes(m.seed);
                hand.write_bytes(m.public_key);
                hand.write_string("comment");
                REQUIRE(std::equal(body.begin(), body.end(), hand.data().begin(), hand.data().end()));
                io.feed(message([](wire::writer& w) { agent::encode_success(w); }));
            });
            const auto ec = co_await client.add_identity(key, "comment");
            REQUIRE_FALSE(ec);
            co_return corral::join;
        };
        REQUIRE_FALSE(client.failure());
    }());
}

TEST_CASE("agent status and extension replies follow RFC 9987", "[agent][client]") {
    TestLoop loop;
    corral::run(loop, []() -> corral::Task<void> {
        agent_io io;
        basic_agent_client<agent_io> client{io};
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                const auto end = co_await await_frame(io, 0);
                std::span<const std::byte> body(io.st->written.data() + 4, end - 4);
                std::string_view token;
                std::string_view pin;
                agent::key_constraints constraints;
                REQUIRE(agent::decode_add_smartcard_key(body, token, pin, constraints));
                REQUIRE(token == "tok");
                REQUIRE(pin == "pin");
                REQUIRE(constraints.confirm);
                io.feed(message([](wire::writer& w) { agent::encode_failure(w); }));
            });
            agent::key_constraints constraints;
            constraints.confirm = true;
            const auto denied = co_await client.add_smartcard_key("tok", "pin", constraints);
            REQUIRE(denied == agent::refusal::failure);
            co_return corral::join;
        };
        REQUIRE_FALSE(client.failure());

        io.st->written.clear();
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                const auto end = co_await await_frame(io, 0);
                REQUIRE(io.st->written[4] == std::byte{19});
                REQUIRE(end == 5);
                io.feed(message([](wire::writer& w) { agent::encode_success(w); }));
            });
            const auto ec = co_await client.remove_all_identities();
            REQUIRE_FALSE(ec);
            co_return corral::join;
        };

        io.st->written.clear();
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                co_await await_frame(io, 0);
                std::string_view pw;
                std::span<const std::byte> body(io.st->written.data() + 4, io.st->written.size() - 4);
                REQUIRE(agent::decode_lock(body, pw));
                REQUIRE(pw == "secret");
                io.feed(message([](wire::writer& w) { agent::encode_success(w); }));
            });
            const auto ec = co_await client.lock("secret");
            REQUIRE_FALSE(ec);
            co_return corral::join;
        };

        io.st->written.clear();
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                co_await await_frame(io, 0);
                std::string_view name;
                std::span<const std::byte> data;
                std::span<const std::byte> body(io.st->written.data() + 4, io.st->written.size() - 4);
                REQUIRE(agent::decode_extension(body, name, data));
                REQUIRE(name == "foo@example.com");
                REQUIRE(std::string_view{reinterpret_cast<const char*>(data.data()), data.size()} == "req");
                io.feed(message([](wire::writer& w) {
                    agent::encode_extension_response(w, "foo@example.com", as_bytes("xyz"));
                }));
            });
            auto [ec, rest] = co_await client.extension("foo@example.com", as_bytes("req"));
            REQUIRE_FALSE(ec);
            REQUIRE(rest == bytes_of("xyz"));
            co_return corral::join;
        };
        REQUIRE_FALSE(client.failure());

        io.st->written.clear();
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                co_await await_frame(io, 0);
                io.feed(message([](wire::writer& w) {
                    agent::encode_extension_response(w, "other", {});
                }));
            });
            auto [ec, rest] = co_await client.extension("foo@example.com", {});
            REQUIRE(ec == code::unexpected_message);
            REQUIRE(rest.empty());
            co_return corral::join;
        };
        REQUIRE(client.failure() == code::unexpected_message);
        const auto written_after_mismatch = io.st->written.size();
        auto [again, ids] = co_await client.list_identities();
        REQUIRE(again == code::unexpected_message);
        REQUIRE(ids.empty());
        REQUIRE(io.st->written.size() == written_after_mismatch);
    }());
}

TEST_CASE("agent query lists extensions and an extension failure does not latch", "[agent][client]") {
    TestLoop loop;
    corral::run(loop, []() -> corral::Task<void> {
        agent_io io;
        basic_agent_client<agent_io> client{io};
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                co_await await_frame(io, 0);
                wire::writer inner;
                inner.write_string("session-bind@openssh.com");
                wire::writer reply;
                agent::encode_extension_response(reply, "query", inner.data());
                io.feed(frame_of(reply.data()));
            });
            auto [ec, names] = co_await client.query_extensions();
            REQUIRE_FALSE(ec);
            REQUIRE(names.size() == 1);
            REQUIRE(names[0] == "session-bind@openssh.com");
            co_return corral::join;
        };
        REQUIRE_FALSE(client.failure());

        io.st->written.clear();
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                co_await await_frame(io, 0);
                io.feed(message([](wire::writer& w) { agent::encode_extension_failure(w); }));
            });
            auto [ec, rest] = co_await client.extension("nope@example.com", {});
            REQUIRE(ec == agent::refusal::extension_failure);
            REQUIRE(rest.empty());
            co_return corral::join;
        };
        REQUIRE_FALSE(client.failure());
    }());
}

