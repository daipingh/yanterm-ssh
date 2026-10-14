#pragma once

#include "handshake_fixture.hpp"
#include "memory_pipe.hpp"
#include "test_loop.hpp"

#include <yanterm-ssh/keys/private_key.hpp>
#include <yanterm-ssh/options.hpp>
#include <yanterm-ssh/session.hpp>

#include <auv/stream.hpp>

#include <utility>

namespace yanterm::ssh::testing {

inline keys::private_key parse_host_key_file(crypto::provider p, std::string_view name) {
    keys::private_key hk;
    REQUIRE_FALSE(keys::private_key::parse(load_fixture(name), p, {}, hk));
    return hk;
}

struct facade_pair {
    TestLoop loop;
    client_session client;
    server_session server;
};

inline facade_pair make_facade_pair(client_options co = {}, server_options so = {}) {
    facade_pair fp;
    auto [a, b] = memory_pipe::make(fp.loop);
    auto p = prov();
    if (so.host_keys.empty()) {
        so.host_keys.push_back(parse_host_key_file(p, "id_ed25519"));
    }
    fp.client = client_session{auv::stream::own(std::move(a)), p, std::move(co)};
    fp.server = server_session{auv::stream::own(std::move(b)), p, std::move(so)};
    return fp;
}

}  // namespace yanterm::ssh::testing
