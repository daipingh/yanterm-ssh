#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/crypto/algorithms.hpp>
#include <yanterm-ssh/crypto/provider.hpp>
#include <yanterm-ssh/transport/packet_mode.hpp>

#include <string>
#include <string_view>

namespace yanterm::ssh::kex {

struct negotiated {
    crypto::kex_id kex{};
    std::string_view kex_name;
    crypto::sig_id host_key{};
    std::string_view host_key_name;
    crypto::hash_id exchange_hash{};        // the KEX method's hash
    crypto::cipher_id cipher_c2s{};
    crypto::cipher_id cipher_s2c{};
    crypto::hash_id mac_c2s{};              // ignored for AEAD modes
    crypto::hash_id mac_s2c{};
    transport::packet_mode mode_c2s{};
    transport::packet_mode mode_s2c{};
    bool strict_kex = false;
    bool peer_supports_ext_info = false;
};

std::string default_kex_algorithms(crypto::provider p);
std::string supported_kex_algorithms(crypto::provider p);
std::string default_host_key_algorithms(crypto::provider p);
std::string supported_host_key_algorithms(crypto::provider p);
std::string default_cipher_algorithms(crypto::provider p);
std::string supported_cipher_algorithms(crypto::provider p);
std::string default_mac_algorithms(crypto::provider p);
std::string supported_mac_algorithms(crypto::provider p);

}  // namespace yanterm::ssh::kex

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/kex/impl/algorithms.ipp>
#endif
