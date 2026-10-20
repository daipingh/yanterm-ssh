#pragma once

#include <yanterm-ssh/detail/config.hpp>

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <yanterm-ssh/crypto/openssl3.hpp>
#else
#include <yanterm-ssh/crypto/openssl11.hpp>
#endif

namespace yanterm::ssh::crypto {

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
namespace detail {
namespace ossl = ossl3;
}  // namespace detail
using openssl_backend = ossl3::openssl_backend;
#else
namespace detail {
namespace ossl = ossl1_1;
}  // namespace detail
using openssl_backend = ossl1_1::openssl_backend;
#endif

}  // namespace yanterm::ssh::crypto
