#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/crypto/provider.hpp>
#include <yanterm-ssh/keys/authorized_keys.hpp>
#include <yanterm-ssh/keys/known_hosts.hpp>
#include <yanterm-ssh/keys/private_key.hpp>
#include <yanterm-ssh/keys/public_key.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace yanterm::ssh::fuzz {
namespace {

constexpr std::uint32_t max_bcrypt_rounds = 2;
constexpr std::byte passphrase_bytes[] = {std::byte{'f'}, std::byte{'u'}, std::byte{'z'},
                                          std::byte{'z'}};
constexpr std::span<const std::byte> passphrase{passphrase_bytes};

}  // namespace

int fuzz_keys_one(std::span<const std::byte> input) {
    if (input.empty() || input.size() > 65536) {
        return 0;
    }

    static crypto::openssl_backend backend;
    static const crypto::provider prov = crypto::provider::wrap(backend);

    const auto selector = std::to_integer<std::uint8_t>(input[0]) % 5u;
    const auto payload = input.subspan(1);
    const std::string_view text{reinterpret_cast<const char*>(payload.data()), payload.size()};

    switch (selector) {
        case 0: {
            keys::public_key pub;
            if (!keys::public_key::parse_blob(payload, pub)) {
                (void)pub.algorithm();
                (void)pub.algorithm_name();
                (void)pub.blob();
                (void)pub.material();
            }
            break;
        }
        case 1: {
            keys::public_key pub;
            std::string comment;
            if (!keys::public_key::parse_line(text, pub, &comment)) {
                (void)pub.algorithm();
                (void)pub.algorithm_name();
                (void)pub.blob();
            }
            keys::public_key pub2;
            if (!keys::public_key::parse_authorized_key_body(text, pub2)) {
                (void)pub2.algorithm();
                (void)pub2.algorithm_name();
                (void)pub2.blob();
            }
            break;
        }
        case 2: {
            // bcrypt cost is linear in rounds; past a handful each input takes
            // long enough to stall the fuzzer without reaching new code.
            const keys::private_key_info info = keys::private_key::inspect(payload);
            if (info.bcrypt_rounds > max_bcrypt_rounds) {
                return 0;
            }
            keys::private_key priv;
            if (!keys::private_key::parse(payload, prov, passphrase, priv)) {
                (void)priv.pub().blob();
                (void)priv.material();
                (void)priv.comment();
            }
            break;
        }
        case 3: {
            keys::known_hosts kh;
            if (!keys::known_hosts::parse(text, kh)) {
                (void)kh.lines().size();
            }
            break;
        }
        case 4: {
            keys::authorized_keys ak;
            if (!keys::authorized_keys::parse(text, ak)) {
                (void)ak.lines().size();
            }
            break;
        }
    }

    return 0;
}

}  // namespace yanterm::ssh::fuzz

#if defined(YANTERM_SSH_FUZZER_STANDALONE)
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    return yanterm::ssh::fuzz::fuzz_keys_one(
        std::span<const std::byte>{reinterpret_cast<const std::byte*>(data), size});
}
#endif
