#pragma once

#include <yanterm-ssh/crypto/provider.hpp>

#include <openssl/opensslv.h>
#include <openssl/rand.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#endif

#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <span>

namespace yanterm::ssh::testing {

// Decorates a real provider, replacing only random_bytes with a deterministic
// stream. Other slots (hash/hmac/cipher/aead/poly1305, and unoverridden
// supports / constant_time_eq) are forwarded by provider::decorate.
//
// OpenSSL's kex_new / kem_new / kem_encaps / ECDSA sig_sign / generate_keypair
// still call RAND_bytes internally. Those overlay entry points open a
// rand_scope that routes OpenSSL randomness to this instance's PRNG so
// multiple fixed_random_provider objects can coexist (client + server
// loopback) without sharing one process-global stream.
class fixed_random_provider {
public:
    fixed_random_provider(crypto::provider inner, std::uint64_t seed)
        : inner_{inner} {
        seed_prng(rng_, seed);
    }

    fixed_random_provider(const fixed_random_provider&) = delete;
    fixed_random_provider& operator=(const fixed_random_provider&) = delete;
    fixed_random_provider(fixed_random_provider&&) = delete;
    fixed_random_provider& operator=(fixed_random_provider&&) = delete;

    [[nodiscard]] crypto::provider inner() const noexcept { return inner_; }
    [[nodiscard]] crypto::provider get() noexcept {
        return crypto::provider::decorate(*this);
    }

    bool random_bytes(std::byte* out, std::size_t len) noexcept {
        fill_random(out, len);
        return true;
    }

    void* kex_new(crypto::kex_id id) noexcept {
        rand_scope scope{this};
        auto h = inner_.new_kex(id);
        if (!h) return nullptr;
        return new (std::nothrow) crypto::kex_agreement(std::move(h));
    }
    void kex_free(void* ctx) noexcept { delete static_cast<crypto::kex_agreement*>(ctx); }
    bool kex_public(void* ctx, std::byte* out, std::size_t cap, std::size_t* out_len) noexcept {
        if (ctx == nullptr || out_len == nullptr) return false;
        return static_cast<crypto::kex_agreement*>(ctx)->public_value(
            std::span<std::byte>{out, cap}, *out_len);
    }
    bool kex_agree(void* ctx, const std::byte* peer, std::size_t peerlen, std::byte* out,
                   std::size_t cap, std::size_t* out_len) noexcept {
        if (ctx == nullptr || out_len == nullptr) return false;
        return static_cast<crypto::kex_agreement*>(ctx)->agree(
            std::span<const std::byte>{peer, peerlen}, std::span<std::byte>{out, cap}, *out_len);
    }

    bool sig_verify(const crypto::public_key_material* key, const std::byte* msg,
                    std::size_t msglen, const crypto::signature_material* sig) noexcept {
        if (key == nullptr || sig == nullptr) return false;
        return inner_.verify(*key, std::span<const std::byte>{msg, msglen}, *sig);
    }
    void* signing_key_new(const crypto::private_key_material* key) noexcept {
        if (key == nullptr) return nullptr;
        auto h = inner_.new_signing_key(*key);
        if (!h) return nullptr;
        return new (std::nothrow) crypto::signing_key(std::move(h));
    }
    void signing_key_free(void* handle) noexcept {
        delete static_cast<crypto::signing_key*>(handle);
    }
    bool sig_sign(void* handle, const std::byte* msg, std::size_t msglen, std::byte* out,
                  std::size_t cap, std::size_t* out_len) noexcept {
        rand_scope scope{this};
        if (handle == nullptr || out_len == nullptr) return false;
        return static_cast<crypto::signing_key*>(handle)->sign(
            std::span<const std::byte>{msg, msglen}, std::span<std::byte>{out, cap}, *out_len);
    }

    bool generate_keypair(crypto::sig_id id, std::uint32_t bits,
                          crypto::private_key_material* out, std::byte* storage,
                          std::size_t storage_cap, std::size_t* storage_used) noexcept {
        rand_scope scope{this};
        if (out == nullptr || storage_used == nullptr) return false;
        if (!inner_.generate_keypair(id, bits, *out, std::span<std::byte>{storage, storage_cap})) {
            return false;
        }
        *storage_used = storage_cap;
        return true;
    }

    void* kem_new(crypto::kem_id id) noexcept {
        rand_scope scope{this};
        auto h = inner_.new_kem(id);
        if (!h) return nullptr;
        return new (std::nothrow) crypto::kem_keypair(std::move(h));
    }
    void kem_free(void* ctx) noexcept { delete static_cast<crypto::kem_keypair*>(ctx); }
    bool kem_public(void* ctx, std::byte* out, std::size_t cap, std::size_t* out_len) noexcept {
        if (ctx == nullptr || out_len == nullptr) return false;
        return static_cast<crypto::kem_keypair*>(ctx)->public_key(
            std::span<std::byte>{out, cap}, *out_len);
    }
    bool kem_decaps(void* ctx, const std::byte* ct, std::size_t ctlen, std::byte* ss,
                    std::size_t cap, std::size_t* ss_len) noexcept {
        if (ctx == nullptr || ss_len == nullptr) return false;
        return static_cast<crypto::kem_keypair*>(ctx)->decapsulate(
            std::span<const std::byte>{ct, ctlen}, std::span<std::byte>{ss, cap}, *ss_len);
    }
    bool kem_encaps(crypto::kem_id id, const std::byte* pub, std::size_t publen, std::byte* ct,
                    std::size_t ctcap, std::size_t* ct_len, std::byte* ss, std::size_t sscap,
                    std::size_t* ss_len) noexcept {
        rand_scope scope{this};
        if (ct_len == nullptr || ss_len == nullptr) return false;
        return inner_.encapsulate(id, std::span<const std::byte>{pub, publen},
                                  std::span<std::byte>{ct, ctcap}, *ct_len,
                                  std::span<std::byte>{ss, sscap}, *ss_len);
    }

private:
    struct xoshiro256ss {
        std::uint64_t s[4]{};
    };

    static std::uint64_t splitmix64(std::uint64_t& x) noexcept {
        x += 0x9e3779b97f4a7c15ull;
        std::uint64_t z = x;
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
        return z ^ (z >> 31);
    }

    static void seed_prng(xoshiro256ss& rng, std::uint64_t seed) noexcept {
        std::uint64_t x = seed;
        rng.s[0] = splitmix64(x);
        rng.s[1] = splitmix64(x);
        rng.s[2] = splitmix64(x);
        rng.s[3] = splitmix64(x);
    }

    static std::uint64_t rotl(std::uint64_t x, int k) noexcept {
        return (x << k) | (x >> (64 - k));
    }

    static std::uint64_t next_u64(xoshiro256ss& rng) noexcept {
        const std::uint64_t result = rotl(rng.s[1] * 5, 7) * 9;
        const std::uint64_t t = rng.s[1] << 17;
        rng.s[2] ^= rng.s[0];
        rng.s[3] ^= rng.s[1];
        rng.s[1] ^= rng.s[2];
        rng.s[0] ^= rng.s[3];
        rng.s[2] ^= t;
        rng.s[3] = rotl(rng.s[3], 45);
        return result;
    }

    void fill_random(std::byte* out, std::size_t len) noexcept {
        while (len > 0) {
            const std::uint64_t v = next_u64(rng_);
            const std::size_t n = len < 8 ? len : 8;
            for (std::size_t i = 0; i < n; ++i) {
                out[i] = static_cast<std::byte>((v >> (8 * i)) & 0xffu);
            }
            out += n;
            len -= n;
        }
    }

    // Scoped OpenSSL RAND redirection for one call into the inner backend.
    struct rand_scope {
        fixed_random_provider* prev_active = nullptr;
        static inline fixed_random_provider* active = nullptr;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        // Every DRBG of the default libctx is YANTERM-FIXED-RAND. OpenSSL 3.0
        // cannot swap DRBGs once instantiated, so the type is installed before
        // first use and generate dispatches on `active`, forwarding to a
        // private libctx when no scope is open.
        static inline OSSL_LIB_CTX* fallback_libctx = nullptr;

        static void* rand_newctx(void*, void*, const OSSL_DISPATCH*) noexcept {
            return reinterpret_cast<void*>(1);
        }
        static void rand_freectx(void*) noexcept {}
        static int rand_instantiate(void*, unsigned int, int, const unsigned char*,
                                    std::size_t, const OSSL_PARAM*) noexcept {
            return 1;
        }
        static int rand_uninstantiate(void*) noexcept { return 1; }
        static int rand_generate(void*, unsigned char* out, std::size_t outlen,
                                 unsigned int strength, int, const unsigned char*,
                                 std::size_t) noexcept {
            if (out == nullptr) return 0;
            if (active == nullptr) {
                // A null libctx would recurse into this provider.
                if (fallback_libctx == nullptr) return 0;
                return RAND_bytes_ex(fallback_libctx, out, outlen, strength) == 1 ? 1 : 0;
            }
            active->fill_random(reinterpret_cast<std::byte*>(out), outlen);
            return 1;
        }
        static int rand_enable_locking(void*) noexcept { return 1; }
        static const OSSL_PARAM* rand_gettable_ctx_params(void*, void*) noexcept {
            static const OSSL_PARAM table[] = {
                OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, nullptr),
                OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, nullptr),
                OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, nullptr),
                OSSL_PARAM_END,
            };
            return table;
        }
        static int rand_get_ctx_params(void*, OSSL_PARAM params[]) noexcept {
            OSSL_PARAM* p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
            if (p != nullptr && !OSSL_PARAM_set_int(p, EVP_RAND_STATE_READY)) return 0;
            p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
            if (p != nullptr && !OSSL_PARAM_set_uint(p, 256)) return 0;
            p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
            if (p != nullptr
                && !OSSL_PARAM_set_size_t(p, static_cast<std::size_t>(INT_MAX))) {
                return 0;
            }
            return 1;
        }
        static const OSSL_ALGORITHM* prov_query(void*, int op_id, int* no_store) noexcept {
            static const OSSL_DISPATCH rand_fns[] = {
                {OSSL_FUNC_RAND_NEWCTX, reinterpret_cast<void (*)()>(&rand_newctx)},
                {OSSL_FUNC_RAND_FREECTX, reinterpret_cast<void (*)()>(&rand_freectx)},
                {OSSL_FUNC_RAND_INSTANTIATE,
                 reinterpret_cast<void (*)()>(&rand_instantiate)},
                {OSSL_FUNC_RAND_UNINSTANTIATE,
                 reinterpret_cast<void (*)()>(&rand_uninstantiate)},
                {OSSL_FUNC_RAND_GENERATE, reinterpret_cast<void (*)()>(&rand_generate)},
                {OSSL_FUNC_RAND_ENABLE_LOCKING,
                 reinterpret_cast<void (*)()>(&rand_enable_locking)},
                {OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
                 reinterpret_cast<void (*)()>(&rand_gettable_ctx_params)},
                {OSSL_FUNC_RAND_GET_CTX_PARAMS,
                 reinterpret_cast<void (*)()>(&rand_get_ctx_params)},
                {0, nullptr},
            };
            static const OSSL_ALGORITHM rand_algs[] = {
                {"YANTERM-FIXED-RAND", "provider=yanterm-fixed-rand", rand_fns, nullptr},
                {nullptr, nullptr, nullptr, nullptr},
            };
            if (no_store != nullptr) *no_store = 0;
            if (op_id == OSSL_OP_RAND) return rand_algs;
            return nullptr;
        }
        static int prov_init(const OSSL_CORE_HANDLE*, const OSSL_DISPATCH*,
                             const OSSL_DISPATCH** out, void** provctx) noexcept {
            static const OSSL_DISPATCH prov_fns[] = {
                {OSSL_FUNC_PROVIDER_QUERY_OPERATION,
                 reinterpret_cast<void (*)()>(&prov_query)},
                {0, nullptr},
            };
            *out = prov_fns;
            *provctx = reinterpret_cast<void*>(1);
            return 1;
        }
        struct installation {
            OSSL_PROVIDER* def_prov = nullptr;
            OSSL_PROVIDER* fix_prov = nullptr;

            // OPENSSL_init_crypto runs first so this destructor precedes
            // OpenSSL's atexit cleanup.
            installation() noexcept {
                const bool ok =
                    OPENSSL_init_crypto(0, nullptr) == 1
                    && (fallback_libctx = OSSL_LIB_CTX_new()) != nullptr
                    && (def_prov = OSSL_PROVIDER_load(nullptr, "default")) != nullptr
                    && OSSL_PROVIDER_add_builtin(nullptr, "yanterm-fixed-rand", &prov_init) == 1
                    && (fix_prov = OSSL_PROVIDER_load(nullptr, "yanterm-fixed-rand")) != nullptr
                    && RAND_set_DRBG_type(nullptr, "YANTERM-FIXED-RAND",
                                          "provider=yanterm-fixed-rand", nullptr, nullptr)
                           == 1;
                if (!ok) {
                    std::fputs("fixed_random_provider: OpenSSL randomness was used before "
                               "YANTERM-FIXED-RAND could be installed\n",
                               stderr);
                    std::abort();
                }
            }

            ~installation() {
                OSSL_LIB_CTX* ctx = fallback_libctx;
                fallback_libctx = nullptr;
                OSSL_LIB_CTX_free(ctx);
                OSSL_PROVIDER_unload(fix_prov);
                OSSL_PROVIDER_unload(def_prov);
            }

            installation(const installation&) = delete;
            installation& operator=(const installation&) = delete;
        };
        // Must run before anything instantiates the default libctx DRBGs.
        static inline installation installed{};

        explicit rand_scope(fixed_random_provider* s) noexcept {
            (void)installed;
            prev_active = active;
            active = s;
        }

        ~rand_scope() { active = prev_active; }
#else
        const RAND_METHOD* prev_method;
        bool prev_installed;
        static inline const RAND_METHOD* saved_method = nullptr;
        static inline bool installed = false;

        static int bytes(unsigned char* buf, int num) {
            if (active == nullptr || buf == nullptr || num < 0) return 0;
            active->fill_random(reinterpret_cast<std::byte*>(buf), static_cast<std::size_t>(num));
            return 1;
        }
        static int status() { return 1; }

        explicit rand_scope(fixed_random_provider* s) noexcept {
            static RAND_METHOD method = {
                nullptr, bytes, nullptr, nullptr, bytes, status,
            };
            prev_active = active;
            prev_method = saved_method;
            prev_installed = installed;
            if (!installed) {
                saved_method = RAND_get_rand_method();
                installed = true;
            }
            active = s;
            RAND_set_rand_method(&method);
        }

        ~rand_scope() {
            active = prev_active;
            if (prev_active != nullptr) {
                // Nested scope: keep method installed, restore active only.
                return;
            }
            if (prev_installed) {
                if (prev_method != nullptr) RAND_set_rand_method(prev_method);
                saved_method = prev_method;
                installed = prev_installed;
            } else {
                if (saved_method != nullptr) RAND_set_rand_method(saved_method);
                saved_method = nullptr;
                installed = false;
            }
        }
#endif

        rand_scope(const rand_scope&) = delete;
        rand_scope& operator=(const rand_scope&) = delete;
    };

    crypto::provider inner_;
    xoshiro256ss rng_{};
};

}  // namespace yanterm::ssh::testing
