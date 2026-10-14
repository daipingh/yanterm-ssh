#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/core/detail/host_key.hpp>
#include <yanterm-ssh/memory/detail/pages.hpp>
#include <yanterm-ssh/core/detail/packet.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/keys/public_key.hpp>
#include <yanterm-ssh/keys/private_key.hpp>
#include <yanterm-ssh/wire/types.hpp>

#include <array>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace yanterm::ssh;

namespace {

crypto::provider prov() {
    static crypto::openssl_backend backend;
    return crypto::provider::wrap(backend);
}

std::vector<std::byte> unhex(std::string_view s) {
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return c - 'A' + 10;
    };
    std::vector<std::byte> out;
    for (std::size_t i = 0; i + 1 < s.size(); i += 2) {
        out.push_back(static_cast<std::byte>(nibble(s[i]) * 16 + nibble(s[i + 1])));
    }
    return out;
}

std::string hex(std::span<const std::byte> in) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    for (std::byte b : in) {
        out.push_back(kDigits[std::to_integer<unsigned>(b) >> 4]);
        out.push_back(kDigits[std::to_integer<unsigned>(b) & 0x0Fu]);
    }
    return out;
}

std::span<const std::byte> bytes_of(std::string_view s) {
    return {reinterpret_cast<const std::byte*>(s.data()), s.size()};
}

const auto k_dc = unhex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
const auto k_ds = unhex("59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21");
const auto k_qc = unhex(
    "04"
    "09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020"
    "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13");
const auto k_qs = unhex(
    "04"
    "04ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73"
    "e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df0");

[[nodiscard]] crypto::signing_key import_sm2(std::span<const std::byte> d,
                                             std::span<const std::byte> q) {
    crypto::private_key_material key;
    key.algorithm = crypto::sig_id::sm2_ecdsa;
    key.seed = d;
    key.public_key = q;
    return prov().new_signing_key(key);
}

// Fixed-key agreement through kex_group_agree, the function provider::kex_agree
// calls. Role comes from kex_id. signing_key owns the key; the kex only borrows it.
[[nodiscard]] bool fixed_key_agree(const crypto::signing_key& self, crypto::kex_id id,
                                   std::span<const std::byte> peer, unsigned char out[32]) {
    auto* sk = static_cast<crypto::detail::openssl_signing_key*>(self.get());
    if (sk == nullptr || sk->pkey == nullptr) return false;
    crypto::detail::ossl::openssl_kex kex{};
    kex.id = id;
    kex.pkey = sk->pkey;
    std::size_t len = 0;
    const bool ok = crypto::detail::ossl::kex_group_agree(
        &kex, peer.data(), peer.size(), reinterpret_cast<std::byte*>(out), 32, &len);
    kex.pkey = nullptr;
    return ok && len == 32;
}

}  // namespace

TEST_CASE("SM3 matches GB/T 32905 abc and empty vectors", "[crypto][gm][sm3]") {
    crypto::provider p = prov();
    REQUIRE(p.supports(crypto::hash_id::sm3));
    std::array<std::byte, 32> out{};
    REQUIRE(p.hash(crypto::hash_id::sm3, bytes_of("abc"), out));
    REQUIRE(hex(out) == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
    REQUIRE(p.hash(crypto::hash_id::sm3, std::span<const std::byte>{}, out));
    REQUIRE(hex(out) == "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b");
}

TEST_CASE("HMAC-SM3 matches the published key/hello vector", "[crypto][gm][sm3]") {
    crypto::provider p = prov();
    crypto::hmac_ctx m = p.new_hmac(crypto::hash_id::sm3, bytes_of("key"));
    REQUIRE(static_cast<bool>(m));
    m.update(bytes_of("hello"));
    std::array<std::byte, 32> out{};
    REQUIRE(m.final_into(out));
    REQUIRE(hex(out) == "798a6ca374c9ac891982f87a4f4c4d60bd6cdddfe8fb0fa344393621a0c02d96");
}

TEST_CASE("SM4-CBC matches GB/T 32907 one-block vector", "[crypto][gm][sm4]") {
    crypto::provider p = prov();
    REQUIRE(p.supports(crypto::cipher_id::sm4_cbc));
    const auto key = unhex("0123456789ABCDEFFEDCBA9876543210");
    const auto iv = unhex("00000000000000000000000000000000");
    const auto plain = unhex("0123456789ABCDEFFEDCBA9876543210");
    std::vector<std::byte> out(plain.size());
    REQUIRE(p.cbc_crypt(crypto::cipher_id::sm4_cbc, true, key, iv, plain, out));
    REQUIRE(hex(out) == "681edf34d206965e86b3e94f536e4246");
    std::vector<std::byte> back(plain.size());
    REQUIRE(p.cbc_crypt(crypto::cipher_id::sm4_cbc, false, key, iv, out, back));
    REQUIRE(hex(back) == hex(plain));
}

TEST_CASE("SM4-CTR round-trips and is distinct from CBC", "[crypto][gm][sm4]") {
    crypto::provider p = prov();
    REQUIRE(p.supports(crypto::cipher_id::sm4_ctr));
    const auto key = unhex("0123456789ABCDEFFEDCBA9876543210");
    const auto iv = unhex("00000000000000000000000000000000");
    const auto plain = unhex("0123456789ABCDEFFEDCBA9876543210");
    crypto::cipher c = p.new_cipher(crypto::cipher_id::sm4_ctr, key, true);
    REQUIRE(static_cast<bool>(c));
    REQUIRE(c.set_iv(iv));
    std::vector<std::byte> ct(plain.size());
    REQUIRE(c.update(plain, ct));
    REQUIRE(hex(ct) != "681edf34d206965e86b3e94f536e4246");
    crypto::cipher d = p.new_cipher(crypto::cipher_id::sm4_ctr, key, true);
    REQUIRE(d.set_iv(iv));
    std::vector<std::byte> back(plain.size());
    REQUIRE(d.update(ct, back));
    REQUIRE(hex(back) == hex(plain));
}

TEST_CASE("sm2-sm3 KAP matches appendix C.2 on both roles", "[crypto][gm][kap]") {
    unsigned char kc[32];
    unsigned char ks[32];
    crypto::signing_key client = import_sm2(k_dc, k_qc);
    crypto::signing_key server = import_sm2(k_ds, k_qs);
    REQUIRE(static_cast<bool>(client));
    REQUIRE(static_cast<bool>(server));
    REQUIRE(fixed_key_agree(client, crypto::kex_id::sm2_kap, k_qs, kc));
    REQUIRE(fixed_key_agree(server, crypto::kex_id::sm2_kap_server, k_qc, ks));
    REQUIRE(hex(std::span<const std::byte>{reinterpret_cast<const std::byte*>(kc), 32})
            == "00910f9c0cc60053e897e87ebd5ae6cb18eddd7eaaad97784368398a0802765a");
    REQUIRE(hex(std::span<const std::byte>{reinterpret_cast<const std::byte*>(ks), 32})
            == hex(std::span<const std::byte>{reinterpret_cast<const std::byte*>(kc), 32}));
}

TEST_CASE("ecgm-sm2-sm3 ECDH x matches appendix C.3 and differs from KAP", "[crypto][gm][ecdh]") {
    unsigned char k_ecdh[32];
    unsigned char k_ecdh_s[32];
    unsigned char k_kap[32];
    crypto::signing_key client = import_sm2(k_dc, k_qc);
    crypto::signing_key server = import_sm2(k_ds, k_qs);
    REQUIRE(static_cast<bool>(client));
    REQUIRE(static_cast<bool>(server));
    REQUIRE(fixed_key_agree(client, crypto::kex_id::ecdh_sm2, k_qs, k_ecdh));
    REQUIRE(fixed_key_agree(server, crypto::kex_id::ecdh_sm2, k_qc, k_ecdh_s));
    REQUIRE(fixed_key_agree(client, crypto::kex_id::sm2_kap, k_qs, k_kap));
    REQUIRE(hex(std::span<const std::byte>{reinterpret_cast<const std::byte*>(k_ecdh), 32})
            == "335e18d751e51f040e27d468138b7ab1dc86ad7f981d7d416222fd6ab3ed230d");
    REQUIRE(hex(std::span<const std::byte>{reinterpret_cast<const std::byte*>(k_ecdh_s), 32})
            == hex(std::span<const std::byte>{reinterpret_cast<const std::byte*>(k_ecdh), 32}));
    REQUIRE(hex(std::span<const std::byte>{reinterpret_cast<const std::byte*>(k_kap), 32})
            != hex(std::span<const std::byte>{reinterpret_cast<const std::byte*>(k_ecdh), 32}));
}

TEST_CASE("SM2 public blob is sm2/sm2/Q", "[keys][gm]") {
    crypto::public_key_material m;
    m.algorithm = crypto::sig_id::sm2_za;
    m.a = k_qc;
    keys::public_key pk;
    REQUIRE_FALSE(keys::public_key::from_material(m, pk));
    REQUIRE(pk.algorithm_name() == "sm2");
    REQUIRE(pk.algorithm() == crypto::sig_id::sm2_za);
    REQUIRE(pk.material().a.size() == 65);

    keys::public_key parsed;
    REQUIRE_FALSE(keys::public_key::parse_blob(pk.blob(), parsed));
    REQUIRE(parsed.algorithm_name() == "sm2");
    REQUIRE(hex(parsed.material().a) == hex(k_qc));
}

TEST_CASE("SM2 host signatures round-trip in both dialects", "[kex][gm][sig]") {
    crypto::provider p = prov();
    std::array<std::byte, crypto::max_generated_key_storage> storage{};
    crypto::private_key_material priv{};
    REQUIRE(p.generate_keypair(crypto::sig_id::sm2_za, 0, priv, storage));
    REQUIRE(priv.public_key.size() == 65);

    const auto msg = bytes_of("yanterm-ssh gm host signature");

    auto sign_and_verify = [&](crypto::sig_id dialect) {
        crypto::private_key_material sk = priv;
        sk.algorithm = dialect;
        auto signer = p.new_signing_key(sk);
        REQUIRE(static_cast<bool>(signer));
        std::array<std::byte, crypto::max_signature_size> raw{};
        std::size_t len = 0;
        REQUIRE(signer.sign(msg, raw, len));
        REQUIRE(len > 0);

        wire::writer blob;
        REQUIRE_FALSE(core::detail::encode_signature("sm2", std::span<const std::byte>{raw}.first(len), blob));

        crypto::public_key_material pub;
        pub.algorithm = crypto::sig_id::sm2_za;
        pub.a = priv.public_key;
        keys::public_key pk;
        REQUIRE_FALSE(keys::public_key::from_material(pub, pk));
        core::detail::host_key_view view;
        REQUIRE_FALSE(core::detail::parse_host_key(pk.blob(), view));
        crypto::sig_id used{};
        REQUIRE_FALSE(core::detail::verify_signature(p, view, "sm2", blob.data(), msg, &used));
        REQUIRE(used == dialect);
    };

    sign_and_verify(crypto::sig_id::sm2_za);
    sign_and_verify(crypto::sig_id::sm2_ecdsa);
}

TEST_CASE("SM2 generate/parse OpenSSH private key", "[keys][gm]") {
    crypto::provider p = prov();
    keys::private_key sk;
    REQUIRE_FALSE(keys::private_key::generate(p, crypto::sig_id::sm2_za, 0, "gm", sk));
    REQUIRE(sk.pub().algorithm_name() == "sm2");
    std::vector<std::byte> file;
    REQUIRE_FALSE(sk.serialize(p, {}, "none", file));
    keys::private_key loaded;
    REQUIRE_FALSE(keys::private_key::parse(file, p, {}, loaded));
    REQUIRE(loaded.pub().algorithm_name() == "sm2");
    REQUIRE(hex(loaded.pub().material().a) == hex(sk.pub().material().a));
}

TEST_CASE("SM4-CTR and SM4-CBC packets round-trip with hmac-sm3", "[packet][gm][sm4]") {
    crypto::provider p = prov();
    const auto payload = bytes_of("gm-packet");
    std::array<std::byte, 16> key{};
    std::array<std::byte, 16> iv{};
    std::array<std::byte, 32> mac_key{};
    for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::byte>(0x11 + i);
    for (std::size_t i = 0; i < iv.size(); ++i) iv[i] = static_cast<std::byte>(0x21 + i);
    for (std::size_t i = 0; i < mac_key.size(); ++i) mac_key[i] = static_cast<std::byte>(0x31 + i);

    auto roundtrip = [&](crypto::cipher_id id, core::detail::packet_mode mode) {
        const bool cbc = mode == core::detail::packet_mode::cbc_encrypt_and_mac
                      || mode == core::detail::packet_mode::cbc_encrypt_then_mac;
        auto make_state = [&](bool encrypt) {
            core::detail::direction_state s;
            s.mode = mode;
            s.block_size = 16;
            s.mac_length = 32;
            s.cipher = p.new_cipher(id, key, cbc ? encrypt : true);
            REQUIRE(static_cast<bool>(s.cipher));
            REQUIRE(s.cipher.set_iv(iv));
            s.mac = p.new_hmac(crypto::hash_id::sm3, mac_key);
            REQUIRE(static_cast<bool>(s.mac));
            return s;
        };
        core::detail::packet_writer w{p};
        core::detail::packet_reader r{p};
        w.install(make_state(true));
        r.install(make_state(false));
        memory::detail::page_pool pool;
        memory::detail::page_slice slice;
        REQUIRE_FALSE(w.write(payload, pool, slice));
        std::size_t consumed = 0;
        memory::detail::page_slice got;
        REQUIRE_FALSE(r.read(slice.bytes(), consumed, pool, got));
        REQUIRE(consumed == slice.bytes().size());
        REQUIRE(hex(got.bytes()) == hex(payload));
    };

    roundtrip(crypto::cipher_id::sm4_ctr, core::detail::packet_mode::ctr_encrypt_and_mac);
    roundtrip(crypto::cipher_id::sm4_cbc, core::detail::packet_mode::cbc_encrypt_and_mac);
    roundtrip(crypto::cipher_id::sm4_cbc, core::detail::packet_mode::cbc_encrypt_then_mac);
}
