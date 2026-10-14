#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/keys/authorized_keys.hpp>
#include <yanterm-ssh/keys/detail/base64.hpp>
#include <yanterm-ssh/keys/public_key.hpp>

#include <algorithm>
#include <fstream>
#include <string>
#include <string_view>

#ifndef YANTERM_SSH_FIXTURE_DIR
#error "YANTERM_SSH_FIXTURE_DIR must be defined"
#endif

using namespace yanterm::ssh;

namespace {

std::string load_text(std::string_view name) {
    const std::string path = std::string{YANTERM_SSH_FIXTURE_DIR} + "/" + std::string{name};
    std::ifstream in{path, std::ios::binary};
    REQUIRE(in);
    in.seekg(0, std::ios::end);
    const auto n = static_cast<std::size_t>(in.tellg());
    in.seekg(0, std::ios::beg);
    std::string out(n, '\0');
    if (n > 0) {
        in.read(out.data(), static_cast<std::streamsize>(n));
        REQUIRE(in);
    }
    return out;
}

keys::public_key load_ed25519_pub() {
    keys::public_key key;
    std::string comment;
    REQUIRE_FALSE(keys::public_key::parse_line(load_text("id_ed25519.pub"), key, &comment));
    return key;
}

std::string key_b64(const keys::public_key& key) {
    return keys::detail::base64_encode(key.blob(), true);
}

bool blobs_equal(const keys::public_key& a, const keys::public_key& b) {
    const auto xa = a.blob();
    const auto xb = b.blob();
    return xa.size() == xb.size() && std::equal(xa.begin(), xa.end(), xb.begin());
}

}  // namespace

TEST_CASE("authorized_keys splits opaque options", "[keys][authorized]") {
    const auto key = load_ed25519_pub();
    const std::string b64 = key_b64(key);
    const std::string text =
        "command=\"/bin/true\",no-pty ssh-ed25519 " + b64 + " user@host\n";

    keys::authorized_keys ak;
    REQUIRE_FALSE(keys::authorized_keys::parse(text, ak));
    REQUIRE(ak.lines().size() == 1);
    REQUIRE(ak.lines()[0].key.has_value());
    REQUIRE(blobs_equal(*ak.lines()[0].key, key));
    REQUIRE(ak.lines()[0].options.find("command=") != std::string::npos);
    REQUIRE(ak.lines()[0].options.find("no-pty") != std::string::npos);
    REQUIRE(ak.lines()[0].comment.find("user@host") != std::string::npos);
}

TEST_CASE("authorized_keys round-trips options string", "[keys][authorized]") {
    const auto key = load_ed25519_pub();
    const std::string b64 = key_b64(key);
    const std::string options = R"(command="echo \"hi\"",no-pty)";
    const std::string text = options + " ssh-ed25519 " + b64 + " user@host\n";

    keys::authorized_keys ak;
    REQUIRE_FALSE(keys::authorized_keys::parse(text, ak));
    REQUIRE(ak.lines().size() == 1);
    REQUIRE(ak.lines()[0].key.has_value());
    REQUIRE(ak.lines()[0].options == options);
    REQUIRE(ak.lines()[0].comment == "user@host");

    const std::string dumped = ak.serialize();
    keys::authorized_keys again;
    REQUIRE_FALSE(keys::authorized_keys::parse(dumped, again));
    REQUIRE(again.lines().size() == 1);
    REQUIRE(again.lines()[0].options == ak.lines()[0].options);
    REQUIRE(again.lines()[0].comment == ak.lines()[0].comment);
    REQUIRE(again.lines()[0].key.has_value());
    REQUIRE(blobs_equal(*again.lines()[0].key, key));
}

TEST_CASE("cert and sk lines are opaque and do not fail the file", "[keys][authorized]") {
    const auto key = load_ed25519_pub();
    const std::string b64 = key_b64(key);
    const std::string cert_line =
        "ssh-ed25519-cert-v01@openssh.com " + b64 + " cert-user";
    const std::string sk_line = "sk-ssh-ed25519@openssh.com " + b64 + " sk-user";
    const std::string real_line = "ssh-ed25519 " + b64 + " real";
    const std::string text = cert_line + "\n" + sk_line + "\n" + real_line + "\n"
                             "# keep this comment\n"
                             "\n"
                             "ssh-ed25519 not-valid-base64!!!! junk\n";

    keys::authorized_keys ak;
    REQUIRE_FALSE(keys::authorized_keys::parse(text, ak));
    REQUIRE(ak.lines().size() == 6);

    std::size_t keyed = 0;
    for (const auto& line : ak.lines()) {
        if (line.key.has_value()) ++keyed;
    }
    REQUIRE(keyed == 1);

    REQUIRE_FALSE(ak.lines()[0].key.has_value());
    REQUIRE(ak.lines()[0].raw == cert_line);
    REQUIRE(ak.lines()[0].options.empty());
    REQUIRE_FALSE(ak.lines()[1].key.has_value());
    REQUIRE(ak.lines()[1].raw == sk_line);
    REQUIRE(ak.lines()[1].options.empty());
    REQUIRE(ak.lines()[2].key.has_value());
    REQUIRE(blobs_equal(*ak.lines()[2].key, key));
    REQUIRE(ak.lines()[2].options.empty());
    REQUIRE(ak.lines()[2].comment == "real");
    REQUIRE_FALSE(ak.lines()[3].key.has_value());
    REQUIRE(ak.lines()[3].raw == "# keep this comment");
    REQUIRE_FALSE(ak.lines()[4].key.has_value());
    REQUIRE(ak.lines()[4].raw.empty());
    REQUIRE_FALSE(ak.lines()[5].key.has_value());
    REQUIRE(ak.lines()[5].raw.find("not-valid-base64") != std::string::npos);
    REQUIRE(ak.lines()[5].options.empty());

    const std::string dumped = ak.serialize();
    REQUIRE(dumped.find(cert_line + "\n") != std::string::npos);
    REQUIRE(dumped.find(sk_line + "\n") != std::string::npos);
    REQUIRE(dumped.find("# keep this comment\n") != std::string::npos);
    REQUIRE(dumped.find("\n\n") != std::string::npos);
    REQUIRE(dumped.find("not-valid-base64!!!!") != std::string::npos);

    keys::authorized_keys again;
    REQUIRE_FALSE(keys::authorized_keys::parse(dumped, again));
    REQUIRE(again.lines().size() == 6);
    REQUIRE_FALSE(again.lines()[0].key.has_value());
    REQUIRE(again.lines()[0].raw == cert_line);
    REQUIRE(again.lines()[2].key.has_value());
}

TEST_CASE("quoted option spaces do not steal the type token", "[keys][authorized]") {
    const auto key = load_ed25519_pub();
    const std::string b64 = key_b64(key);
    const std::string options = R"(command="ssh-ed25519 decoy",no-pty)";
    const std::string text = options + " ssh-ed25519 " + b64 + " user@host\n";

    keys::authorized_keys ak;
    REQUIRE_FALSE(keys::authorized_keys::parse(text, ak));
    REQUIRE(ak.lines().size() == 1);
    REQUIRE(ak.lines()[0].key.has_value());
    REQUIRE(blobs_equal(*ak.lines()[0].key, key));
    REQUIRE(ak.lines()[0].options == options);
    REQUIRE(ak.lines()[0].comment == "user@host");
}
