#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/keys/io.hpp>
#include <yanterm-ssh/keys/private_key.hpp>
#include <yanterm-ssh/keys/public_key.hpp>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using namespace yanterm::ssh;

namespace {

crypto::provider prov() {
    static crypto::openssl_backend backend;
    return crypto::provider::wrap(backend);
}


bool have_ssh_keygen() {
    return std::system("command -v ssh-keygen >/dev/null") == 0;
}

struct tmp_sandbox {
    std::filesystem::path dir;

    tmp_sandbox() {
        auto tmpl = (std::filesystem::temp_directory_path() / "yanterm-ssh-keygen-XXXXXX").string();
        std::vector<char> buf(tmpl.begin(), tmpl.end());
        buf.push_back('\0');
        char* created = ::mkdtemp(buf.data());
        REQUIRE(created != nullptr);
        dir = created;
    }

    tmp_sandbox(const tmp_sandbox&) = delete;
    tmp_sandbox& operator=(const tmp_sandbox&) = delete;

    ~tmp_sandbox() {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }

    std::string file(std::string_view name) const { return (dir / std::string{name}).string(); }
};

std::string slurp(const std::string& path) {
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

std::string run_stdout(const std::string& cmd) {
    FILE* pipe = ::popen(cmd.c_str(), "r");
    REQUIRE(pipe != nullptr);
    std::string out;
    char buf[512];
    while (std::fgets(buf, sizeof buf, pipe) != nullptr) out += buf;
    const int rc = ::pclose(pipe);
    REQUIRE(rc == 0);
    return out;
}

void write_bytes_0600(const std::string& path, std::span<const std::byte> data) {
    REQUIRE_FALSE(keys::io::atomic_write(path.c_str(), data));
    REQUIRE(::chmod(path.c_str(), 0600) == 0);
}

bool blobs_equal(const keys::public_key& a, const keys::public_key& b) {
    const auto xa = a.blob();
    const auto xb = b.blob();
    return xa.size() == xb.size() && std::equal(xa.begin(), xa.end(), xb.begin());
}

}  // namespace

TEST_CASE("ssh-keygen -y accepts our unencrypted serialize", "[keys][keygen][interop]") {
    if (!have_ssh_keygen()) SKIP("ssh-keygen not found");

    crypto::provider p = prov();
    keys::private_key k;
    REQUIRE_FALSE(keys::private_key::generate(p, crypto::sig_id::ed25519, 0, "yanterm-m2", k));

    std::vector<std::byte> serialized;
    REQUIRE_FALSE(k.serialize(p, {}, "none", serialized));
    const auto text = std::string_view{reinterpret_cast<const char*>(serialized.data()),
                                       serialized.size()};
    REQUIRE(text.find("-----BEGIN OPENSSH PRIVATE KEY-----") != std::string_view::npos);
    REQUIRE(text.find("-----END OPENSSH PRIVATE KEY-----") != std::string_view::npos);

    tmp_sandbox tmp;
    const auto path = tmp.file("id_ed25519");
    write_bytes_0600(path, serialized);

    const std::string pub_line = run_stdout("ssh-keygen -y -f '" + path + "'");
    keys::public_key from_keygen;
    REQUIRE_FALSE(keys::public_key::parse_line(pub_line, from_keygen));
    REQUIRE(blobs_equal(k.pub(), from_keygen));
}

TEST_CASE("we parse ssh-keygen -N encrypted file", "[keys][keygen][interop]") {
    if (!have_ssh_keygen()) SKIP("ssh-keygen not found");

    tmp_sandbox tmp;
    const auto path = tmp.file("id_ed25519");
    const std::string cmd =
        "ssh-keygen -q -t ed25519 -N 'pass' -C yanterm-m2 -f '" + path + "'";
    REQUIRE(std::system(cmd.c_str()) == 0);

    const auto on_disk = slurp(path);
    REQUIRE(on_disk.find("-----BEGIN OPENSSH PRIVATE KEY-----") != std::string::npos);
    REQUIRE(on_disk.find("-----END OPENSSH PRIVATE KEY-----") != std::string::npos);

    crypto::provider p = prov();
    const auto pass = std::span<const std::byte>{
        reinterpret_cast<const std::byte*>("pass"), 4};
    keys::private_key k;
    REQUIRE_FALSE(keys::io::load_private_key(path.c_str(), p, pass, k));

    const std::string pub_line = run_stdout("ssh-keygen -y -P pass -f '" + path + "'");
    keys::public_key from_keygen;
    REQUIRE_FALSE(keys::public_key::parse_line(pub_line, from_keygen));
    REQUIRE(blobs_equal(k.pub(), from_keygen));
}
