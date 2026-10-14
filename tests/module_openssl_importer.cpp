import yanterm.ssh.openssl;

int main() {
    yanterm::ssh::crypto::openssl_backend backend;
    const auto provider =
        yanterm::ssh::crypto::provider::wrap(backend);
    return provider ? 0 : 1;
}
