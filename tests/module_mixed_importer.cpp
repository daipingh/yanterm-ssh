import yanterm.ssh;
import yanterm.ssh.openssl;

#include <yanterm-ssh/crypto/provider.hpp>
#include <yanterm-ssh/keys/public_key.hpp>

int main() {
    yanterm::ssh::crypto::openssl_backend backend;
    const auto provider =
        yanterm::ssh::crypto::provider::wrap(backend);
    yanterm::ssh::client_session session;
    yanterm::ssh::keys::public_key key;
    (void)session;
    (void)key;
    return provider ? 0 : 1;
}
