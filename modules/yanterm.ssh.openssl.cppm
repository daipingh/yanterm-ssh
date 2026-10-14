module;
#include <yanterm-ssh/crypto/openssl.hpp>

export module yanterm.ssh.openssl;

export namespace yanterm::ssh::crypto {
using ::yanterm::ssh::crypto::hash_id;
using ::yanterm::ssh::crypto::cipher_id;
using ::yanterm::ssh::crypto::mac_id;
using ::yanterm::ssh::crypto::kex_id;
using ::yanterm::ssh::crypto::sig_id;
using ::yanterm::ssh::crypto::primitive_kind;
using ::yanterm::ssh::crypto::hash_output_size;
using ::yanterm::ssh::crypto::cipher_key_size;
using ::yanterm::ssh::crypto::cipher_block_size;
using ::yanterm::ssh::crypto::cipher_iv_size;
using ::yanterm::ssh::crypto::is_rsa_sig;
using ::yanterm::ssh::crypto::is_ecdsa_sig;
using ::yanterm::ssh::crypto::is_sm2_sig;
using ::yanterm::ssh::crypto::max_generated_key_storage;
using ::yanterm::ssh::crypto::max_signature_size;
using ::yanterm::ssh::crypto::generated_key_storage_size;
using ::yanterm::ssh::crypto::kex_public_size;
using ::yanterm::ssh::crypto::kex_secret_size;
using ::yanterm::ssh::crypto::public_key_material;
using ::yanterm::ssh::crypto::signature_material;
using ::yanterm::ssh::crypto::private_key_material;
using ::yanterm::ssh::crypto::secure_zero;
using ::yanterm::ssh::crypto::provider_vtable;
using ::yanterm::ssh::crypto::hash_ctx;
using ::yanterm::ssh::crypto::hmac_ctx;
using ::yanterm::ssh::crypto::cipher;
using ::yanterm::ssh::crypto::aead_cipher;
using ::yanterm::ssh::crypto::kex_agreement;
using ::yanterm::ssh::crypto::signing_key;
using ::yanterm::ssh::crypto::provider;
using ::yanterm::ssh::crypto::openssl_backend;
}
