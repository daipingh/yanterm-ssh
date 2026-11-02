#pragma once

// Spec §4 public headers for the core ODR smoke test.
// Facade headers (session.hpp, channel.hpp, options.hpp, facade_types.hpp)
// live in yanterm_ssh_facade_header_only — they need corral / auv.
// crypto/detail/bcrypt_pbkdf.hpp is the existing compiled-scope ODR exception.
// keys/io.hpp is opt-in blocking I/O and is intentionally omitted.
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/memory/page_resource.hpp>
#include <yanterm-ssh/version.hpp>
#include <yanterm-ssh/core/connection.hpp>
#include <yanterm-ssh/core/handler.hpp>
#include <yanterm-ssh/core/config.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/wire/message_ids.hpp>
#include <yanterm-ssh/kex/algorithms.hpp>
#include <yanterm-ssh/transport/packet_mode.hpp>
#include <yanterm-ssh/channels/types.hpp>
#include <yanterm-ssh/channels/requests.hpp>
#include <yanterm-ssh/sftp/types.hpp>
#include <yanterm-ssh/sftp/packets.hpp>
#include <yanterm-ssh/auth/types.hpp>
#include <yanterm-ssh/crypto/algorithms.hpp>
#include <yanterm-ssh/crypto/provider.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/crypto/detail/bcrypt_pbkdf.hpp>
#include <yanterm-ssh/keys/public_key.hpp>
#include <yanterm-ssh/keys/fingerprint.hpp>
#include <yanterm-ssh/keys/private_key.hpp>
#include <yanterm-ssh/keys/known_hosts.hpp>
#include <yanterm-ssh/keys/authorized_keys.hpp>
