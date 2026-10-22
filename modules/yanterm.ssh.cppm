module;
#include <yanterm-ssh/session.hpp>
#include <yanterm-ssh/channel.hpp>
#include <yanterm-ssh/options.hpp>
#include <yanterm-ssh/facade_types.hpp>
#include <yanterm-ssh/memory/page_resource.hpp>

export module yanterm.ssh;

export namespace yanterm::ssh {
using ::yanterm::ssh::disconnect_reason;
using ::yanterm::ssh::auth_result;
using ::yanterm::ssh::auth_verdict;
using ::yanterm::ssh::verdict_kind;
using ::yanterm::ssh::kbdint_prompt;
using ::yanterm::ssh::publickey_sign_request;
using ::yanterm::ssh::channel_id;
using ::yanterm::ssh::channel_open_reason;
using ::yanterm::ssh::channel_type;
using ::yanterm::ssh::pty_spec;
using ::yanterm::ssh::x11_req_spec;
using ::yanterm::ssh::window_size;
using ::yanterm::ssh::exit_signal;
using ::yanterm::ssh::disconnect_info;
using ::yanterm::ssh::host_key_view;
using ::yanterm::ssh::auth_request;
using ::yanterm::ssh::session_options;
using ::yanterm::ssh::client_options;
using ::yanterm::ssh::server_options;
using ::yanterm::ssh::session;
using ::yanterm::ssh::client_session;
using ::yanterm::ssh::server_session;
using ::yanterm::ssh::run_with;
using ::yanterm::ssh::publickey_signer;
using ::yanterm::ssh::channel;
using ::yanterm::ssh::channel_open_result;
using ::yanterm::ssh::inbound_channel_open;
using ::yanterm::ssh::inbound_channel_request;
using ::yanterm::ssh::inbound_global_request;
}

export namespace yanterm::ssh::keys {
using ::yanterm::ssh::keys::public_key;
using ::yanterm::ssh::keys::private_key;
}

export namespace yanterm::ssh::kex {
using ::yanterm::ssh::kex::negotiated;
}

export namespace yanterm::ssh::crypto {
using ::yanterm::ssh::crypto::provider;
}

export namespace yanterm::ssh::memory {
using ::yanterm::ssh::memory::default_page_size;
using ::yanterm::ssh::memory::page_resource_options;
using ::yanterm::ssh::memory::page_resource;
using ::yanterm::ssh::memory::unsynchronized_page_resource;
using ::yanterm::ssh::memory::default_page_resource;
}
