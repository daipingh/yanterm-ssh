#pragma once

#include <yanterm-ssh/core/detail/channel_codec.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/core/detail/impl/channel_codec.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/channels/requests.hpp>
#include <yanterm-ssh/wire/detail/messages.hpp>

namespace yanterm::ssh::core::detail {

YANTERM_SSH_INLINE channels::open_request_view make_open_view(const wire::detail::channel_open& msg) {
    channels::open_request_view view{};
    view.type = channels::parse_type(msg.type);
    view.type_name = msg.type;
    view.window = msg.window;
    view.max_packet = msg.max_packet;
    view.extra = msg.extra;
    switch (view.type) {
    case channels::channel_type::session:
    case channels::channel_type::unknown:
        break;
    case channels::channel_type::direct_tcpip:
    case channels::channel_type::forwarded_tcpip:
        (void)channels::decode_direct_tcpip(msg.extra, view.host, view.port, view.originator_host,
                                            view.originator_port);
        break;
    case channels::channel_type::x11:
        (void)channels::decode_x11(msg.extra, view.originator_host, view.originator_port);
        break;
    case channels::channel_type::direct_streamlocal: {
        std::string_view reserved;
        (void)channels::decode_streamlocal(msg.extra, view.socket_path, reserved);
        break;
    }
    case channels::channel_type::forwarded_streamlocal: {
        std::string_view reserved;
        (void)channels::decode_forwarded_streamlocal(msg.extra, view.socket_path, reserved);
        break;
    }
    }
    return view;
}

YANTERM_SSH_INLINE void encode_open_extra(const channels::channel_open_spec& spec, wire::writer& extra) {
    switch (spec.type) {
    case channels::channel_type::session:
    case channels::channel_type::unknown:
        extra.write_bytes(spec.extra);
        break;
    case channels::channel_type::direct_tcpip:
    case channels::channel_type::forwarded_tcpip:
        channels::encode_direct_tcpip(extra, spec.host, spec.port, spec.originator_host, spec.originator_port);
        break;
    case channels::channel_type::x11:
        channels::encode_x11(extra, spec.originator_host, spec.originator_port);
        break;
    case channels::channel_type::direct_streamlocal:
        channels::encode_streamlocal(extra, spec.socket_path);
        break;
    case channels::channel_type::forwarded_streamlocal:
        channels::encode_forwarded_streamlocal(extra, spec.socket_path);
        break;
    }
}

}  // namespace yanterm::ssh::core::detail
