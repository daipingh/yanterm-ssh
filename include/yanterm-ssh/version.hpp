#pragma once

#include <yanterm-ssh/detail/config.hpp>

#define YANTERM_SSH_VERSION_MAJOR 0
#define YANTERM_SSH_VERSION_MINOR 2
#define YANTERM_SSH_VERSION_PATCH 0

#define YANTERM_SSH_DETAIL_STRINGIFY_(x) #x
#define YANTERM_SSH_DETAIL_STRINGIFY(x)  YANTERM_SSH_DETAIL_STRINGIFY_(x)

#define YANTERM_SSH_VERSION_STRING             \
    YANTERM_SSH_DETAIL_STRINGIFY(YANTERM_SSH_VERSION_MAJOR) "." \
    YANTERM_SSH_DETAIL_STRINGIFY(YANTERM_SSH_VERSION_MINOR) "." \
    YANTERM_SSH_DETAIL_STRINGIFY(YANTERM_SSH_VERSION_PATCH)

namespace yanterm::ssh {

[[nodiscard]] inline const char* version_string() noexcept {
    return YANTERM_SSH_VERSION_STRING;
}

[[nodiscard]] inline const char* default_software() noexcept {
    return "yanterm_ssh_" YANTERM_SSH_VERSION_STRING;
}

}  // namespace yanterm::ssh
