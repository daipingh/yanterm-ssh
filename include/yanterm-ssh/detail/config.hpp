#pragma once

// Mode detection for header-only vs static library (see SOURCE_LAYOUT.md [M-7]).

#if defined(YANTERM_SSH_HEADER_ONLY)
#error "YANTERM_SSH_HEADER_ONLY is derived, not user-settable. \
Use YANTERM_SSH_SEPARATE_COMPILATION to opt into the static library."
#endif

#if defined(YANTERM_SSH_SOURCE) && !defined(YANTERM_SSH_SEPARATE_COMPILATION)
#error "yanterm-ssh library sources must be compiled with \
YANTERM_SSH_SEPARATE_COMPILATION defined (see the yanterm-ssh-static target)."
#endif

#if !defined(YANTERM_SSH_SEPARATE_COMPILATION)
#define YANTERM_SSH_HEADER_ONLY 1
#endif

#if defined(YANTERM_SSH_HEADER_ONLY)
#define YANTERM_SSH_INLINE inline
#else
#define YANTERM_SSH_INLINE
#endif
