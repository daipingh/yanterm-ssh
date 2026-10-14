include("${PROJECT_SOURCE_DIR}/cmake/YantermSSHStaticLibstdcxx.cmake")

find_package(OpenSSL 1.1.1 COMPONENTS Crypto)

# Keep executables at the project binary dir so tools/run-openssh-interop.sh
# can find $YANTERM_SSH_BUILD_DIR/<tool> the same way as before the tests/
# subdirectory split.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")

set(YANTERM_SSH_LIBUV_TARGET "")
if(TARGET uv_a)
    set(YANTERM_SSH_LIBUV_TARGET uv_a)
else()
    find_package(libuv CONFIG QUIET)
    if(TARGET libuv::uv_a)
        set(YANTERM_SSH_LIBUV_TARGET libuv::uv_a)
    endif()
endif()
if(NOT YANTERM_SSH_LIBUV_TARGET)
    message(STATUS "yanterm-ssh: libuv not found; benchmark tool skipped")
endif()

if(YANTERM_SSH_LIBUV_TARGET AND OpenSSL_FOUND)
    add_executable(yanterm-ssh-bench
        "${CMAKE_CURRENT_SOURCE_DIR}/bench/main.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/bench/options.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/bench/report.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/bench/net.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/bench/server.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/bench/client.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/bench/spawn.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/bench/proc.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/bench/tty.cpp")
    target_include_directories(yanterm-ssh-bench PRIVATE
        ${PROJECT_SOURCE_DIR}/tests
        ${CMAKE_CURRENT_SOURCE_DIR}/bench)
    target_link_libraries(yanterm-ssh-bench PRIVATE
        yanterm::ssh-static
        OpenSSL::Crypto
        ${YANTERM_SSH_LIBUV_TARGET})
    if(UNIX)
        target_link_libraries(yanterm-ssh-bench PRIVATE util)
    endif()
    yanterm_ssh_link_static_libstdcxx(yanterm-ssh-bench)
endif()

if(OpenSSL_FOUND)
    add_executable(yanterm-ssh-interop-handshake
        "${PROJECT_SOURCE_DIR}/tools/interop_handshake.cpp")
    target_include_directories(yanterm-ssh-interop-handshake PRIVATE
        ${PROJECT_SOURCE_DIR}/tests)
    target_link_libraries(yanterm-ssh-interop-handshake PRIVATE
        yanterm::ssh-core
        OpenSSL::Crypto)
    yanterm_ssh_link_static_libstdcxx(yanterm-ssh-interop-handshake)

    add_executable(yanterm-ssh-interop-auth
        "${PROJECT_SOURCE_DIR}/tools/interop_auth.cpp")
    target_include_directories(yanterm-ssh-interop-auth PRIVATE
        ${PROJECT_SOURCE_DIR}/tests)
    target_link_libraries(yanterm-ssh-interop-auth PRIVATE
        yanterm::ssh-core
        OpenSSL::Crypto)
    yanterm_ssh_link_static_libstdcxx(yanterm-ssh-interop-auth)

    add_executable(yanterm-ssh-interop-channels
        "${PROJECT_SOURCE_DIR}/tools/interop_channels.cpp")
    target_include_directories(yanterm-ssh-interop-channels PRIVATE
        ${PROJECT_SOURCE_DIR}/tests)
    target_link_libraries(yanterm-ssh-interop-channels PRIVATE
        yanterm::ssh-core
        OpenSSL::Crypto)
    yanterm_ssh_link_static_libstdcxx(yanterm-ssh-interop-channels)

    add_test(
        NAME yanterm_ssh_openssh_interop
        COMMAND ${PROJECT_SOURCE_DIR}/tools/run-openssh-interop.sh
    )
    set_tests_properties(yanterm_ssh_openssh_interop PROPERTIES
        LABELS "interop"
        DISABLED $<NOT:$<BOOL:${YANTERM_SSH_INTEROP_TESTS}>>
        ENVIRONMENT
            "YANTERM_SSH_BUILD_DIR=${PROJECT_BINARY_DIR};YANTERM_SSH_CORPUS_DIR=${PROJECT_SOURCE_DIR}/corpus;YANTERM_SSH_INTEROP_TOOL=$<TARGET_FILE:yanterm-ssh-interop-handshake>;YANTERM_SSH_INTEROP_AUTH_TOOL=$<TARGET_FILE:yanterm-ssh-interop-auth>;YANTERM_SSH_INTEROP_CHAN_TOOL=$<TARGET_FILE:yanterm-ssh-interop-channels>"
    )
endif()
