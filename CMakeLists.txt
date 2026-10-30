cmake_minimum_required(VERSION 3.22)

# CMP0135 (CMake 3.24+): URL downloads should stamp extracted files with the
# extraction time so FetchContent rebuilds when the archive URL changes.
# Guarded so CMake 3.22 (our minimum) still configures.
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()

project(yanterm-ssh VERSION 0.2.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(YANTERM_SSH_INSTALL "Install yanterm-ssh headers and CMake package" ${PROJECT_IS_TOP_LEVEL})
option(YANTERM_SSH_BUILD_TESTS "Build yanterm-ssh tests" ${PROJECT_IS_TOP_LEVEL})
option(YANTERM_SSH_INTEROP_TESTS "Enable OpenSSH interop CTest (requires sshd)" OFF)
option(YANTERM_SSH_ENABLE_ASAN "Instrument with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(YANTERM_SSH_STATIC_LIBSTDCXX "Statically link libgcc/libstdc++ into test and tool binaries" ON)
option(YANTERM_SSH_BUILD_FUZZERS "Build libFuzzer targets (requires Clang and OpenSSL)" OFF)

if(YANTERM_SSH_ENABLE_ASAN)
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "YANTERM_SSH_ENABLE_ASAN requires GCC or Clang")
    endif()
    add_compile_options(
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
        -fno-sanitize-recover=all
    )
    add_link_options(-fsanitize=address,undefined)
endif()

if(YANTERM_SSH_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "YANTERM_SSH_BUILD_FUZZERS requires Clang")
    endif()
    if(NOT YANTERM_SSH_BUILD_TESTS)
        message(FATAL_ERROR "YANTERM_SSH_BUILD_FUZZERS requires YANTERM_SSH_BUILD_TESTS")
    endif()
    add_compile_options(
        -fsanitize=fuzzer-no-link,address,undefined
        -fno-sanitize=vptr
        -fno-omit-frame-pointer
        -fno-sanitize-recover=all
    )
    add_link_options(
        -fsanitize=address,undefined
        -fno-sanitize=vptr
        -fno-sanitize-recover=all
    )
endif()

# ---- core target: sans-IO protocol core, no corral, no auv, no I/O ----
add_library(yanterm-ssh-core INTERFACE)
add_library(yanterm::ssh-core ALIAS yanterm-ssh-core)

target_include_directories(yanterm-ssh-core INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_compile_features(yanterm-ssh-core INTERFACE cxx_std_20)

# Facade INTERFACE target. Does not propagate corral/auv include dirs;
# consumers (including xssh) must supply their own.
add_library(yanterm-ssh INTERFACE)
add_library(yanterm::ssh ALIAS yanterm-ssh)
target_link_libraries(yanterm-ssh INTERFACE yanterm-ssh-core)

add_library(yanterm-ssh-static STATIC
    src/core.cpp
    src/keys.cpp
    src/keys_io.cpp
    src/bcrypt_pbkdf.cpp
)
add_library(yanterm::ssh-static ALIAS yanterm-ssh-static)

set_target_properties(yanterm-ssh-static PROPERTIES UNITY_BUILD OFF)
target_link_libraries(yanterm-ssh-static PUBLIC yanterm-ssh-core)
target_compile_definitions(yanterm-ssh-static
    PUBLIC YANTERM_SSH_SEPARATE_COMPILATION
)

if(YANTERM_SSH_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
    add_subdirectory(tools)
endif()

if(YANTERM_SSH_INSTALL)
    install(
        TARGETS yanterm-ssh-core yanterm-ssh yanterm-ssh-static
        EXPORT yanterm-sshTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )
    install(DIRECTORY include/yanterm-ssh DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    install(
        FILES
            modules/yanterm.ssh.cppm
            modules/yanterm.ssh.openssl.cppm
        DESTINATION ${CMAKE_INSTALL_DATADIR}/yanterm-ssh/modules
    )
    install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DATADIR}/yanterm-ssh)
    install(
        EXPORT yanterm-sshTargets
        FILE yanterm-sshTargets.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/yanterm-ssh
    )
    configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/yanterm-sshConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/yanterm-sshConfig.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/yanterm-ssh
    )
    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/yanterm-sshConfigVersion.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )
    install(
        FILES
            ${CMAKE_CURRENT_BINARY_DIR}/yanterm-sshConfig.cmake
            ${CMAKE_CURRENT_BINARY_DIR}/yanterm-sshConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/yanterm-ssh
    )
endif()
