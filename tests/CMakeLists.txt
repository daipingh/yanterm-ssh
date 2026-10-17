include(FetchContent)
include("${PROJECT_SOURCE_DIR}/cmake/YantermSSHStaticLibstdcxx.cmake")

# Keep executables at the project binary dir so tools/run-openssh-interop.sh
# can find $YANTERM_SSH_BUILD_DIR/<tool> the same way as before the tests/
# subdirectory split.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")

add_test(NAME yanterm_ssh_source_layout
         COMMAND "${PROJECT_SOURCE_DIR}/scripts/check-source-layout.sh"
         WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")

find_package(OpenSSL 1.1.1 COMPONENTS Crypto)
if(NOT OpenSSL_FOUND)
    message(STATUS "yanterm-ssh: OpenSSL not found; OpenSSL-backed tests skipped")
endif()

# [V-3] Standalone compile of each public and detail header ([H-2]).
# impl/ files are half a header and are excluded. Discovery is automatic;
# generated TUs live only under ${CMAKE_CURRENT_BINARY_DIR}/header-self-contained/.
file(GLOB_RECURSE _yanterm_ssh_sc_headers CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/include/yanterm-ssh/*.hpp")
set(_yanterm_ssh_sc_dir "${CMAKE_CURRENT_BINARY_DIR}/header-self-contained")
file(MAKE_DIRECTORY "${_yanterm_ssh_sc_dir}")
set(_yanterm_ssh_sc_sources)
foreach(_hdr IN LISTS _yanterm_ssh_sc_headers)
    if(_hdr MATCHES "/impl/")
        continue()
    endif()
    # OpenSSL backends need OpenSSL headers. The OpenSSL 3 implementation does
    # not parse against 1.1.1, so skip it when the found Crypto is older.
    if(NOT OpenSSL_FOUND AND _hdr MATCHES "/crypto/(openssl[.]hpp$|detail/openssl(3|11|_common)[.]hpp$)")
        continue()
    endif()
    if(OpenSSL_FOUND AND OPENSSL_VERSION VERSION_LESS "3.0.0"
       AND _hdr MATCHES "/crypto/detail/ossl3[.]hpp$")
        continue()
    endif()
    file(RELATIVE_PATH _rel "${PROJECT_SOURCE_DIR}/include" "${_hdr}")
    string(REPLACE "/" "__" _mangled "${_rel}")
    string(REPLACE ".hpp" ".cpp" _cpp_name "${_mangled}")
    set(_cpp "${_yanterm_ssh_sc_dir}/${_cpp_name}")
    set(_content "#include <${_rel}>\n")
    if(EXISTS "${_cpp}")
        file(READ "${_cpp}" _old)
    else()
        set(_old "")
    endif()
    if(NOT _old STREQUAL _content)
        file(WRITE "${_cpp}" "${_content}")
    endif()
    list(APPEND _yanterm_ssh_sc_sources "${_cpp}")
    # The 1.1.1 backend still typechecks against OpenSSL 3 headers. Its
    # deprecation warnings are the reason the 3.x backend exists; keep them
    # out of this TU so the selected public header stays the warning-free path.
    if(OpenSSL_FOUND AND OPENSSL_VERSION VERSION_GREATER_EQUAL "3.0.0"
       AND _hdr MATCHES "/crypto/detail/ossl1_1[.]hpp$")
        set_source_files_properties("${_cpp}" PROPERTIES
            COMPILE_OPTIONS "-Wno-deprecated-declarations")
    endif()
endforeach()

add_library(yanterm-ssh-header-self-contained OBJECT
    ${_yanterm_ssh_sc_sources})
set_target_properties(yanterm-ssh-header-self-contained PROPERTIES
    UNITY_BUILD OFF)
target_link_libraries(yanterm-ssh-header-self-contained PRIVATE
    yanterm::ssh-core)
target_include_directories(yanterm-ssh-header-self-contained PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}")
if(OpenSSL_FOUND)
    target_link_libraries(yanterm-ssh-header-self-contained PRIVATE
        OpenSSL::Crypto)
endif()
add_test(NAME yanterm_ssh_header_self_contained
         COMMAND "${CMAKE_COMMAND}" --build "${CMAKE_BINARY_DIR}"
                 --target yanterm-ssh-header-self-contained
                 --config $<CONFIG>)

if(OpenSSL_FOUND AND NOT TARGET Catch2::Catch2WithMain)
    find_package(Catch2 3 CONFIG QUIET)
    if(NOT Catch2_FOUND)
        set(CATCH_BUILD_TESTING OFF CACHE BOOL "" FORCE)
        set(CATCH_INSTALL_DOCS OFF CACHE BOOL "" FORCE)
        set(CATCH_INSTALL_EXTRAS OFF CACHE BOOL "" FORCE)
        set(_yanterm_ssh_saved_build_shared_libs "${BUILD_SHARED_LIBS}")
        set(BUILD_SHARED_LIBS OFF)
        if(EXISTS "${PROJECT_SOURCE_DIR}/.deps/Catch2-3.16.1.tar.gz")
            FetchContent_Declare(
                catch2_src
                URL "${PROJECT_SOURCE_DIR}/.deps/Catch2-3.16.1.tar.gz"
            )
        else()
            FetchContent_Declare(
                catch2_src
                URL https://github.com/catchorg/Catch2/archive/refs/tags/v3.16.1.tar.gz
            )
        endif()
        FetchContent_MakeAvailable(catch2_src)
        set(BUILD_SHARED_LIBS "${_yanterm_ssh_saved_build_shared_libs}")
        unset(_yanterm_ssh_saved_build_shared_libs)
    endif()
endif()

if(OpenSSL_FOUND)
    if(NOT TARGET Catch2::Catch2WithMain)
        message(FATAL_ERROR
            "YANTERM_SSH_BUILD_TESTS=ON but Catch2::Catch2WithMain is unavailable "
            "(find_package and FetchContent both failed)")
    endif()

    add_executable(yanterm-ssh-tests
        test_error.cpp
        test_pages.cpp
        test_page_resource.cpp
        test_wire_types.cpp
        test_wire_messages.cpp
        test_provider.cpp
        test_secure_buffer.cpp
        test_provider_adapt.cpp
        test_openssl_digest.cpp
        test_openssl_cipher.cpp
        test_openssl_kex_sig.cpp
        test_gm_crypto.cpp
        test_bcrypt_pbkdf.cpp
        test_base64.cpp
        test_intrusive_list.cpp
        test_public_key.cpp
        test_private_key.cpp
        test_known_hosts.cpp
        test_authorized_keys.cpp
        test_keys_io.cpp
        test_keygen_roundtrip.cpp
        test_version_exchange.cpp
        test_packet_ctr.cpp
        test_packet_aead.cpp
        test_kex_negotiation.cpp
        test_host_key.cpp
        test_kex_exchange.cpp
        test_kdf.cpp
        test_connection_handshake.cpp
        test_strict_kex.cpp
        test_rekey.cpp
        test_replay.cpp
        test_auth_types.cpp
        test_auth_service.cpp
        test_auth_password.cpp
        test_auth_signature.cpp
        test_auth_publickey.cpp
        test_auth_kbdint.cpp
        test_channel_types.cpp
        test_channel_open.cpp
        test_channel_data.cpp
        test_channel_requests.cpp
        test_callback_contract.cpp
        test_handles.cpp
        test_global_requests.cpp
        test_memory_pipe.cpp
        test_session_run.cpp
        test_session_handshake.cpp
        test_session_auth.cpp
        test_session_channel.cpp
        test_session_serve.cpp
        test_session_cancel.cpp
        test_session_memory.cpp
    )
    target_include_directories(yanterm-ssh-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(yanterm-ssh-tests PRIVATE
        YANTERM_SSH_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
        YANTERM_SSH_CORPUS_DIR="${PROJECT_SOURCE_DIR}/corpus")
    target_link_libraries(yanterm-ssh-tests PRIVATE
        yanterm::ssh-static
        OpenSSL::Crypto
        Catch2::Catch2WithMain)
    yanterm_ssh_link_static_libstdcxx(yanterm-ssh-tests)
    add_test(NAME yanterm_ssh_tests COMMAND yanterm-ssh-tests)

    add_executable(yanterm-ssh-header-only-test
        header_only_consumer_a.cpp
        header_only_consumer_main.cpp
    )
    target_include_directories(yanterm-ssh-header-only-test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(yanterm-ssh-header-only-test PRIVATE
        yanterm::ssh-core
        OpenSSL::Crypto)
    yanterm_ssh_link_static_libstdcxx(yanterm-ssh-header-only-test)
    add_test(NAME yanterm_ssh_header_only COMMAND yanterm-ssh-header-only-test)

    # Offline corpus replay (subset of yanterm-ssh-tests tagged [corpus]).
    add_test(
        NAME yanterm_ssh_replay_tests
        COMMAND yanterm-ssh-tests "[replay]"
    )
endif() # OpenSSL_FOUND

add_executable(yanterm-ssh-facade-header-only-test
    facade_header_only_a.cpp
    facade_header_only_main.cpp
)
target_include_directories(yanterm-ssh-facade-header-only-test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(yanterm-ssh-facade-header-only-test PRIVATE yanterm::ssh)
yanterm_ssh_link_static_libstdcxx(yanterm-ssh-facade-header-only-test)
add_test(NAME yanterm_ssh_facade_header_only COMMAND yanterm-ssh-facade-header-only-test)

include("${PROJECT_SOURCE_DIR}/cmake/YantermSSHModuleProbe.cmake")
yanterm_ssh_probe_modules(YANTERM_SSH_MODULE_TESTS_AVAILABLE)
if(YANTERM_SSH_MODULE_TESTS_AVAILABLE)
    add_library(yanterm-ssh-module-corral STATIC)
    target_sources(yanterm-ssh-module-corral
        PUBLIC
            FILE_SET CXX_MODULES
            BASE_DIRS "${PROJECT_SOURCE_DIR}"
            FILES "${PROJECT_SOURCE_DIR}/modules/yanterm.ssh.cppm"
    )
    target_compile_features(yanterm-ssh-module-corral PUBLIC cxx_std_20)
    target_include_directories(yanterm-ssh-module-corral
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_link_libraries(yanterm-ssh-module-corral
        PUBLIC yanterm::ssh
    )
    set_target_properties(yanterm-ssh-module-corral PROPERTIES
        CXX_SCAN_FOR_MODULES ON
    )

    add_executable(yanterm-ssh-module-corral-test
        module_corral_importer.cpp
    )
    target_link_libraries(yanterm-ssh-module-corral-test
        PRIVATE yanterm-ssh-module-corral
    )
    set_target_properties(yanterm-ssh-module-corral-test PROPERTIES
        CXX_SCAN_FOR_MODULES ON
    )
    yanterm_ssh_link_static_libstdcxx(yanterm-ssh-module-corral-test)
    add_test(
        NAME yanterm_ssh_module_corral
        COMMAND yanterm-ssh-module-corral-test
    )

    if(OpenSSL_FOUND)
        add_library(yanterm-ssh-module-openssl STATIC)
        target_sources(yanterm-ssh-module-openssl
            PUBLIC
                FILE_SET CXX_MODULES
                BASE_DIRS "${PROJECT_SOURCE_DIR}"
                FILES "${PROJECT_SOURCE_DIR}/modules/yanterm.ssh.openssl.cppm"
        )
        target_compile_features(yanterm-ssh-module-openssl PUBLIC cxx_std_20)
        target_link_libraries(yanterm-ssh-module-openssl
            PUBLIC
                yanterm::ssh-core
                OpenSSL::Crypto
        )
        set_target_properties(yanterm-ssh-module-openssl PROPERTIES
            CXX_SCAN_FOR_MODULES ON
        )

        add_executable(yanterm-ssh-module-openssl-test
            module_openssl_importer.cpp
        )
        target_link_libraries(yanterm-ssh-module-openssl-test
            PRIVATE yanterm-ssh-module-openssl
        )
        set_target_properties(yanterm-ssh-module-openssl-test PROPERTIES
            CXX_SCAN_FOR_MODULES ON
        )
        yanterm_ssh_link_static_libstdcxx(yanterm-ssh-module-openssl-test)
        add_test(
            NAME yanterm_ssh_module_openssl
            COMMAND yanterm-ssh-module-openssl-test
        )

        add_executable(yanterm-ssh-module-mixed-test
            module_mixed_importer.cpp
        )
        target_link_libraries(yanterm-ssh-module-mixed-test PRIVATE
            yanterm-ssh-module-corral
            yanterm-ssh-module-openssl
        )
        set_target_properties(yanterm-ssh-module-mixed-test PROPERTIES
            CXX_SCAN_FOR_MODULES ON
        )
        yanterm_ssh_link_static_libstdcxx(yanterm-ssh-module-mixed-test)
        add_test(
            NAME yanterm_ssh_module_mixed
            COMMAND yanterm-ssh-module-mixed-test
        )
    endif()
endif()
