add_executable(tinychacha_tests
    test_main.cpp
    test_chacha20.cpp
    test_poly1305.cpp
    test_aead.cpp
    test_aead_auth_failure.cpp
    test_nonce_generation.cpp
    test_cpuid.cpp
    test_fuzz.cpp
    test_security.cpp
    test_backend_equivalence.cpp
    test_primitives.cpp
    test_inplace.cpp
    test_determinism.cpp
    test_aead_backend_equivalence.cpp
    test_rfc_per_backend.cpp
)

target_link_libraries(tinychacha_tests PRIVATE tinychacha)
target_include_directories(tinychacha_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
set_target_properties(tinychacha_tests PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

# Warning flags for tests
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(tinychacha_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set_property(TARGET tinychacha_tests APPEND_STRING PROPERTY LINK_FLAGS
            " -Wl,-z,relro,-z,now -Wl,-z,noexecstack")
    endif()
    if(MINGW)
        set_property(TARGET tinychacha_tests APPEND_STRING PROPERTY LINK_FLAGS
            " -Wl,--nxcompat -Wl,--dynamicbase -Wl,--high-entropy-va")
    endif()
elseif(MSVC)
    target_compile_options(tinychacha_tests PRIVATE /W4 /WX)
    set_property(TARGET tinychacha_tests APPEND_STRING PROPERTY LINK_FLAGS
        " /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA")
endif()

add_test(NAME tinychacha_tests COMMAND tinychacha_tests)
