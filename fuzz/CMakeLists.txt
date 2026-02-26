if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    return()
endif()

# libFuzzer is only reliably available on Linux Clang.
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    return()
endif()

set(FUZZ_TARGETS
    fuzz_chacha20
    fuzz_poly1305
    fuzz_aead
)

foreach(target ${FUZZ_TARGETS})
    add_executable(${target} ${target}.cpp)
    target_link_libraries(${target} PRIVATE tinychacha)
    set_target_properties(${target} PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
    )
    target_include_directories(${target} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_compile_options(${target} PRIVATE
        -Wall -Wextra -Wpedantic -Werror
        -fsanitize=fuzzer,address
    )
    set_property(TARGET ${target} APPEND_STRING PROPERTY LINK_FLAGS " -fsanitize=fuzzer,address")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set_property(TARGET ${target} APPEND_STRING PROPERTY LINK_FLAGS
            " -Wl,-z,relro,-z,now -Wl,-z,noexecstack")
    endif()
endforeach()
