cmake_minimum_required(VERSION 3.10)
project(tinychacha VERSION 0.1.0 LANGUAGES CXX)

include(CheckCXXCompilerFlag)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(BUILD_SHARED_LIBS "Build shared library" OFF)
option(BUILD_TESTS "Build unit tests" OFF)
option(BUILD_BENCH "Build benchmarks" OFF)
option(BUILD_FUZZ "Build fuzz targets" OFF)
option(FORCE_PORTABLE "Disable SIMD backends; use only portable code" OFF)

# --- Library sources ---
set(TINYCHACHA_SOURCES
    src/secure_zero.cpp
    src/cpuid.cpp
    src/nonce_generate.cpp
    src/chacha20.cpp
    src/poly1305.cpp
    src/aead.cpp
    src/backend/chacha20_portable.cpp
    src/backend/poly1305_portable.cpp
)

# Conditionally add SIMD backend sources on x86_64
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64" AND NOT FORCE_PORTABLE)
    list(APPEND TINYCHACHA_SOURCES
        src/backend/chacha20_avx2.cpp
        src/backend/chacha20_avx512.cpp
        src/backend/poly1305_avx2.cpp
    )
endif()

# Conditionally add NEON backend sources on ARM64
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64" AND NOT FORCE_PORTABLE)
    list(APPEND TINYCHACHA_SOURCES
        src/backend/chacha20_neon.cpp
        src/backend/poly1305_neon.cpp
    )
endif()

add_library(tinychacha ${TINYCHACHA_SOURCES})

# --- Shared library symbol visibility ---
if(BUILD_SHARED_LIBS)
    set_target_properties(tinychacha PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
    )
    target_compile_definitions(tinychacha PUBLIC TINYCHACHA_SHARED=1)
    target_compile_definitions(tinychacha PRIVATE TINYCHACHA_BUILDING=1)
endif()

if(FORCE_PORTABLE)
    target_compile_definitions(tinychacha PUBLIC TINYCHACHA_FORCE_PORTABLE=1)
endif()

target_include_directories(tinychacha PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
# Consumers treat tinychacha headers as system headers (suppresses their warnings)
target_include_directories(tinychacha SYSTEM INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_include_directories(tinychacha PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

set_target_properties(tinychacha PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

# --- Link bcrypt on Windows for nonce generation ---
if(WIN32)
    target_link_libraries(tinychacha PRIVATE bcrypt)
endif()

# --- Detect MinGW environment ---
# Only use CMake's built-in MINGW (set for GCC with MinGW). Clang on Windows can
# target either MinGW or MSVC ABI, and the linker varies (GNU ld vs lld-link) —
# applying the wrong linker flags breaks the build. We let Clang on Windows rely
# on the OS defaults for DEP/ASLR (enabled by default on modern Windows) rather
# than guessing the linker style.

# --- Hardening flags ---
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(tinychacha PRIVATE
        -Wall -Wextra -Wpedantic -Werror
        -Wconversion -Wsign-conversion -Wshadow
        -Wcast-align -Wundef
        -Wformat=2 -Wformat-security
        -fno-strict-overflow
        -fno-delete-null-pointer-checks
    )
    # Stack protector: requires libssp or compiler-rt at link time.
    # Probe with try_compile to catch Clang+MinGW toolchains that lack libssp.
    include(CheckCXXSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-fstack-protector-strong")
    check_cxx_source_compiles("int main() { char buf[64]; buf[0] = 0; return buf[0]; }" HAS_STACK_PROTECTOR_STRONG)
    unset(CMAKE_REQUIRED_FLAGS)
    if(HAS_STACK_PROTECTOR_STRONG)
        target_compile_options(tinychacha PRIVATE -fstack-protector-strong)
    endif()
    # -fPIC is implied on Windows PE; only needed on ELF/Mach-O
    if(NOT WIN32)
        target_compile_options(tinychacha PRIVATE -fPIC)
        # Stack clash protection (Linux only — not supported on macOS/Apple Clang)
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            target_compile_options(tinychacha PRIVATE -fstack-clash-protection)
        endif()
    endif()
    # Intel CET control flow integrity (x86_64 only)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
        check_cxx_compiler_flag("-fcf-protection=full" HAS_CF_PROTECTION)
        if(HAS_CF_PROTECTION)
            target_compile_options(tinychacha PRIVATE -fcf-protection=full)
        endif()
    endif()
    # -Wstrict-aliasing=2 only for GCC (Clang doesn't support the =2 level)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(tinychacha PRIVATE -Wstrict-aliasing=2)
        # libstdc++ container assertions in Debug (bounds checks on operator[], etc.)
        target_compile_options(tinychacha PRIVATE
            $<$<CONFIG:Debug>:-D_GLIBCXX_ASSERTIONS>
        )
    endif()
    # _FORTIFY_SOURCE requires optimization; not reliably supported on MinGW
    if(NOT WIN32)
        target_compile_options(tinychacha PRIVATE
            $<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=2>
        )
    endif()
    # Linker hardening (use LINK_FLAGS for CMake 3.10 compat)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set_property(TARGET tinychacha APPEND_STRING PROPERTY LINK_FLAGS
            " -Wl,-z,relro,-z,now -Wl,-z,noexecstack")
        # Reject undefined symbols in shared libs (catches missing TINYCHACHA_API)
        if(BUILD_SHARED_LIBS)
            set_property(TARGET tinychacha APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-z,defs")
        endif()
    endif()
    # MinGW linker hardening (DEP + ASLR) — only for GCC+MinGW (known GNU ld)
    if(MINGW)
        set_property(TARGET tinychacha APPEND_STRING PROPERTY LINK_FLAGS
            " -Wl,--nxcompat -Wl,--dynamicbase -Wl,--high-entropy-va")
    endif()
elseif(MSVC)
    target_compile_options(tinychacha PRIVATE
        /W4 /WX
        /sdl
        /GS
        /guard:cf
    )
    check_cxx_compiler_flag("/Qspectre" HAS_QSPECTRE)
    if(HAS_QSPECTRE)
        target_compile_options(tinychacha PRIVATE /Qspectre)
    endif()
    set_property(TARGET tinychacha APPEND_STRING PROPERTY LINK_FLAGS
        " /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /GUARD:CF")
    # CET shadow stack compatibility
    check_cxx_compiler_flag("/guard:ehcont" HAS_GUARD_EHCONT)
    if(HAS_GUARD_EHCONT)
        target_compile_options(tinychacha PRIVATE /guard:ehcont)
        set_property(TARGET tinychacha APPEND_STRING PROPERTY LINK_FLAGS " /guard:ehcont /CETCOMPAT")
    endif()
endif()

# --- Per-backend SIMD compile flags ---
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64" AND NOT FORCE_PORTABLE)
    # MinGW GCC + Debug: Windows x64 ABI only guarantees 16-byte stack alignment,
    # but YMM/ZMM registers need 32/64-byte alignment. At -O0, GCC spills AVX
    # registers to the stack with aligned moves (vmovdqa), which SIGSEGV on the
    # misaligned stack. Force -O1 for SIMD backends in Debug mode so GCC keeps
    # values in registers. -mpreferred-stack-boundary=5 is blocked by the ABI.
    set(_MINGW_SIMD_FIX "")
    if(MINGW AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        set(_MINGW_SIMD_FIX " $<$<CONFIG:Debug>:-O1>")
    endif()
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        set_source_files_properties(src/backend/chacha20_avx2.cpp src/backend/poly1305_avx2.cpp PROPERTIES
            COMPILE_FLAGS "-mavx2${_MINGW_SIMD_FIX}")
        set_source_files_properties(src/backend/chacha20_avx512.cpp PROPERTIES
            COMPILE_FLAGS "-mavx512f${_MINGW_SIMD_FIX}")
    elseif(MSVC)
        set_source_files_properties(src/backend/chacha20_avx2.cpp src/backend/poly1305_avx2.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX2")
        set_source_files_properties(src/backend/chacha20_avx512.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX512")
    endif()
endif()

# --- Per-backend NEON compile flags (32-bit ARM only; AArch64 has NEON baseline) ---
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64" AND NOT FORCE_PORTABLE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^armv[78]" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        set_source_files_properties(src/backend/chacha20_neon.cpp src/backend/poly1305_neon.cpp
            PROPERTIES COMPILE_FLAGS "-mfpu=neon")
    endif()
    # MSVC on ARM64: NEON is enabled by default, no extra flags needed
endif()

# --- Tests ---
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# --- Benchmarks ---
if(BUILD_BENCH)
    add_subdirectory(bench)
endif()

# --- Fuzzing (Clang + Linux only) ---
if(BUILD_FUZZ)
    add_subdirectory(fuzz)
endif()
