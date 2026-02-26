// Copyright (c) 2025-2026, Brandon Lehmann
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

// Symbol visibility for shared library builds
#if defined(TINYCHACHA_SHARED)
#if defined(_WIN32) || defined(__CYGWIN__)
#if defined(TINYCHACHA_BUILDING)
#define TINYCHACHA_API __declspec(dllexport)
#else
#define TINYCHACHA_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) || defined(__clang__)
#define TINYCHACHA_API __attribute__((visibility("default")))
#else
#define TINYCHACHA_API
#endif
#else
#define TINYCHACHA_API
#endif

// Nodiscard for C API functions
#if defined(__cplusplus) && __cplusplus >= 201703L
#define TINYCHACHA_NODISCARD [[nodiscard]]
#elif defined(__GNUC__) || defined(__clang__)
#define TINYCHACHA_NODISCARD __attribute__((warn_unused_result))
#elif defined(_MSC_VER) && _MSC_VER >= 1700
#define TINYCHACHA_NODISCARD _Check_return_
#else
#define TINYCHACHA_NODISCARD
#endif

// ChaCha20-Poly1305 constants
#define TINYCHACHA_KEY_SIZE 32
#define TINYCHACHA_NONCE_SIZE 12
#define TINYCHACHA_TAG_SIZE 16

// C error codes
#define TINYCHACHA_OK 0
#define TINYCHACHA_INVALID_KEY_SIZE (-1)
#define TINYCHACHA_INVALID_NONCE_SIZE (-2)
#define TINYCHACHA_INVALID_INPUT_SIZE (-3)
#define TINYCHACHA_AUTH_FAILED (-4)
#define TINYCHACHA_INTERNAL_ERROR (-5)

#ifdef __cplusplus
extern "C" {
#endif

TINYCHACHA_API void tinychacha_secure_zero(void *ptr, size_t len);

TINYCHACHA_NODISCARD TINYCHACHA_API int
tinychacha_constant_time_eq(const void *a, const void *b, size_t len);

TINYCHACHA_NODISCARD TINYCHACHA_API int tinychacha_generate_nonce(uint8_t out[12]);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

namespace tinychacha {

enum class [[nodiscard]] Result {
  Ok = 0,
  InvalidKeySize = -1,
  InvalidNonceSize = -2,
  InvalidInputSize = -3,
  AuthenticationFailed = -4,
  InternalError = -5
};

inline void secure_zero(void *ptr, size_t len) {
  tinychacha_secure_zero(ptr, len);
}

inline bool constant_time_eq(const void *a, const void *b, size_t len) {
  return tinychacha_constant_time_eq(a, b, len) == 1;
}

inline bool constant_time_eq(const std::vector<uint8_t> &a,
                             const std::vector<uint8_t> &b) {
  if (a.size() != b.size())
    return false;
  return constant_time_eq(a.data(), b.data(), a.size());
}

[[nodiscard]] int generate_nonce(uint8_t *out, size_t len);

[[nodiscard]] std::vector<uint8_t> generate_nonce();

} // namespace tinychacha

#endif
