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

#ifndef TINYCHACHA_INTERNAL_ENDIAN_H
#define TINYCHACHA_INTERNAL_ENDIAN_H

#include <cstdint>
#include <cstring>

namespace tinychacha {
namespace detail {

inline uint32_t load_le32(const void *src) {
  uint32_t v;
  std::memcpy(&v, src, 4);
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  v = ((v & 0x000000FFU) << 24) | ((v & 0x0000FF00U) << 8) |
      ((v & 0x00FF0000U) >> 8) | ((v & 0xFF000000U) >> 24);
#endif
  return v;
}

inline void store_le32(void *dst, uint32_t v) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  v = ((v & 0x000000FFU) << 24) | ((v & 0x0000FF00U) << 8) |
      ((v & 0x00FF0000U) >> 8) | ((v & 0xFF000000U) >> 24);
#endif
  std::memcpy(dst, &v, 4);
}

inline uint64_t load_le64(const void *src) {
  uint64_t v;
  std::memcpy(&v, src, 8);
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  v = ((v & 0x00000000000000FFULL) << 56) |
      ((v & 0x000000000000FF00ULL) << 40) |
      ((v & 0x0000000000FF0000ULL) << 24) | ((v & 0x00000000FF000000ULL) << 8) |
      ((v & 0x000000FF00000000ULL) >> 8) | ((v & 0x0000FF0000000000ULL) >> 24) |
      ((v & 0x00FF000000000000ULL) >> 40) | ((v & 0xFF00000000000000ULL) >> 56);
#endif
  return v;
}

inline void store_le64(void *dst, uint64_t v) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  v = ((v & 0x00000000000000FFULL) << 56) |
      ((v & 0x000000000000FF00ULL) << 40) |
      ((v & 0x0000000000FF0000ULL) << 24) | ((v & 0x00000000FF000000ULL) << 8) |
      ((v & 0x000000FF00000000ULL) >> 8) | ((v & 0x0000FF0000000000ULL) >> 24) |
      ((v & 0x00FF000000000000ULL) >> 40) | ((v & 0xFF00000000000000ULL) >> 56);
#endif
  std::memcpy(dst, &v, 8);
}

} /* namespace detail */
} /* namespace tinychacha */

#endif /* TINYCHACHA_INTERNAL_ENDIAN_H */
