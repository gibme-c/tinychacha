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

#include "internal/chacha20_impl.h"
#include "internal/endian.h"
#include "tinychacha/common.h"

// Only enable NEON on little-endian targets (AArch64 is overwhelmingly LE).
// On big-endian, the vreinterpretq_u8_u32 XOR path produces wrong byte order.
#if (defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_NEON)) &&       \
    (!defined(__BYTE_ORDER__) || __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ ||   \
     defined(_M_ARM64))

#if defined(_MSC_VER)
#include <arm64_neon.h>
#else
#include <arm_neon.h>
#endif
#include <cstring>

namespace tinychacha {
namespace internal {

// NEON rotate-left for 32-bit lanes
// 16-bit rotation: byte-swap within 32-bit lanes via vrev32q_u16
#define ROTL16_NEON(v)                                                         \
  vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(v)))

// 12-bit and 7-bit rotation: shift-right-insert pattern (2 instructions)
#define ROTL12_NEON(v) vsriq_n_u32(vshlq_n_u32((v), 12), (v), 20)

#define ROTL7_NEON(v) vsriq_n_u32(vshlq_n_u32((v), 7), (v), 25)

// 8-bit rotation: table lookup shuffle on AArch64
static inline uint32x4_t rotl8_neon(uint32x4_t v) {
  static const uint8_t tbl[16] = {3,  0, 1, 2,  7,  4,  5,  6,
                                  11, 8, 9, 10, 15, 12, 13, 14};
  const uint8x16_t idx = vld1q_u8(tbl);
  return vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(v), idx));
}

// NEON quarter round on row vectors
#define QR_NEON(a, b, c, d)                                                    \
  do {                                                                         \
    a = vaddq_u32(a, b);                                                       \
    d = veorq_u32(d, a);                                                       \
    d = ROTL16_NEON(d);                                                        \
    c = vaddq_u32(c, d);                                                       \
    b = veorq_u32(b, c);                                                       \
    b = ROTL12_NEON(b);                                                        \
    a = vaddq_u32(a, b);                                                       \
    d = veorq_u32(d, a);                                                       \
    d = rotl8_neon(d);                                                         \
    c = vaddq_u32(c, d);                                                       \
    b = veorq_u32(b, c);                                                       \
    b = ROTL7_NEON(b);                                                         \
  } while (0)

void chacha20_neon(const uint8_t key[32], const uint8_t nonce[12],
                   uint32_t counter, const uint8_t *input, size_t input_len,
                   uint8_t *output) {
  // Build initial state
  // row0: constants "expand 32-byte k"
  const uint32x4_t k_const = {0x61707865u, 0x3320646eu, 0x79622d32u,
                              0x6b206574u};
  // Load key through load_le32 to avoid strict aliasing violation and handle
  // endianness correctly
  uint32_t key_words[8];
  for (int i = 0; i < 8; ++i)
    key_words[i] = detail::load_le32(key + i * 4);
  const uint32x4_t k_row1 = vld1q_u32(key_words);
  const uint32x4_t k_row2 = vld1q_u32(key_words + 4);

  uint32_t n0 = detail::load_le32(nonce);
  uint32_t n1 = detail::load_le32(nonce + 4);
  uint32_t n2 = detail::load_le32(nonce + 8);

  while (input_len > 0) {
    uint32x4_t row3_init = {counter, n0, n1, n2};

    uint32x4_t row0 = k_const;
    uint32x4_t row1 = k_row1;
    uint32x4_t row2 = k_row2;
    uint32x4_t row3 = row3_init;

    // 20 rounds = 10 double-rounds
    for (int i = 0; i < 10; ++i) {
      // Column round
      QR_NEON(row0, row1, row2, row3);

      // Diagonal round: rotate rows for diagonal alignment
      row1 = vextq_u32(row1, row1, 1);
      row2 = vextq_u32(row2, row2, 2);
      row3 = vextq_u32(row3, row3, 3);

      QR_NEON(row0, row1, row2, row3);

      // Undo rotation
      row1 = vextq_u32(row1, row1, 3);
      row2 = vextq_u32(row2, row2, 2);
      row3 = vextq_u32(row3, row3, 1);
    }

    // Add initial state back
    row0 = vaddq_u32(row0, k_const);
    row1 = vaddq_u32(row1, k_row1);
    row2 = vaddq_u32(row2, k_row2);
    row3 = vaddq_u32(row3, row3_init);

    if (input_len >= 64) {
      // Full block: load, XOR, store
      uint8x16_t in0 = vld1q_u8(input);
      uint8x16_t in1 = vld1q_u8(input + 16);
      uint8x16_t in2 = vld1q_u8(input + 32);
      uint8x16_t in3 = vld1q_u8(input + 48);

      vst1q_u8(output, veorq_u8(in0, vreinterpretq_u8_u32(row0)));
      vst1q_u8(output + 16, veorq_u8(in1, vreinterpretq_u8_u32(row1)));
      vst1q_u8(output + 32, veorq_u8(in2, vreinterpretq_u8_u32(row2)));
      vst1q_u8(output + 48, veorq_u8(in3, vreinterpretq_u8_u32(row3)));

      input += 64;
      output += 64;
      input_len -= 64;
    } else {
      // Partial tail: serialize keystream block, XOR byte by byte
      uint8_t block[64];
      vst1q_u8(block, vreinterpretq_u8_u32(row0));
      vst1q_u8(block + 16, vreinterpretq_u8_u32(row1));
      vst1q_u8(block + 32, vreinterpretq_u8_u32(row2));
      vst1q_u8(block + 48, vreinterpretq_u8_u32(row3));

      for (size_t j = 0; j < input_len; ++j) {
        output[j] = input[j] ^ block[j];
      }
      tinychacha_secure_zero(block, sizeof(block));
      input_len = 0;
    }

    ++counter;
  }

  tinychacha_secure_zero(key_words, sizeof(key_words));
}

} // namespace internal
} // namespace tinychacha

#else // !NEON or big-endian

namespace tinychacha {
namespace internal {

void chacha20_neon(const uint8_t key[32], const uint8_t nonce[12],
                   uint32_t counter, const uint8_t *input, size_t input_len,
                   uint8_t *output) {
  chacha20_portable(key, nonce, counter, input, input_len, output);
}

} // namespace internal
} // namespace tinychacha

#endif
