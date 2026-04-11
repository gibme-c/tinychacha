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

#if defined(__AVX512F__)

#include <cstring>
#include <immintrin.h>

namespace tinychacha
{
    namespace internal
    {

// AVX-512 has native 32-bit rotate
#define QR_AVX512(a, b, c, d)        \
    do                               \
    {                                \
        a = _mm512_add_epi32(a, b);  \
        d = _mm512_xor_si512(d, a);  \
        d = _mm512_rol_epi32(d, 16); \
        c = _mm512_add_epi32(c, d);  \
        b = _mm512_xor_si512(b, c);  \
        b = _mm512_rol_epi32(b, 12); \
        a = _mm512_add_epi32(a, b);  \
        d = _mm512_xor_si512(d, a);  \
        d = _mm512_rol_epi32(d, 8);  \
        c = _mm512_add_epi32(c, d);  \
        b = _mm512_xor_si512(b, c);  \
        b = _mm512_rol_epi32(b, 7);  \
    } while (0)

        void chacha20_avx512(
            const uint8_t key[32],
            const uint8_t nonce[12],
            uint32_t counter,
            const uint8_t *input,
            size_t input_len,
            uint8_t *output)
        {
            // Set up base state
            uint32_t state[16];
            state[0] = 0x61707865;
            state[1] = 0x3320646e;
            state[2] = 0x79622d32;
            state[3] = 0x6b206574;
            for (int i = 0; i < 8; ++i)
                state[4 + i] = detail::load_le32(key + i * 4);
            state[12] = counter;
            state[13] = detail::load_le32(nonce);
            state[14] = detail::load_le32(nonce + 4);
            state[15] = detail::load_le32(nonce + 8);

            size_t offset = 0;

            // Process 16 blocks (1024 bytes) at a time
            while (input_len - offset >= 1024)
            {
                // Load state into 16 x __m512i, each holding the same word from 16 blocks
                // Only v12 differs (counter values: counter+0 through counter+15)
                __m512i v[16];
                for (int i = 0; i < 16; ++i)
                {
                    if (i == 12)
                    {
                        v[i] = _mm512_setr_epi32(
                            static_cast<int>(state[12]),
                            static_cast<int>(state[12] + 1),
                            static_cast<int>(state[12] + 2),
                            static_cast<int>(state[12] + 3),
                            static_cast<int>(state[12] + 4),
                            static_cast<int>(state[12] + 5),
                            static_cast<int>(state[12] + 6),
                            static_cast<int>(state[12] + 7),
                            static_cast<int>(state[12] + 8),
                            static_cast<int>(state[12] + 9),
                            static_cast<int>(state[12] + 10),
                            static_cast<int>(state[12] + 11),
                            static_cast<int>(state[12] + 12),
                            static_cast<int>(state[12] + 13),
                            static_cast<int>(state[12] + 14),
                            static_cast<int>(state[12] + 15));
                    }
                    else
                    {
                        v[i] = _mm512_set1_epi32(static_cast<int>(state[i]));
                    }
                }

                // Save original for add-back
                __m512i orig[16];
                for (int i = 0; i < 16; ++i)
                    orig[i] = v[i];

                // 20 rounds = 10 double-rounds
                for (int i = 0; i < 10; ++i)
                {
                    // Column rounds
                    QR_AVX512(v[0], v[4], v[8], v[12]);
                    QR_AVX512(v[1], v[5], v[9], v[13]);
                    QR_AVX512(v[2], v[6], v[10], v[14]);
                    QR_AVX512(v[3], v[7], v[11], v[15]);
                    // Diagonal rounds
                    QR_AVX512(v[0], v[5], v[10], v[15]);
                    QR_AVX512(v[1], v[6], v[11], v[12]);
                    QR_AVX512(v[2], v[7], v[8], v[13]);
                    QR_AVX512(v[3], v[4], v[9], v[14]);
                }

                // Add original state
                for (int i = 0; i < 16; ++i)
                    v[i] = _mm512_add_epi32(v[i], orig[i]);

                // Extract each block's 16 words and XOR with input
                for (int blk = 0; blk < 16; ++blk)
                {
                    uint8_t keystream[64];
                    alignas(64) uint32_t tmp[16];
                    for (int w = 0; w < 16; ++w)
                    {
                        // Extract the blk-th 32-bit element from v[w]
                        // _mm512_store_si512 to a temporary and index
                        _mm512_store_si512(reinterpret_cast<__m512i *>(tmp), v[w]);
                        detail::store_le32(keystream + w * 4, tmp[blk]);
                    }
                    for (size_t j = 0; j < 64; ++j)
                    {
                        output[offset + j] = input[offset + j] ^ keystream[j];
                    }
                    tinychacha_secure_zero(keystream, sizeof(keystream));
                    tinychacha_secure_zero(tmp, sizeof(tmp));
                    offset += 64;
                }

                // Defense-in-depth: zero the round-state and the saved-state copies so no
                // keystream-derived values survive beyond the chunk loop iteration.
                tinychacha_secure_zero(v, sizeof(v));
                tinychacha_secure_zero(orig, sizeof(orig));

                state[12] += 16;
            }

            // Handle remaining bytes — delegate to AVX2 for 4+ blocks, else portable
            if (offset < input_len)
            {
                chacha20_avx2(key, nonce, state[12], input + offset, input_len - offset, output + offset);
            }

            tinychacha_secure_zero(state, sizeof(state));
        }

#undef QR_AVX512

    } // namespace internal
} // namespace tinychacha

#else

namespace tinychacha
{
    namespace internal
    {

        void chacha20_avx512(
            const uint8_t key[32],
            const uint8_t nonce[12],
            uint32_t counter,
            const uint8_t *input,
            size_t input_len,
            uint8_t *output)
        {
            chacha20_avx2(key, nonce, counter, input, input_len, output);
        }

    } // namespace internal
} // namespace tinychacha

#endif
