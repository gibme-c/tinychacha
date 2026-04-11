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

#include <cstring>

namespace tinychacha
{
    namespace internal
    {

        static inline uint32_t rotl32(uint32_t v, int n)
        {
            return (v << n) | (v >> (32 - n));
        }

#define QUARTERROUND(a, b, c, d) \
    do                           \
    {                            \
        a += b;                  \
        d ^= a;                  \
        d = rotl32(d, 16);       \
        c += d;                  \
        b ^= c;                  \
        b = rotl32(b, 12);       \
        a += b;                  \
        d ^= a;                  \
        d = rotl32(d, 8);        \
        c += d;                  \
        b ^= c;                  \
        b = rotl32(b, 7);        \
    } while (0)

        static void chacha20_block(const uint32_t state[16], uint8_t out[64])
        {
            uint32_t x[16];
            std::memcpy(x, state, 64);

            // 20 rounds = 10 double-rounds
            for (int i = 0; i < 10; ++i)
            {
                // Column rounds
                QUARTERROUND(x[0], x[4], x[8], x[12]);
                QUARTERROUND(x[1], x[5], x[9], x[13]);
                QUARTERROUND(x[2], x[6], x[10], x[14]);
                QUARTERROUND(x[3], x[7], x[11], x[15]);
                // Diagonal rounds
                QUARTERROUND(x[0], x[5], x[10], x[15]);
                QUARTERROUND(x[1], x[6], x[11], x[12]);
                QUARTERROUND(x[2], x[7], x[8], x[13]);
                QUARTERROUND(x[3], x[4], x[9], x[14]);
            }

            // Add original state
            for (int i = 0; i < 16; ++i)
            {
                x[i] += state[i];
            }

            // Serialize as little-endian
            for (int i = 0; i < 16; ++i)
            {
                detail::store_le32(out + i * 4, x[i]);
            }

            tinychacha_secure_zero(x, sizeof(x));
        }

#undef QUARTERROUND

        void chacha20_portable(
            const uint8_t key[32],
            const uint8_t nonce[12],
            uint32_t counter,
            const uint8_t *input,
            size_t input_len,
            uint8_t *output)
        {
            // "expand 32-byte k"
            uint32_t state[16];
            state[0] = 0x61707865;
            state[1] = 0x3320646e;
            state[2] = 0x79622d32;
            state[3] = 0x6b206574;

            // Key words (LE)
            for (int i = 0; i < 8; ++i)
            {
                state[4 + i] = detail::load_le32(key + i * 4);
            }

            // Counter at position 12
            state[12] = counter;

            // Nonce words (LE)
            state[13] = detail::load_le32(nonce);
            state[14] = detail::load_le32(nonce + 4);
            state[15] = detail::load_le32(nonce + 8);

            size_t offset = 0;
            while (offset < input_len)
            {
                uint8_t keystream[64];
                chacha20_block(state, keystream);

                size_t chunk = input_len - offset;
                if (chunk > 64)
                    chunk = 64;

                for (size_t i = 0; i < chunk; ++i)
                {
                    output[offset + i] = input[offset + i] ^ keystream[i];
                }

                tinychacha_secure_zero(keystream, sizeof(keystream));

                offset += chunk;
                state[12]++; // Increment counter
            }

            tinychacha_secure_zero(state, sizeof(state));
        }

    } // namespace internal
} // namespace tinychacha
