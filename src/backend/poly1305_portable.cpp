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

#include "internal/endian.h"
#include "internal/poly1305_impl.h"
#include "tinychacha/common.h"

#include <cstring>

namespace tinychacha
{
    namespace internal
    {

        // ============================================================================
        // MSVC path: 5-limb radix-2^26, all multiplies fit in 64 bits
        // GCC/Clang path: 3-limb radix-2^44 with __uint128_t
        // ============================================================================

#if defined(_MSC_VER) && !defined(__clang__)

        // 5-limb radix-2^26 implementation for MSVC (no __uint128_t)
        void poly1305_portable(const uint8_t key[32], const uint8_t *message, size_t message_len, uint8_t tag[16])
        {
            // Load and clamp r at 32-bit word level (donna-style)
            uint32_t t0 = detail::load_le32(key + 0) & 0x0fffffff;
            uint32_t t1 = detail::load_le32(key + 4) & 0x0ffffffc;
            uint32_t t2 = detail::load_le32(key + 8) & 0x0ffffffc;
            uint32_t t3 = detail::load_le32(key + 12) & 0x0ffffffc;

            // Decompose into radix-2^26 limbs
            uint32_t r0 = t0 & 0x03ffffff;
            uint32_t r1 = ((t0 >> 26) | (t1 << 6)) & 0x03ffffff;
            uint32_t r2 = ((t1 >> 20) | (t2 << 12)) & 0x03ffffff;
            uint32_t r3 = ((t2 >> 14) | (t3 << 18)) & 0x03ffffff;
            uint32_t r4 = (t3 >> 8);

            // Precompute 5*r for reduction
            uint32_t s1 = r1 * 5;
            uint32_t s2 = r2 * 5;
            uint32_t s3 = r3 * 5;
            uint32_t s4 = r4 * 5;

            // Accumulator
            uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

            while (message_len > 0)
            {
                // Load block
                size_t blen = (message_len >= 16) ? 16 : message_len;
                uint8_t block[17] = {};
                std::memcpy(block, message, blen);
                block[blen] = 0x01; // hibit

                // Decompose block into radix-2^26
                uint32_t b0 = detail::load_le32(block + 0);
                uint32_t b1 = detail::load_le32(block + 4);
                uint32_t b2 = detail::load_le32(block + 8);
                uint32_t b3 = detail::load_le32(block + 12);
                uint32_t b4 = block[16]; // 1 on full blocks; 0 on a final partial block

                h0 += b0 & 0x03ffffff;
                h1 += ((b0 >> 26) | (b1 << 6)) & 0x03ffffff;
                h2 += ((b1 >> 20) | (b2 << 12)) & 0x03ffffff;
                h3 += ((b2 >> 14) | (b3 << 18)) & 0x03ffffff;
                h4 += (b3 >> 8) | (b4 << 24);

                // h *= r mod p
                uint64_t d0 =
                    (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
                uint64_t d1 =
                    (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
                uint64_t d2 =
                    (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
                uint64_t d3 =
                    (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
                uint64_t d4 =
                    (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

                // Partial reduction
                uint32_t c;
                c = static_cast<uint32_t>(d0 >> 26);
                h0 = static_cast<uint32_t>(d0) & 0x03ffffff;
                d1 += c;
                c = static_cast<uint32_t>(d1 >> 26);
                h1 = static_cast<uint32_t>(d1) & 0x03ffffff;
                d2 += c;
                c = static_cast<uint32_t>(d2 >> 26);
                h2 = static_cast<uint32_t>(d2) & 0x03ffffff;
                d3 += c;
                c = static_cast<uint32_t>(d3 >> 26);
                h3 = static_cast<uint32_t>(d3) & 0x03ffffff;
                d4 += c;
                c = static_cast<uint32_t>(d4 >> 26);
                h4 = static_cast<uint32_t>(d4) & 0x03ffffff;
                h0 += c * 5;
                c = h0 >> 26;
                h0 &= 0x03ffffff;
                h1 += c;

                message += blen;
                message_len -= blen;
            }

            // Full reduction
            uint32_t c;
            c = h1 >> 26;
            h1 &= 0x03ffffff;
            h2 += c;
            c = h2 >> 26;
            h2 &= 0x03ffffff;
            h3 += c;
            c = h3 >> 26;
            h3 &= 0x03ffffff;
            h4 += c;
            c = h4 >> 26;
            h4 &= 0x03ffffff;
            h0 += c * 5;
            c = h0 >> 26;
            h0 &= 0x03ffffff;
            h1 += c;

            // Compute h + 5, check if >= 2^130
            uint32_t g0, g1, g2, g3, g4;
            g0 = h0 + 5;
            c = g0 >> 26;
            g0 &= 0x03ffffff;
            g1 = h1 + c;
            c = g1 >> 26;
            g1 &= 0x03ffffff;
            g2 = h2 + c;
            c = g2 >> 26;
            g2 &= 0x03ffffff;
            g3 = h3 + c;
            c = g3 >> 26;
            g3 &= 0x03ffffff;
            g4 = h4 + c - (1u << 26);

            // Constant-time select: if g4 didn't underflow (bit 31 clear), use g
            uint32_t mask = (g4 >> 31) - 1;
            g0 &= mask;
            g1 &= mask;
            g2 &= mask;
            g3 &= mask;
            g4 &= mask;
            mask = ~mask;
            h0 = (h0 & mask) | g0;
            h1 = (h1 & mask) | g1;
            h2 = (h2 & mask) | g2;
            h3 = (h3 & mask) | g3;
            h4 = (h4 & mask) | g4;

            // Convert from radix-2^26 to 4 x 32-bit words (truncate overlapping bits)
            uint32_t w0 = static_cast<uint32_t>((uint64_t)h0 | ((uint64_t)h1 << 26));
            uint32_t w1 = static_cast<uint32_t>(((uint64_t)h1 >> 6) | ((uint64_t)h2 << 20));
            uint32_t w2 = static_cast<uint32_t>(((uint64_t)h2 >> 12) | ((uint64_t)h3 << 14));
            uint32_t w3 = static_cast<uint32_t>(((uint64_t)h3 >> 18) | ((uint64_t)h4 << 8));

            // Add s (mod 2^128) with carry chain
            uint64_t f;
            f = (uint64_t)w0 + detail::load_le32(key + 16);
            w0 = static_cast<uint32_t>(f);
            f = (uint64_t)w1 + detail::load_le32(key + 20) + (f >> 32);
            w1 = static_cast<uint32_t>(f);
            f = (uint64_t)w2 + detail::load_le32(key + 24) + (f >> 32);
            w2 = static_cast<uint32_t>(f);
            f = (uint64_t)w3 + detail::load_le32(key + 28) + (f >> 32);
            w3 = static_cast<uint32_t>(f);

            detail::store_le32(tag + 0, w0);
            detail::store_le32(tag + 4, w1);
            detail::store_le32(tag + 8, w2);
            detail::store_le32(tag + 12, w3);

            // Zero all key-derived and accumulator locals
            tinychacha_secure_zero(&r0, sizeof(r0));
            tinychacha_secure_zero(&r1, sizeof(r1));
            tinychacha_secure_zero(&r2, sizeof(r2));
            tinychacha_secure_zero(&r3, sizeof(r3));
            tinychacha_secure_zero(&r4, sizeof(r4));
            tinychacha_secure_zero(&s1, sizeof(s1));
            tinychacha_secure_zero(&s2, sizeof(s2));
            tinychacha_secure_zero(&s3, sizeof(s3));
            tinychacha_secure_zero(&s4, sizeof(s4));
            tinychacha_secure_zero(&h0, sizeof(h0));
            tinychacha_secure_zero(&h1, sizeof(h1));
            tinychacha_secure_zero(&h2, sizeof(h2));
            tinychacha_secure_zero(&h3, sizeof(h3));
            tinychacha_secure_zero(&h4, sizeof(h4));
        }

#else

        // 3-limb radix-2^44 implementation with __uint128_t (GCC/Clang)
        void poly1305_portable(const uint8_t key[32], const uint8_t *message, size_t message_len, uint8_t tag[16])
        {
            // Load and clamp r
            uint64_t t0 = detail::load_le64(key);
            uint64_t t1 = detail::load_le64(key + 8);

            t0 &= 0x0ffffffc0fffffff;
            t1 &= 0x0ffffffc0ffffffc;

            // Convert to radix-2^44
            uint64_t r0 = t0 & 0xfffffffffff;
            uint64_t r1 = ((t0 >> 44) | (t1 << 20)) & 0xfffffffffff;
            uint64_t r2 = (t1 >> 24) & 0x3ffffffffff;

            uint64_t s1 = r1 * 20;
            uint64_t s2 = r2 * 20;

            // Load s
            uint64_t pad0 = detail::load_le64(key + 16);
            uint64_t pad1 = detail::load_le64(key + 24);

            // Accumulator
            uint64_t h0 = 0, h1 = 0, h2 = 0;

            while (message_len > 0)
            {
                size_t blen = (message_len >= 16) ? 16 : message_len;
                uint8_t block[17] = {};
                std::memcpy(block, message, blen);
                block[blen] = 0x01;

                uint64_t hibit = (blen == 16) ? 1 : 0;

                uint64_t b0 = detail::load_le64(block);
                uint64_t b1 = detail::load_le64(block + 8);

                h0 += b0 & 0xfffffffffff;
                h1 += ((b0 >> 44) | (b1 << 20)) & 0xfffffffffff;
                h2 += ((b1 >> 24)) | (hibit << 40);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
                using u128 = unsigned __int128;
#pragma GCC diagnostic pop
                u128 d0 = (u128)h0 * r0 + (u128)h1 * s2 + (u128)h2 * s1;
                u128 d1 = (u128)h0 * r1 + (u128)h1 * r0 + (u128)h2 * s2;
                u128 d2 = (u128)h0 * r2 + (u128)h1 * r1 + (u128)h2 * r0;

                uint64_t c;
                c = static_cast<uint64_t>(d0 >> 44);
                h0 = static_cast<uint64_t>(d0) & 0xfffffffffff;
                d1 += c;
                c = static_cast<uint64_t>(d1 >> 44);
                h1 = static_cast<uint64_t>(d1) & 0xfffffffffff;
                d2 += c;
                c = static_cast<uint64_t>(d2 >> 42);
                h2 = static_cast<uint64_t>(d2) & 0x3ffffffffff;
                h0 += c * 5;
                c = h0 >> 44;
                h0 &= 0xfffffffffff;
                h1 += c;

                message += blen;
                message_len -= blen;
            }

            // Full reduction
            uint64_t c;
            c = h1 >> 44;
            h1 &= 0xfffffffffff;
            h2 += c;
            c = h2 >> 42;
            h2 &= 0x3ffffffffff;
            h0 += c * 5;
            c = h0 >> 44;
            h0 &= 0xfffffffffff;
            h1 += c;
            c = h1 >> 44;
            h1 &= 0xfffffffffff;
            h2 += c;
            c = h2 >> 42;
            h2 &= 0x3ffffffffff;
            h0 += c * 5;
            c = h0 >> 44;
            h0 &= 0xfffffffffff;
            h1 += c;

            // Compute h + 5
            uint64_t g0 = h0 + 5;
            c = g0 >> 44;
            g0 &= 0xfffffffffff;
            uint64_t g1 = h1 + c;
            c = g1 >> 44;
            g1 &= 0xfffffffffff;
            uint64_t g2 = h2 + c - (1ULL << 42);

            uint64_t mask = (g2 >> 63) - 1;
            g0 &= mask;
            g1 &= mask;
            g2 &= mask;
            mask = ~mask;
            h0 = (h0 & mask) | g0;
            h1 = (h1 & mask) | g1;
            h2 = (h2 & mask) | g2;

            // Convert to two 64-bit words
            uint64_t out0 = h0 | (h1 << 44);
            uint64_t out1 = (h1 >> 20) | (h2 << 24);

            // Add s (mod 2^128)
            out0 += pad0;
            out1 += pad1 + (out0 < pad0 ? 1 : 0);

            detail::store_le64(tag, out0);
            detail::store_le64(tag + 8, out1);

            // Zero all key-derived and accumulator locals
            tinychacha_secure_zero(&r0, sizeof(r0));
            tinychacha_secure_zero(&r1, sizeof(r1));
            tinychacha_secure_zero(&r2, sizeof(r2));
            tinychacha_secure_zero(&s1, sizeof(s1));
            tinychacha_secure_zero(&s2, sizeof(s2));
            tinychacha_secure_zero(&h0, sizeof(h0));
            tinychacha_secure_zero(&h1, sizeof(h1));
            tinychacha_secure_zero(&h2, sizeof(h2));
            tinychacha_secure_zero(&pad0, sizeof(pad0));
            tinychacha_secure_zero(&pad1, sizeof(pad1));
        }

#endif

    } // namespace internal
} // namespace tinychacha
