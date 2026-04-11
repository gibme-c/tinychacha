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

// Permanent cross-backend equivalence regression test.
//
// Links directly against the internal backend symbols so we can invoke each
// SIMD backend independently of the runtime dispatch and compare byte-for-byte
// against the portable scalar reference. This is the ground-truth correctness
// gate for the SIMD implementations, and in particular for the AVX2 Poly1305
// rewrite. A divergence here means a real correctness regression even if the
// RFC 8439 vector tests happen to pass.

#include "internal/chacha20_impl.h"
#include "internal/poly1305_impl.h"
#include "test_harness.h"

#include <cstdint>
#include <cstring>
#include <vector>

using test::fill_pattern;

// -------- ChaCha20 cross-backend equivalence --------

TEST(backend_equivalence_chacha20_portable_vs_simd)
{
    static const size_t kSizes[] = {0,   1,   63,  64,  65,   127,  128,  129,  255,  256,
                                    257, 511, 512, 513, 1023, 1024, 1025, 2048, 4096, 8192};
    static const uint32_t kCounters[] = {0, 1, 7, 0x7ffffffeu, 0xfffffffdu};

    uint8_t key[32];
    uint8_t nonce[12];
    fill_pattern(key, sizeof(key), 0xA1B2C3D4u);
    fill_pattern(nonce, sizeof(nonce), 0xDEADBEEFu);

    for (size_t size : kSizes)
    {
        std::vector<uint8_t> input(size);
        fill_pattern(input.data(), size, static_cast<uint32_t>(size) ^ 0xC0FFEEu);

        for (uint32_t counter : kCounters)
        {
            if (tinychacha::internal::counter_would_overflow(counter, size))
                continue;

            std::vector<uint8_t> ref(size);
            tinychacha::internal::chacha20_portable(key, nonce, counter, input.data(), size, ref.data());

#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)) \
    && !defined(TINYCHACHA_FORCE_PORTABLE)
            {
                std::vector<uint8_t> got(size);
                tinychacha::internal::chacha20_avx2(key, nonce, counter, input.data(), size, got.data());
                ASSERT_BYTES_EQ(got.data(), ref.data(), size);
            }
            {
                std::vector<uint8_t> got(size);
                tinychacha::internal::chacha20_avx512(key, nonce, counter, input.data(), size, got.data());
                ASSERT_BYTES_EQ(got.data(), ref.data(), size);
            }
#endif
#if (defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_NEON)) && !defined(TINYCHACHA_FORCE_PORTABLE)
            {
                std::vector<uint8_t> got(size);
                tinychacha::internal::chacha20_neon(key, nonce, counter, input.data(), size, got.data());
                ASSERT_BYTES_EQ(got.data(), ref.data(), size);
            }
#endif
        }
    }
}

// -------- Poly1305 cross-backend equivalence --------

TEST(backend_equivalence_poly1305_portable_vs_simd)
{
    static const size_t kSizes[] = {0,   1,   15,  16,  17,  31,  32,  33,   63,   64,  65,
                                    127, 128, 129, 255, 256, 511, 512, 1023, 1024, 4096};

    uint8_t key[32];
    fill_pattern(key, sizeof(key), 0x12345678u);

    for (size_t size : kSizes)
    {
        std::vector<uint8_t> msg(size);
        fill_pattern(msg.data(), size, static_cast<uint32_t>(size) * 31u + 7u);

        uint8_t ref[16];
        tinychacha::internal::poly1305_portable(key, msg.data(), size, ref);

#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)) \
    && !defined(TINYCHACHA_FORCE_PORTABLE)
        {
            uint8_t got[16];
            tinychacha::internal::poly1305_avx2(key, msg.data(), size, got);
            ASSERT_BYTES_EQ(got, ref, 16);
        }
#endif
#if (defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_NEON)) && !defined(TINYCHACHA_FORCE_PORTABLE)
        {
            uint8_t got[16];
            tinychacha::internal::poly1305_neon(key, msg.data(), size, got);
            ASSERT_BYTES_EQ(got, ref, 16);
        }
#endif
    }
}

// -------- Poly1305 across multiple independent keys --------
//
// A lane-parallel Horner AVX2 implementation is key-dependent via the
// r / r^2 / r^3 / r^4 precompute, so single-key coverage is insufficient —
// iterate over several unrelated keys to exercise the precompute path.

TEST(backend_equivalence_poly1305_multi_key)
{
    static const uint32_t kKeySeeds[] = {0x00000000u, 0x11111111u, 0xA5A5A5A5u, 0xFFFFFFFFu, 0xCAFEBABEu};
    static const size_t kSizes[] = {64, 80, 96, 112, 128, 192, 256, 320, 1024};

    for (uint32_t seed : kKeySeeds)
    {
        uint8_t key[32];
        fill_pattern(key, sizeof(key), seed);

        for (size_t size : kSizes)
        {
            std::vector<uint8_t> msg(size);
            fill_pattern(msg.data(), size, seed ^ static_cast<uint32_t>(size));

            uint8_t ref[16];
            tinychacha::internal::poly1305_portable(key, msg.data(), size, ref);

#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)) \
    && !defined(TINYCHACHA_FORCE_PORTABLE)
            uint8_t got[16];
            tinychacha::internal::poly1305_avx2(key, msg.data(), size, got);
            ASSERT_BYTES_EQ(got, ref, 16);
#endif
        }
    }
}
