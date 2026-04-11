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

// Run RFC 8439 known-answer vectors directly against each compiled backend,
// bypassing the runtime dispatcher — catches the failure mode where dispatch
// is hardwired to portable while SIMD backends are silently broken.

#include "cpu_features.h"
#include "internal/chacha20_impl.h"
#include "internal/poly1305_impl.h"
#include "test_harness.h"
#include "vectors/chacha20_vectors.inl"
#include "vectors/poly1305_vectors.inl"

#include <cstdint>
#include <cstring>
#include <vector>

namespace
{
    // Lists populated at runtime so we only call backends whose instruction
    // set the host CPU actually supports. Fixed-capacity inline arrays avoid a
    // GCC 13 -O3 -Werror=nonnull false positive on std::vector NRVO paths.
    struct ChachaList
    {
        tinychacha::internal::chacha20_block_fn data[4];
        size_t count = 0;
        void add(tinychacha::internal::chacha20_block_fn fn)
        {
            data[count++] = fn;
        }
    };
    struct PolyList
    {
        tinychacha::internal::poly1305_mac_fn data[4];
        size_t count = 0;
        void add(tinychacha::internal::poly1305_mac_fn fn)
        {
            data[count++] = fn;
        }
    };

    ChachaList collect_chacha_backends()
    {
        using namespace tinychacha::internal;
        ChachaList out;
        out.add(chacha20_portable);
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)) \
    && !defined(TINYCHACHA_FORCE_PORTABLE)
        const auto &f = tinychacha::cpu::detect();
        if (f.avx2)
            out.add(chacha20_avx2);
        if (f.avx512f)
            out.add(chacha20_avx512);
#endif
#if (defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_NEON)) && !defined(TINYCHACHA_FORCE_PORTABLE)
        if (tinychacha::cpu::detect().neon)
            out.add(chacha20_neon);
#endif
        return out;
    }

    PolyList collect_poly_backends()
    {
        using namespace tinychacha::internal;
        PolyList out;
        out.add(poly1305_portable);
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)) \
    && !defined(TINYCHACHA_FORCE_PORTABLE)
        if (tinychacha::cpu::detect().avx2)
            out.add(poly1305_avx2);
#endif
#if (defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_NEON)) && !defined(TINYCHACHA_FORCE_PORTABLE)
        if (tinychacha::cpu::detect().neon)
            out.add(poly1305_neon);
#endif
        return out;
    }
} // namespace

TEST(rfc_chacha20_encryption_vectors_per_backend)
{
    auto backends = collect_chacha_backends();
    for (const auto &v : chacha20_encryption_vectors)
    {
        auto key = test::hex_to_bytes(v.key);
        auto nonce = test::hex_to_bytes(v.nonce);
        auto pt = test::hex_to_bytes(v.plaintext);
        auto expected = test::hex_to_bytes(v.ciphertext);
        ASSERT_EQ(key.size(), static_cast<size_t>(32));
        ASSERT_EQ(nonce.size(), static_cast<size_t>(12));
        ASSERT_EQ(pt.size(), expected.size());

        for (size_t i = 0; i < backends.count; ++i)
        {
            std::vector<uint8_t> out(pt.size());
            backends.data[i](key.data(), nonce.data(), v.counter, pt.data(), pt.size(), out.data());
            ASSERT_BYTES_EQ(out.data(), expected.data(), pt.size());
        }
    }
}

TEST(rfc_chacha20_keystream_vectors_per_backend)
{
    auto backends = collect_chacha_backends();
    for (const auto &v : chacha20_keystream_vectors)
    {
        auto key = test::hex_to_bytes(v.key);
        auto nonce = test::hex_to_bytes(v.nonce);
        auto expected = test::hex_to_bytes(v.keystream);
        ASSERT_EQ(key.size(), static_cast<size_t>(32));
        ASSERT_EQ(nonce.size(), static_cast<size_t>(12));
        ASSERT_EQ(expected.size(), static_cast<size_t>(64));

        std::vector<uint8_t> zeros(64, 0);
        for (size_t i = 0; i < backends.count; ++i)
        {
            std::vector<uint8_t> out(64);
            backends.data[i](key.data(), nonce.data(), v.counter, zeros.data(), 64, out.data());
            ASSERT_BYTES_EQ(out.data(), expected.data(), 64);
        }
    }
}

TEST(rfc_poly1305_mac_vectors_per_backend)
{
    auto backends = collect_poly_backends();
    for (const auto &v : poly1305_rfc_vectors)
    {
        auto key = test::hex_to_bytes(v.key);
        auto msg = test::hex_to_bytes(v.message);
        auto expected = test::hex_to_bytes(v.tag);
        ASSERT_EQ(key.size(), static_cast<size_t>(32));
        ASSERT_EQ(expected.size(), static_cast<size_t>(16));

        for (size_t i = 0; i < backends.count; ++i)
        {
            uint8_t tag[16];
            backends.data[i](key.data(), msg.data(), msg.size(), tag);
            ASSERT_BYTES_EQ(tag, expected.data(), 16);
        }
    }
}
