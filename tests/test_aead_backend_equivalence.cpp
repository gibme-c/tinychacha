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

// Reimplements the RFC 8439 AEAD construction parameterized on backend
// function pointers and asserts every {chacha20, poly1305} backend pair
// produces byte-identical (ciphertext, tag), and matches the library's
// dispatched aead_encrypt output.

#include "internal/chacha20_impl.h"
#include "internal/endian.h"
#include "internal/poly1305_impl.h"
#include "test_harness.h"

#include <cstdint>
#include <cstring>
#include <tinychacha/aead.h>
#include <vector>

namespace
{
    using chacha_fn = tinychacha::internal::chacha20_block_fn;
    using poly_fn = tinychacha::internal::poly1305_mac_fn;

    using test::fill_pattern;

    inline size_t pad16(size_t len)
    {
        return (16 - (len & 15u)) & 15u;
    }

    void aead_encrypt_ref(
        chacha_fn chacha,
        poly_fn poly,
        const uint8_t key[32],
        const uint8_t nonce[12],
        const uint8_t *aad,
        size_t aad_len,
        const uint8_t *plaintext,
        size_t pt_len,
        uint8_t *ct,
        uint8_t tag[16])
    {
        uint8_t zeros[64] = {};
        uint8_t block[64] = {};
        chacha(key, nonce, 0, zeros, 64, block);
        uint8_t poly_key[32];
        std::memcpy(poly_key, block, 32);

        if (pt_len > 0)
            chacha(key, nonce, 1, plaintext, pt_len, ct);

        size_t mac_len = aad_len + pad16(aad_len) + pt_len + pad16(pt_len) + 16;
        std::vector<uint8_t> mac_data(mac_len, 0);
        size_t off = 0;
        if (aad_len > 0)
            std::memcpy(mac_data.data() + off, aad, aad_len);
        off += aad_len + pad16(aad_len);
        if (pt_len > 0)
            std::memcpy(mac_data.data() + off, ct, pt_len);
        off += pt_len + pad16(pt_len);
        tinychacha::detail::store_le64(mac_data.data() + off, static_cast<uint64_t>(aad_len));
        tinychacha::detail::store_le64(mac_data.data() + off + 8, static_cast<uint64_t>(pt_len));

        poly(poly_key, mac_data.data(), mac_data.size(), tag);
    }

    struct BackendPair
    {
        chacha_fn chacha;
        poly_fn poly;
    };

    // Static array (rather than vector-returning helper) to sidestep a
    // GCC 13 -O3 -Werror=nonnull false positive on the NRVO path that fires
    // when the list collapses to a single entry under FORCE_PORTABLE.
    const BackendPair kBackendPairs[] = {
        {tinychacha::internal::chacha20_portable, tinychacha::internal::poly1305_portable},
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)) \
    && !defined(TINYCHACHA_FORCE_PORTABLE)
        {tinychacha::internal::chacha20_avx2, tinychacha::internal::poly1305_portable},
        {tinychacha::internal::chacha20_avx512, tinychacha::internal::poly1305_portable},
        {tinychacha::internal::chacha20_portable, tinychacha::internal::poly1305_avx2},
        {tinychacha::internal::chacha20_avx2, tinychacha::internal::poly1305_avx2},
        {tinychacha::internal::chacha20_avx512, tinychacha::internal::poly1305_avx2},
#endif
#if (defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_NEON)) && !defined(TINYCHACHA_FORCE_PORTABLE)
        {tinychacha::internal::chacha20_neon, tinychacha::internal::poly1305_portable},
        {tinychacha::internal::chacha20_portable, tinychacha::internal::poly1305_neon},
        {tinychacha::internal::chacha20_neon, tinychacha::internal::poly1305_neon},
#endif
    };
} // namespace

TEST(backend_equivalence_aead_all_pairs)
{
    static const size_t kAadSizes[] = {0, 1, 15, 16, 17, 63, 64, 128};
    static const size_t kPtSizes[] = {0, 1, 15, 16, 17, 63, 64, 65, 1023, 1024, 1025, 4096};

    uint8_t key[32];
    uint8_t nonce[12];
    fill_pattern(key, 32, 0xA5A5A5A5u);
    fill_pattern(nonce, 12, 0x5A5A5A5Au);

    std::vector<uint8_t> lib_key(key, key + 32);
    std::vector<uint8_t> lib_nonce(nonce, nonce + 12);
    constexpr size_t kNumPairs = sizeof(kBackendPairs) / sizeof(kBackendPairs[0]);

    for (size_t aad_len : kAadSizes)
    {
        std::vector<uint8_t> aad(aad_len);
        if (aad_len > 0)
            fill_pattern(aad.data(), aad_len, static_cast<uint32_t>(aad_len) * 131u);

        for (size_t pt_len : kPtSizes)
        {
            std::vector<uint8_t> pt(pt_len);
            if (pt_len > 0)
                fill_pattern(pt.data(), pt_len, static_cast<uint32_t>(pt_len) * 17u + 3u);

            std::vector<uint8_t> ref_ct(pt_len);
            uint8_t ref_tag[16];
            aead_encrypt_ref(
                kBackendPairs[0].chacha,
                kBackendPairs[0].poly,
                key,
                nonce,
                aad.data(),
                aad_len,
                pt.data(),
                pt_len,
                ref_ct.data(),
                ref_tag);

            for (size_t p = 1; p < kNumPairs; ++p)
            {
                std::vector<uint8_t> got_ct(pt_len);
                uint8_t got_tag[16];
                aead_encrypt_ref(
                    kBackendPairs[p].chacha,
                    kBackendPairs[p].poly,
                    key,
                    nonce,
                    aad.data(),
                    aad_len,
                    pt.data(),
                    pt_len,
                    got_ct.data(),
                    got_tag);
                if (pt_len > 0)
                    ASSERT_BYTES_EQ(got_ct.data(), ref_ct.data(), pt_len);
                ASSERT_BYTES_EQ(got_tag, ref_tag, 16);
            }

            std::vector<uint8_t> lib_ct, lib_tag;
            auto result = tinychacha::aead_encrypt(lib_key, lib_nonce, aad, pt, lib_ct, lib_tag);
            ASSERT_EQ(static_cast<int>(result), static_cast<int>(tinychacha::Result::Ok));
            ASSERT_EQ(lib_ct.size(), pt_len);
            ASSERT_EQ(lib_tag.size(), static_cast<size_t>(16));
            if (pt_len > 0)
                ASSERT_BYTES_EQ(lib_ct.data(), ref_ct.data(), pt_len);
            ASSERT_BYTES_EQ(lib_tag.data(), ref_tag, 16);
        }
    }
}
