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

// Meta-invariants: determinism, nonce dependence, key avalanche, XOR linearity.
// These catch subtle backend bugs that size-grid equivalence tests cannot.

#include "test_harness.h"

#include <cstdint>
#include <cstring>
#include <tinychacha/aead.h>
#include <tinychacha/chacha20.h>
#include <vector>

using test::fill_pattern;

namespace
{
    int popcount_u8(uint8_t b)
    {
        int c = 0;
        while (b)
        {
            c += (b & 1);
            b >>= 1;
        }
        return c;
    }
} // namespace

TEST(chacha20_is_deterministic)
{
    uint8_t key[32], nonce[12];
    fill_pattern(key, 32, 0xA1u);
    fill_pattern(nonce, 12, 0xB2u);
    std::vector<uint8_t> pt(1024);
    fill_pattern(pt.data(), pt.size(), 0xC3u);

    std::vector<uint8_t> out1(1024), out2(1024);
    ASSERT_EQ(tinychacha_chacha20(key, nonce, 7, pt.data(), 1024, out1.data()), TINYCHACHA_OK);
    ASSERT_EQ(tinychacha_chacha20(key, nonce, 7, pt.data(), 1024, out2.data()), TINYCHACHA_OK);
    ASSERT_BYTES_EQ(out1.data(), out2.data(), 1024);
}

TEST(aead_is_deterministic)
{
    uint8_t key[32], nonce[12];
    fill_pattern(key, 32, 0x11u);
    fill_pattern(nonce, 12, 0x22u);
    std::vector<uint8_t> aad(32), pt(256);
    fill_pattern(aad.data(), aad.size(), 0x33u);
    fill_pattern(pt.data(), pt.size(), 0x44u);

    std::vector<uint8_t> ct1(256), ct2(256);
    uint8_t tag1[16], tag2[16];
    ASSERT_EQ(
        tinychacha_aead_encrypt(key, nonce, aad.data(), aad.size(), pt.data(), pt.size(), ct1.data(), pt.size(), tag1),
        TINYCHACHA_OK);
    ASSERT_EQ(
        tinychacha_aead_encrypt(key, nonce, aad.data(), aad.size(), pt.data(), pt.size(), ct2.data(), pt.size(), tag2),
        TINYCHACHA_OK);
    ASSERT_BYTES_EQ(ct1.data(), ct2.data(), 256);
    ASSERT_BYTES_EQ(tag1, tag2, 16);
}

TEST(chacha20_nonce_changes_output)
{
    uint8_t key[32], nonce_a[12], nonce_b[12];
    fill_pattern(key, 32, 0x55u);
    fill_pattern(nonce_a, 12, 0x66u);
    fill_pattern(nonce_b, 12, 0x77u);
    ASSERT_TRUE(std::memcmp(nonce_a, nonce_b, 12) != 0);

    std::vector<uint8_t> pt(128);
    fill_pattern(pt.data(), pt.size(), 0x88u);
    std::vector<uint8_t> ct_a(128), ct_b(128);
    ASSERT_EQ(tinychacha_chacha20(key, nonce_a, 1, pt.data(), 128, ct_a.data()), TINYCHACHA_OK);
    ASSERT_EQ(tinychacha_chacha20(key, nonce_b, 1, pt.data(), 128, ct_b.data()), TINYCHACHA_OK);
    ASSERT_TRUE(std::memcmp(ct_a.data(), ct_b.data(), 128) != 0);
}

TEST(chacha20_key_avalanche_bit_flip)
{
    uint8_t key_a[32], nonce[12];
    fill_pattern(key_a, 32, 0xAAu);
    fill_pattern(nonce, 12, 0xBBu);
    uint8_t key_b[32];
    std::memcpy(key_b, key_a, 32);
    key_b[0] ^= 0x01;

    // Zero plaintext: ciphertext is the raw keystream, so diff = keystream diff.
    std::vector<uint8_t> pt(1024, 0);
    std::vector<uint8_t> ct_a(1024), ct_b(1024);
    ASSERT_EQ(tinychacha_chacha20(key_a, nonce, 1, pt.data(), 1024, ct_a.data()), TINYCHACHA_OK);
    ASSERT_EQ(tinychacha_chacha20(key_b, nonce, 1, pt.data(), 1024, ct_b.data()), TINYCHACHA_OK);

    int differing_bits = 0;
    for (size_t i = 0; i < 1024; ++i)
        differing_bits += popcount_u8(static_cast<uint8_t>(ct_a[i] ^ ct_b[i]));
    // 1024 bytes = 8192 bits. Ideal avalanche is ~4096 differing bits (50%).
    // Use a loose lower bound of 40% (3277) to avoid flakiness on a healthy
    // implementation while still catching catastrophic avalanche failures.
    ASSERT_TRUE(differing_bits > 3277);
}

// ChaCha20 ciphertext = plaintext XOR keystream, so a single plaintext bit
// flip must flip exactly the same bit in the ciphertext and nothing else.
TEST(chacha20_xor_linearity_single_bit)
{
    uint8_t key[32], nonce[12];
    fill_pattern(key, 32, 0x01u);
    fill_pattern(nonce, 12, 0x02u);

    const size_t len = 256;
    std::vector<uint8_t> pt_a(len, 0);
    std::vector<uint8_t> pt_b(len, 0);
    pt_b[137] ^= (1u << 3);

    std::vector<uint8_t> ct_a(len), ct_b(len);
    ASSERT_EQ(tinychacha_chacha20(key, nonce, 1, pt_a.data(), len, ct_a.data()), TINYCHACHA_OK);
    ASSERT_EQ(tinychacha_chacha20(key, nonce, 1, pt_b.data(), len, ct_b.data()), TINYCHACHA_OK);

    for (size_t i = 0; i < len; ++i)
    {
        uint8_t diff = static_cast<uint8_t>(ct_a[i] ^ ct_b[i]);
        if (i == 137)
            ASSERT_EQ(diff, static_cast<uint8_t>(1u << 3));
        else
            ASSERT_EQ(diff, static_cast<uint8_t>(0));
    }
}
