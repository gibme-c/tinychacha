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

// Verifies that ChaCha20 and the AEAD payload path support input==output
// aliasing through the C API.

#include "test_harness.h"

#include <cstdint>
#include <cstring>
#include <tinychacha/aead.h>
#include <tinychacha/chacha20.h>
#include <vector>

using test::fill_pattern;

// --- ChaCha20 in-place ---

TEST(chacha20_inplace_roundtrip)
{
    static const size_t kSizes[] = {1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 1023, 1024, 4096};

    uint8_t key[32], nonce[12];
    fill_pattern(key, 32, 0xC0FFEEu);
    fill_pattern(nonce, 12, 0xFEEDFACEu);

    for (size_t size : kSizes)
    {
        std::vector<uint8_t> original(size);
        fill_pattern(original.data(), size, static_cast<uint32_t>(size) * 7919u);

        std::vector<uint8_t> ref(size);
        ASSERT_EQ(tinychacha_chacha20(key, nonce, 1, original.data(), size, ref.data()), TINYCHACHA_OK);

        std::vector<uint8_t> work(original);
        ASSERT_EQ(tinychacha_chacha20(key, nonce, 1, work.data(), size, work.data()), TINYCHACHA_OK);
        if (size > 0)
            ASSERT_BYTES_EQ(work.data(), ref.data(), size);

        // Re-encrypt in place: ChaCha20 is its own inverse.
        ASSERT_EQ(tinychacha_chacha20(key, nonce, 1, work.data(), size, work.data()), TINYCHACHA_OK);
        if (size > 0)
            ASSERT_BYTES_EQ(work.data(), original.data(), size);
    }
}

// --- AEAD in-place (C API: ciphertext buffer == plaintext buffer) ---

TEST(aead_inplace_encrypt_decrypt)
{
    static const size_t kSizes[] = {0, 1, 15, 16, 17, 63, 64, 65, 1023, 1024};

    uint8_t key[32], nonce[12];
    fill_pattern(key, 32, 0xB0BAB0BAu);
    fill_pattern(nonce, 12, 0xCAFEBABEu);

    std::vector<uint8_t> aad(24);
    fill_pattern(aad.data(), aad.size(), 0x12345678u);

    for (size_t size : kSizes)
    {
        std::vector<uint8_t> original(size);
        if (size > 0)
            fill_pattern(original.data(), size, static_cast<uint32_t>(size) ^ 0xDEADBEEFu);

        std::vector<uint8_t> ref_ct(size);
        uint8_t ref_tag[16];
        ASSERT_EQ(
            tinychacha_aead_encrypt(
                key, nonce, aad.data(), aad.size(), original.data(), size, ref_ct.data(), size, ref_tag),
            TINYCHACHA_OK);

        std::vector<uint8_t> work(original);
        uint8_t tag[16];
        ASSERT_EQ(
            tinychacha_aead_encrypt(key, nonce, aad.data(), aad.size(), work.data(), size, work.data(), size, tag),
            TINYCHACHA_OK);
        if (size > 0)
            ASSERT_BYTES_EQ(work.data(), ref_ct.data(), size);
        ASSERT_BYTES_EQ(tag, ref_tag, 16);


        ASSERT_EQ(
            tinychacha_aead_decrypt(key, nonce, aad.data(), aad.size(), work.data(), size, work.data(), size, tag),
            TINYCHACHA_OK);
        if (size > 0)
            ASSERT_BYTES_EQ(work.data(), original.data(), size);
    }
}
