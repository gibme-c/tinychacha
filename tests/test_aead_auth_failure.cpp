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

#include "test_harness.h"

#include <tinychacha/aead.h>

static void setup_encrypted(
    std::vector<uint8_t> &key,
    std::vector<uint8_t> &nonce,
    std::vector<uint8_t> &aad,
    std::vector<uint8_t> &ct,
    std::vector<uint8_t> &tag)
{
    key = test::hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    nonce = test::hex_to_bytes("070000004041424344454647");
    aad = {0x01, 0x02, 0x03};
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    (void)tinychacha::aead_encrypt(key, nonce, aad, plaintext, ct, tag);
}

TEST(auth_fail_tampered_ciphertext)
{
    std::vector<uint8_t> key, nonce, aad, ct, tag;
    setup_encrypted(key, nonce, aad, ct, tag);

    ct[0] ^= 0x01; // tamper
    std::vector<uint8_t> pt;
    auto result = tinychacha::aead_decrypt(key, nonce, aad, ct, tag, pt);
    ASSERT_EQ(result, tinychacha::Result::AuthenticationFailed);
    ASSERT_TRUE(pt.empty());
}

TEST(auth_fail_tampered_aad)
{
    std::vector<uint8_t> key, nonce, aad, ct, tag;
    setup_encrypted(key, nonce, aad, ct, tag);

    aad[0] ^= 0x01; // tamper
    std::vector<uint8_t> pt;
    auto result = tinychacha::aead_decrypt(key, nonce, aad, ct, tag, pt);
    ASSERT_EQ(result, tinychacha::Result::AuthenticationFailed);
    ASSERT_TRUE(pt.empty());
}

TEST(auth_fail_tampered_tag)
{
    std::vector<uint8_t> key, nonce, aad, ct, tag;
    setup_encrypted(key, nonce, aad, ct, tag);

    tag[0] ^= 0x01; // tamper
    std::vector<uint8_t> pt;
    auto result = tinychacha::aead_decrypt(key, nonce, aad, ct, tag, pt);
    ASSERT_EQ(result, tinychacha::Result::AuthenticationFailed);
    ASSERT_TRUE(pt.empty());
}

TEST(auth_fail_wrong_key)
{
    std::vector<uint8_t> key, nonce, aad, ct, tag;
    setup_encrypted(key, nonce, aad, ct, tag);

    key[0] ^= 0x01; // wrong key
    std::vector<uint8_t> pt;
    auto result = tinychacha::aead_decrypt(key, nonce, aad, ct, tag, pt);
    ASSERT_EQ(result, tinychacha::Result::AuthenticationFailed);
    ASSERT_TRUE(pt.empty());
}

TEST(auth_fail_wrong_nonce)
{
    std::vector<uint8_t> key, nonce, aad, ct, tag;
    setup_encrypted(key, nonce, aad, ct, tag);

    nonce[0] ^= 0x01; // wrong nonce
    std::vector<uint8_t> pt;
    auto result = tinychacha::aead_decrypt(key, nonce, aad, ct, tag, pt);
    ASSERT_EQ(result, tinychacha::Result::AuthenticationFailed);
    ASSERT_TRUE(pt.empty());
}
