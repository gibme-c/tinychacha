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
#include "vectors/aead_vectors.inl"

#include <tinychacha/aead.h>
#include <tinychacha/chacha20.h>

// --- Poly1305 Key Generation (RFC 8439 §2.6.2) ---
TEST(aead_poly_key_generation)
{
    for (const auto &v : poly_key_gen_vectors)
    {
        auto key = test::hex_to_bytes(v.key);
        auto nonce = test::hex_to_bytes(v.nonce);
        auto expected = test::hex_to_bytes(v.expected_poly_key);

        // Generate keystream at counter=0, first 32 bytes = poly key
        std::vector<uint8_t> ks;
        auto result = tinychacha::chacha20_keystream(key, nonce, 0, 64, ks);
        ASSERT_EQ(result, tinychacha::Result::Ok);
        ASSERT_BYTES_EQ(ks.data(), expected.data(), 32);
    }
}

// --- RFC 8439 §2.8.2 AEAD encrypt ---
TEST(aead_rfc_encrypt)
{
    for (const auto &v : aead_rfc_vectors)
    {
        auto key = test::hex_to_bytes(v.key);
        auto nonce = test::hex_to_bytes(v.nonce);
        auto aad = test::hex_to_bytes(v.aad);
        auto plaintext = test::hex_to_bytes(v.plaintext);
        auto expected_ct = test::hex_to_bytes(v.ciphertext);
        auto expected_tag = test::hex_to_bytes(v.tag);

        std::vector<uint8_t> ct, tag;
        auto result = tinychacha::aead_encrypt(key, nonce, aad, plaintext, ct, tag);
        ASSERT_EQ(result, tinychacha::Result::Ok);
        ASSERT_EQ(ct.size(), expected_ct.size());
        ASSERT_BYTES_EQ(ct.data(), expected_ct.data(), expected_ct.size());
        ASSERT_BYTES_EQ(tag.data(), expected_tag.data(), 16);
    }
}

// --- RFC 8439 §2.8.2 AEAD decrypt ---
TEST(aead_rfc_decrypt)
{
    for (const auto &v : aead_rfc_vectors)
    {
        auto key = test::hex_to_bytes(v.key);
        auto nonce = test::hex_to_bytes(v.nonce);
        auto aad = test::hex_to_bytes(v.aad);
        auto ciphertext = test::hex_to_bytes(v.ciphertext);
        auto tag = test::hex_to_bytes(v.tag);
        auto expected_pt = test::hex_to_bytes(v.plaintext);

        std::vector<uint8_t> pt;
        auto result = tinychacha::aead_decrypt(key, nonce, aad, ciphertext, tag, pt);
        ASSERT_EQ(result, tinychacha::Result::Ok);
        ASSERT_EQ(pt.size(), expected_pt.size());
        ASSERT_BYTES_EQ(pt.data(), expected_pt.data(), expected_pt.size());
    }
}

// --- Roundtrip ---
TEST(aead_roundtrip)
{
    auto key = test::hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    auto nonce = test::hex_to_bytes("070000004041424344454647");
    std::vector<uint8_t> aad = {0x01, 0x02, 0x03};
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};

    std::vector<uint8_t> ct, tag;
    auto r1 = tinychacha::aead_encrypt(key, nonce, aad, plaintext, ct, tag);
    ASSERT_EQ(r1, tinychacha::Result::Ok);

    std::vector<uint8_t> pt;
    auto r2 = tinychacha::aead_decrypt(key, nonce, aad, ct, tag, pt);
    ASSERT_EQ(r2, tinychacha::Result::Ok);
    ASSERT_EQ(pt.size(), plaintext.size());
    ASSERT_BYTES_EQ(pt.data(), plaintext.data(), plaintext.size());
}

// --- AAD-only (empty plaintext) ---
TEST(aead_aad_only)
{
    auto key = test::hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    auto nonce = test::hex_to_bytes("070000004041424344454647");
    std::vector<uint8_t> aad = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> empty;

    std::vector<uint8_t> ct, tag;
    auto r1 = tinychacha::aead_encrypt(key, nonce, aad, empty, ct, tag);
    ASSERT_EQ(r1, tinychacha::Result::Ok);
    ASSERT_EQ(ct.size(), static_cast<size_t>(0));

    std::vector<uint8_t> pt;
    auto r2 = tinychacha::aead_decrypt(key, nonce, aad, ct, tag, pt);
    ASSERT_EQ(r2, tinychacha::Result::Ok);
    ASSERT_EQ(pt.size(), static_cast<size_t>(0));
}

// --- Plaintext-only (empty AAD) ---
TEST(aead_plaintext_only)
{
    auto key = test::hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    auto nonce = test::hex_to_bytes("070000004041424344454647");
    std::vector<uint8_t> empty_aad;
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};

    std::vector<uint8_t> ct, tag;
    auto r1 = tinychacha::aead_encrypt(key, nonce, empty_aad, plaintext, ct, tag);
    ASSERT_EQ(r1, tinychacha::Result::Ok);

    std::vector<uint8_t> pt;
    auto r2 = tinychacha::aead_decrypt(key, nonce, empty_aad, ct, tag, pt);
    ASSERT_EQ(r2, tinychacha::Result::Ok);
    ASSERT_BYTES_EQ(pt.data(), plaintext.data(), plaintext.size());
}

// --- Empty both ---
TEST(aead_empty_both)
{
    auto key = test::hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    auto nonce = test::hex_to_bytes("070000004041424344454647");
    std::vector<uint8_t> empty;

    std::vector<uint8_t> ct, tag;
    auto r1 = tinychacha::aead_encrypt(key, nonce, empty, empty, ct, tag);
    ASSERT_EQ(r1, tinychacha::Result::Ok);

    std::vector<uint8_t> pt;
    auto r2 = tinychacha::aead_decrypt(key, nonce, empty, ct, tag, pt);
    ASSERT_EQ(r2, tinychacha::Result::Ok);
}

// --- Convenience overload: ct||tag ---
TEST(aead_combined_ct_tag)
{
    auto key = test::hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    auto nonce = test::hex_to_bytes("070000004041424344454647");
    std::vector<uint8_t> aad = {0x01, 0x02};
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};

    std::vector<uint8_t> ct_tag;
    auto r1 = tinychacha::aead_encrypt(key, nonce, plaintext, aad, ct_tag);
    ASSERT_EQ(r1, tinychacha::Result::Ok);
    ASSERT_EQ(ct_tag.size(), plaintext.size() + 16);

    std::vector<uint8_t> pt;
    auto r2 = tinychacha::aead_decrypt(key, nonce, ct_tag, aad, pt);
    ASSERT_EQ(r2, tinychacha::Result::Ok);
    ASSERT_BYTES_EQ(pt.data(), plaintext.data(), plaintext.size());
}

// --- Convenience overload: nonce||ct||tag ---
TEST(aead_auto_nonce)
{
    auto key = test::hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    std::vector<uint8_t> aad = {0x01, 0x02};
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};

    std::vector<uint8_t> nonce_ct_tag;
    auto r1 = tinychacha::aead_encrypt(key, plaintext, aad, nonce_ct_tag);
    ASSERT_EQ(r1, tinychacha::Result::Ok);
    ASSERT_EQ(nonce_ct_tag.size(), 12 + plaintext.size() + 16);

    std::vector<uint8_t> pt;
    auto r2 = tinychacha::aead_decrypt(key, nonce_ct_tag, aad, pt);
    ASSERT_EQ(r2, tinychacha::Result::Ok);
    ASSERT_BYTES_EQ(pt.data(), plaintext.data(), plaintext.size());
}

// --- Multi-block roundtrip ---
TEST(aead_multiblock)
{
    auto key = test::hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    auto nonce = test::hex_to_bytes("070000004041424344454647");
    std::vector<uint8_t> aad(100, 0xAA);
    std::vector<uint8_t> plaintext(1024, 0xBB);

    std::vector<uint8_t> ct, tag;
    auto r1 = tinychacha::aead_encrypt(key, nonce, aad, plaintext, ct, tag);
    ASSERT_EQ(r1, tinychacha::Result::Ok);

    std::vector<uint8_t> pt;
    auto r2 = tinychacha::aead_decrypt(key, nonce, aad, ct, tag, pt);
    ASSERT_EQ(r2, tinychacha::Result::Ok);
    ASSERT_BYTES_EQ(pt.data(), plaintext.data(), plaintext.size());
}

// --- C API ---
TEST(aead_c_api)
{
    auto key = test::hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    auto nonce = test::hex_to_bytes("070000004041424344454647");
    auto aad = test::hex_to_bytes("50515253c0c1c2c3c4c5c6c7");
    auto plaintext = test::hex_to_bytes("4c616469657320616e642047656e746c"
                                        "656d656e206f662074686520636c6173"
                                        "73206f66202739393a20496620492063"
                                        "6f756c64206f6666657220796f75206f"
                                        "6e6c79206f6e652074697020666f7220"
                                        "746865206675747572652c2073756e73"
                                        "637265656e20776f756c642062652069"
                                        "742e");
    auto expected_ct = test::hex_to_bytes("d31a8d34648e60db7b86afbc53ef7ec2"
                                          "a4aded51296e08fea9e2b5a736ee62d6"
                                          "3dbea45e8ca9671282fafb69da92728b"
                                          "1a71de0a9e060b2905d6a5b67ecd3b36"
                                          "92ddbd7f2d778b8c9803aee328091b58"
                                          "fab324e4fad675945585808b4831d7bc"
                                          "3ff4def08e4b7a9de576d26586cec64b"
                                          "6116");
    auto expected_tag = test::hex_to_bytes("1ae10b594f09e26a7e902ecbd0600691");

    std::vector<uint8_t> ct(plaintext.size());
    uint8_t tag[16] = {};
    int ret = tinychacha_aead_encrypt(
        key.data(),
        nonce.data(),
        aad.data(),
        aad.size(),
        plaintext.data(),
        plaintext.size(),
        ct.data(),
        ct.size(),
        tag);
    ASSERT_EQ(ret, TINYCHACHA_OK);
    ASSERT_BYTES_EQ(ct.data(), expected_ct.data(), expected_ct.size());
    ASSERT_BYTES_EQ(tag, expected_tag.data(), 16);

    std::vector<uint8_t> pt(ct.size());
    ret = tinychacha_aead_decrypt(
        key.data(), nonce.data(), aad.data(), aad.size(), ct.data(), ct.size(), pt.data(), pt.size(), tag);
    ASSERT_EQ(ret, TINYCHACHA_OK);
    ASSERT_BYTES_EQ(pt.data(), plaintext.data(), plaintext.size());
}
