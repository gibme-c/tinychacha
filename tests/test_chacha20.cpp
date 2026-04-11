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
#include "vectors/chacha20_vectors.inl"

#include <tinychacha/chacha20.h>

// --- RFC keystream vectors (block function) ---
TEST(chacha20_keystream_rfc_vectors)
{
    for (const auto &v : chacha20_keystream_vectors)
    {
        auto key = test::hex_to_bytes(v.key);
        auto nonce = test::hex_to_bytes(v.nonce);
        auto expected = test::hex_to_bytes(v.keystream);

        std::vector<uint8_t> output;
        auto result = tinychacha::chacha20_keystream(key, nonce, v.counter, 64, output);
        ASSERT_EQ(result, tinychacha::Result::Ok);
        ASSERT_EQ(output.size(), static_cast<size_t>(64));
        ASSERT_BYTES_EQ(output.data(), expected.data(), 64);
    }
}

// --- RFC encryption vectors ---
TEST(chacha20_encryption_rfc_vectors)
{
    for (const auto &v : chacha20_encryption_vectors)
    {
        auto key = test::hex_to_bytes(v.key);
        auto nonce = test::hex_to_bytes(v.nonce);
        auto plaintext = test::hex_to_bytes(v.plaintext);
        auto expected_ct = test::hex_to_bytes(v.ciphertext);

        std::vector<uint8_t> output;
        auto result = tinychacha::chacha20(key, nonce, v.counter, plaintext, output);
        ASSERT_EQ(result, tinychacha::Result::Ok);
        ASSERT_EQ(output.size(), expected_ct.size());
        ASSERT_BYTES_EQ(output.data(), expected_ct.data(), expected_ct.size());
    }
}

// --- Roundtrip: encrypt then decrypt ---
TEST(chacha20_roundtrip)
{
    auto key = test::hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    auto nonce = test::hex_to_bytes("000000000000004a00000000");

    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
    std::vector<uint8_t> ciphertext, decrypted;

    auto r1 = tinychacha::chacha20(key, nonce, 1, plaintext, ciphertext);
    ASSERT_EQ(r1, tinychacha::Result::Ok);

    auto r2 = tinychacha::chacha20(key, nonce, 1, ciphertext, decrypted);
    ASSERT_EQ(r2, tinychacha::Result::Ok);
    ASSERT_EQ(decrypted.size(), plaintext.size());
    ASSERT_BYTES_EQ(decrypted.data(), plaintext.data(), plaintext.size());
}

// --- Empty input ---
TEST(chacha20_empty_input)
{
    auto key = test::hex_to_bytes("0000000000000000000000000000000000000000000000000000000000000000");
    auto nonce = test::hex_to_bytes("000000000000000000000000");

    std::vector<uint8_t> empty;
    std::vector<uint8_t> output;
    auto result = tinychacha::chacha20(key, nonce, 0, empty, output);
    ASSERT_EQ(result, tinychacha::Result::Ok);
    ASSERT_EQ(output.size(), static_cast<size_t>(0));
}

// --- 1-byte input ---
TEST(chacha20_1byte)
{
    auto key = test::hex_to_bytes("0000000000000000000000000000000000000000000000000000000000000000");
    auto nonce = test::hex_to_bytes("000000000000000000000000");

    std::vector<uint8_t> input = {0x00};
    std::vector<uint8_t> output;
    auto result = tinychacha::chacha20(key, nonce, 0, input, output);
    ASSERT_EQ(result, tinychacha::Result::Ok);
    ASSERT_EQ(output.size(), static_cast<size_t>(1));
    // First byte of keystream for all-zero key/nonce/counter=0 is 0x76
    ASSERT_EQ(output[0], static_cast<uint8_t>(0x76));
}

// --- 63-byte input (just under one block) ---
TEST(chacha20_63bytes)
{
    auto key = test::hex_to_bytes("0000000000000000000000000000000000000000000000000000000000000000");
    auto nonce = test::hex_to_bytes("000000000000000000000000");

    std::vector<uint8_t> input(63, 0);
    std::vector<uint8_t> output;
    auto result = tinychacha::chacha20(key, nonce, 0, input, output);
    ASSERT_EQ(result, tinychacha::Result::Ok);
    ASSERT_EQ(output.size(), static_cast<size_t>(63));

    // Should match first 63 bytes of keystream
    auto expected_ks = test::hex_to_bytes("76b8e0ada0f13d90405d6ae55386bd28"
                                          "bdd219b8a08ded1aa836efcc8b770dc7"
                                          "da41597c5157488d7724e03fb8d84a37"
                                          "6a43b8f41518a11cc387b669b2ee65");
    ASSERT_BYTES_EQ(output.data(), expected_ks.data(), 63);
}

// --- 65-byte input (just over one block) ---
TEST(chacha20_65bytes)
{
    auto key = test::hex_to_bytes("0000000000000000000000000000000000000000000000000000000000000000");
    auto nonce = test::hex_to_bytes("000000000000000000000000");

    std::vector<uint8_t> input(65, 0);
    std::vector<uint8_t> output;
    auto result = tinychacha::chacha20(key, nonce, 0, input, output);
    ASSERT_EQ(result, tinychacha::Result::Ok);
    ASSERT_EQ(output.size(), static_cast<size_t>(65));

    // First 64 bytes = block 0 keystream
    auto ks_block0 = test::hex_to_bytes("76b8e0ada0f13d90405d6ae55386bd28"
                                        "bdd219b8a08ded1aa836efcc8b770dc7"
                                        "da41597c5157488d7724e03fb8d84a37"
                                        "6a43b8f41518a11cc387b669b2ee6586");
    ASSERT_BYTES_EQ(output.data(), ks_block0.data(), 64);

    // Byte 65 = first byte of block 1 keystream (counter=1)
    ASSERT_EQ(output[64], static_cast<uint8_t>(0x9f));
}

// --- Invalid key size ---
TEST(chacha20_invalid_key_size)
{
    std::vector<uint8_t> bad_key(16, 0);
    std::vector<uint8_t> nonce(12, 0);
    std::vector<uint8_t> input = {0x00};
    std::vector<uint8_t> output;
    auto result = tinychacha::chacha20(bad_key, nonce, 0, input, output);
    ASSERT_EQ(result, tinychacha::Result::InvalidKeySize);
}

// --- Invalid nonce size ---
TEST(chacha20_invalid_nonce_size)
{
    std::vector<uint8_t> key(32, 0);
    std::vector<uint8_t> bad_nonce(8, 0);
    std::vector<uint8_t> input = {0x00};
    std::vector<uint8_t> output;
    auto result = tinychacha::chacha20(key, bad_nonce, 0, input, output);
    ASSERT_EQ(result, tinychacha::Result::InvalidNonceSize);
}

// --- C API ---
TEST(chacha20_c_api)
{
    auto key = test::hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    auto nonce = test::hex_to_bytes("000000000000004a00000000");
    auto plaintext = test::hex_to_bytes("4c616469657320616e642047656e746c"
                                        "656d656e206f662074686520636c6173"
                                        "73206f66202739393a20496620492063"
                                        "6f756c64206f6666657220796f75206f"
                                        "6e6c79206f6e652074697020666f7220"
                                        "746865206675747572652c2073756e73"
                                        "637265656e20776f756c642062652069"
                                        "742e");
    auto expected = test::hex_to_bytes("6e2e359a2568f98041ba0728dd0d6981"
                                       "e97e7aec1d4360c20a27afccfd9fae0b"
                                       "f91b65c5524733ab8f593dabcd62b357"
                                       "1639d624e65152ab8f530c359f0861d8"
                                       "07ca0dbf500d6a6156a38e088a22b65e"
                                       "52bc514d16ccf806818ce91ab7793736"
                                       "5af90bbf74a35be6b40b8eedf2785e42"
                                       "874d");

    std::vector<uint8_t> output(plaintext.size());
    int ret = tinychacha_chacha20(key.data(), nonce.data(), 1, plaintext.data(), plaintext.size(), output.data());
    ASSERT_EQ(ret, TINYCHACHA_OK);
    ASSERT_BYTES_EQ(output.data(), expected.data(), expected.size());
}
