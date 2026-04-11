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

#include <cstring>
#include <tinychacha/aead.h>
#include <tinychacha/chacha20.h>
#include <tinychacha/poly1305.h>
#include <vector>

// --- C API null pointer handling ---

TEST(c_api_chacha20_null_key)
{
    uint8_t nonce[12] = {};
    uint8_t data[64] = {};
    uint8_t out[64] = {};
    ASSERT_EQ(tinychacha_chacha20(nullptr, nonce, 0, data, 64, out), TINYCHACHA_INTERNAL_ERROR);
}

TEST(c_api_chacha20_null_nonce)
{
    uint8_t key[32] = {};
    uint8_t data[64] = {};
    uint8_t out[64] = {};
    ASSERT_EQ(tinychacha_chacha20(key, nullptr, 0, data, 64, out), TINYCHACHA_INTERNAL_ERROR);
}

TEST(c_api_chacha20_null_input)
{
    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    uint8_t out[64] = {};
    ASSERT_EQ(tinychacha_chacha20(key, nonce, 0, nullptr, 64, out), TINYCHACHA_INTERNAL_ERROR);
}

TEST(c_api_chacha20_null_output)
{
    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    uint8_t data[64] = {};
    ASSERT_EQ(tinychacha_chacha20(key, nonce, 0, data, 64, nullptr), TINYCHACHA_INTERNAL_ERROR);
}

TEST(c_api_poly1305_mac_null_key)
{
    uint8_t data[16] = {};
    uint8_t tag[16] = {};
    ASSERT_EQ(tinychacha_poly1305_mac(nullptr, data, 16, tag), TINYCHACHA_INTERNAL_ERROR);
}

TEST(c_api_poly1305_mac_null_tag)
{
    uint8_t key[32] = {};
    uint8_t data[16] = {};
    ASSERT_EQ(tinychacha_poly1305_mac(key, data, 16, nullptr), TINYCHACHA_INTERNAL_ERROR);
}

TEST(c_api_poly1305_mac_null_message)
{
    uint8_t key[32] = {};
    uint8_t tag[16] = {};
    ASSERT_EQ(tinychacha_poly1305_mac(key, nullptr, 16, tag), TINYCHACHA_INTERNAL_ERROR);
}

TEST(c_api_poly1305_verify_null_key)
{
    uint8_t data[16] = {};
    uint8_t tag[16] = {};
    ASSERT_EQ(tinychacha_poly1305_verify(nullptr, data, 16, tag), TINYCHACHA_INTERNAL_ERROR);
}

TEST(c_api_poly1305_verify_null_tag)
{
    uint8_t key[32] = {};
    uint8_t data[16] = {};
    ASSERT_EQ(tinychacha_poly1305_verify(key, data, 16, nullptr), TINYCHACHA_INTERNAL_ERROR);
}

TEST(c_api_aead_encrypt_null_key)
{
    uint8_t nonce[12] = {};
    uint8_t data[16] = {};
    uint8_t ct[16] = {};
    uint8_t tag[16] = {};
    ASSERT_EQ(tinychacha_aead_encrypt(nullptr, nonce, nullptr, 0, data, 16, ct, 16, tag), TINYCHACHA_INTERNAL_ERROR);
}

TEST(c_api_aead_encrypt_null_nonce)
{
    uint8_t key[32] = {};
    uint8_t data[16] = {};
    uint8_t ct[16] = {};
    uint8_t tag[16] = {};
    ASSERT_EQ(tinychacha_aead_encrypt(key, nullptr, nullptr, 0, data, 16, ct, 16, tag), TINYCHACHA_INTERNAL_ERROR);
}

TEST(c_api_aead_encrypt_null_tag)
{
    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    uint8_t data[16] = {};
    uint8_t ct[16] = {};
    ASSERT_EQ(tinychacha_aead_encrypt(key, nonce, nullptr, 0, data, 16, ct, 16, nullptr), TINYCHACHA_INTERNAL_ERROR);
}

TEST(c_api_aead_decrypt_null_key)
{
    uint8_t nonce[12] = {};
    uint8_t ct[16] = {};
    uint8_t pt[16] = {};
    uint8_t tag[16] = {};
    ASSERT_EQ(tinychacha_aead_decrypt(nullptr, nonce, nullptr, 0, ct, 16, pt, 16, tag), TINYCHACHA_INTERNAL_ERROR);
}

TEST(c_api_aead_decrypt_null_nonce)
{
    uint8_t key[32] = {};
    uint8_t ct[16] = {};
    uint8_t pt[16] = {};
    uint8_t tag[16] = {};
    ASSERT_EQ(tinychacha_aead_decrypt(key, nullptr, nullptr, 0, ct, 16, pt, 16, tag), TINYCHACHA_INTERNAL_ERROR);
}

TEST(c_api_aead_decrypt_null_tag)
{
    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    uint8_t ct[16] = {};
    uint8_t pt[16] = {};
    ASSERT_EQ(tinychacha_aead_decrypt(key, nonce, nullptr, 0, ct, 16, pt, 16, nullptr), TINYCHACHA_INTERNAL_ERROR);
}

// --- Counter overflow rejection ---

TEST(counter_overflow_chacha20_c_api)
{
    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    uint8_t data[128] = {};
    uint8_t out[128] = {};
    // counter=0xFFFFFFFF with >64 bytes should fail
    ASSERT_EQ(tinychacha_chacha20(key, nonce, 0xFFFFFFFF, data, 128, out), TINYCHACHA_INVALID_INPUT_SIZE);
}

TEST(counter_overflow_chacha20_exact_fit)
{
    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    uint8_t data[64] = {};
    uint8_t out[64] = {};
    // counter=0xFFFFFFFF with exactly 64 bytes should succeed (1 block)
    ASSERT_EQ(tinychacha_chacha20(key, nonce, 0xFFFFFFFF, data, 64, out), TINYCHACHA_OK);
}

TEST(counter_overflow_chacha20_cpp_api)
{
    std::vector<uint8_t> key(32, 0);
    std::vector<uint8_t> nonce(12, 0);
    std::vector<uint8_t> input(128, 0);
    std::vector<uint8_t> output;
    auto result = tinychacha::chacha20(key, nonce, 0xFFFFFFFF, input, output);
    ASSERT_EQ(static_cast<int>(result), static_cast<int>(tinychacha::Result::InvalidInputSize));
}

TEST(counter_overflow_keystream_cpp_api)
{
    std::vector<uint8_t> key(32, 0);
    std::vector<uint8_t> nonce(12, 0);
    std::vector<uint8_t> output;
    auto result = tinychacha::chacha20_keystream(key, nonce, 0xFFFFFFFF, 128, output);
    ASSERT_EQ(static_cast<int>(result), static_cast<int>(tinychacha::Result::InvalidInputSize));
}

// --- AEAD invalid key/nonce sizes (C++ API) ---

TEST(aead_encrypt_invalid_key_size)
{
    std::vector<uint8_t> key(16, 0); // Wrong size
    std::vector<uint8_t> nonce(12, 0);
    std::vector<uint8_t> aad;
    std::vector<uint8_t> plaintext(32, 0);
    std::vector<uint8_t> ct, tag;
    auto result = tinychacha::aead_encrypt(key, nonce, aad, plaintext, ct, tag);
    ASSERT_EQ(static_cast<int>(result), static_cast<int>(tinychacha::Result::InvalidKeySize));
}

TEST(aead_encrypt_invalid_nonce_size)
{
    std::vector<uint8_t> key(32, 0);
    std::vector<uint8_t> nonce(8, 0); // Wrong size
    std::vector<uint8_t> aad;
    std::vector<uint8_t> plaintext(32, 0);
    std::vector<uint8_t> ct, tag;
    auto result = tinychacha::aead_encrypt(key, nonce, aad, plaintext, ct, tag);
    ASSERT_EQ(static_cast<int>(result), static_cast<int>(tinychacha::Result::InvalidNonceSize));
}

TEST(aead_decrypt_invalid_key_size)
{
    std::vector<uint8_t> key(16, 0); // Wrong size
    std::vector<uint8_t> nonce(12, 0);
    std::vector<uint8_t> aad;
    std::vector<uint8_t> ciphertext(32, 0);
    std::vector<uint8_t> tag(16, 0);
    std::vector<uint8_t> pt;
    auto result = tinychacha::aead_decrypt(key, nonce, aad, ciphertext, tag, pt);
    ASSERT_EQ(static_cast<int>(result), static_cast<int>(tinychacha::Result::InvalidKeySize));
}

TEST(aead_decrypt_invalid_nonce_size)
{
    std::vector<uint8_t> key(32, 0);
    std::vector<uint8_t> nonce(8, 0); // Wrong size
    std::vector<uint8_t> aad;
    std::vector<uint8_t> ciphertext(32, 0);
    std::vector<uint8_t> tag(16, 0);
    std::vector<uint8_t> pt;
    auto result = tinychacha::aead_decrypt(key, nonce, aad, ciphertext, tag, pt);
    ASSERT_EQ(static_cast<int>(result), static_cast<int>(tinychacha::Result::InvalidNonceSize));
}

// --- tinychacha_generate_nonce C API ---

TEST(c_api_generate_nonce_success)
{
    uint8_t nonce[12] = {};
    int rc = tinychacha_generate_nonce(nonce);
    ASSERT_EQ(rc, TINYCHACHA_OK);
    // Verify at least some bytes are non-zero (overwhelmingly likely)
    bool all_zero = true;
    for (int i = 0; i < 12; ++i)
    {
        if (nonce[i] != 0)
        {
            all_zero = false;
            break;
        }
    }
    ASSERT_TRUE(!all_zero);
}

TEST(c_api_generate_nonce_null)
{
    int rc = tinychacha_generate_nonce(nullptr);
    ASSERT_EQ(rc, TINYCHACHA_INTERNAL_ERROR);
}

// --- generate_nonce C++ API ---

TEST(cpp_generate_nonce_raw_success)
{
    uint8_t buf[12] = {};
    int rc = tinychacha::generate_nonce(buf, 12);
    ASSERT_EQ(rc, 0);
}

TEST(cpp_generate_nonce_raw_null)
{
    int rc = tinychacha::generate_nonce(nullptr, 12);
    ASSERT_EQ(rc, TINYCHACHA_INTERNAL_ERROR);
}

TEST(cpp_generate_nonce_vector)
{
    auto nonce = tinychacha::generate_nonce();
    ASSERT_EQ(static_cast<int>(nonce.size()), 12);
}

// --- AEAD convenience overload short inputs ---

TEST(aead_decrypt_ciphertext_and_tag_too_short)
{
    std::vector<uint8_t> key(32, 0);
    std::vector<uint8_t> nonce(12, 0);
    std::vector<uint8_t> aad;
    std::vector<uint8_t> ct_tag(15, 0); // Too short (need at least 16 for tag)
    std::vector<uint8_t> pt;
    auto result = tinychacha::aead_decrypt(key, nonce, ct_tag, aad, pt);
    ASSERT_EQ(static_cast<int>(result), static_cast<int>(tinychacha::Result::InvalidInputSize));
}

TEST(aead_decrypt_nonce_ciphertext_tag_too_short)
{
    std::vector<uint8_t> key(32, 0);
    std::vector<uint8_t> aad;
    std::vector<uint8_t> nct(27, 0); // Too short (need at least 12+16=28)
    std::vector<uint8_t> pt;
    auto result = tinychacha::aead_decrypt(key, nct, aad, pt);
    ASSERT_EQ(static_cast<int>(result), static_cast<int>(tinychacha::Result::InvalidInputSize));
}

// --- C API null aad with nonzero aad_len ---

TEST(c_api_aead_encrypt_null_aad_nonzero_len)
{
    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    uint8_t data[16] = {};
    uint8_t ct[16] = {};
    uint8_t tag[16] = {};
    ASSERT_EQ(tinychacha_aead_encrypt(key, nonce, nullptr, 4, data, 16, ct, 16, tag), TINYCHACHA_INTERNAL_ERROR);
}

TEST(c_api_aead_decrypt_null_aad_nonzero_len)
{
    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    uint8_t ct[16] = {};
    uint8_t pt[16] = {};
    uint8_t tag[16] = {};
    ASSERT_EQ(tinychacha_aead_decrypt(key, nonce, nullptr, 4, ct, 16, pt, 16, tag), TINYCHACHA_INTERNAL_ERROR);
}

// --- Zero-length operations should succeed ---

TEST(c_api_chacha20_zero_length)
{
    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    ASSERT_EQ(tinychacha_chacha20(key, nonce, 0, nullptr, 0, nullptr), TINYCHACHA_OK);
}

TEST(c_api_poly1305_mac_zero_length)
{
    uint8_t key[32] = {};
    uint8_t tag[16] = {};
    ASSERT_EQ(tinychacha_poly1305_mac(key, nullptr, 0, tag), TINYCHACHA_OK);
}

// --- size_t-wraparound regression guards (load-bearing on 32-bit targets
// where size_t is 32 bits; symbolically enforced on 64-bit) ---

TEST(chacha20_rejects_len_near_size_max)
{
    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    uint8_t dummy_in[1] = {};
    uint8_t dummy_out[1] = {};
    // Plaintext whose byte count exceeds (2^32 - 1) * 64 bytes is unreachable
    // in a live process, but the pre-check must still reject it without touching
    // the pointers. Pass non-null pointers so we exercise the size path rather
    // than the null-pointer path.
    int rc = tinychacha_chacha20(key, nonce, 0, dummy_in, SIZE_MAX, dummy_out);
    ASSERT_EQ(rc, TINYCHACHA_INVALID_INPUT_SIZE);
}

TEST(aead_encrypt_rejects_len_near_size_max)
{
    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    uint8_t dummy_pt[1] = {};
    uint8_t dummy_ct[1] = {};
    uint8_t tag[16] = {};
    // plaintext_len = SIZE_MAX must be rejected by the AEAD counter / mac_len
    // pre-checks. ciphertext_len is 0, which is below plaintext_len, so the
    // ciphertext_len < plaintext_len guard would also reject it — but that
    // returns the same TINYCHACHA_INVALID_INPUT_SIZE, so the test is still
    // exercising an InvalidInputSize rejection path.
    int rc = tinychacha_aead_encrypt(key, nonce, nullptr, 0, dummy_pt, SIZE_MAX, dummy_ct, SIZE_MAX, tag);
    ASSERT_EQ(rc, TINYCHACHA_INVALID_INPUT_SIZE);
}

TEST(aead_encrypt_rejects_impossible_aad_len_c_api)
{
    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    uint8_t dummy_aad[1] = {};
    uint8_t dummy_pt[1] = {};
    uint8_t dummy_ct[1] = {};
    uint8_t tag[16] = {};
    // aad_len = SIZE_MAX - 16 would make aad_len + pad16 + ct_len + 48 wrap.
    // The mac_len overflow guard must reject it before any allocation. Pass a
    // tiny plaintext with ciphertext buffer large enough to satisfy the
    // ciphertext_len >= plaintext_len guard, so we actually reach the size
    // validation inside aead_encrypt.
    int rc = tinychacha_aead_encrypt(key, nonce, dummy_aad, SIZE_MAX - 16, dummy_pt, 1, dummy_ct, 1, tag);
    ASSERT_EQ(rc, TINYCHACHA_INVALID_INPUT_SIZE);
}

TEST(aead_decrypt_rejects_impossible_aad_len_c_api)
{
    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    uint8_t dummy_aad[1] = {};
    uint8_t dummy_ct[1] = {};
    uint8_t dummy_pt[1] = {};
    uint8_t tag[16] = {};
    int rc = tinychacha_aead_decrypt(key, nonce, dummy_aad, SIZE_MAX - 16, dummy_ct, 1, dummy_pt, 1, tag);
    ASSERT_EQ(rc, TINYCHACHA_INVALID_INPUT_SIZE);
}

// --- Additional counter-overflow boundary cases ---

TEST(counter_overflow_chacha20_multi_block_at_boundary)
{
    // counter = 0xFFFFFFFE with 128 bytes needs blocks at 0xFFFFFFFE and
    // 0xFFFFFFFF — exactly fits, must succeed.
    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    uint8_t data[128] = {};
    uint8_t out[128] = {};
    ASSERT_EQ(tinychacha_chacha20(key, nonce, 0xFFFFFFFEu, data, 128, out), TINYCHACHA_OK);
}

TEST(counter_overflow_chacha20_multi_block_one_byte_over)
{
    // counter = 0xFFFFFFFE with 129 bytes needs blocks at 0xFFFFFFFE,
    // 0xFFFFFFFF, and 0x00000000 — must be rejected.
    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    uint8_t data[129] = {};
    uint8_t out[129] = {};
    ASSERT_EQ(tinychacha_chacha20(key, nonce, 0xFFFFFFFEu, data, 129, out), TINYCHACHA_INVALID_INPUT_SIZE);
}

TEST(counter_overflow_chacha20_zero_len_at_max_counter)
{
    // Zero-length input at any counter (including 0xFFFFFFFF) must succeed
    // without consuming any block.
    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    ASSERT_EQ(tinychacha_chacha20(key, nonce, 0xFFFFFFFFu, nullptr, 0, nullptr), TINYCHACHA_OK);
}

// --- C API output buffer size mismatch handling ---

TEST(c_api_aead_encrypt_undersized_output_rejects)
{
    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    uint8_t pt[32] = {};
    uint8_t ct[32] = {};
    uint8_t tag[16] = {};
    ASSERT_EQ(tinychacha_aead_encrypt(key, nonce, nullptr, 0, pt, 32, ct, 31, tag), TINYCHACHA_INVALID_INPUT_SIZE);
}

TEST(c_api_aead_decrypt_undersized_output_rejects)
{
    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    uint8_t ct[32] = {};
    uint8_t pt[32] = {};
    uint8_t tag[16] = {};
    ASSERT_EQ(tinychacha_aead_decrypt(key, nonce, nullptr, 0, ct, 32, pt, 31, tag), TINYCHACHA_INVALID_INPUT_SIZE);
}

TEST(c_api_aead_encrypt_oversized_output_does_not_overrun)
{
    // Oversized output buffer is allowed. Only the first plaintext_len bytes
    // should be written; trailing sentinel bytes must remain untouched.
    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    uint8_t pt[32] = {};
    for (int i = 0; i < 32; ++i)
        pt[i] = static_cast<uint8_t>(i);
    uint8_t ct[64];
    std::memset(ct, 0xAB, sizeof(ct));
    uint8_t tag[16] = {};
    ASSERT_EQ(tinychacha_aead_encrypt(key, nonce, nullptr, 0, pt, 32, ct, 64, tag), TINYCHACHA_OK);
    for (int i = 32; i < 64; ++i)
        ASSERT_EQ(ct[i], static_cast<uint8_t>(0xAB));
}

// --- Systematic tamper loop: every byte of CT and AAD, every tag byte ---

TEST(aead_tamper_every_ciphertext_byte_fails)
{
    uint8_t key[32];
    uint8_t nonce[12];
    for (int i = 0; i < 32; ++i)
        key[i] = static_cast<uint8_t>(i);
    for (int i = 0; i < 12; ++i)
        nonce[i] = static_cast<uint8_t>(0x40 + i);

    uint8_t aad[16];
    for (int i = 0; i < 16; ++i)
        aad[i] = static_cast<uint8_t>(0x80 + i);

    const size_t pt_len = 64;
    uint8_t pt[pt_len];
    for (size_t i = 0; i < pt_len; ++i)
        pt[i] = static_cast<uint8_t>(i * 7u);

    uint8_t ct[pt_len];
    uint8_t tag[16];
    ASSERT_EQ(tinychacha_aead_encrypt(key, nonce, aad, 16, pt, pt_len, ct, pt_len, tag), TINYCHACHA_OK);

    for (size_t i = 0; i < pt_len; ++i)
    {
        uint8_t bad_ct[pt_len];
        std::memcpy(bad_ct, ct, pt_len);
        bad_ct[i] ^= 0x01;
        uint8_t out_pt[pt_len];
        int rc = tinychacha_aead_decrypt(key, nonce, aad, 16, bad_ct, pt_len, out_pt, pt_len, tag);
        ASSERT_EQ(rc, TINYCHACHA_AUTH_FAILED);
    }
}

TEST(aead_tamper_every_aad_byte_fails)
{
    uint8_t key[32];
    uint8_t nonce[12];
    for (int i = 0; i < 32; ++i)
        key[i] = static_cast<uint8_t>(i);
    for (int i = 0; i < 12; ++i)
        nonce[i] = static_cast<uint8_t>(0x40 + i);

    const size_t aad_len = 32;
    uint8_t aad[aad_len];
    for (size_t i = 0; i < aad_len; ++i)
        aad[i] = static_cast<uint8_t>(0x80 + i);

    const size_t pt_len = 48;
    uint8_t pt[pt_len];
    for (size_t i = 0; i < pt_len; ++i)
        pt[i] = static_cast<uint8_t>(i);

    uint8_t ct[pt_len];
    uint8_t tag[16];
    ASSERT_EQ(tinychacha_aead_encrypt(key, nonce, aad, aad_len, pt, pt_len, ct, pt_len, tag), TINYCHACHA_OK);

    for (size_t i = 0; i < aad_len; ++i)
    {
        uint8_t bad_aad[aad_len];
        std::memcpy(bad_aad, aad, aad_len);
        bad_aad[i] ^= 0x80;
        uint8_t out_pt[pt_len];
        int rc = tinychacha_aead_decrypt(key, nonce, bad_aad, aad_len, ct, pt_len, out_pt, pt_len, tag);
        ASSERT_EQ(rc, TINYCHACHA_AUTH_FAILED);
    }
}

TEST(aead_tamper_every_tag_byte_fails)
{
    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    uint8_t pt[32];
    for (int i = 0; i < 32; ++i)
        pt[i] = static_cast<uint8_t>(i);

    uint8_t ct[32];
    uint8_t tag[16];
    ASSERT_EQ(tinychacha_aead_encrypt(key, nonce, nullptr, 0, pt, 32, ct, 32, tag), TINYCHACHA_OK);

    for (int i = 0; i < 16; ++i)
    {
        uint8_t bad_tag[16];
        std::memcpy(bad_tag, tag, 16);
        bad_tag[i] ^= 0xFF;
        uint8_t out_pt[32];
        int rc = tinychacha_aead_decrypt(key, nonce, nullptr, 0, ct, 32, out_pt, 32, bad_tag);
        ASSERT_EQ(rc, TINYCHACHA_AUTH_FAILED);
    }
}
