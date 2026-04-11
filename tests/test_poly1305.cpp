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
#include "vectors/poly1305_vectors.inl"

#include <tinychacha/poly1305.h>

TEST(poly1305_rfc_vectors)
{
    for (const auto &v : poly1305_rfc_vectors)
    {
        auto key = test::hex_to_bytes(v.key);
        auto msg = test::hex_to_bytes(v.message);
        auto expected = test::hex_to_bytes(v.tag);

        std::vector<uint8_t> tag;
        auto result = tinychacha::poly1305_mac(key, msg, tag);
        ASSERT_EQ(result, tinychacha::Result::Ok);
        ASSERT_EQ(tag.size(), static_cast<size_t>(16));
        ASSERT_BYTES_EQ(tag.data(), expected.data(), 16);
    }
}

TEST(poly1305_appendix_vectors)
{
    for (const auto &v : poly1305_appendix_vectors)
    {
        auto key = test::hex_to_bytes(v.key);
        auto msg = test::hex_to_bytes(v.message);
        auto expected = test::hex_to_bytes(v.tag);

        std::vector<uint8_t> tag;
        auto result = tinychacha::poly1305_mac(key, msg, tag);
        ASSERT_EQ(result, tinychacha::Result::Ok);
        ASSERT_EQ(tag.size(), static_cast<size_t>(16));
        ASSERT_BYTES_EQ(tag.data(), expected.data(), 16);
    }
}

TEST(poly1305_empty_message)
{
    // Empty message with a known key — result should be just s
    auto key = test::hex_to_bytes("85d6be7857556d337f4452fe42d506a8"
                                  "0103808afb0db2fd4abff6af4149f51b");
    std::vector<uint8_t> empty;
    std::vector<uint8_t> tag;
    auto result = tinychacha::poly1305_mac(key, empty, tag);
    ASSERT_EQ(result, tinychacha::Result::Ok);
    ASSERT_EQ(tag.size(), static_cast<size_t>(16));

    // With empty message, h = 0, so tag = 0 + s = s
    auto expected_s = test::hex_to_bytes("0103808afb0db2fd4abff6af4149f51b");
    ASSERT_BYTES_EQ(tag.data(), expected_s.data(), 16);
}

TEST(poly1305_verify_ok)
{
    auto key = test::hex_to_bytes("85d6be7857556d337f4452fe42d506a8"
                                  "0103808afb0db2fd4abff6af4149f51b");
    auto msg = test::hex_to_bytes("43727970746f6772617068696320466f"
                                  "72756d205265736561726368204772"
                                  "6f7570");
    auto tag = test::hex_to_bytes("a8061dc1305136c6c22b8baf0c0127a9");

    auto result = tinychacha::poly1305_verify(key, msg, tag);
    ASSERT_EQ(result, tinychacha::Result::Ok);
}

TEST(poly1305_verify_reject)
{
    auto key = test::hex_to_bytes("85d6be7857556d337f4452fe42d506a8"
                                  "0103808afb0db2fd4abff6af4149f51b");
    auto msg = test::hex_to_bytes("43727970746f6772617068696320466f"
                                  "72756d205265736561726368204772"
                                  "6f7570");
    auto bad_tag = test::hex_to_bytes("a8061dc1305136c6c22b8baf0c0127aa");

    auto result = tinychacha::poly1305_verify(key, msg, bad_tag);
    ASSERT_EQ(result, tinychacha::Result::AuthenticationFailed);
}

TEST(poly1305_c_api)
{
    auto key = test::hex_to_bytes("85d6be7857556d337f4452fe42d506a8"
                                  "0103808afb0db2fd4abff6af4149f51b");
    auto msg = test::hex_to_bytes("43727970746f6772617068696320466f"
                                  "72756d205265736561726368204772"
                                  "6f7570");
    auto expected = test::hex_to_bytes("a8061dc1305136c6c22b8baf0c0127a9");

    uint8_t tag[16] = {};
    int ret = tinychacha_poly1305_mac(key.data(), msg.data(), msg.size(), tag);
    ASSERT_EQ(ret, TINYCHACHA_OK);
    ASSERT_BYTES_EQ(tag, expected.data(), 16);

    // Verify
    ret = tinychacha_poly1305_verify(key.data(), msg.data(), msg.size(), tag);
    ASSERT_EQ(ret, TINYCHACHA_OK);

    // Tamper and verify should fail
    tag[0] ^= 0x01;
    ret = tinychacha_poly1305_verify(key.data(), msg.data(), msg.size(), tag);
    ASSERT_EQ(ret, TINYCHACHA_AUTH_FAILED);
}

TEST(poly1305_invalid_key_size)
{
    std::vector<uint8_t> bad_key(16, 0);
    std::vector<uint8_t> msg = {0x00};
    std::vector<uint8_t> tag;
    auto result = tinychacha::poly1305_mac(bad_key, msg, tag);
    ASSERT_EQ(result, tinychacha::Result::InvalidKeySize);
}
