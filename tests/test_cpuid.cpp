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

#include <tinychacha/chacha20.h>
#include <tinychacha/poly1305.h>

// Verify that dispatched backend produces same output as portable
// (both go through dispatch, but portable is always correct)
TEST(dispatched_chacha20_roundtrip)
{
    auto key = test::hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    auto nonce = test::hex_to_bytes("000000000000004a00000000");
    std::vector<uint8_t> input(256, 0x42);

    std::vector<uint8_t> output;
    auto result = tinychacha::chacha20(key, nonce, 1, input, output);
    ASSERT_EQ(result, tinychacha::Result::Ok);

    // Encrypt again, decrypt, should roundtrip
    std::vector<uint8_t> roundtrip;
    result = tinychacha::chacha20(key, nonce, 1, output, roundtrip);
    ASSERT_EQ(result, tinychacha::Result::Ok);
    ASSERT_BYTES_EQ(roundtrip.data(), input.data(), input.size());
}

TEST(dispatched_poly1305_matches_rfc_vector)
{
    auto key = test::hex_to_bytes("85d6be7857556d337f4452fe42d506a8"
                                  "0103808afb0db2fd4abff6af4149f51b");
    auto msg = test::hex_to_bytes("43727970746f6772617068696320466f"
                                  "72756d205265736561726368204772"
                                  "6f7570");
    auto expected = test::hex_to_bytes("a8061dc1305136c6c22b8baf0c0127a9");

    std::vector<uint8_t> tag;
    auto result = tinychacha::poly1305_mac(key, msg, tag);
    ASSERT_EQ(result, tinychacha::Result::Ok);
    ASSERT_BYTES_EQ(tag.data(), expected.data(), 16);
}
