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

#include <tinychacha/common.h>

TEST(generate_nonce_returns_12_bytes)
{
    auto nonce = tinychacha::generate_nonce();
    ASSERT_EQ(nonce.size(), static_cast<size_t>(12));
}

TEST(generate_nonce_nonzero)
{
    auto nonce = tinychacha::generate_nonce();
    ASSERT_EQ(nonce.size(), static_cast<size_t>(12));

    // Check not all zeros (extremely unlikely with CSPRNG)
    bool all_zero = true;
    for (auto b : nonce)
    {
        if (b != 0)
        {
            all_zero = false;
            break;
        }
    }
    ASSERT_TRUE(!all_zero);
}

TEST(generate_nonce_unique)
{
    auto n1 = tinychacha::generate_nonce();
    auto n2 = tinychacha::generate_nonce();
    ASSERT_EQ(n1.size(), static_cast<size_t>(12));
    ASSERT_EQ(n2.size(), static_cast<size_t>(12));

    // Two random nonces should differ
    bool differ = false;
    for (size_t i = 0; i < 12; ++i)
    {
        if (n1[i] != n2[i])
        {
            differ = true;
            break;
        }
    }
    ASSERT_TRUE(differ);
}
