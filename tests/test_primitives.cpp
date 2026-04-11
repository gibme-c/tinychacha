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

// Direct tests for secure_zero (DSE resistance) and constant_time_eq
// (timing-safe tag comparison).

#include "test_harness.h"

#include <cstdint>
#include <cstring>
#include <tinychacha/common.h>
#include <vector>

// --- secure_zero ---

// Volatile read to defeat DSE so we actually observe secure_zero's writes.
static uint8_t volatile_read(const uint8_t *p, size_t i)
{
    const volatile uint8_t *vp = p;
    return vp[i];
}

TEST(secure_zero_zero_length_is_noop)
{
    uint8_t sentinel[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    tinychacha_secure_zero(sentinel, 0);
    ASSERT_EQ(sentinel[0], static_cast<uint8_t>(0xDE));
    ASSERT_EQ(sentinel[1], static_cast<uint8_t>(0xAD));
    ASSERT_EQ(sentinel[2], static_cast<uint8_t>(0xBE));
    ASSERT_EQ(sentinel[3], static_cast<uint8_t>(0xEF));
}

TEST(secure_zero_clears_all_bytes)
{
    static const size_t kSizes[] = {1, 7, 8, 15, 16, 17, 31, 32, 63, 64, 65, 127, 128, 1024};
    for (size_t size : kSizes)
    {
        std::vector<uint8_t> buf(size, 0xAA);
        tinychacha_secure_zero(buf.data(), size);
        for (size_t i = 0; i < size; ++i)
        {
            ASSERT_EQ(volatile_read(buf.data(), i), static_cast<uint8_t>(0));
        }
    }
}

TEST(secure_zero_does_not_overrun)
{
    uint8_t buf[64];
    std::memset(buf, 0xAA, sizeof(buf));
    tinychacha_secure_zero(buf + 8, 32);
    for (size_t i = 0; i < 8; ++i)
        ASSERT_EQ(buf[i], static_cast<uint8_t>(0xAA));
    for (size_t i = 8; i < 40; ++i)
        ASSERT_EQ(buf[i], static_cast<uint8_t>(0));
    for (size_t i = 40; i < 64; ++i)
        ASSERT_EQ(buf[i], static_cast<uint8_t>(0xAA));
}

TEST(secure_zero_cpp_wrapper)
{
    std::vector<uint8_t> buf(128, 0x5A);
    tinychacha::secure_zero(buf.data(), buf.size());
    for (size_t i = 0; i < buf.size(); ++i)
        ASSERT_EQ(volatile_read(buf.data(), i), static_cast<uint8_t>(0));
}

// --- constant_time_eq ---

TEST(constant_time_eq_zero_length_is_equal)
{
    // By convention a zero-length comparison is trivially equal.
    int rc = tinychacha_constant_time_eq(nullptr, nullptr, 0);
    ASSERT_EQ(rc, 1);
}

TEST(constant_time_eq_equal_buffers)
{
    static const size_t kSizes[] = {1, 15, 16, 17, 31, 32, 33, 64, 128};
    for (size_t size : kSizes)
    {
        std::vector<uint8_t> a(size), b(size);
        for (size_t i = 0; i < size; ++i)
        {
            a[i] = static_cast<uint8_t>((i * 31u + 7u) & 0xFFu);
            b[i] = a[i];
        }
        ASSERT_EQ(tinychacha_constant_time_eq(a.data(), b.data(), size), 1);
    }
}

TEST(constant_time_eq_differ_at_first_byte)
{
    std::vector<uint8_t> a(32, 0x55), b(32, 0x55);
    b[0] ^= 0x01;
    ASSERT_EQ(tinychacha_constant_time_eq(a.data(), b.data(), 32), 0);
}

TEST(constant_time_eq_differ_at_last_byte)
{
    std::vector<uint8_t> a(32, 0x55), b(32, 0x55);
    b[31] ^= 0x80;
    ASSERT_EQ(tinychacha_constant_time_eq(a.data(), b.data(), 32), 0);
}

TEST(constant_time_eq_differ_at_middle_byte)
{
    std::vector<uint8_t> a(32, 0x55), b(32, 0x55);
    b[15] ^= 0x10;
    ASSERT_EQ(tinychacha_constant_time_eq(a.data(), b.data(), 32), 0);
}

TEST(constant_time_eq_single_bit_flip_every_position)
{
    for (size_t byte = 0; byte < 32; ++byte)
    {
        for (int bit = 0; bit < 8; ++bit)
        {
            std::vector<uint8_t> a(32);
            std::vector<uint8_t> b(32);
            for (size_t i = 0; i < 32; ++i)
            {
                a[i] = static_cast<uint8_t>(i * 17u + 3u);
                b[i] = a[i];
            }
            b[byte] = static_cast<uint8_t>(b[byte] ^ (1u << bit));
            ASSERT_EQ(tinychacha_constant_time_eq(a.data(), b.data(), 32), 0);
        }
    }
}

TEST(constant_time_eq_all_zero_vs_all_zero)
{
    std::vector<uint8_t> a(64, 0);
    std::vector<uint8_t> b(64, 0);
    ASSERT_EQ(tinychacha_constant_time_eq(a.data(), b.data(), 64), 1);
}

TEST(constant_time_eq_all_ones_vs_all_ones)
{
    std::vector<uint8_t> a(64, 0xFF);
    std::vector<uint8_t> b(64, 0xFF);
    ASSERT_EQ(tinychacha_constant_time_eq(a.data(), b.data(), 64), 1);
}

TEST(constant_time_eq_all_zero_vs_all_ones)
{
    std::vector<uint8_t> a(64, 0);
    std::vector<uint8_t> b(64, 0xFF);
    ASSERT_EQ(tinychacha_constant_time_eq(a.data(), b.data(), 64), 0);
}

TEST(constant_time_eq_cpp_vector_overload_size_mismatch_is_false)
{
    std::vector<uint8_t> a(16, 0);
    std::vector<uint8_t> b(17, 0);
    ASSERT_TRUE(!tinychacha::constant_time_eq(a, b));
}

TEST(constant_time_eq_cpp_vector_overload_equal)
{
    std::vector<uint8_t> a(32, 0xA5);
    std::vector<uint8_t> b(32, 0xA5);
    ASSERT_TRUE(tinychacha::constant_time_eq(a, b));
}
