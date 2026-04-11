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

// Simple deterministic PRNG (xorshift64) for generating test inputs
static uint64_t prng_state = 0x123456789abcdef0ULL;

static uint64_t xorshift64()
{
    uint64_t x = prng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    prng_state = x;
    return x;
}

static void fill_random(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; ++i)
    {
        if (i % 8 == 0)
        {
            uint64_t r = xorshift64();
            std::memcpy(buf + i, &r, (len - i < 8) ? (len - i) : 8);
        }
    }
}

// ── ChaCha20 roundtrip fuzz: encrypt then decrypt, verify plaintext matches ──

static void fuzz_chacha20_one(const uint8_t *data, size_t size)
{
    if (size < 48)
        return;

    const uint8_t *key = data;
    const uint8_t *nonce = data + 32;
    uint32_t counter = static_cast<uint32_t>(data[44]) | (static_cast<uint32_t>(data[45]) << 8)
                       | (static_cast<uint32_t>(data[46]) << 16) | (static_cast<uint32_t>(data[47]) << 24);
    const uint8_t *plaintext = data + 48;
    size_t pt_len = size - 48;

    std::vector<uint8_t> ct(pt_len);
    if (pt_len > 0)
        (void)tinychacha_chacha20(key, nonce, counter, plaintext, pt_len, ct.data());

    std::vector<uint8_t> rt(pt_len);
    if (pt_len > 0)
        (void)tinychacha_chacha20(key, nonce, counter, ct.data(), pt_len, rt.data());

    if (pt_len > 0)
        ASSERT_BYTES_EQ(rt.data(), plaintext, pt_len);
}

// ── Poly1305 roundtrip fuzz: compute tag, verify, then check tampered fails ──

static void fuzz_poly1305_one(const uint8_t *data, size_t size)
{
    if (size < 32)
        return;

    const uint8_t *key = data;
    const uint8_t *msg = data + 32;
    size_t msg_len = size - 32;

    uint8_t tag[16];
    (void)tinychacha_poly1305_mac(key, msg, msg_len, tag);

    int rc = tinychacha_poly1305_verify(key, msg, msg_len, tag);
    ASSERT_EQ(rc, TINYCHACHA_OK);

    uint8_t bad_tag[16];
    std::memcpy(bad_tag, tag, 16);
    bad_tag[0] ^= 0x01;
    rc = tinychacha_poly1305_verify(key, msg, msg_len, bad_tag);
    ASSERT_EQ(rc, TINYCHACHA_AUTH_FAILED);
}

// ── AEAD roundtrip fuzz: encrypt, decrypt, verify, then check tampered fails
// ──

static void fuzz_aead_one(const uint8_t *data, size_t size)
{
    if (size < 45)
        return;

    const uint8_t *key = data;
    const uint8_t *nonce = data + 32;
    size_t aad_len = data[44];
    if (45 + aad_len > size)
        return;

    const uint8_t *aad = data + 45;
    const uint8_t *plaintext = data + 45 + aad_len;
    size_t pt_len = size - 45 - aad_len;

    std::vector<uint8_t> ct(pt_len);
    uint8_t tag[16];
    int rc = tinychacha_aead_encrypt(key, nonce, aad, aad_len, plaintext, pt_len, ct.data(), pt_len, tag);
    ASSERT_EQ(rc, TINYCHACHA_OK);

    std::vector<uint8_t> rt(pt_len);
    rc = tinychacha_aead_decrypt(key, nonce, aad, aad_len, ct.data(), pt_len, rt.data(), pt_len, tag);
    ASSERT_EQ(rc, TINYCHACHA_OK);

    if (pt_len > 0)
        ASSERT_BYTES_EQ(rt.data(), plaintext, pt_len);

    if (pt_len > 0)
    {
        std::vector<uint8_t> bad_ct(ct);
        bad_ct[0] ^= 0x01;
        std::vector<uint8_t> bad_pt(pt_len);
        rc = tinychacha_aead_decrypt(key, nonce, aad, aad_len, bad_ct.data(), pt_len, bad_pt.data(), pt_len, tag);
        ASSERT_EQ(rc, TINYCHACHA_AUTH_FAILED);
    }
}

// ── Test cases: run each fuzz harness with edge cases + random inputs ──

TEST(fuzz_chacha20_roundtrip)
{
    prng_state = 0xdeadbeefcafe1234ULL;

    // Edge: exactly 48 bytes (zero-length plaintext)
    uint8_t minimal[48];
    fill_random(minimal, 48);
    fuzz_chacha20_one(minimal, 48);

    // Edge: 49 bytes (1-byte plaintext)
    uint8_t one_byte[49];
    fill_random(one_byte, 49);
    fuzz_chacha20_one(one_byte, 49);

    // Edge: 112 bytes (64-byte plaintext = exactly 1 block)
    uint8_t one_block[112];
    fill_random(one_block, 112);
    fuzz_chacha20_one(one_block, 112);

    // Edge: 111 bytes (63-byte plaintext = partial block)
    uint8_t partial[111];
    fill_random(partial, 111);
    fuzz_chacha20_one(partial, 111);

    // Edge: 113 bytes (65-byte plaintext = 1 block + 1 byte)
    uint8_t cross[113];
    fill_random(cross, 113);
    fuzz_chacha20_one(cross, 113);

    // Random inputs at various sizes
    static const size_t sizes[] = {48, 49, 64, 100, 128, 256, 512, 1024, 4096};
    for (size_t s : sizes)
    {
        for (int i = 0; i < 50; ++i)
        {
            std::vector<uint8_t> buf(s);
            fill_random(buf.data(), s);
            fuzz_chacha20_one(buf.data(), s);
        }
    }
}

TEST(fuzz_poly1305_roundtrip)
{
    prng_state = 0xfeedface12345678ULL;

    // Edge: exactly 32 bytes (zero-length message)
    uint8_t minimal[32];
    fill_random(minimal, 32);
    fuzz_poly1305_one(minimal, 32);

    // Edge: 33 bytes (1-byte message)
    uint8_t one_byte[33];
    fill_random(one_byte, 33);
    fuzz_poly1305_one(one_byte, 33);

    // Random inputs at various sizes
    static const size_t sizes[] = {32, 33, 48, 64, 100, 128, 256, 512, 1024};
    for (size_t s : sizes)
    {
        for (int i = 0; i < 50; ++i)
        {
            std::vector<uint8_t> buf(s);
            fill_random(buf.data(), s);
            fuzz_poly1305_one(buf.data(), s);
        }
    }
}

static void fuzz_chacha20_inplace_one(const uint8_t *data, size_t size)
{
    if (size < 48)
        return;
    const uint8_t *key = data;
    const uint8_t *nonce = data + 32;
    uint32_t counter = static_cast<uint32_t>(data[44]) | (static_cast<uint32_t>(data[45]) << 8)
                       | (static_cast<uint32_t>(data[46]) << 16) | (static_cast<uint32_t>(data[47]) << 24);
    size_t pt_len = size - 48;

    std::vector<uint8_t> original(pt_len);
    if (pt_len > 0)
        std::memcpy(original.data(), data + 48, pt_len);

    std::vector<uint8_t> work(original);
    int rc = tinychacha_chacha20(key, nonce, counter, work.data(), pt_len, work.data());
    if (rc != TINYCHACHA_OK)
        return; // counter overflow is acceptable; skip
    rc = tinychacha_chacha20(key, nonce, counter, work.data(), pt_len, work.data());
    ASSERT_EQ(rc, TINYCHACHA_OK);
    if (pt_len > 0)
        ASSERT_BYTES_EQ(work.data(), original.data(), pt_len);
}

TEST(fuzz_chacha20_inplace_roundtrip)
{
    prng_state = 0xb1b2b3b4c1c2c3c4ULL;
    static const size_t sizes[] = {48, 49, 112, 127, 128, 192, 512, 1024, 4096};
    for (size_t s : sizes)
    {
        for (int i = 0; i < 50; ++i)
        {
            std::vector<uint8_t> buf(s);
            fill_random(buf.data(), s);
            fuzz_chacha20_inplace_one(buf.data(), s);
        }
    }
}

TEST(fuzz_chacha20_counter_boundary)
{
    prng_state = 0xcafed00dbeefface;

    uint8_t key[32];
    uint8_t nonce[12];
    fill_random(key, 32);
    fill_random(nonce, 12);

    for (int i = 0; i < 400; ++i)
    {
        size_t len = static_cast<size_t>(xorshift64() % 512u);
        uint32_t counter = 0xFFFFFF00u + static_cast<uint32_t>(xorshift64() & 0xFFu);

        std::vector<uint8_t> pt(len);
        fill_random(pt.data(), len);
        std::vector<uint8_t> ct(len);
        int rc = tinychacha_chacha20(key, nonce, counter, pt.data(), len, ct.data());
        if (rc == TINYCHACHA_OK)
        {
            std::vector<uint8_t> rt(len);
            int rc2 = tinychacha_chacha20(key, nonce, counter, ct.data(), len, rt.data());
            ASSERT_EQ(rc2, TINYCHACHA_OK);
            if (len > 0)
                ASSERT_BYTES_EQ(rt.data(), pt.data(), len);
        }
        else
        {
            ASSERT_EQ(rc, TINYCHACHA_INVALID_INPUT_SIZE);
        }
    }
}

TEST(fuzz_poly1305_partial_blocks)
{
    prng_state = 0x0123456789abcdefULL;

    uint8_t key[32];
    fill_random(key, 32);

    auto run_at = [&](size_t size)
    {
        std::vector<uint8_t> msg(size);
        fill_random(msg.data(), size);
        uint8_t tag[16];
        int rc = tinychacha_poly1305_mac(key, msg.data(), size, tag);
        ASSERT_EQ(rc, TINYCHACHA_OK);
        int vrc = tinychacha_poly1305_verify(key, msg.data(), size, tag);
        ASSERT_EQ(vrc, TINYCHACHA_OK);
        // Flip every byte of tag once; must fail for all.
        for (int i = 0; i < 16; ++i)
        {
            uint8_t bad[16];
            std::memcpy(bad, tag, 16);
            bad[i] ^= 0xFF;
            int brc = tinychacha_poly1305_verify(key, msg.data(), size, bad);
            ASSERT_EQ(brc, TINYCHACHA_AUTH_FAILED);
        }
    };

    for (size_t s = 1; s <= 48; ++s)
        run_at(s);
    for (size_t s = 63; s <= 66; ++s)
        run_at(s);
    for (size_t s = 127; s <= 130; ++s)
        run_at(s);
}

// Exercises multi-block SIMD loops. Kept small so ctest stays fast.
TEST(fuzz_aead_large_roundtrip)
{
    prng_state = 0xfacefeed12345678ULL;

    uint8_t key[32];
    uint8_t nonce[12];
    fill_random(key, 32);
    fill_random(nonce, 12);
    uint8_t aad[64];
    fill_random(aad, 64);

    static const size_t sizes[] = {8192, 16384, 65536, 131072};
    for (size_t s : sizes)
    {
        std::vector<uint8_t> pt(s);
        fill_random(pt.data(), s);
        std::vector<uint8_t> ct(s);
        uint8_t tag[16];
        int rc = tinychacha_aead_encrypt(key, nonce, aad, 64, pt.data(), s, ct.data(), s, tag);
        ASSERT_EQ(rc, TINYCHACHA_OK);
        std::vector<uint8_t> rt(s);
        rc = tinychacha_aead_decrypt(key, nonce, aad, 64, ct.data(), s, rt.data(), s, tag);
        ASSERT_EQ(rc, TINYCHACHA_OK);
        ASSERT_BYTES_EQ(rt.data(), pt.data(), s);
    }
}

TEST(fuzz_aead_roundtrip)
{
    prng_state = 0xabad1deacafebabe;

    // Edge: 45 bytes (zero aad, zero plaintext)
    uint8_t minimal[45];
    fill_random(minimal, 45);
    minimal[44] = 0; // aad_len = 0
    fuzz_aead_one(minimal, 45);

    // Edge: 46 bytes with 0 aad (1-byte plaintext)
    uint8_t one_byte[46];
    fill_random(one_byte, 46);
    one_byte[44] = 0;
    fuzz_aead_one(one_byte, 46);

    // Edge: with aad
    uint8_t with_aad[256];
    fill_random(with_aad, 256);
    with_aad[44] = 16; // 16 bytes of aad
    fuzz_aead_one(with_aad, 256);

    // Random inputs at various sizes
    static const size_t sizes[] = {45, 46, 64, 100, 128, 256, 512, 1024};
    for (size_t s : sizes)
    {
        for (int i = 0; i < 50; ++i)
        {
            std::vector<uint8_t> buf(s);
            fill_random(buf.data(), s);
            // Clamp aad_len so it doesn't exceed remaining buffer
            if (s > 45)
            {
                size_t max_aad = s - 45;
                if (max_aad > 255)
                    max_aad = 255;
                buf[44] = static_cast<uint8_t>(buf[44] % (max_aad + 1));
            }
            else
            {
                buf[44] = 0;
            }
            fuzz_aead_one(buf.data(), s);
        }
    }
}
