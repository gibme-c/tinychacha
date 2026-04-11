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

// AEAD decrypt fuzzer. Invariant: for any well-sized input, decrypt returns
// only OK or AUTH_FAILED — never crashes, never returns a stray code, never
// trips ASAN/UBSAN. On OK, re-encrypting the recovered plaintext must
// reproduce the input ciphertext and tag.
//
// Input layout: [32 key][12 nonce][1 aad_len][aad_len aad][16 tag][...ciphertext]

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <tinychacha/aead.h>

static constexpr size_t kMaxCtLen = 8192;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 61)
        return 0;

    const uint8_t *key = data;
    const uint8_t *nonce = data + 32;
    size_t aad_len = data[44];
    if (45 + aad_len + 16 > size)
        return 0;

    const uint8_t *aad = data + 45;
    const uint8_t *tag = data + 45 + aad_len;
    const uint8_t *ct = data + 45 + aad_len + 16;
    size_t ct_len = size - 45 - aad_len - 16;
    if (ct_len > kMaxCtLen)
        return 0;

    uint8_t pt[kMaxCtLen];
    int rc = tinychacha_aead_decrypt(key, nonce, aad, aad_len, ct, ct_len, pt, ct_len, tag);

    if (rc == TINYCHACHA_OK)
    {
        uint8_t ct2[kMaxCtLen];
        uint8_t tag2[16];
        int rc2 = tinychacha_aead_encrypt(key, nonce, aad, aad_len, pt, ct_len, ct2, ct_len, tag2);
        if (rc2 != TINYCHACHA_OK)
            __builtin_trap();
        if (ct_len > 0 && std::memcmp(ct2, ct, ct_len) != 0)
            __builtin_trap();
        if (std::memcmp(tag2, tag, 16) != 0)
            __builtin_trap();
    }
    else if (rc != TINYCHACHA_AUTH_FAILED)
    {
        __builtin_trap();
    }
    return 0;
}
