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

// Structure-aware AEAD fuzzer using FuzzedDataProvider: bounded key/nonce/
// aad/plaintext, runs roundtrip + one-bit tamper checks on ciphertext, AAD,
// and tag on each iteration.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <tinychacha/aead.h>

static constexpr size_t kMaxAad = 1024;
static constexpr size_t kMaxPt = 4096;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    uint8_t key[32];
    uint8_t nonce[12];
    if (fdp.ConsumeData(key, 32) != 32)
        return 0;
    if (fdp.ConsumeData(nonce, 12) != 12)
        return 0;

    size_t aad_len = fdp.ConsumeIntegralInRange<size_t>(0, kMaxAad);
    uint8_t aad[kMaxAad];
    aad_len = fdp.ConsumeData(aad, aad_len);

    size_t pt_len = fdp.ConsumeIntegralInRange<size_t>(0, kMaxPt);
    uint8_t pt[kMaxPt];
    pt_len = fdp.ConsumeData(pt, pt_len);

    uint8_t ct[kMaxPt];
    uint8_t tag[16];
    int rc = tinychacha_aead_encrypt(key, nonce, aad, aad_len, pt, pt_len, ct, pt_len, tag);
    if (rc != TINYCHACHA_OK)
        __builtin_trap();

    uint8_t rt[kMaxPt];
    rc = tinychacha_aead_decrypt(key, nonce, aad, aad_len, ct, pt_len, rt, pt_len, tag);
    if (rc != TINYCHACHA_OK)
        __builtin_trap();
    if (pt_len > 0 && std::memcmp(rt, pt, pt_len) != 0)
        __builtin_trap();

    {
        uint8_t bad_tag[16];
        std::memcpy(bad_tag, tag, 16);
        bad_tag[0] ^= 0x01;
        rc = tinychacha_aead_decrypt(key, nonce, aad, aad_len, ct, pt_len, rt, pt_len, bad_tag);
        if (rc != TINYCHACHA_AUTH_FAILED)
            __builtin_trap();
    }

    if (pt_len > 0)
    {
        uint8_t saved = ct[0];
        ct[0] ^= 0x80;
        rc = tinychacha_aead_decrypt(key, nonce, aad, aad_len, ct, pt_len, rt, pt_len, tag);
        if (rc != TINYCHACHA_AUTH_FAILED)
            __builtin_trap();
        ct[0] = saved;
    }

    if (aad_len > 0)
    {
        uint8_t saved = aad[0];
        aad[0] ^= 0x40;
        rc = tinychacha_aead_decrypt(key, nonce, aad, aad_len, ct, pt_len, rt, pt_len, tag);
        if (rc != TINYCHACHA_AUTH_FAILED)
            __builtin_trap();
        aad[0] = saved;
    }

    return 0;
}
