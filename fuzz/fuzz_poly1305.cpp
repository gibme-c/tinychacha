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

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <tinychacha/poly1305.h>

/*
 * Fuzz target: Poly1305 MAC compute + verify roundtrip.
 * Input layout: [32 key][...message]
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Need at least a 32-byte key
    if (size < 32)
        return 0;

    const uint8_t *key = data;
    const uint8_t *msg = data + 32;
    size_t msg_len = size - 32;

    // Compute tag
    uint8_t tag[16];
    tinychacha_poly1305_mac(key, msg, msg_len, tag);

    // Verify must succeed
    int rc = tinychacha_poly1305_verify(key, msg, msg_len, tag);
    if (rc != TINYCHACHA_OK)
        __builtin_trap();

    // Flip one bit in tag — verify must fail
    uint8_t bad_tag[16];
    std::memcpy(bad_tag, tag, 16);
    bad_tag[0] ^= 0x01;
    rc = tinychacha_poly1305_verify(key, msg, msg_len, bad_tag);
    if (rc != TINYCHACHA_AUTH_FAILED)
        __builtin_trap();

    return 0;
}
