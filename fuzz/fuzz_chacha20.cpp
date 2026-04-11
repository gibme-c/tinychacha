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
#include <tinychacha/chacha20.h>
#include <vector>

/*
 * Fuzz target: ChaCha20 encrypt/decrypt roundtrip.
 * Input layout: [32 key][12 nonce][4 counter_le][...plaintext]
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Need at least key(32) + nonce(12) + counter(4) = 48 bytes
    if (size < 48)
        return 0;

    const uint8_t *key = data;
    const uint8_t *nonce = data + 32;
    uint32_t counter = static_cast<uint32_t>(data[44]) | (static_cast<uint32_t>(data[45]) << 8)
                       | (static_cast<uint32_t>(data[46]) << 16) | (static_cast<uint32_t>(data[47]) << 24);
    const uint8_t *plaintext = data + 48;
    size_t pt_len = size - 48;

    // Encrypt
    std::vector<uint8_t> ct(pt_len);
    if (pt_len > 0)
    {
        tinychacha_chacha20(key, nonce, counter, plaintext, pt_len, ct.data());
    }

    // Decrypt (roundtrip)
    std::vector<uint8_t> rt(pt_len);
    if (pt_len > 0)
    {
        tinychacha_chacha20(key, nonce, counter, ct.data(), pt_len, rt.data());
    }

    // Roundtrip must match original plaintext
    if (pt_len > 0 && std::memcmp(plaintext, rt.data(), pt_len) != 0)
        __builtin_trap();

    return 0;
}
