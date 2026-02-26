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

#pragma once

#include "tinychacha/common.h"

#ifdef __cplusplus
extern "C" {
#endif

TINYCHACHA_NODISCARD TINYCHACHA_API int tinychacha_aead_encrypt(
    const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad,
    size_t aad_len, const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, size_t ciphertext_len, uint8_t tag[16]);

TINYCHACHA_NODISCARD TINYCHACHA_API int tinychacha_aead_decrypt(
    const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad,
    size_t aad_len, const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext, size_t plaintext_len, const uint8_t tag[16]);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

#include <vector>

namespace tinychacha {

// Full separation: separate ciphertext and tag outputs
[[nodiscard]] Result aead_encrypt(const std::vector<uint8_t> &key,
                    const std::vector<uint8_t> &nonce,
                    const std::vector<uint8_t> &aad,
                    const std::vector<uint8_t> &plaintext,
                    std::vector<uint8_t> &ciphertext,
                    std::vector<uint8_t> &tag);

[[nodiscard]] Result aead_decrypt(const std::vector<uint8_t> &key,
                    const std::vector<uint8_t> &nonce,
                    const std::vector<uint8_t> &aad,
                    const std::vector<uint8_t> &ciphertext,
                    const std::vector<uint8_t> &tag,
                    std::vector<uint8_t> &plaintext);

// Caller provides nonce, tag appended to ciphertext
[[nodiscard]] Result aead_encrypt(const std::vector<uint8_t> &key,
                    const std::vector<uint8_t> &nonce,
                    const std::vector<uint8_t> &plaintext,
                    const std::vector<uint8_t> &aad,
                    std::vector<uint8_t> &ciphertext_and_tag);

// Caller provides nonce, input is ciphertext||tag
[[nodiscard]] Result aead_decrypt(const std::vector<uint8_t> &key,
                    const std::vector<uint8_t> &nonce,
                    const std::vector<uint8_t> &ciphertext_and_tag,
                    const std::vector<uint8_t> &aad,
                    std::vector<uint8_t> &plaintext);

// Library generates nonce, output is nonce||ciphertext||tag
[[nodiscard]] Result aead_encrypt(const std::vector<uint8_t> &key,
                    const std::vector<uint8_t> &plaintext,
                    const std::vector<uint8_t> &aad,
                    std::vector<uint8_t> &nonce_ciphertext_tag);

// Nonce is first 12 bytes of input, rest is ciphertext||tag
[[nodiscard]] Result aead_decrypt(const std::vector<uint8_t> &key,
                    const std::vector<uint8_t> &nonce_ciphertext_tag,
                    const std::vector<uint8_t> &aad,
                    std::vector<uint8_t> &plaintext);

} // namespace tinychacha

#endif
