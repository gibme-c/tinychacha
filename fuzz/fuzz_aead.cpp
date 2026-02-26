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

#include <tinychacha/aead.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

/*
 * Fuzz target: AEAD encrypt/decrypt roundtrip + tampered auth failure.
 * Input layout: [32 key][12 nonce][1 aad_len][aad_len aad][...plaintext]
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Need at least key(32) + nonce(12) + aad_len(1) = 45 bytes
  if (size < 45)
    return 0;

  const uint8_t *key = data;
  const uint8_t *nonce = data + 32;
  size_t aad_len = data[44];
  if (45 + aad_len > size)
    return 0;

  const uint8_t *aad = data + 45;
  const uint8_t *plaintext = data + 45 + aad_len;
  size_t pt_len = size - 45 - aad_len;

  // Encrypt
  std::vector<uint8_t> ct(pt_len);
  uint8_t tag[16];
  int rc = tinychacha_aead_encrypt(key, nonce, aad, aad_len, plaintext, pt_len,
                                   ct.data(), pt_len, tag);
  if (rc != TINYCHACHA_OK)
    __builtin_trap();

  // Decrypt roundtrip
  std::vector<uint8_t> rt(pt_len);
  rc = tinychacha_aead_decrypt(key, nonce, aad, aad_len, ct.data(), pt_len,
                               rt.data(), pt_len, tag);
  if (rc != TINYCHACHA_OK)
    __builtin_trap();

  // Roundtrip must match
  if (pt_len > 0 && std::memcmp(plaintext, rt.data(), pt_len) != 0)
    __builtin_trap();

  // Tampered ciphertext must fail auth
  if (pt_len > 0) {
    std::vector<uint8_t> bad_ct(ct);
    bad_ct[0] ^= 0x01;
    std::vector<uint8_t> bad_pt(pt_len);
    rc = tinychacha_aead_decrypt(key, nonce, aad, aad_len, bad_ct.data(),
                                 pt_len, bad_pt.data(), pt_len, tag);
    if (rc != TINYCHACHA_AUTH_FAILED)
      __builtin_trap();
  }

  return 0;
}
