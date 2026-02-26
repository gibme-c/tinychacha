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

#include "tinychacha/poly1305.h"
#include "cpu_features.h"
#include "internal/poly1305_impl.h"

namespace tinychacha {
namespace internal {

poly1305_mac_fn get_poly1305_mac() {
#if !defined(TINYCHACHA_FORCE_PORTABLE)
  const auto &feat = cpu::detect();
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) ||             \
    defined(_M_IX86)
  if (feat.avx2)
    return poly1305_avx2;
#endif
#if defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_NEON)
  if (feat.neon)
    return poly1305_neon;
#endif
#endif
  return poly1305_portable;
}

} // namespace internal

Result poly1305_mac(const std::vector<uint8_t> &key,
                    const std::vector<uint8_t> &message,
                    std::vector<uint8_t> &tag) {
  if (key.size() != 32)
    return Result::InvalidKeySize;

  tag.resize(16);
  auto mac_fn = internal::get_poly1305_mac();
  mac_fn(key.data(), message.data(), message.size(), tag.data());
  return Result::Ok;
}

Result poly1305_verify(const std::vector<uint8_t> &key,
                       const std::vector<uint8_t> &message,
                       const std::vector<uint8_t> &tag) {
  if (key.size() != 32)
    return Result::InvalidKeySize;
  if (tag.size() != 16)
    return Result::InvalidInputSize;

  uint8_t computed[16];
  auto mac_fn = internal::get_poly1305_mac();
  mac_fn(key.data(), message.data(), message.size(), computed);

  bool ok = constant_time_eq(computed, tag.data(), 16);
  secure_zero(computed, 16);

  return ok ? Result::Ok : Result::AuthenticationFailed;
}

} // namespace tinychacha

extern "C" int tinychacha_poly1305_mac(const uint8_t key[32],
                                       const uint8_t *message,
                                       size_t message_len, uint8_t tag[16]) {
  if (!key || !tag || (!message && message_len > 0))
    return TINYCHACHA_INTERNAL_ERROR;

  try {
    auto mac_fn = tinychacha::internal::get_poly1305_mac();
    mac_fn(key, message, message_len, tag);
    return TINYCHACHA_OK;
  } catch (...) {
    return TINYCHACHA_INTERNAL_ERROR;
  }
}

extern "C" int tinychacha_poly1305_verify(const uint8_t key[32],
                                          const uint8_t *message,
                                          size_t message_len,
                                          const uint8_t tag[16]) {
  if (!key || !tag || (!message && message_len > 0))
    return TINYCHACHA_INTERNAL_ERROR;

  try {
    uint8_t computed[16];
    auto mac_fn = tinychacha::internal::get_poly1305_mac();
    mac_fn(key, message, message_len, computed);

    int eq = tinychacha_constant_time_eq(computed, tag, 16);
    tinychacha_secure_zero(computed, 16);

    return eq == 1 ? TINYCHACHA_OK : TINYCHACHA_AUTH_FAILED;
  } catch (...) {
    return TINYCHACHA_INTERNAL_ERROR;
  }
}
