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

// Cross-backend equivalence fuzzer. For every input, runs ChaCha20 and
// Poly1305 through the portable reference and every compiled SIMD backend,
// trapping on divergence.
//
// Input layout: [32 key][12 nonce][4 counter_le][...payload]

#include "cpu_features.h"
#include "internal/chacha20_impl.h"
#include "internal/endian.h"
#include "internal/poly1305_impl.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

static constexpr size_t kMaxPayload = 16384;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 48)
        return 0;

    const uint8_t *key = data;
    const uint8_t *nonce = data + 32;
    uint32_t counter = tinychacha::detail::load_le32(data + 44);
    const uint8_t *payload = data + 48;
    size_t payload_len = size - 48;
    if (payload_len > kMaxPayload)
        return 0;

    const auto &features = tinychacha::cpu::detect();

    if (!tinychacha::internal::counter_would_overflow(counter, payload_len))
    {
        uint8_t ref[kMaxPayload];
        uint8_t got[kMaxPayload];
        tinychacha::internal::chacha20_portable(key, nonce, counter, payload, payload_len, ref);

        auto check_chacha = [&](tinychacha::internal::chacha20_block_fn fn)
        {
            fn(key, nonce, counter, payload, payload_len, got);
            if (payload_len > 0 && std::memcmp(got, ref, payload_len) != 0)
                __builtin_trap();
        };
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)) \
    && !defined(TINYCHACHA_FORCE_PORTABLE)
        if (features.avx2)
            check_chacha(tinychacha::internal::chacha20_avx2);
        if (features.avx512f)
            check_chacha(tinychacha::internal::chacha20_avx512);
#endif
#if (defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_NEON)) && !defined(TINYCHACHA_FORCE_PORTABLE)
        if (features.neon)
            check_chacha(tinychacha::internal::chacha20_neon);
#endif
    }

    uint8_t ref_tag[16];
    uint8_t got_tag[16];
    tinychacha::internal::poly1305_portable(key, payload, payload_len, ref_tag);

    auto check_poly = [&](tinychacha::internal::poly1305_mac_fn fn)
    {
        fn(key, payload, payload_len, got_tag);
        if (std::memcmp(got_tag, ref_tag, 16) != 0)
            __builtin_trap();
    };
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)) \
    && !defined(TINYCHACHA_FORCE_PORTABLE)
    if (features.avx2)
        check_poly(tinychacha::internal::poly1305_avx2);
#endif
#if (defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_NEON)) && !defined(TINYCHACHA_FORCE_PORTABLE)
    if (features.neon)
        check_poly(tinychacha::internal::poly1305_neon);
#endif

    return 0;
}
