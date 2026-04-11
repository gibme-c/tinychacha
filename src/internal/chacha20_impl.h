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

#ifndef TINYCHACHA_INTERNAL_CHACHA20_IMPL_H
#define TINYCHACHA_INTERNAL_CHACHA20_IMPL_H

#include <cstddef>
#include <cstdint>

namespace tinychacha
{
    namespace internal
    {

        // Encrypts/decrypts input by XORing with ChaCha20 keystream.
        // key: 32 bytes, nonce: 12 bytes, counter: initial block counter
        // Returns number of bytes processed (should equal input_len on success).
        using chacha20_block_fn = void (*)(
            const uint8_t key[32],
            const uint8_t nonce[12],
            uint32_t counter,
            const uint8_t *input,
            size_t input_len,
            uint8_t *output);

        // Backend declarations
        void chacha20_portable(
            const uint8_t key[32],
            const uint8_t nonce[12],
            uint32_t counter,
            const uint8_t *input,
            size_t input_len,
            uint8_t *output);

        void chacha20_avx2(
            const uint8_t key[32],
            const uint8_t nonce[12],
            uint32_t counter,
            const uint8_t *input,
            size_t input_len,
            uint8_t *output);

        void chacha20_avx512(
            const uint8_t key[32],
            const uint8_t nonce[12],
            uint32_t counter,
            const uint8_t *input,
            size_t input_len,
            uint8_t *output);

        void chacha20_neon(
            const uint8_t key[32],
            const uint8_t nonce[12],
            uint32_t counter,
            const uint8_t *input,
            size_t input_len,
            uint8_t *output);

        chacha20_block_fn get_chacha20_block();

        // Reject (counter, len) pairs whose encryption would advance the 32-bit
        // ChaCha20 block counter past its maximum. Uses an overflow-safe ceil-divide
        // so no intermediate wraps on any size_t width. Shared between chacha20.cpp,
        // aead.cpp (which passes counter=1 — the AEAD counter always starts at 1),
        // and the cross-backend equivalence test.
        inline bool counter_would_overflow(uint32_t counter, size_t len)
        {
            if (len == 0)
                return false;
            constexpr uint64_t kMaxBytes = static_cast<uint64_t>(0xFFFFFFFFu) * 64u; // (2^32 - 1) * 64
            if (static_cast<uint64_t>(len) > kMaxBytes)
                return true;
            uint64_t blocks_needed = static_cast<uint64_t>(len) / 64u + ((len & 63u) != 0u ? 1u : 0u);
            uint64_t blocks_available = static_cast<uint64_t>(0xFFFFFFFFu) - counter + 1u;
            return blocks_needed > blocks_available;
        }

    } /* namespace internal */
} /* namespace tinychacha */

#endif /* TINYCHACHA_INTERNAL_CHACHA20_IMPL_H */
