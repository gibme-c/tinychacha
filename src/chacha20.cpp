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

#include "tinychacha/chacha20.h"

#include "cpu_features.h"
#include "internal/chacha20_impl.h"

namespace tinychacha
{
    namespace internal
    {

        chacha20_block_fn get_chacha20_block()
        {
#if !defined(TINYCHACHA_FORCE_PORTABLE)
            const auto &feat = cpu::detect();
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
            if (feat.avx512f)
                return chacha20_avx512;
            if (feat.avx2)
                return chacha20_avx2;
#endif
#if defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_NEON)
            if (feat.neon)
                return chacha20_neon;
#endif
#endif
            return chacha20_portable;
        }

    } // namespace internal

    Result chacha20(
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &nonce,
        uint32_t counter,
        const std::vector<uint8_t> &input,
        std::vector<uint8_t> &output)
    {
        try
        {
            if (key.size() != 32)
                return Result::InvalidKeySize;
            if (nonce.size() != 12)
                return Result::InvalidNonceSize;
            if (internal::counter_would_overflow(counter, input.size()))
                return Result::InvalidInputSize;

            output.resize(input.size());
            if (input.empty())
                return Result::Ok;

            auto block_fn = internal::get_chacha20_block();
            block_fn(key.data(), nonce.data(), counter, input.data(), input.size(), output.data());
            return Result::Ok;
        }
        catch (...)
        {
            return Result::InternalError;
        }
    }

    Result chacha20_keystream(
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &nonce,
        uint32_t counter,
        size_t length,
        std::vector<uint8_t> &output)
    {
        try
        {
            if (key.size() != 32)
                return Result::InvalidKeySize;
            if (nonce.size() != 12)
                return Result::InvalidNonceSize;
            if (internal::counter_would_overflow(counter, length))
                return Result::InvalidInputSize;

            // Generate keystream by encrypting zeros
            std::vector<uint8_t> zeros(length, 0);
            output.resize(length);
            if (length == 0)
                return Result::Ok;

            auto block_fn = internal::get_chacha20_block();
            block_fn(key.data(), nonce.data(), counter, zeros.data(), length, output.data());
            return Result::Ok;
        }
        catch (...)
        {
            return Result::InternalError;
        }
    }

} // namespace tinychacha

extern "C" int tinychacha_chacha20(
    const uint8_t key[32],
    const uint8_t nonce[12],
    uint32_t counter,
    const uint8_t *input,
    size_t input_len,
    uint8_t *output)
{
    if (!key || !nonce || (!input && input_len > 0) || (!output && input_len > 0))
        return TINYCHACHA_INTERNAL_ERROR;

    if (input_len == 0)
        return TINYCHACHA_OK;

    if (tinychacha::internal::counter_would_overflow(counter, input_len))
        return TINYCHACHA_INVALID_INPUT_SIZE;

    try
    {
        auto block_fn = tinychacha::internal::get_chacha20_block();
        block_fn(key, nonce, counter, input, input_len, output);
        return TINYCHACHA_OK;
    }
    catch (...)
    {
        return TINYCHACHA_INTERNAL_ERROR;
    }
}
