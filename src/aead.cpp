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

#include "tinychacha/aead.h"

#include "internal/chacha20_impl.h"
#include "internal/endian.h"
#include "internal/poly1305_impl.h"

#include <cstdint>
#include <cstring>
#include <vector>

namespace tinychacha
{
    namespace
    {

        // pad16: returns number of zero padding bytes needed to reach 16-byte boundary
        inline size_t pad16(size_t len)
        {
            return (16 - (len & 15)) & 15;
        }

        // Build Poly1305 construction: AAD || pad16(AAD) || CT || pad16(CT) ||
        // LE64(aad_len) || LE64(ct_len) Then compute tag with the one-time poly key.
        void compute_tag(
            const uint8_t poly_key[32],
            const uint8_t *aad,
            size_t aad_len,
            const uint8_t *ct,
            size_t ct_len,
            uint8_t tag[16])
        {
            // Build the MAC input
            size_t mac_len = aad_len + pad16(aad_len) + ct_len + pad16(ct_len) + 16;
            std::vector<uint8_t> mac_data(mac_len, 0);
            size_t offset = 0;

            // AAD
            if (aad && aad_len > 0)
            {
                std::memcpy(mac_data.data() + offset, aad, aad_len);
            }
            offset += aad_len + pad16(aad_len);

            // Ciphertext
            if (ct && ct_len > 0)
            {
                std::memcpy(mac_data.data() + offset, ct, ct_len);
            }
            offset += ct_len + pad16(ct_len);

            // Lengths in LE 64-bit (BYTES, not bits)
            detail::store_le64(mac_data.data() + offset, static_cast<uint64_t>(aad_len));
            detail::store_le64(mac_data.data() + offset + 8, static_cast<uint64_t>(ct_len));

            // Compute Poly1305 tag
            auto mac_fn = internal::get_poly1305_mac();
            mac_fn(poly_key, mac_data.data(), mac_data.size(), tag);

            // Wipe MAC data
            secure_zero(mac_data.data(), mac_data.size());
        }

    } // anonymous namespace

    // Check whether the Poly1305 mac_data length
    // (AAD || pad16(AAD) || CT || pad16(CT) || LE64(aad_len) || LE64(ct_len))
    // would wrap size_t. The worst-case growth on top of aad_len + ct_len is
    // 15 (aad pad) + 15 (ct pad) + 16 (lengths) = 46; we guard with 48 for a
    // round headroom. Each subtraction must be ordered so that no intermediate
    // expression wraps around on its own — in particular, SIZE_MAX - ct_len
    // wraps low for ct_len near SIZE_MAX, which is why we bound ct_len first.
    static bool aead_mac_len_would_overflow(size_t aad_len, size_t ct_len)
    {
        if (ct_len > SIZE_MAX - 48u)
            return true;
        if (aad_len > SIZE_MAX - ct_len - 48u)
            return true;
        return false;
    }

    // Full separation: separate ciphertext and tag
    Result aead_encrypt(
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &nonce,
        const std::vector<uint8_t> &aad,
        const std::vector<uint8_t> &plaintext,
        std::vector<uint8_t> &ciphertext,
        std::vector<uint8_t> &tag)
    {
        try
        {
            if (key.size() != 32)
                return Result::InvalidKeySize;
            if (nonce.size() != 12)
                return Result::InvalidNonceSize;
            if (internal::counter_would_overflow(1u, plaintext.size()))
                return Result::InvalidInputSize;
            if (aead_mac_len_would_overflow(aad.size(), plaintext.size()))
                return Result::InvalidInputSize;

            auto block_fn = internal::get_chacha20_block();

            // Step 1: Derive one-time Poly1305 key from counter=0 block
            uint8_t poly_key_block[64] = {};
            uint8_t zeros[64] = {};
            block_fn(key.data(), nonce.data(), 0, zeros, 64, poly_key_block);
            // Only first 32 bytes are the Poly1305 key
            uint8_t poly_key[32];
            std::memcpy(poly_key, poly_key_block, 32);
            secure_zero(poly_key_block, 64);

            // Step 2: Encrypt plaintext at counter=1
            ciphertext.resize(plaintext.size());
            if (!plaintext.empty())
            {
                block_fn(key.data(), nonce.data(), 1, plaintext.data(), plaintext.size(), ciphertext.data());
            }

            // Step 3: Compute tag
            tag.resize(16);
            compute_tag(poly_key, aad.data(), aad.size(), ciphertext.data(), ciphertext.size(), tag.data());

            // Wipe poly key
            secure_zero(poly_key, 32);

            return Result::Ok;
        }
        catch (...)
        {
            return Result::InternalError;
        }
    }

    // Full separation: decrypt with separate tag
    Result aead_decrypt(
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &nonce,
        const std::vector<uint8_t> &aad,
        const std::vector<uint8_t> &ciphertext,
        const std::vector<uint8_t> &tag,
        std::vector<uint8_t> &plaintext)
    {
        try
        {
            if (key.size() != 32)
                return Result::InvalidKeySize;
            if (nonce.size() != 12)
                return Result::InvalidNonceSize;
            if (tag.size() != 16)
                return Result::InvalidInputSize;
            if (internal::counter_would_overflow(1u, ciphertext.size()))
                return Result::InvalidInputSize;
            if (aead_mac_len_would_overflow(aad.size(), ciphertext.size()))
                return Result::InvalidInputSize;

            auto block_fn = internal::get_chacha20_block();

            // Step 1: Derive one-time Poly1305 key from counter=0 block
            uint8_t poly_key_block[64] = {};
            uint8_t zeros[64] = {};
            block_fn(key.data(), nonce.data(), 0, zeros, 64, poly_key_block);
            uint8_t poly_key[32];
            std::memcpy(poly_key, poly_key_block, 32);
            secure_zero(poly_key_block, 64);

            // Step 2: Compute expected tag over ciphertext
            uint8_t computed_tag[16];
            compute_tag(poly_key, aad.data(), aad.size(), ciphertext.data(), ciphertext.size(), computed_tag);

            // Step 3: Verify tag (constant-time)
            bool ok = constant_time_eq(computed_tag, tag.data(), 16);
            secure_zero(computed_tag, 16);

            if (!ok)
            {
                secure_zero(poly_key, 32);
                plaintext.clear();
                return Result::AuthenticationFailed;
            }

            // Step 4: Decrypt at counter=1 (only after tag verified)
            plaintext.resize(ciphertext.size());
            if (!ciphertext.empty())
            {
                block_fn(key.data(), nonce.data(), 1, ciphertext.data(), ciphertext.size(), plaintext.data());
            }

            secure_zero(poly_key, 32);
            return Result::Ok;
        }
        catch (...)
        {
            return Result::InternalError;
        }
    }

    // Caller provides nonce, tag appended to ciphertext
    Result aead_encrypt(
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &nonce,
        const std::vector<uint8_t> &plaintext,
        const std::vector<uint8_t> &aad,
        std::vector<uint8_t> &ciphertext_and_tag)
    {
        try
        {
            std::vector<uint8_t> ct, tag;
            auto result = aead_encrypt(key, nonce, aad, plaintext, ct, tag);
            if (result != Result::Ok)
                return result;

            ciphertext_and_tag.resize(ct.size() + 16);
            if (!ct.empty())
                std::memcpy(ciphertext_and_tag.data(), ct.data(), ct.size());
            std::memcpy(ciphertext_and_tag.data() + ct.size(), tag.data(), 16);
            return Result::Ok;
        }
        catch (...)
        {
            return Result::InternalError;
        }
    }

    // Caller provides nonce, input is ciphertext||tag
    Result aead_decrypt(
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &nonce,
        const std::vector<uint8_t> &ciphertext_and_tag,
        const std::vector<uint8_t> &aad,
        std::vector<uint8_t> &plaintext)
    {
        try
        {
            if (ciphertext_and_tag.size() < 16)
                return Result::InvalidInputSize;

            size_t ct_len = ciphertext_and_tag.size() - 16;
            std::vector<uint8_t> ct(
                ciphertext_and_tag.begin(), ciphertext_and_tag.begin() + static_cast<ptrdiff_t>(ct_len));
            std::vector<uint8_t> tag(ciphertext_and_tag.end() - 16, ciphertext_and_tag.end());
            return aead_decrypt(key, nonce, aad, ct, tag, plaintext);
        }
        catch (...)
        {
            return Result::InternalError;
        }
    }

    // Library generates nonce, output is nonce||ciphertext||tag
    Result aead_encrypt(
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &plaintext,
        const std::vector<uint8_t> &aad,
        std::vector<uint8_t> &nonce_ciphertext_tag)
    {
        try
        {
            auto nonce = generate_nonce();
            if (nonce.empty())
                return Result::InternalError;

            std::vector<uint8_t> ct_tag;
            auto result = aead_encrypt(key, nonce, plaintext, aad, ct_tag);
            if (result != Result::Ok)
                return result;

            nonce_ciphertext_tag.resize(12 + ct_tag.size());
            std::memcpy(nonce_ciphertext_tag.data(), nonce.data(), 12);
            std::memcpy(nonce_ciphertext_tag.data() + 12, ct_tag.data(), ct_tag.size());
            return Result::Ok;
        }
        catch (...)
        {
            return Result::InternalError;
        }
    }

    // Nonce is first 12 bytes of input, rest is ciphertext||tag
    Result aead_decrypt(
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &nonce_ciphertext_tag,
        const std::vector<uint8_t> &aad,
        std::vector<uint8_t> &plaintext)
    {
        try
        {
            if (nonce_ciphertext_tag.size() < 12 + 16)
                return Result::InvalidInputSize;

            std::vector<uint8_t> nonce(nonce_ciphertext_tag.begin(), nonce_ciphertext_tag.begin() + 12);
            std::vector<uint8_t> ct_tag(nonce_ciphertext_tag.begin() + 12, nonce_ciphertext_tag.end());
            return aead_decrypt(key, nonce, ct_tag, aad, plaintext);
        }
        catch (...)
        {
            return Result::InternalError;
        }
    }

} // namespace tinychacha

// --- C API ---

extern "C" int tinychacha_aead_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t tag[16])
{
    if (!key || !nonce || !tag)
        return TINYCHACHA_INTERNAL_ERROR;
    if ((!aad && aad_len > 0) || (!plaintext && plaintext_len > 0) || (!ciphertext && plaintext_len > 0))
        return TINYCHACHA_INTERNAL_ERROR;
    if (ciphertext_len < plaintext_len)
        return TINYCHACHA_INVALID_INPUT_SIZE;
    // Reject sizes that would wrap internal length computations or exceed the
    // ChaCha20 counter. These checks must run before any allocation so that the
    // C API returns InvalidInputSize rather than InternalError on hostile sizes.
    if (tinychacha::internal::counter_would_overflow(1u, plaintext_len))
        return TINYCHACHA_INVALID_INPUT_SIZE;
    if (tinychacha::aead_mac_len_would_overflow(aad_len, plaintext_len))
        return TINYCHACHA_INVALID_INPUT_SIZE;

    try
    {
        std::vector<uint8_t> k(key, key + 32);
        std::vector<uint8_t> n(nonce, nonce + 12);
        std::vector<uint8_t> a(aad, aad + aad_len);
        std::vector<uint8_t> pt(plaintext, plaintext + plaintext_len);
        std::vector<uint8_t> ct, t;

        auto result = tinychacha::aead_encrypt(k, n, a, pt, ct, t);

        tinychacha::secure_zero(k.data(), k.size());
        tinychacha::secure_zero(n.data(), n.size());
        tinychacha::secure_zero(pt.data(), pt.size());

        if (result != tinychacha::Result::Ok)
            return static_cast<int>(result);

        std::memcpy(ciphertext, ct.data(), ct.size());
        std::memcpy(tag, t.data(), 16);
        return TINYCHACHA_OK;
    }
    catch (...)
    {
        return TINYCHACHA_INTERNAL_ERROR;
    }
}

extern "C" int tinychacha_aead_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t tag[16])
{
    if (!key || !nonce || !tag)
        return TINYCHACHA_INTERNAL_ERROR;
    if ((!aad && aad_len > 0) || (!ciphertext && ciphertext_len > 0) || (!plaintext && ciphertext_len > 0))
        return TINYCHACHA_INTERNAL_ERROR;
    if (plaintext_len < ciphertext_len)
        return TINYCHACHA_INVALID_INPUT_SIZE;
    if (tinychacha::internal::counter_would_overflow(1u, ciphertext_len))
        return TINYCHACHA_INVALID_INPUT_SIZE;
    if (tinychacha::aead_mac_len_would_overflow(aad_len, ciphertext_len))
        return TINYCHACHA_INVALID_INPUT_SIZE;

    try
    {
        std::vector<uint8_t> k(key, key + 32);
        std::vector<uint8_t> n(nonce, nonce + 12);
        std::vector<uint8_t> a(aad, aad + aad_len);
        std::vector<uint8_t> ct(ciphertext, ciphertext + ciphertext_len);
        std::vector<uint8_t> t(tag, tag + 16);
        std::vector<uint8_t> pt;

        auto result = tinychacha::aead_decrypt(k, n, a, ct, t, pt);

        tinychacha::secure_zero(k.data(), k.size());
        tinychacha::secure_zero(n.data(), n.size());

        if (result != tinychacha::Result::Ok)
        {
            return static_cast<int>(result);
        }

        std::memcpy(plaintext, pt.data(), pt.size());
        tinychacha::secure_zero(pt.data(), pt.size());
        return TINYCHACHA_OK;
    }
    catch (...)
    {
        return TINYCHACHA_INTERNAL_ERROR;
    }
}
