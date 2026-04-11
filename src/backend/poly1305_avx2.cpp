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

// 4-way lane-parallel AVX2 Poly1305.
//
// Algorithm (RFC 8439 §2.5; Bernstein 2005, "The Poly1305-AES
// message-authentication code"):
//
//   Accumulator h and key factor r are each represented as five radix-2^26
//   limbs. For each 64-byte chunk of message we absorb four 16-byte blocks
//   together via the Horner identity
//
//     h_new = ((((h_old + m0) * r + m1) * r + m2) * r + m3) * r
//           = (h_old + m0) * r^4 + m1 * r^3 + m2 * r^2 + m3 * r      (mod p)
//
//   where p = 2^130 - 5. We precompute r, r^2, r^3, r^4 as 5-limb values
//   (mod p) and pack them as four 64-bit lanes in __m256i registers so that
//   the four (block_i * power_i) products run in lock-step. A lane-parallel
//   schoolbook 5x5 multiply produces 5 per-lane u64 accumulators; a
//   horizontal sum across the 4 lanes collapses them to scalar u64 limbs,
//   which are then carry-propagated and folded through the 2^130 - 5
//   reduction trick (c * 5 added back into limb 0).
//
//   Message tails (anything that does not fill a 64-byte chunk — including
//   messages shorter than 64 bytes, and the final 0..63 bytes of longer
//   messages) are absorbed one 16-byte block at a time using the scalar
//   mul_reduce by r, exactly mirroring the portable MSVC 5-limb path. This
//   keeps the partial-block handling bit-identical to the portable backend.
//
// Constraints:
//   - Output must be byte-identical to poly1305_portable for every message
//     length; the permanent cross-backend equivalence test
//     (tests/test_backend_equivalence.cpp) is the acceptance gate.
//   - Constant-time with respect to message content. Tail length is a public
//     quantity (it matches the portable path's branching on message_len).
//   - All key-derived scratch is zeroed before return.

#include "internal/endian.h"
#include "internal/poly1305_impl.h"
#include "tinychacha/common.h"

#if defined(__AVX2__)

#include <cstring>
#include <immintrin.h>

namespace tinychacha
{
    namespace internal
    {

        namespace
        {

            constexpr uint32_t kLimbMask = 0x03ffffffu; // 2^26 - 1

            // Clamp the 16-byte r half of the key and decompose into five radix-2^26
            // limbs. Mirrors src/backend/poly1305_portable.cpp:49-59 (MSVC 5-limb path).
            inline void clamp_and_split(const uint8_t key[32], uint32_t r[5])
            {
                uint32_t t0 = detail::load_le32(key + 0) & 0x0fffffffu;
                uint32_t t1 = detail::load_le32(key + 4) & 0x0ffffffcu;
                uint32_t t2 = detail::load_le32(key + 8) & 0x0ffffffcu;
                uint32_t t3 = detail::load_le32(key + 12) & 0x0ffffffcu;
                r[0] = t0 & kLimbMask;
                r[1] = ((t0 >> 26) | (t1 << 6)) & kLimbMask;
                r[2] = ((t1 >> 20) | (t2 << 12)) & kLimbMask;
                r[3] = ((t2 >> 14) | (t3 << 18)) & kLimbMask;
                r[4] = (t3 >> 8);
            }

            // Scalar 5-limb multiply-reduce: out = a * b mod (2^130 - 5).
            // Mirrors src/backend/poly1305_portable.cpp:91-121 (MSVC 5-limb path).
            // Accepts a-limbs up to about 2^28 and b-limbs strictly less than 2^26 (the
            // canonical output form), which matches how both the power precompute and
            // the tail absorb invoke it.
            void mul_reduce(uint32_t out[5], const uint32_t a[5], const uint32_t b[5])
            {
                uint32_t s1 = b[1] * 5u;
                uint32_t s2 = b[2] * 5u;
                uint32_t s3 = b[3] * 5u;
                uint32_t s4 = b[4] * 5u;

                uint64_t d0 = (uint64_t)a[0] * b[0] + (uint64_t)a[1] * s4 + (uint64_t)a[2] * s3 + (uint64_t)a[3] * s2
                              + (uint64_t)a[4] * s1;
                uint64_t d1 = (uint64_t)a[0] * b[1] + (uint64_t)a[1] * b[0] + (uint64_t)a[2] * s4 + (uint64_t)a[3] * s3
                              + (uint64_t)a[4] * s2;
                uint64_t d2 = (uint64_t)a[0] * b[2] + (uint64_t)a[1] * b[1] + (uint64_t)a[2] * b[0]
                              + (uint64_t)a[3] * s4 + (uint64_t)a[4] * s3;
                uint64_t d3 = (uint64_t)a[0] * b[3] + (uint64_t)a[1] * b[2] + (uint64_t)a[2] * b[1]
                              + (uint64_t)a[3] * b[0] + (uint64_t)a[4] * s4;
                uint64_t d4 = (uint64_t)a[0] * b[4] + (uint64_t)a[1] * b[3] + (uint64_t)a[2] * b[2]
                              + (uint64_t)a[3] * b[1] + (uint64_t)a[4] * b[0];

                uint32_t c;
                c = static_cast<uint32_t>(d0 >> 26);
                out[0] = static_cast<uint32_t>(d0) & kLimbMask;
                d1 += c;
                c = static_cast<uint32_t>(d1 >> 26);
                out[1] = static_cast<uint32_t>(d1) & kLimbMask;
                d2 += c;
                c = static_cast<uint32_t>(d2 >> 26);
                out[2] = static_cast<uint32_t>(d2) & kLimbMask;
                d3 += c;
                c = static_cast<uint32_t>(d3 >> 26);
                out[3] = static_cast<uint32_t>(d3) & kLimbMask;
                d4 += c;
                c = static_cast<uint32_t>(d4 >> 26);
                out[4] = static_cast<uint32_t>(d4) & kLimbMask;
                out[0] += c * 5u;
                c = out[0] >> 26;
                out[0] &= kLimbMask;
                out[1] += c;
            }

            // Full reduction of h (to [0, 2^130 - 5)) followed by addition of the s
            // half of the key mod 2^128 and the 16-byte little-endian store. Mirrors
            // src/backend/poly1305_portable.cpp:127-198 exactly.
            void finalize_tag(uint32_t h[5], const uint8_t key[32], uint8_t tag[16])
            {
                uint32_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];

                uint32_t c;
                c = h1 >> 26;
                h1 &= kLimbMask;
                h2 += c;
                c = h2 >> 26;
                h2 &= kLimbMask;
                h3 += c;
                c = h3 >> 26;
                h3 &= kLimbMask;
                h4 += c;
                c = h4 >> 26;
                h4 &= kLimbMask;
                h0 += c * 5u;
                c = h0 >> 26;
                h0 &= kLimbMask;
                h1 += c;

                uint32_t g0 = h0 + 5u;
                c = g0 >> 26;
                g0 &= kLimbMask;
                uint32_t g1 = h1 + c;
                c = g1 >> 26;
                g1 &= kLimbMask;
                uint32_t g2 = h2 + c;
                c = g2 >> 26;
                g2 &= kLimbMask;
                uint32_t g3 = h3 + c;
                c = g3 >> 26;
                g3 &= kLimbMask;
                uint32_t g4 = h4 + c - (1u << 26);

                uint32_t mask = (g4 >> 31) - 1u;
                g0 &= mask;
                g1 &= mask;
                g2 &= mask;
                g3 &= mask;
                g4 &= mask;
                mask = ~mask;
                h0 = (h0 & mask) | g0;
                h1 = (h1 & mask) | g1;
                h2 = (h2 & mask) | g2;
                h3 = (h3 & mask) | g3;
                h4 = (h4 & mask) | g4;

                uint32_t w0 = static_cast<uint32_t>((uint64_t)h0 | ((uint64_t)h1 << 26));
                uint32_t w1 = static_cast<uint32_t>(((uint64_t)h1 >> 6) | ((uint64_t)h2 << 20));
                uint32_t w2 = static_cast<uint32_t>(((uint64_t)h2 >> 12) | ((uint64_t)h3 << 14));
                uint32_t w3 = static_cast<uint32_t>(((uint64_t)h3 >> 18) | ((uint64_t)h4 << 8));

                uint64_t f;
                f = (uint64_t)w0 + detail::load_le32(key + 16);
                w0 = static_cast<uint32_t>(f);
                f = (uint64_t)w1 + detail::load_le32(key + 20) + (f >> 32);
                w1 = static_cast<uint32_t>(f);
                f = (uint64_t)w2 + detail::load_le32(key + 24) + (f >> 32);
                w2 = static_cast<uint32_t>(f);
                f = (uint64_t)w3 + detail::load_le32(key + 28) + (f >> 32);
                w3 = static_cast<uint32_t>(f);

                detail::store_le32(tag + 0, w0);
                detail::store_le32(tag + 4, w1);
                detail::store_le32(tag + 8, w2);
                detail::store_le32(tag + 12, w3);
            }

            // Scalar absorb of one 16-byte or partial block (RFC 8439 §2.5.1): append
            // the 2^128 bit (or a 0x01 inside the lower limbs for a partial block),
            // add into h, then multiply-reduce by r.
            inline void scalar_absorb_block(uint32_t h[5], const uint32_t r[5], const uint8_t *data, size_t len)
            {
                uint8_t block[17] = {};
                std::memcpy(block, data, len);
                block[len] = 0x01;

                uint32_t b0 = detail::load_le32(block + 0);
                uint32_t b1 = detail::load_le32(block + 4);
                uint32_t b2 = detail::load_le32(block + 8);
                uint32_t b3 = detail::load_le32(block + 12);
                uint32_t b4 = block[16]; // 1 on full blocks; 0 on the final partial block

                uint32_t sum[5];
                sum[0] = h[0] + (b0 & kLimbMask);
                sum[1] = h[1] + (((b0 >> 26) | (b1 << 6)) & kLimbMask);
                sum[2] = h[2] + (((b1 >> 20) | (b2 << 12)) & kLimbMask);
                sum[3] = h[3] + (((b2 >> 14) | (b3 << 18)) & kLimbMask);
                sum[4] = h[4] + ((b3 >> 8) | (b4 << 24));

                mul_reduce(h, sum, r);

                tinychacha_secure_zero(block, sizeof(block));
                tinychacha_secure_zero(sum, sizeof(sum));
            }

        } // anonymous namespace

        void poly1305_avx2(const uint8_t key[32], const uint8_t *message, size_t message_len, uint8_t tag[16])
        {
            // Clamp + split r.
            uint32_t r[5];
            clamp_and_split(key, r);

            // Precompute r, r^2, r^3, r^4. powers[k] = r^(k+1). In the Horner form
            // h_new = (h+m0)*r^4 + m1*r^3 + m2*r^2 + m3*r the lane processing block k
            // uses r^(4-k), so lane 0 holds r^4, lane 1 holds r^3, lane 2 holds r^2,
            // lane 3 holds r. _mm256_set_epi64x takes (lane3, lane2, lane1, lane0)
            // order, so the argument order below reads powers[0..3] top-to-bottom.
            uint32_t powers[4][5];
            std::memcpy(powers[0], r, sizeof(r));
            mul_reduce(powers[1], powers[0], r);
            mul_reduce(powers[2], powers[1], r);
            mul_reduce(powers[3], powers[2], r);

            __m256i v_pow[5];
            __m256i v_pow_x5[5];
            for (int i = 0; i < 5; ++i)
            {
                v_pow[i] = _mm256_set_epi64x(
                    static_cast<int64_t>(powers[0][i]),
                    static_cast<int64_t>(powers[1][i]),
                    static_cast<int64_t>(powers[2][i]),
                    static_cast<int64_t>(powers[3][i]));
                v_pow_x5[i] = _mm256_set_epi64x(
                    static_cast<int64_t>(powers[0][i] * 5u),
                    static_cast<int64_t>(powers[1][i] * 5u),
                    static_cast<int64_t>(powers[2][i] * 5u),
                    static_cast<int64_t>(powers[3][i] * 5u));
            }

            uint32_t h[5] = {0, 0, 0, 0, 0};

            // Block + spill scratch, declared once so a single end-of-function scrub
            // covers the last iteration's contents. The values here are message ×
            // public powers (in lane 0 also mixed with h), so scrubbing is
            // defense-in-depth rather than strictly necessary for message secrecy.
            uint32_t m[4][5] = {};
            uint32_t m0[5] = {};
            alignas(32) uint64_t spill0[4] = {};
            alignas(32) uint64_t spill1[4] = {};
            alignas(32) uint64_t spill2[4] = {};
            alignas(32) uint64_t spill3[4] = {};
            alignas(32) uint64_t spill4[4] = {};

            // ---- 4-block parallel main loop ----
            while (message_len >= 64)
            {
                // Decompose 4 consecutive 16-byte blocks into 5 radix-2^26 limbs each.
                // Full blocks always set the 2^128 bit (limb4 high bit).
                for (int blk = 0; blk < 4; ++blk)
                {
                    const uint8_t *p = message + 16 * blk;
                    uint32_t b0 = detail::load_le32(p + 0);
                    uint32_t b1 = detail::load_le32(p + 4);
                    uint32_t b2 = detail::load_le32(p + 8);
                    uint32_t b3 = detail::load_le32(p + 12);
                    m[blk][0] = b0 & kLimbMask;
                    m[blk][1] = ((b0 >> 26) | (b1 << 6)) & kLimbMask;
                    m[blk][2] = ((b1 >> 20) | (b2 << 12)) & kLimbMask;
                    m[blk][3] = ((b2 >> 14) | (b3 << 18)) & kLimbMask;
                    m[blk][4] = (b3 >> 8) | (1u << 24);
                }

                // h limbs are at most 2^27, block limbs at most 2^26, so m0[i] < 2^28.
                m0[0] = m[0][0] + h[0];
                m0[1] = m[0][1] + h[1];
                m0[2] = m[0][2] + h[2];
                m0[3] = m[0][3] + h[3];
                m0[4] = m[0][4] + h[4];

                __m256i v_m[5];
                for (int i = 0; i < 5; ++i)
                {
                    v_m[i] = _mm256_set_epi64x(
                        static_cast<int64_t>(m[3][i]),
                        static_cast<int64_t>(m[2][i]),
                        static_cast<int64_t>(m[1][i]),
                        static_cast<int64_t>(m0[i]));
                }

                // Lane-parallel schoolbook 5x5 multiply mod (2^130 - 5).
                // Per-lane limit: a <= 2^28, b <= 2^26, 5*b < 2^29. Max single product
                // a_i * (5*b_j) < 2^28 * 2^29 = 2^57. d_k = sum of 5 such < 5 * 2^57 =
                // ~2^59.3. Per-lane fits in u64. 4-lane horizontal sum < 4 * 2^59.3 =
                // ~2^61.3. Also fits in u64 with headroom.
                __m256i d0 = _mm256_mul_epu32(v_m[0], v_pow[0]);
                d0 = _mm256_add_epi64(d0, _mm256_mul_epu32(v_m[1], v_pow_x5[4]));
                d0 = _mm256_add_epi64(d0, _mm256_mul_epu32(v_m[2], v_pow_x5[3]));
                d0 = _mm256_add_epi64(d0, _mm256_mul_epu32(v_m[3], v_pow_x5[2]));
                d0 = _mm256_add_epi64(d0, _mm256_mul_epu32(v_m[4], v_pow_x5[1]));

                __m256i d1 = _mm256_mul_epu32(v_m[0], v_pow[1]);
                d1 = _mm256_add_epi64(d1, _mm256_mul_epu32(v_m[1], v_pow[0]));
                d1 = _mm256_add_epi64(d1, _mm256_mul_epu32(v_m[2], v_pow_x5[4]));
                d1 = _mm256_add_epi64(d1, _mm256_mul_epu32(v_m[3], v_pow_x5[3]));
                d1 = _mm256_add_epi64(d1, _mm256_mul_epu32(v_m[4], v_pow_x5[2]));

                __m256i d2 = _mm256_mul_epu32(v_m[0], v_pow[2]);
                d2 = _mm256_add_epi64(d2, _mm256_mul_epu32(v_m[1], v_pow[1]));
                d2 = _mm256_add_epi64(d2, _mm256_mul_epu32(v_m[2], v_pow[0]));
                d2 = _mm256_add_epi64(d2, _mm256_mul_epu32(v_m[3], v_pow_x5[4]));
                d2 = _mm256_add_epi64(d2, _mm256_mul_epu32(v_m[4], v_pow_x5[3]));

                __m256i d3 = _mm256_mul_epu32(v_m[0], v_pow[3]);
                d3 = _mm256_add_epi64(d3, _mm256_mul_epu32(v_m[1], v_pow[2]));
                d3 = _mm256_add_epi64(d3, _mm256_mul_epu32(v_m[2], v_pow[1]));
                d3 = _mm256_add_epi64(d3, _mm256_mul_epu32(v_m[3], v_pow[0]));
                d3 = _mm256_add_epi64(d3, _mm256_mul_epu32(v_m[4], v_pow_x5[4]));

                __m256i d4 = _mm256_mul_epu32(v_m[0], v_pow[4]);
                d4 = _mm256_add_epi64(d4, _mm256_mul_epu32(v_m[1], v_pow[3]));
                d4 = _mm256_add_epi64(d4, _mm256_mul_epu32(v_m[2], v_pow[2]));
                d4 = _mm256_add_epi64(d4, _mm256_mul_epu32(v_m[3], v_pow[1]));
                d4 = _mm256_add_epi64(d4, _mm256_mul_epu32(v_m[4], v_pow[0]));

                // Horizontal sum each d_k across 4 lanes into a scalar u64. Today this
                // spills through memory; a future perf pass could replace this with an
                // in-register extracti128 + add_epi64 + shuffle chain.
                // TODO(perf): keep the horizontal reduction in registers.
                _mm256_store_si256(reinterpret_cast<__m256i *>(spill0), d0);
                _mm256_store_si256(reinterpret_cast<__m256i *>(spill1), d1);
                _mm256_store_si256(reinterpret_cast<__m256i *>(spill2), d2);
                _mm256_store_si256(reinterpret_cast<__m256i *>(spill3), d3);
                _mm256_store_si256(reinterpret_cast<__m256i *>(spill4), d4);

                uint64_t e0 = spill0[0] + spill0[1] + spill0[2] + spill0[3];
                uint64_t e1 = spill1[0] + spill1[1] + spill1[2] + spill1[3];
                uint64_t e2 = spill2[0] + spill2[1] + spill2[2] + spill2[3];
                uint64_t e3 = spill3[0] + spill3[1] + spill3[2] + spill3[3];
                uint64_t e4 = spill4[0] + spill4[1] + spill4[2] + spill4[3];

                // Carry-propagate through limbs then fold via the c * 5 trick. All carry
                // arithmetic must be u64 because e4 can exceed 2^58 so e4 >> 26 can
                // exceed 2^32 and overflow a uint32_t.
                uint64_t c;
                c = e0 >> 26;
                e0 &= kLimbMask;
                e1 += c;
                c = e1 >> 26;
                e1 &= kLimbMask;
                e2 += c;
                c = e2 >> 26;
                e2 &= kLimbMask;
                e3 += c;
                c = e3 >> 26;
                e3 &= kLimbMask;
                e4 += c;
                c = e4 >> 26;
                e4 &= kLimbMask;
                e0 += c * 5u;
                c = e0 >> 26;
                e0 &= kLimbMask;
                e1 += c;

                h[0] = static_cast<uint32_t>(e0);
                h[1] = static_cast<uint32_t>(e1);
                h[2] = static_cast<uint32_t>(e2);
                h[3] = static_cast<uint32_t>(e3);
                h[4] = static_cast<uint32_t>(e4);

                message += 64;
                message_len -= 64;
            }

            // ---- Scalar tail loop: 0..3 full 16-byte blocks plus an optional final
            // partial block — mirrors the portable scalar inner loop exactly. ----
            while (message_len > 0)
            {
                size_t blen = (message_len >= 16) ? 16 : message_len;
                scalar_absorb_block(h, r, message, blen);
                message += blen;
                message_len -= blen;
            }

            // Finalize into the 16-byte tag.
            finalize_tag(h, key, tag);

            // Zero all key-derived and block-derived stack scratch. The __m256i power
            // registers (v_pow / v_pow_x5) are compiler-managed locals with no stable
            // backing memory to wipe, so we rely on _mm256_zeroupper() to clear the
            // upper halves of the YMM registers on exit.
            tinychacha_secure_zero(r, sizeof(r));
            tinychacha_secure_zero(powers, sizeof(powers));
            tinychacha_secure_zero(h, sizeof(h));
            tinychacha_secure_zero(m, sizeof(m));
            tinychacha_secure_zero(m0, sizeof(m0));
            tinychacha_secure_zero(spill0, sizeof(spill0));
            tinychacha_secure_zero(spill1, sizeof(spill1));
            tinychacha_secure_zero(spill2, sizeof(spill2));
            tinychacha_secure_zero(spill3, sizeof(spill3));
            tinychacha_secure_zero(spill4, sizeof(spill4));
            _mm256_zeroupper();
        }

    } // namespace internal
} // namespace tinychacha

#else

namespace tinychacha
{
    namespace internal
    {

        // Non-AVX2 build: pass through to portable. This preserves the dispatch
        // contract on targets (or configurations) where __AVX2__ is not defined.
        void poly1305_avx2(const uint8_t key[32], const uint8_t *message, size_t message_len, uint8_t tag[16])
        {
            poly1305_portable(key, message, message_len, tag);
        }

    } // namespace internal
} // namespace tinychacha

#endif
