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

#include "cpu_features.h"

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#define TINYCHACHA_X86 1
#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#endif
#endif

namespace tinychacha
{
    namespace cpu
    {

        static Features query_features()
        {
            Features f;

#if defined(TINYCHACHA_X86)
#if defined(_MSC_VER)
            int regs[4] = {0, 0, 0, 0};

            __cpuid(regs, 0);
            int max_leaf = regs[0];
            if (max_leaf >= 7)
            {
                __cpuidex(regs, 7, 0);
                f.avx2 = (regs[1] & (1 << 5)) != 0;
                f.avx512f = (regs[1] & (1 << 16)) != 0;
            }
#else
            unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;

            __get_cpuid(0, &eax, &ebx, &ecx, &edx);
            if (eax >= 7)
            {
                __get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);
                f.avx2 = (ebx & (1u << 5)) != 0;
                f.avx512f = (ebx & (1u << 16)) != 0;
            }
#endif

            // Check OSXSAVE (CPUID.1:ECX bit 27) before using XGETBV
            bool osxsave = false;
#if defined(_MSC_VER)
            __cpuid(regs, 1);
            osxsave = (regs[2] & (1 << 27)) != 0;
#else
            __get_cpuid(1, &eax, &ebx, &ecx, &edx);
            osxsave = (ecx & (1u << 27)) != 0;
#endif

            if ((f.avx2 || f.avx512f) && osxsave)
            {
#if defined(_MSC_VER)
                unsigned long long xcr0 = _xgetbv(0);
#else
                unsigned int lo, hi;
                __asm__ __volatile__("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
                unsigned long long xcr0 = ((unsigned long long)hi << 32) | lo;
#endif

                bool os_avx = (xcr0 & 0x06) == 0x06;
                bool os_avx512 = (xcr0 & 0xE6) == 0xE6;

                if (!os_avx)
                {
                    f.avx2 = false;
                    f.avx512f = false;
                }
                if (!os_avx512)
                {
                    f.avx512f = false;
                }
            }
            else if (f.avx2 || f.avx512f)
            {
                // OSXSAVE not set — OS doesn't support XSAVE, disable AVX
                f.avx2 = false;
                f.avx512f = false;
            }
#endif /* TINYCHACHA_X86 */

#if defined(__aarch64__) || defined(_M_ARM64)
            f.neon = true;
#elif defined(__ARM_NEON)
            f.neon = true;
#endif

            return f;
        }

        const Features &detect()
        {
            static const Features cached = query_features();
            return cached;
        }

    } /* namespace cpu */
} /* namespace tinychacha */
