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

#include "tinychacha/common.h"

#include <cstdint>
#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#endif

extern "C" void tinychacha_secure_zero(void *ptr, size_t len)
{
    if (!ptr || len == 0)
        return;

#if defined(_WIN32)
    SecureZeroMemory(ptr, len);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(ptr, len, 0, len);
#elif defined(__GLIBC__) || defined(__FreeBSD__)
    explicit_bzero(ptr, len);
#else
    volatile unsigned char *p = static_cast<volatile unsigned char *>(ptr);
    while (len--)
    {
        *p++ = 0;
    }
#endif
}

extern "C" int tinychacha_constant_time_eq(const void *a, const void *b, size_t len)
{
    const volatile uint8_t *pa = static_cast<const volatile uint8_t *>(a);
    const volatile uint8_t *pb = static_cast<const volatile uint8_t *>(b);
    volatile uint8_t diff = 0;

    for (size_t i = 0; i < len; ++i)
    {
        diff |= static_cast<uint8_t>(pa[i] ^ pb[i]);
    }

    return static_cast<int>(1 & ((static_cast<uint32_t>(diff) - 1u) >> 8));
}
