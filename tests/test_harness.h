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

#ifndef TINYCHACHA_TEST_HARNESS_H
#define TINYCHACHA_TEST_HARNESS_H

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace test
{

    struct TestCase
    {
        const char *name;
        void (*func)();
        TestCase *next;
    };

    inline TestCase *&test_list_head()
    {
        static TestCase *head = nullptr;
        return head;
    }

    inline int &pass_count()
    {
        static int c = 0;
        return c;
    }
    inline int &fail_count()
    {
        static int c = 0;
        return c;
    }

    struct TestRegistrar
    {
        TestRegistrar(const char *name, void (*func)())
        {
            static TestCase storage[1024];
            static int idx = 0;
            if (idx >= 1024)
            {
                std::fprintf(stderr, "FATAL: test registration overflow\n");
                std::abort();
            }
            TestCase &tc = storage[idx++];
            tc.name = name;
            tc.func = func;
            tc.next = test_list_head();
            test_list_head() = &tc;
        }
    };

    inline void assert_fail(const char *expr, const char *file, int line)
    {
        std::fprintf(stderr, "  FAIL: %s (%s:%d)\n", expr, file, line);
        fail_count()++;
    }

    inline void assert_pass()
    {
        pass_count()++;
    }

    /* Compare two byte arrays */
    inline bool bytes_eq(const uint8_t *a, const uint8_t *b, size_t len)
    {
        return std::memcmp(a, b, len) == 0;
    }

    /* Hex string to bytes */
    inline std::vector<uint8_t> hex_to_bytes(const char *hex)
    {
        std::vector<uint8_t> out;
        size_t len = std::strlen(hex);
        for (size_t i = 0; i + 1 < len; i += 2)
        {
            char buf[3] = {hex[i], hex[i + 1], '\0'};
            out.push_back(static_cast<uint8_t>(std::strtoul(buf, nullptr, 16)));
        }
        return out;
    }

    /* Bytes to hex string */
    inline std::string bytes_to_hex(const uint8_t *data, size_t len)
    {
        static const char hx[] = "0123456789abcdef";
        std::string out;
        out.reserve(len * 2);
        for (size_t i = 0; i < len; ++i)
        {
            out.push_back(hx[data[i] >> 4]);
            out.push_back(hx[data[i] & 0x0F]);
        }
        return out;
    }

    inline int run_all()
    {
        int total = 0;
        /* Count tests */
        for (TestCase *tc = test_list_head(); tc; tc = tc->next)
            total++;

        std::printf("Running %d test(s)...\n", total);

        int ran = 0;
        for (TestCase *tc = test_list_head(); tc; tc = tc->next)
        {
            int prev_fail = fail_count();
            std::printf("[%d/%d] %s ... ", ++ran, total, tc->name);
            std::fflush(stdout);
            tc->func();
            if (fail_count() == prev_fail)
            {
                std::printf("OK\n");
            }
            else
            {
                std::printf("FAILED\n");
            }
        }

        std::printf("\nResults: %d passed, %d failed\n", pass_count(), fail_count());
        return fail_count() > 0 ? 1 : 0;
    }

} /* namespace test */

#define TEST(name)                                             \
    static void test_##name();                                 \
    static test::TestRegistrar reg_##name(#name, test_##name); \
    static void test_##name()

#define ASSERT_TRUE(expr)                                 \
    do                                                    \
    {                                                     \
        if (!(expr))                                      \
        {                                                 \
            test::assert_fail(#expr, __FILE__, __LINE__); \
            return;                                       \
        }                                                 \
        else                                              \
        {                                                 \
            test::assert_pass();                          \
        }                                                 \
    } while (0)

#define ASSERT_EQ(a, b)                                          \
    do                                                           \
    {                                                            \
        if ((a) != (b))                                          \
        {                                                        \
            test::assert_fail(#a " == " #b, __FILE__, __LINE__); \
            return;                                              \
        }                                                        \
        else                                                     \
        {                                                        \
            test::assert_pass();                                 \
        }                                                        \
    } while (0)

#define ASSERT_BYTES_EQ(a, b, len)                                                         \
    do                                                                                     \
    {                                                                                      \
        if (!test::bytes_eq((a), (b), (len)))                                              \
        {                                                                                  \
            std::fprintf(stderr, "    got: %s\n", test::bytes_to_hex((a), (len)).c_str()); \
            std::fprintf(stderr, "    exp: %s\n", test::bytes_to_hex((b), (len)).c_str()); \
            test::assert_fail(#a " == " #b, __FILE__, __LINE__);                           \
            return;                                                                        \
        }                                                                                  \
        else                                                                               \
        {                                                                                  \
            test::assert_pass();                                                           \
        }                                                                                  \
    } while (0)

#define TEST_MAIN()             \
    int main()                  \
    {                           \
        return test::run_all(); \
    }

#endif /* TINYCHACHA_TEST_HARNESS_H */
