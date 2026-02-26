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

#include <tinychacha.h>

#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <vector>

static double measure_throughput(const char *label,
                                 void (*fn)(const uint8_t *, size_t, size_t),
                                 size_t block_size, size_t iterations) {
  std::vector<uint8_t> data(block_size, 0xAB);

  auto start = std::chrono::high_resolution_clock::now();
  fn(data.data(), data.size(), iterations);
  auto end = std::chrono::high_resolution_clock::now();

  double secs = std::chrono::duration<double>(end - start).count();
  double total_bytes = static_cast<double>(block_size) * iterations;
  double mib_per_sec = (total_bytes / (1024.0 * 1024.0)) / secs;

  std::printf("%-30s %8zu bytes x %6zu iters = %8.2f MiB/s  (%.4f s)\n", label,
              block_size, iterations, mib_per_sec, secs);
  return mib_per_sec;
}

// --- ChaCha20 benchmarks ---

static const uint8_t bench_key[32] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a,
    0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
    0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f};
static const uint8_t bench_nonce[12] = {0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                                        0x42, 0x43, 0x44, 0x45, 0x46, 0x47};

static void bench_chacha20(const uint8_t *data, size_t len, size_t iters) {
  std::vector<uint8_t> out(len);
  for (size_t i = 0; i < iters; ++i) {
    int rc = tinychacha_chacha20(bench_key, bench_nonce, 0, data, len, out.data());
    if (rc != TINYCHACHA_OK) {
      std::fprintf(stderr, "bench_chacha20 failed: %d\n", rc);
      std::abort();
    }
  }
}

// --- Poly1305 benchmarks ---

static void bench_poly1305(const uint8_t *data, size_t len, size_t iters) {
  uint8_t tag[16];
  for (size_t i = 0; i < iters; ++i) {
    int rc = tinychacha_poly1305_mac(bench_key, data, len, tag);
    if (rc != TINYCHACHA_OK) {
      std::fprintf(stderr, "bench_poly1305 failed: %d\n", rc);
      std::abort();
    }
  }
}

// --- AEAD benchmarks ---

static void bench_aead_encrypt(const uint8_t *data, size_t len, size_t iters) {
  std::vector<uint8_t> ct(len);
  uint8_t tag[16];
  const uint8_t aad[] = {0x50, 0x51, 0x52, 0x53};
  for (size_t i = 0; i < iters; ++i) {
    int rc = tinychacha_aead_encrypt(bench_key, bench_nonce, aad, 4, data, len,
                                     ct.data(), len, tag);
    if (rc != TINYCHACHA_OK) {
      std::fprintf(stderr, "bench_aead_encrypt failed: %d\n", rc);
      std::abort();
    }
  }
}

static void bench_aead_decrypt(const uint8_t *data, size_t len, size_t iters) {
  // First encrypt to get valid ciphertext + tag
  std::vector<uint8_t> ct(len);
  uint8_t tag[16];
  const uint8_t aad[] = {0x50, 0x51, 0x52, 0x53};
  int rc = tinychacha_aead_encrypt(bench_key, bench_nonce, aad, 4, data, len,
                                   ct.data(), len, tag);
  if (rc != TINYCHACHA_OK) {
    std::fprintf(stderr, "bench_aead_decrypt setup failed: %d\n", rc);
    std::abort();
  }

  std::vector<uint8_t> pt(len);
  for (size_t i = 0; i < iters; ++i) {
    rc = tinychacha_aead_decrypt(bench_key, bench_nonce, aad, 4, ct.data(), len,
                                 pt.data(), len, tag);
    if (rc != TINYCHACHA_OK) {
      std::fprintf(stderr, "bench_aead_decrypt failed: %d\n", rc);
      std::abort();
    }
  }
}

int main() {
  std::printf("=== TinyChaCha Benchmarks ===\n\n");

  std::printf("--- ChaCha20 ---\n");
  measure_throughput("ChaCha20  64B", bench_chacha20, 64, 100000);
  measure_throughput("ChaCha20  256B", bench_chacha20, 256, 100000);
  measure_throughput("ChaCha20  1KiB", bench_chacha20, 1024, 50000);
  measure_throughput("ChaCha20  4KiB", bench_chacha20, 4096, 20000);
  measure_throughput("ChaCha20  64KiB", bench_chacha20, 65536, 2000);
  measure_throughput("ChaCha20  1MiB", bench_chacha20, 1048576, 100);

  std::printf("\n--- Poly1305 ---\n");
  measure_throughput("Poly1305  64B", bench_poly1305, 64, 100000);
  measure_throughput("Poly1305  256B", bench_poly1305, 256, 100000);
  measure_throughput("Poly1305  1KiB", bench_poly1305, 1024, 50000);
  measure_throughput("Poly1305  4KiB", bench_poly1305, 4096, 20000);
  measure_throughput("Poly1305  64KiB", bench_poly1305, 65536, 2000);
  measure_throughput("Poly1305  1MiB", bench_poly1305, 1048576, 100);

  std::printf("\n--- AEAD Encrypt ---\n");
  measure_throughput("AEAD-Enc  64B", bench_aead_encrypt, 64, 100000);
  measure_throughput("AEAD-Enc  256B", bench_aead_encrypt, 256, 100000);
  measure_throughput("AEAD-Enc  1KiB", bench_aead_encrypt, 1024, 50000);
  measure_throughput("AEAD-Enc  4KiB", bench_aead_encrypt, 4096, 20000);
  measure_throughput("AEAD-Enc  64KiB", bench_aead_encrypt, 65536, 2000);
  measure_throughput("AEAD-Enc  1MiB", bench_aead_encrypt, 1048576, 100);

  std::printf("\n--- AEAD Decrypt ---\n");
  measure_throughput("AEAD-Dec  64B", bench_aead_decrypt, 64, 100000);
  measure_throughput("AEAD-Dec  256B", bench_aead_decrypt, 256, 100000);
  measure_throughput("AEAD-Dec  1KiB", bench_aead_decrypt, 1024, 50000);
  measure_throughput("AEAD-Dec  4KiB", bench_aead_decrypt, 4096, 20000);
  measure_throughput("AEAD-Dec  64KiB", bench_aead_decrypt, 65536, 2000);
  measure_throughput("AEAD-Dec  1MiB", bench_aead_decrypt, 1048576, 100);

  std::printf("\nDone.\n");
  return 0;
}
