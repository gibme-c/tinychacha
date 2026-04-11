# TinyChacha

[![CI Build Tests](https://github.com/gibme-c/tinychacha/actions/workflows/ci.yml/badge.svg)](https://github.com/gibme-c/tinychacha/actions/workflows/ci.yml)

A zero-dependency C++17 library for ChaCha20-Poly1305 authenticated encryption, with SIMD-accelerated backends and runtime CPU dispatch.

TinyChacha implements ChaCha20 stream cipher, Poly1305 one-time authenticator, and ChaCha20-Poly1305 AEAD (RFC 8439). Each algorithm has a portable backend that compiles everywhere plus platform-specific backends (AVX2, AVX-512, ARM NEON) that are selected automatically at runtime based on detected CPU features. All intermediate key material is securely zeroed using platform-specific mechanisms the compiler can't optimize away.

Both a C++ API and a plain C API (`extern "C"`) are provided. The C++ API uses `std::vector<uint8_t>` and returns a `Result` enum. The C API uses caller-provided buffers and returns `int` error codes with full input validation.

## Features

### Algorithms

| Algorithm | Key Size | Nonce Size | Tag Size | Standard |
|-----------|----------|------------|----------|----------|
| ChaCha20 | 32 bytes | 12 bytes | — | RFC 8439 |
| Poly1305 | 32 bytes | — | 16 bytes | RFC 8439 |
| ChaCha20-Poly1305 AEAD | 32 bytes | 12 bytes | 16 bytes | RFC 8439 |

### SIMD Backends

Backend availability by platform:

| Algorithm | Portable | AVX2 | AVX-512 | ARM NEON |
|-----------|----------|------|---------|----------|
| ChaCha20 | yes | yes | yes | yes |
| Poly1305 | yes | yes | — | stub (portable fallthrough) |

### AEAD Convenience Overloads

The C++ AEAD API provides three levels of abstraction:

- **Separate outputs** — caller provides key, nonce, AAD, plaintext; receives ciphertext and tag separately
- **Combined ciphertext||tag** — caller provides nonce; output is ciphertext with tag appended
- **Automatic nonce** — library generates a random nonce; output is nonce||ciphertext||tag

All three decrypt overloads mirror the encrypt variants.

### Security

- **Secure memory erasure** — all intermediate state is zeroed via `secure_zero()`, which uses `SecureZeroMemory` (Windows), `memset_s` (C11), or a volatile function pointer to prevent dead-store elimination
- **Constant-time comparison** — `constant_time_eq()` for tag verification, with volatile accumulator to prevent short-circuit optimization
- **Input validation** — all C API functions validate pointers, lengths, and bounds before any computation; invalid inputs return typed error codes
- **Nonce generation** — cryptographically random nonces via `BCryptGenRandom` (Windows), `getrandom` (Linux), or `/dev/urandom` fallback
- **Build hardening** — stack protectors, control flow integrity, ASLR, DEP, RELRO, and symbol visibility hiding across GCC, Clang, MSVC, and MinGW

### Nonce usage

RFC 8439 §4 requires: **"A nonce MUST never be used twice with the same key, nor MUST it be guessable."** Reusing a (key, nonce) pair destroys confidentiality — the XOR of the two plaintexts leaks — and allows trivial tag forgery. This is the single most important operational rule when using ChaCha20-Poly1305.

Two safe patterns:

- **Counter-based nonces** — treat the 96-bit nonce as a monotonic counter that persists across process restarts. Simplest for message-oriented protocols where each message is numbered. No collision risk as long as the counter never goes backwards and the same counter value is never used twice under the same key.
- **Random nonces via `generate_nonce()`** — the library generates 96-bit CSPRNG nonces. Because the nonce is only 96 bits wide, the birthday bound imposes a ~50% collision probability after about 2<sup>48</sup> encryptions **under the same key**. For high-message-count workloads under a long-lived key, either rotate keys (conservative: every ~2<sup>40</sup> messages) or switch to counter-based nonces. If you need to encrypt very large numbers of messages under a single key, an XChaCha20-based construction (192-bit extended nonce) is a better fit — this library does not currently provide one.

## Building

Requires CMake 3.10+ and a C++17 compiler.

```bash
# Configure and build
cmake -S . -B build -DBUILD_TESTS=ON
cmake --build build --config Release -j

# Run tests
./build/tinychacha_tests          # Linux / macOS / MinGW
./build/Release/tinychacha_tests  # Windows (MSVC)
```

### CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_TESTS` | `OFF` | Build the unit test executable (`tinychacha_tests`) |
| `BUILD_BENCH` | `OFF` | Build the benchmark tool (`tinychacha_bench`) |
| `BUILD_FUZZ` | `OFF` | Build fuzz targets (Clang + Linux only) |
| `BUILD_SHARED_LIBS` | `OFF` | Build as a shared library (`.so`/`.dll`/`.dylib`) |
| `FORCE_PORTABLE` | `OFF` | Disable all SIMD backends; use only portable C++ code |
| `CMAKE_BUILD_TYPE` | `Release` | `Debug`, `Release`, or `RelWithDebInfo` |

## Usage

Include the umbrella header for everything:

```cpp
#include <tinychacha.h>
```

Or include individual headers:

```cpp
#include <tinychacha/chacha20.h>
#include <tinychacha/poly1305.h>
#include <tinychacha/aead.h>
```

Link against the `tinychacha` library target in your CMake project:

```cmake
add_subdirectory(tinychacha)
target_link_libraries(your_target tinychacha)
```

### C++ API

```cpp
#include <tinychacha.h>

// AEAD encrypt (automatic nonce)
std::vector<uint8_t> key(32), plaintext, aad;
std::vector<uint8_t> nonce_ciphertext_tag;
auto result = tinychacha::aead_encrypt(key, plaintext, aad, nonce_ciphertext_tag);

// AEAD decrypt (automatic nonce)
std::vector<uint8_t> decrypted;
result = tinychacha::aead_decrypt(key, nonce_ciphertext_tag, aad, decrypted);

// AEAD encrypt (caller provides nonce, separate tag)
std::vector<uint8_t> nonce(12), ciphertext, tag;
result = tinychacha::aead_encrypt(key, nonce, aad, plaintext, ciphertext, tag);

// AEAD decrypt (separate tag)
result = tinychacha::aead_decrypt(key, nonce, aad, ciphertext, tag, decrypted);

// Raw ChaCha20
std::vector<uint8_t> output;
result = tinychacha::chacha20(key, nonce, 0, plaintext, output);

// Poly1305 MAC
std::vector<uint8_t> mac_tag;
result = tinychacha::poly1305_mac(key, plaintext, mac_tag);
result = tinychacha::poly1305_verify(key, plaintext, mac_tag);

// Utilities
auto random_nonce = tinychacha::generate_nonce();
bool equal = tinychacha::constant_time_eq(a, b);
```

### C API

All C functions return 0 on success, negative error codes on failure.

```c
#include <tinychacha/aead.h>
#include <tinychacha/chacha20.h>
#include <tinychacha/poly1305.h>

uint8_t key[32], nonce[12], tag[16];
uint8_t plaintext[128], ciphertext[128];

/* AEAD encrypt */
tinychacha_aead_encrypt(key, nonce, aad, aad_len,
                        plaintext, sizeof(plaintext),
                        ciphertext, sizeof(ciphertext), tag);

/* AEAD decrypt */
tinychacha_aead_decrypt(key, nonce, aad, aad_len,
                        ciphertext, sizeof(ciphertext),
                        plaintext, sizeof(plaintext), tag);

/* Raw ChaCha20 */
tinychacha_chacha20(key, nonce, 0, plaintext, sizeof(plaintext), ciphertext);

/* Poly1305 MAC */
tinychacha_poly1305_mac(key, plaintext, sizeof(plaintext), tag);
tinychacha_poly1305_verify(key, plaintext, sizeof(plaintext), tag);

/* Nonce generation */
tinychacha_generate_nonce(nonce);

/* Constant-time comparison */
int eq = tinychacha_constant_time_eq(tag_a, tag_b, 16);
```

## Architecture

### Dispatch

Each primitive uses runtime dispatch to select the best available backend. On the first call, CPUID (x86) or feature detection (ARM) selects the optimal implementation. No mutexes or `std::call_once` — redundant resolution under contention is harmless by design.

Dispatch priority on x86_64:

- **ChaCha20**: AVX-512F > AVX2 > portable
- **Poly1305**: AVX2 > portable

Dispatch priority on ARM64:

- **ChaCha20**: NEON > portable
- **Poly1305**: NEON > portable

All other platforms use the portable backend unconditionally.

### ChaCha20 Internals

ChaCha20 operates on a 4x4 matrix of 32-bit words initialized from a 256-bit key, a 96-bit nonce, and a 32-bit block counter. Each block performs 20 rounds (10 column rounds + 10 diagonal rounds) of quarter-round operations, then adds the original state and XORs with plaintext to produce 64 bytes of output.

Little-endian byte order throughout: key and nonce words loaded little-endian per RFC 8439.

### Poly1305 Internals

Poly1305 computes a one-time MAC over a message using a 256-bit key split into a 128-bit `r` (clamped) and a 128-bit `s`. The message is processed in 16-byte blocks as coefficients of a polynomial evaluated modulo 2^130 - 5, with `s` added to the final result.

### AEAD Construction

ChaCha20-Poly1305 AEAD follows RFC 8439 Section 2.8:

1. Generate a one-time Poly1305 key by encrypting 64 zero bytes with ChaCha20 (counter=0) and taking the first 32 bytes
2. Encrypt plaintext with ChaCha20 starting at counter=1
3. Construct the Poly1305 input: AAD || pad || ciphertext || pad || AAD length (8 bytes LE) || ciphertext length (8 bytes LE)
4. Compute the 16-byte authentication tag with Poly1305

## Testing

Build with `-DBUILD_TESTS=ON` to get the `tinychacha_tests` executable. The test suite covers:

- **ChaCha20 known-answer tests** — RFC 8439 test vectors
- **Poly1305 known-answer tests** — RFC 8439 test vectors
- **AEAD known-answer tests** — RFC 8439 test vectors for authenticated encryption/decryption
- **Authentication failure tests** — verify that tampered ciphertext, AAD, nonce, and tags are rejected
- **Nonce generation tests** — verify cryptographic random nonce generation
- **CPUID tests** — verify CPU feature detection runs without crashing
- **Fuzz-style tests** — round-trip encrypt/decrypt with random inputs
- **Security tests** — constant-time comparison, secure zeroing, input validation

The test harness is a custom header-only framework (`test_harness.h`) with `TEST`/`ASSERT_EQ` macros — no external test dependencies.

## Benchmarking

Build with `-DBUILD_BENCH=ON` to get the `tinychacha_bench` executable. This benchmarks ChaCha20, Poly1305, and AEAD operations across various message sizes.

## Fuzzing

Fuzz targets are built automatically when using Clang on Linux:

```bash
cmake -S . -B build-fuzz -DCMAKE_CXX_COMPILER=clang++ -DBUILD_FUZZ=ON
cmake --build build-fuzz
./build-fuzz/fuzz_chacha20 corpus/chacha20/
```

Three fuzz targets cover ChaCha20, Poly1305, and AEAD. Each links with `-fsanitize=fuzzer,address`.

## CI

GitHub Actions runs on every push, pull request, weekly schedule, and release. Every compiler is tested in both portable and native/SIMD configurations:

| Platform | Compilers | Configs |
|----------|-----------|---------|
| Linux x86_64 | GCC 11, GCC 12, Clang 14, Clang 15 | portable, native |
| Linux ARM64 | GCC, Clang | portable, arm64 |
| macOS ARM64 | AppleClang, Homebrew Clang | portable, arm64 |
| Windows x86_64 | MSVC, MinGW GCC | portable, native |

Unit tests and benchmarks run for every combination.

## License

BSD-3-Clause. See [LICENSE](LICENSE) for the full text.
