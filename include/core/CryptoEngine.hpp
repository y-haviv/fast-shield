#ifndef FASTSHIELD_CRYPTO_ENGINE_HPP
#define FASTSHIELD_CRYPTO_ENGINE_HPP

#include "core/ChaCha20.hpp"
#include "core/Pbkdf2.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace fastshield {

struct KeyMaterial {
    /// Encryption key for ChaCha20 (256-bit).
    std::array<uint8_t, 32> encKey{};
    /// MAC key for HMAC-SHA256 (256-bit).
    std::array<uint8_t, 32> macKey{};
};

class CryptoEngine {
public:
    /// PBKDF2 iteration count chosen to balance strength and speed.
    static constexpr uint32_t kDefaultIterations = 200000;
    /// Random salt size stored in the file header.
    static constexpr size_t kSaltSize = 16;
    /// 96-bit nonce for ChaCha20 (IETF variant).
    static constexpr size_t kNonceSize = 12;
    /// HMAC-SHA256 output size.
    static constexpr size_t kMacSize = 32;
    /// Maximum bytes that can be processed with a 32-bit ChaCha20 counter.
    static constexpr uint64_t kMaxBytes = 0xFFFFFFFFULL * 64ULL;

    /// Derive encryption and MAC keys from a password and salt.
    static KeyMaterial deriveKey(
        const std::string& password,
        const uint8_t* salt,
        size_t saltLen,
        uint32_t iterations);

    /// XOR the buffer in-place with a ChaCha20 keystream.
    static void cryptBuffer(
        uint8_t* data,
        size_t len,
        const KeyMaterial& keys,
        const std::array<uint8_t, kNonceSize>& nonce,
        uint64_t streamOffset);
};

} // namespace fastshield

#endif // FASTSHIELD_CRYPTO_ENGINE_HPP
