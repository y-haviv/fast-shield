#ifndef FASTSHIELD_CRYPTO_ENGINE_HPP
#define FASTSHIELD_CRYPTO_ENGINE_HPP

#include "core/ChaCha20.hpp"
#include "core/ChaCha20Poly1305.hpp"
#include "core/Pbkdf2.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace fastshield {

struct KeyMaterial {
    /// AEAD key for ChaCha20-Poly1305 (256-bit).
    std::array<uint8_t, 32> aeadKey{};
};

class CryptoEngine {
public:
    /// PBKDF2 iteration count chosen to balance strength and speed.
    static constexpr uint32_t kDefaultIterations = 200000;
    /// Random salt size stored in the file header.
    static constexpr size_t kSaltSize = 16;
    /// 96-bit nonce for ChaCha20 (IETF variant).
    static constexpr size_t kNonceSize = 12;
    /// Authentication tag size for ChaCha20-Poly1305.
    static constexpr size_t kTagSize = ChaCha20Poly1305::kTagSize;

    /// Derive a ChaCha20-Poly1305 key from password and salt.
    static KeyMaterial deriveKey(
        const std::string& password,
        const uint8_t* salt,
        size_t saltLen,
        uint32_t iterations);

    /// Build a unique per-chunk nonce by combining base nonce with chunk index.
    static std::array<uint8_t, kNonceSize> nonceForChunk(
        const std::array<uint8_t, kNonceSize>& baseNonce,
        uint64_t chunkIndex);
};

} // namespace fastshield

#endif // FASTSHIELD_CRYPTO_ENGINE_HPP
