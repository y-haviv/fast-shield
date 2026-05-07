#include "core/CryptoEngine.hpp"
#include "utils/SecureZero.hpp"

#include <algorithm>
#include <array>

namespace fastshield {

KeyMaterial CryptoEngine::deriveKey(
    const std::string& password,
    const uint8_t* salt,
    size_t saltLen,
    uint32_t iterations) {
    KeyMaterial keys;
    std::array<uint8_t, 32> out{};
    pbkdf2HmacSha256(
        reinterpret_cast<const uint8_t*>(password.data()),
        password.size(),
        salt,
        saltLen,
        iterations,
        out.data(),
        out.size());

    std::copy(out.begin(), out.end(), keys.aeadKey.begin());
    secureZero(out.data(), out.size());
    return keys;
}

std::array<uint8_t, CryptoEngine::kNonceSize> CryptoEngine::nonceForChunk(
    const std::array<uint8_t, kNonceSize>& baseNonce,
    uint64_t chunkIndex) {
    std::array<uint8_t, kNonceSize> nonce = baseNonce;
    for (size_t i = 0; i < 8; ++i) {
        nonce[4 + i] ^= static_cast<uint8_t>((chunkIndex >> (i * 8)) & 0xffu);
    }
    return nonce;
}

} // namespace fastshield
