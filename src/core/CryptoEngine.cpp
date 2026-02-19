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
    std::array<uint8_t, 64> out{};
    pbkdf2HmacSha256(
        reinterpret_cast<const uint8_t*>(password.data()),
        password.size(),
        salt,
        saltLen,
        iterations,
        out.data(),
        out.size());

    std::copy(out.begin(), out.begin() + 32, keys.encKey.begin());
    std::copy(out.begin() + 32, out.end(), keys.macKey.begin());
    secureZero(out.data(), out.size());
    return keys;
}

void CryptoEngine::cryptBuffer(
    uint8_t* data,
    size_t len,
    const KeyMaterial& keys,
    const std::array<uint8_t, kNonceSize>& nonce,
    uint64_t streamOffset) {
    chacha20Xor(data, len, keys.encKey, nonce, streamOffset);
}

} // namespace fastshield
