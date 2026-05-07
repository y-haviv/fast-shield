#ifndef FASTSHIELD_CHACHA20_POLY1305_HPP
#define FASTSHIELD_CHACHA20_POLY1305_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace fastshield {

class ChaCha20Poly1305 {
public:
    static constexpr size_t kNonceSize = 12;
    static constexpr size_t kTagSize = 16;

    static std::array<uint8_t, kTagSize> encrypt(
        uint8_t* data,
        size_t len,
        const std::array<uint8_t, 32>& key,
        const std::array<uint8_t, kNonceSize>& nonce,
        const uint8_t* aad,
        size_t aadLen);

    static bool decryptAndVerify(
        uint8_t* data,
        size_t len,
        const std::array<uint8_t, 32>& key,
        const std::array<uint8_t, kNonceSize>& nonce,
        const uint8_t* aad,
        size_t aadLen,
        const std::array<uint8_t, kTagSize>& tag);
};

} // namespace fastshield

#endif // FASTSHIELD_CHACHA20_POLY1305_HPP
