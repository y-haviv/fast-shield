#include "core/ChaCha20Poly1305.hpp"

#include "core/ChaCha20.hpp"
#include "core/Poly1305.hpp"

namespace fastshield {

namespace {

inline void writeLE64(uint8_t* out, uint64_t value) {
    out[0] = static_cast<uint8_t>(value & 0xffu);
    out[1] = static_cast<uint8_t>((value >> 8) & 0xffu);
    out[2] = static_cast<uint8_t>((value >> 16) & 0xffu);
    out[3] = static_cast<uint8_t>((value >> 24) & 0xffu);
    out[4] = static_cast<uint8_t>((value >> 32) & 0xffu);
    out[5] = static_cast<uint8_t>((value >> 40) & 0xffu);
    out[6] = static_cast<uint8_t>((value >> 48) & 0xffu);
    out[7] = static_cast<uint8_t>((value >> 56) & 0xffu);
}

void pad16(Poly1305& poly, size_t len) {
    size_t rem = len % 16;
    if (rem == 0) {
        return;
    }
    static const uint8_t zeros[16] = {0};
    poly.update(zeros, 16 - rem);
}

bool constantTimeEqual(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

std::array<uint8_t, 32> polyKeyFromNonce(
    const std::array<uint8_t, 32>& key,
    const std::array<uint8_t, ChaCha20Poly1305::kNonceSize>& nonce) {
    std::array<uint8_t, 32> polyKey{};
    uint8_t block[64]{};
    chacha20Block(key, nonce, 0u, block);
    for (size_t i = 0; i < polyKey.size(); ++i) {
        polyKey[i] = block[i];
    }
    return polyKey;
}

std::array<uint8_t, ChaCha20Poly1305::kTagSize> computeTag(
    const uint8_t* cipher,
    size_t cipherLen,
    const std::array<uint8_t, 32>& polyKey,
    const uint8_t* aad,
    size_t aadLen) {
    Poly1305 poly(polyKey.data());
    if (aad && aadLen > 0) {
        poly.update(aad, aadLen);
        pad16(poly, aadLen);
    }

    if (cipherLen > 0) {
        poly.update(cipher, cipherLen);
        pad16(poly, cipherLen);
    }

    uint8_t lens[16]{};
    writeLE64(lens + 0, static_cast<uint64_t>(aadLen));
    writeLE64(lens + 8, static_cast<uint64_t>(cipherLen));
    poly.update(lens, sizeof(lens));

    return poly.final();
}

} // namespace

std::array<uint8_t, ChaCha20Poly1305::kTagSize> ChaCha20Poly1305::encrypt(
    uint8_t* data,
    size_t len,
    const std::array<uint8_t, 32>& key,
    const std::array<uint8_t, kNonceSize>& nonce,
    const uint8_t* aad,
    size_t aadLen) {
    auto polyKey = polyKeyFromNonce(key, nonce);

    // RFC 8439: payload encryption starts at block counter 1.
    chacha20XorWithCounter(data, len, key, nonce, 1u, 0u);

    return computeTag(data, len, polyKey, aad, aadLen);
}

bool ChaCha20Poly1305::decryptAndVerify(
    uint8_t* data,
    size_t len,
    const std::array<uint8_t, 32>& key,
    const std::array<uint8_t, kNonceSize>& nonce,
    const uint8_t* aad,
    size_t aadLen,
    const std::array<uint8_t, kTagSize>& tag) {
    auto polyKey = polyKeyFromNonce(key, nonce);
    auto actual = computeTag(data, len, polyKey, aad, aadLen);
    if (!constantTimeEqual(actual.data(), tag.data(), tag.size())) {
        return false;
    }

    chacha20XorWithCounter(data, len, key, nonce, 1u, 0u);
    return true;
}

} // namespace fastshield
