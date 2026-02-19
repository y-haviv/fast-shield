#include "core/HmacSha256.hpp"

#include <cstring>

namespace fastshield {

namespace {

constexpr size_t kBlockSize = 64;

} // namespace

HmacSha256::HmacSha256(const uint8_t* key, size_t keyLen)
    : m_finalized(false) {
    uint8_t keyBlock[kBlockSize];
    std::memset(keyBlock, 0, sizeof(keyBlock));

    if (keyLen > kBlockSize) {
        auto hashed = Sha256::digest(key, keyLen);
        std::memcpy(keyBlock, hashed.data(), hashed.size());
    } else if (keyLen > 0) {
        std::memcpy(keyBlock, key, keyLen);
    }

    uint8_t innerPad[kBlockSize];
    uint8_t outerPad[kBlockSize];
    for (size_t i = 0; i < kBlockSize; ++i) {
        innerPad[i] = static_cast<uint8_t>(keyBlock[i] ^ 0x36);
        outerPad[i] = static_cast<uint8_t>(keyBlock[i] ^ 0x5c);
    }

    m_inner.reset();
    m_inner.update(innerPad, sizeof(innerPad));
    m_outer.reset();
    m_outer.update(outerPad, sizeof(outerPad));
}

void HmacSha256::update(const uint8_t* data, size_t len) {
    if (m_finalized) {
        return;
    }
    m_inner.update(data, len);
}

std::array<uint8_t, 32> HmacSha256::final() {
    if (m_finalized) {
        return std::array<uint8_t, 32>{};
    }
    auto innerHash = m_inner.final();
    m_outer.update(innerHash.data(), innerHash.size());
    m_finalized = true;
    return m_outer.final();
}

} // namespace fastshield
