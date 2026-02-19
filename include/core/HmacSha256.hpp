#ifndef FASTSHIELD_HMAC_SHA256_HPP
#define FASTSHIELD_HMAC_SHA256_HPP

#include "core/Sha256.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace fastshield {

class HmacSha256 {
public:
    HmacSha256(const uint8_t* key, size_t keyLen);

    void update(const uint8_t* data, size_t len);
    std::array<uint8_t, 32> final();

private:
    Sha256 m_inner;
    Sha256 m_outer;
    bool m_finalized;
};

} // namespace fastshield

#endif // FASTSHIELD_HMAC_SHA256_HPP
