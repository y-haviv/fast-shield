#include "core/Pbkdf2.hpp"
#include "core/HmacSha256.hpp"

#include <array>
#include <cstring>
#include <vector>

namespace fastshield {

void pbkdf2HmacSha256(
    const uint8_t* password,
    size_t passwordLen,
    const uint8_t* salt,
    size_t saltLen,
    uint32_t iterations,
    uint8_t* out,
    size_t outLen) {
    if (!out || outLen == 0) {
        return;
    }
    if (!password) {
        password = reinterpret_cast<const uint8_t*>("");
        passwordLen = 0;
    }

    const size_t hashLen = 32;
    uint32_t blockCount = static_cast<uint32_t>((outLen + hashLen - 1) / hashLen);

    for (uint32_t block = 1; block <= blockCount; ++block) {
        std::vector<uint8_t> saltBlock(saltLen + 4);
        if (saltLen > 0) {
            std::memcpy(saltBlock.data(), salt, saltLen);
        }
        saltBlock[saltLen + 0] = static_cast<uint8_t>((block >> 24) & 0xff);
        saltBlock[saltLen + 1] = static_cast<uint8_t>((block >> 16) & 0xff);
        saltBlock[saltLen + 2] = static_cast<uint8_t>((block >> 8) & 0xff);
        saltBlock[saltLen + 3] = static_cast<uint8_t>(block & 0xff);

        HmacSha256 hmac(password, passwordLen);
        hmac.update(saltBlock.data(), saltBlock.size());
        auto u = hmac.final();

        std::array<uint8_t, 32> t = u;

        for (uint32_t i = 1; i < iterations; ++i) {
            HmacSha256 hmacIter(password, passwordLen);
            hmacIter.update(u.data(), u.size());
            u = hmacIter.final();
            for (size_t j = 0; j < hashLen; ++j) {
                t[j] ^= u[j];
            }
        }

        size_t offset = static_cast<size_t>(block - 1) * hashLen;
        size_t toCopy = (outLen - offset < hashLen) ? (outLen - offset) : hashLen;
        std::memcpy(out + offset, t.data(), toCopy);
    }
}

} // namespace fastshield
