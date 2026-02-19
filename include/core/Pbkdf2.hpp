#ifndef FASTSHIELD_PBKDF2_HPP
#define FASTSHIELD_PBKDF2_HPP

#include <cstddef>
#include <cstdint>

namespace fastshield {

/// PBKDF2-HMAC-SHA256 key derivation function.
/// Writes `outLen` bytes to `out`.
void pbkdf2HmacSha256(
    const uint8_t* password,
    size_t passwordLen,
    const uint8_t* salt,
    size_t saltLen,
    uint32_t iterations,
    uint8_t* out,
    size_t outLen);

} // namespace fastshield

#endif // FASTSHIELD_PBKDF2_HPP
