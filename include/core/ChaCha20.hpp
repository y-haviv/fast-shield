#ifndef FASTSHIELD_CHACHA20_HPP
#define FASTSHIELD_CHACHA20_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace fastshield {

void chacha20Xor(
    uint8_t* data,
    size_t len,
    const std::array<uint8_t, 32>& key,
    const std::array<uint8_t, 12>& nonce,
    uint64_t streamOffset);

} // namespace fastshield

#endif // FASTSHIELD_CHACHA20_HPP
