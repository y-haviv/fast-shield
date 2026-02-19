#ifndef FASTSHIELD_SHA256_HPP
#define FASTSHIELD_SHA256_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace fastshield {

class Sha256 {
public:
    /// Construct a new SHA-256 context.
    Sha256();

    /// Reset internal state to initial IVs.
    void reset();
    /// Add data to the hash state.
    void update(const uint8_t* data, size_t len);
    /// Finalize and return the digest.
    std::array<uint8_t, 32> final();

    /// Convenience one-shot hashing function.
    static std::array<uint8_t, 32> digest(const uint8_t* data, size_t len);

private:
    /// Process a 512-bit block.
    void transform(const uint8_t* chunk);

    uint32_t m_state[8];
    uint64_t m_bitlen;
    uint8_t m_buffer[64];
    size_t m_bufferLen;
};

} // namespace fastshield

#endif // FASTSHIELD_SHA256_HPP
