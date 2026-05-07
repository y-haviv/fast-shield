#ifndef FASTSHIELD_POLY1305_HPP
#define FASTSHIELD_POLY1305_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace fastshield {

class Poly1305 {
public:
    explicit Poly1305(const uint8_t key[32]);

    void update(const uint8_t* data, size_t len);
    std::array<uint8_t, 16> final();

private:
    void processBlock(const uint8_t block[16], bool isFinalPartial);

    uint32_t m_r[5]{};
    uint32_t m_h[5]{};
    uint32_t m_pad[4]{};

    std::array<uint8_t, 16> m_buffer{};
    size_t m_bufferUsed = 0;
    bool m_finished = false;
};

} // namespace fastshield

#endif // FASTSHIELD_POLY1305_HPP
