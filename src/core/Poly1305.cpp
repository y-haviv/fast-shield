#include "core/Poly1305.hpp"

#include <algorithm>
#include <stdexcept>

namespace fastshield {

namespace {

inline uint32_t readLE32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline void writeLE32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

} // namespace

Poly1305::Poly1305(const uint8_t key[32]) {
    uint64_t t0 = readLE32(key + 0);
    uint64_t t1 = readLE32(key + 4);
    uint64_t t2 = readLE32(key + 8);
    uint64_t t3 = readLE32(key + 12);

    m_r[0] = static_cast<uint32_t>(t0) & 0x3ffffffu;
    m_r[1] = static_cast<uint32_t>(((t0 >> 26) | (t1 << 6)) & 0x3ffff03u);
    m_r[2] = static_cast<uint32_t>(((t1 >> 20) | (t2 << 12)) & 0x3ffc0ffu);
    m_r[3] = static_cast<uint32_t>(((t2 >> 14) | (t3 << 18)) & 0x3f03fffu);
    m_r[4] = static_cast<uint32_t>((t3 >> 8) & 0x00fffffu);

    m_pad[0] = readLE32(key + 16);
    m_pad[1] = readLE32(key + 20);
    m_pad[2] = readLE32(key + 24);
    m_pad[3] = readLE32(key + 28);
}

void Poly1305::processBlock(const uint8_t block[16], bool isFinalPartial) {
    uint32_t hibit = isFinalPartial ? 0u : (1u << 24);

    uint64_t t0 = readLE32(block + 0);
    uint64_t t1 = readLE32(block + 4);
    uint64_t t2 = readLE32(block + 8);
    uint64_t t3 = readLE32(block + 12);

    m_h[0] += static_cast<uint32_t>(t0) & 0x3ffffffu;
    m_h[1] += static_cast<uint32_t>(((t0 >> 26) | (t1 << 6)) & 0x3ffffffu);
    m_h[2] += static_cast<uint32_t>(((t1 >> 20) | (t2 << 12)) & 0x3ffffffu);
    m_h[3] += static_cast<uint32_t>(((t2 >> 14) | (t3 << 18)) & 0x3ffffffu);
    m_h[4] += static_cast<uint32_t>((t3 >> 8) & 0x00ffffffu) | hibit;

    uint64_t r0 = m_r[0];
    uint64_t r1 = m_r[1];
    uint64_t r2 = m_r[2];
    uint64_t r3 = m_r[3];
    uint64_t r4 = m_r[4];

    uint64_t s1 = r1 * 5u;
    uint64_t s2 = r2 * 5u;
    uint64_t s3 = r3 * 5u;
    uint64_t s4 = r4 * 5u;

    uint64_t d0 = static_cast<uint64_t>(m_h[0]) * r0 + static_cast<uint64_t>(m_h[1]) * s4 +
                  static_cast<uint64_t>(m_h[2]) * s3 + static_cast<uint64_t>(m_h[3]) * s2 +
                  static_cast<uint64_t>(m_h[4]) * s1;
    uint64_t d1 = static_cast<uint64_t>(m_h[0]) * r1 + static_cast<uint64_t>(m_h[1]) * r0 +
                  static_cast<uint64_t>(m_h[2]) * s4 + static_cast<uint64_t>(m_h[3]) * s3 +
                  static_cast<uint64_t>(m_h[4]) * s2;
    uint64_t d2 = static_cast<uint64_t>(m_h[0]) * r2 + static_cast<uint64_t>(m_h[1]) * r1 +
                  static_cast<uint64_t>(m_h[2]) * r0 + static_cast<uint64_t>(m_h[3]) * s4 +
                  static_cast<uint64_t>(m_h[4]) * s3;
    uint64_t d3 = static_cast<uint64_t>(m_h[0]) * r3 + static_cast<uint64_t>(m_h[1]) * r2 +
                  static_cast<uint64_t>(m_h[2]) * r1 + static_cast<uint64_t>(m_h[3]) * r0 +
                  static_cast<uint64_t>(m_h[4]) * s4;
    uint64_t d4 = static_cast<uint64_t>(m_h[0]) * r4 + static_cast<uint64_t>(m_h[1]) * r3 +
                  static_cast<uint64_t>(m_h[2]) * r2 + static_cast<uint64_t>(m_h[3]) * r1 +
                  static_cast<uint64_t>(m_h[4]) * r0;

    uint64_t c = 0;
    c = (d0 >> 26); m_h[0] = static_cast<uint32_t>(d0) & 0x3ffffffu; d1 += c;
    c = (d1 >> 26); m_h[1] = static_cast<uint32_t>(d1) & 0x3ffffffu; d2 += c;
    c = (d2 >> 26); m_h[2] = static_cast<uint32_t>(d2) & 0x3ffffffu; d3 += c;
    c = (d3 >> 26); m_h[3] = static_cast<uint32_t>(d3) & 0x3ffffffu; d4 += c;
    c = (d4 >> 26); m_h[4] = static_cast<uint32_t>(d4) & 0x3ffffffu;
    m_h[0] += static_cast<uint32_t>(c * 5u);
    c = (m_h[0] >> 26);
    m_h[0] &= 0x3ffffffu;
    m_h[1] += static_cast<uint32_t>(c);
}

void Poly1305::update(const uint8_t* data, size_t len) {
    if (m_finished) {
        throw std::runtime_error("Poly1305 update after final().");
    }
    if (!data || len == 0) {
        return;
    }

    if (m_bufferUsed > 0) {
        size_t need = 16 - m_bufferUsed;
        size_t take = std::min(need, len);
        std::copy(data, data + take, m_buffer.begin() + static_cast<std::ptrdiff_t>(m_bufferUsed));
        m_bufferUsed += take;
        data += take;
        len -= take;

        if (m_bufferUsed == 16) {
            processBlock(m_buffer.data(), false);
            m_bufferUsed = 0;
        }
    }

    while (len >= 16) {
        processBlock(data, false);
        data += 16;
        len -= 16;
    }

    if (len > 0) {
        std::fill(m_buffer.begin(), m_buffer.end(), static_cast<uint8_t>(0));
        std::copy(data, data + len, m_buffer.begin());
        m_bufferUsed = len;
    }
}

std::array<uint8_t, 16> Poly1305::final() {
    if (m_finished) {
        throw std::runtime_error("Poly1305 final() called twice.");
    }

    if (m_bufferUsed > 0) {
        m_buffer[m_bufferUsed] = 1;
        for (size_t i = m_bufferUsed + 1; i < 16; ++i) {
            m_buffer[i] = 0;
        }
        processBlock(m_buffer.data(), true);
    }

    uint32_t c = m_h[1] >> 26; m_h[1] &= 0x3ffffffu;
    m_h[2] += c; c = m_h[2] >> 26; m_h[2] &= 0x3ffffffu;
    m_h[3] += c; c = m_h[3] >> 26; m_h[3] &= 0x3ffffffu;
    m_h[4] += c; c = m_h[4] >> 26; m_h[4] &= 0x3ffffffu;
    m_h[0] += c * 5u;
    c = m_h[0] >> 26; m_h[0] &= 0x3ffffffu;
    m_h[1] += c;

    uint32_t g0 = m_h[0] + 5u;
    c = g0 >> 26; g0 &= 0x3ffffffu;
    uint32_t g1 = m_h[1] + c;
    c = g1 >> 26; g1 &= 0x3ffffffu;
    uint32_t g2 = m_h[2] + c;
    c = g2 >> 26; g2 &= 0x3ffffffu;
    uint32_t g3 = m_h[3] + c;
    c = g3 >> 26; g3 &= 0x3ffffffu;
    uint32_t g4 = m_h[4] + c - (1u << 26);

    uint32_t mask = (g4 >> 31) - 1u;
    uint32_t nmask = ~mask;
    m_h[0] = (m_h[0] & nmask) | (g0 & mask);
    m_h[1] = (m_h[1] & nmask) | (g1 & mask);
    m_h[2] = (m_h[2] & nmask) | (g2 & mask);
    m_h[3] = (m_h[3] & nmask) | (g3 & mask);
    m_h[4] = (m_h[4] & nmask) | (g4 & mask);

    uint64_t f0 = (static_cast<uint64_t>(m_h[0])      ) | (static_cast<uint64_t>(m_h[1]) << 26);
    uint64_t f1 = (static_cast<uint64_t>(m_h[1]) >> 6 ) | (static_cast<uint64_t>(m_h[2]) << 20);
    uint64_t f2 = (static_cast<uint64_t>(m_h[2]) >> 12) | (static_cast<uint64_t>(m_h[3]) << 14);
    uint64_t f3 = (static_cast<uint64_t>(m_h[3]) >> 18) | (static_cast<uint64_t>(m_h[4]) << 8);

    f0 += m_pad[0];
    f1 += m_pad[1] + (f0 >> 32); f0 &= 0xffffffffu;
    f2 += m_pad[2] + (f1 >> 32); f1 &= 0xffffffffu;
    f3 += m_pad[3] + (f2 >> 32); f2 &= 0xffffffffu;

    std::array<uint8_t, 16> out{};
    writeLE32(out.data() + 0, static_cast<uint32_t>(f0));
    writeLE32(out.data() + 4, static_cast<uint32_t>(f1));
    writeLE32(out.data() + 8, static_cast<uint32_t>(f2));
    writeLE32(out.data() + 12, static_cast<uint32_t>(f3));

    m_finished = true;
    return out;
}

} // namespace fastshield
