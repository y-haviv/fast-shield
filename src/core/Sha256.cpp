#include "core/Sha256.hpp"

#include <cstring>

namespace fastshield {

namespace {

constexpr uint32_t kTable[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t bigSigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint32_t bigSigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint32_t smallSigma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline uint32_t smallSigma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

inline uint32_t readBE32(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8)  |
           (static_cast<uint32_t>(data[3]));
}

inline void writeBE32(uint8_t* out, uint32_t value) {
    out[0] = static_cast<uint8_t>((value >> 24) & 0xff);
    out[1] = static_cast<uint8_t>((value >> 16) & 0xff);
    out[2] = static_cast<uint8_t>((value >> 8) & 0xff);
    out[3] = static_cast<uint8_t>(value & 0xff);
}

} // namespace

Sha256::Sha256() {
    reset();
}

void Sha256::reset() {
    m_state[0] = 0x6a09e667u;
    m_state[1] = 0xbb67ae85u;
    m_state[2] = 0x3c6ef372u;
    m_state[3] = 0xa54ff53au;
    m_state[4] = 0x510e527fu;
    m_state[5] = 0x9b05688cu;
    m_state[6] = 0x1f83d9abu;
    m_state[7] = 0x5be0cd19u;
    m_bitlen = 0;
    m_bufferLen = 0;
}

void Sha256::update(const uint8_t* data, size_t len) {
    if (!data || len == 0) {
        return;
    }

    m_bitlen += static_cast<uint64_t>(len) * 8u;

    size_t offset = 0;
    while (offset < len) {
        size_t toCopy = (len - offset);
        size_t space = 64 - m_bufferLen;
        if (toCopy > space) {
            toCopy = space;
        }
        std::memcpy(m_buffer + m_bufferLen, data + offset, toCopy);
        m_bufferLen += toCopy;
        offset += toCopy;

        if (m_bufferLen == 64) {
            transform(m_buffer);
            m_bufferLen = 0;
        }
    }
}

std::array<uint8_t, 32> Sha256::final() {
    uint8_t padding[64] = {0x80};
    uint8_t lengthBytes[8];

    uint64_t bitlen = m_bitlen;
    for (int i = 7; i >= 0; --i) {
        lengthBytes[i] = static_cast<uint8_t>(bitlen & 0xffu);
        bitlen >>= 8;
    }

    size_t padLen = (m_bufferLen < 56) ? (56 - m_bufferLen) : (120 - m_bufferLen);
    update(padding, padLen);
    update(lengthBytes, 8);

    std::array<uint8_t, 32> out{};
    for (int i = 0; i < 8; ++i) {
        writeBE32(out.data() + i * 4, m_state[i]);
    }

    return out;
}

std::array<uint8_t, 32> Sha256::digest(const uint8_t* data, size_t len) {
    Sha256 sha;
    sha.update(data, len);
    return sha.final();
}

void Sha256::transform(const uint8_t* chunk) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = readBE32(chunk + i * 4);
    }
    for (int i = 16; i < 64; ++i) {
        w[i] = smallSigma1(w[i - 2]) + w[i - 7] + smallSigma0(w[i - 15]) + w[i - 16];
    }

    uint32_t a = m_state[0];
    uint32_t b = m_state[1];
    uint32_t c = m_state[2];
    uint32_t d = m_state[3];
    uint32_t e = m_state[4];
    uint32_t f = m_state[5];
    uint32_t g = m_state[6];
    uint32_t h = m_state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t temp1 = h + bigSigma1(e) + ch(e, f, g) + kTable[i] + w[i];
        uint32_t temp2 = bigSigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    m_state[0] += a;
    m_state[1] += b;
    m_state[2] += c;
    m_state[3] += d;
    m_state[4] += e;
    m_state[5] += f;
    m_state[6] += g;
    m_state[7] += h;
}

} // namespace fastshield
