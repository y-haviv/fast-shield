#include "core/ChaCha20.hpp"

#include <array>
#include <cstring>
#include <stdexcept>

namespace fastshield {

namespace {

constexpr uint32_t kConstants[4] = {
    0x61707865u,
    0x3320646eu,
    0x79622d32u,
    0x6b206574u
};

inline uint32_t rotl(uint32_t v, uint32_t n) {
    return (v << n) | (v >> (32 - n));
}

inline void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotl(d, 16);
    c += d; b ^= c; b = rotl(b, 12);
    a += b; d ^= a; d = rotl(d, 8);
    c += d; b ^= c; b = rotl(b, 7);
}

inline uint32_t readLE32(const uint8_t* data) {
    return static_cast<uint32_t>(data[0]) |
           (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) |
           (static_cast<uint32_t>(data[3]) << 24);
}

inline void writeLE32(uint8_t* out, uint32_t value) {
    out[0] = static_cast<uint8_t>(value & 0xff);
    out[1] = static_cast<uint8_t>((value >> 8) & 0xff);
    out[2] = static_cast<uint8_t>((value >> 16) & 0xff);
    out[3] = static_cast<uint8_t>((value >> 24) & 0xff);
}

void chachaBlock(const std::array<uint8_t, 32>& key,
                 const std::array<uint8_t, 12>& nonce,
                 uint32_t counter,
                 uint8_t out[64]) {
    uint32_t state[16];
    state[0] = kConstants[0];
    state[1] = kConstants[1];
    state[2] = kConstants[2];
    state[3] = kConstants[3];

    for (int i = 0; i < 8; ++i) {
        state[4 + i] = readLE32(key.data() + i * 4);
    }

    state[12] = counter;
    state[13] = readLE32(nonce.data() + 0);
    state[14] = readLE32(nonce.data() + 4);
    state[15] = readLE32(nonce.data() + 8);

    uint32_t working[16];
    std::memcpy(working, state, sizeof(state));

    for (int i = 0; i < 10; ++i) {
        // 20-round ChaCha: 10 double-rounds (column + diagonal).
        quarterRound(working[0], working[4], working[8], working[12]);
        quarterRound(working[1], working[5], working[9], working[13]);
        quarterRound(working[2], working[6], working[10], working[14]);
        quarterRound(working[3], working[7], working[11], working[15]);

        quarterRound(working[0], working[5], working[10], working[15]);
        quarterRound(working[1], working[6], working[11], working[12]);
        quarterRound(working[2], working[7], working[8], working[13]);
        quarterRound(working[3], working[4], working[9], working[14]);
    }

    for (int i = 0; i < 16; ++i) {
        working[i] += state[i];
    }

    for (int i = 0; i < 16; ++i) {
        writeLE32(out + i * 4, working[i]);
    }
}

} // namespace

void chacha20Xor(
    uint8_t* data,
    size_t len,
    const std::array<uint8_t, 32>& key,
    const std::array<uint8_t, 12>& nonce,
    uint64_t streamOffset) {
    if (!data || len == 0) {
        return;
    }

    // RFC 8439 recommends starting the block counter at 1.
    constexpr uint32_t kInitialCounter = 1;
    uint64_t counter64 = (streamOffset / 64) + kInitialCounter;
    uint32_t blockOffset = static_cast<uint32_t>(streamOffset % 64);

    if (counter64 > 0xFFFFFFFFULL) {
        throw std::runtime_error("ChaCha20 counter overflow.");
    }

    size_t remaining = len;
    size_t dataOffset = 0;

    while (remaining > 0) {
        uint32_t counter = static_cast<uint32_t>(counter64);
        uint8_t block[64];
        chachaBlock(key, nonce, counter, block);

        size_t take = 64 - blockOffset;
        if (take > remaining) {
            take = remaining;
        }

        for (size_t i = 0; i < take; ++i) {
            data[dataOffset + i] ^= block[blockOffset + i];
        }

        remaining -= take;
        dataOffset += take;
        blockOffset = 0;
        ++counter64;

        if (counter64 > 0xFFFFFFFFULL && remaining > 0) {
            throw std::runtime_error("ChaCha20 counter overflow.");
        }
    }
}

} // namespace fastshield
