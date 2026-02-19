#ifndef FASTSHIELD_FILE_FORMAT_HPP
#define FASTSHIELD_FILE_FORMAT_HPP

#include "core/CryptoEngine.hpp"

#include <array>
#include <cstdint>
#include <cstring>

namespace fastshield {

static constexpr char kMagic[8] = {'F', 'S', 'T', 'S', 'H', 'L', 'D', '\0'};
static constexpr uint16_t kFormatVersion = 1;

#pragma pack(push, 1)
struct FileHeader {
    char magic[8];
    uint16_t version;
    uint16_t headerSize;
    uint32_t flags;
    uint32_t chunkSize;
    uint32_t kdfIterations;
    uint64_t originalSize;
    uint8_t salt[CryptoEngine::kSaltSize];
    uint8_t nonce[CryptoEngine::kNonceSize];
    uint8_t reserved[4];
};
#pragma pack(pop)

static_assert(sizeof(FileHeader) == 64, "FileHeader must be 64 bytes.");

inline FileHeader makeHeader(
    uint64_t originalSize,
    uint32_t chunkSize,
    uint32_t kdfIterations,
    const uint8_t* salt,
    const uint8_t* nonce) {
    FileHeader header{};
    std::memcpy(header.magic, kMagic, sizeof(header.magic));
    header.version = kFormatVersion;
    header.headerSize = static_cast<uint16_t>(sizeof(FileHeader));
    header.flags = 0;
    header.chunkSize = chunkSize;
    header.kdfIterations = kdfIterations;
    header.originalSize = originalSize;
    std::memcpy(header.salt, salt, CryptoEngine::kSaltSize);
    std::memcpy(header.nonce, nonce, CryptoEngine::kNonceSize);
    std::memset(header.reserved, 0, sizeof(header.reserved));
    return header;
}

inline bool validateHeader(const FileHeader& header) {
    if (std::memcmp(header.magic, kMagic, sizeof(header.magic)) != 0) {
        return false;
    }
    if (header.version != kFormatVersion) {
        return false;
    }
    if (header.headerSize != sizeof(FileHeader)) {
        return false;
    }
    if (header.chunkSize == 0) {
        return false;
    }
    if (header.kdfIterations == 0) {
        return false;
    }
    return true;
}

} // namespace fastshield

#endif // FASTSHIELD_FILE_FORMAT_HPP
