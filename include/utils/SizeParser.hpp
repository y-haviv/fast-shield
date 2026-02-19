#ifndef FASTSHIELD_SIZE_PARSER_HPP
#define FASTSHIELD_SIZE_PARSER_HPP

#include <cctype>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace fastshield {

inline uint64_t parseSize(const std::string& value) {
    if (value.empty()) {
        throw std::runtime_error("Size value is empty.");
    }

    size_t idx = 0;
    while (idx < value.size() && (std::isdigit(static_cast<unsigned char>(value[idx])))) {
        ++idx;
    }

    if (idx == 0) {
        throw std::runtime_error("Size value must start with a number.");
    }

    uint64_t number = std::stoull(value.substr(0, idx));
    uint64_t multiplier = 1;

    if (idx < value.size()) {
        char suffix = static_cast<char>(std::toupper(static_cast<unsigned char>(value[idx])));
        switch (suffix) {
        case 'K':
            multiplier = 1024ULL;
            break;
        case 'M':
            multiplier = 1024ULL * 1024ULL;
            break;
        case 'G':
            multiplier = 1024ULL * 1024ULL * 1024ULL;
            break;
        default:
            throw std::runtime_error("Unknown size suffix. Use K, M, or G.");
        }
        if (idx + 1 != value.size()) {
            throw std::runtime_error("Invalid size format.");
        }
    }

    return number * multiplier;
}

} // namespace fastshield

#endif // FASTSHIELD_SIZE_PARSER_HPP
