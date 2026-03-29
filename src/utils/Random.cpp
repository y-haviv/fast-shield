#include "utils/Random.hpp"

#ifdef _WIN32

#include <windows.h>
#include <bcrypt.h>
#include <stdexcept>

namespace fastshield {

void secureRandom(uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return;
    }
    NTSTATUS status = BCryptGenRandom(
        NULL,
        reinterpret_cast<PUCHAR>(data),
        static_cast<ULONG>(size),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    if (status != 0) {
        throw std::runtime_error("BCryptGenRandom failed.");
    }
}

} // namespace fastshield

#else

#include <random>
#include <stdexcept>

namespace fastshield {

void secureRandom(uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return;
    }

    std::random_device rd;
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>(rd());
    }
}

} // namespace fastshield

#endif
