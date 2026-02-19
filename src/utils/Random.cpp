#include "utils/Random.hpp"

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
