#include "utils/SecureZero.hpp"

#include <windows.h>

namespace fastshield {

void secureZero(void* data, size_t len) {
    if (!data || len == 0) {
        return;
    }
    SecureZeroMemory(data, len);
}

} // namespace fastshield
