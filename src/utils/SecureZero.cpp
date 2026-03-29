#include "utils/SecureZero.hpp"

#ifdef _WIN32

#include <windows.h>

namespace fastshield {

void secureZero(void* data, size_t len) {
    if (!data || len == 0) {
        return;
    }
    SecureZeroMemory(data, len);
}

} // namespace fastshield

#else

namespace fastshield {

void secureZero(void* data, size_t len) {
    if (!data || len == 0) {
        return;
    }

    volatile unsigned char* p = static_cast<volatile unsigned char*>(data);
    while (len--) {
        *p++ = 0;
    }
}

} // namespace fastshield

#endif
