#ifndef FASTSHIELD_SECURE_ZERO_HPP
#define FASTSHIELD_SECURE_ZERO_HPP

#include <cstddef>

namespace fastshield {

/// Best-effort secure memory wipe using platform primitives.
void secureZero(void* data, size_t len);

} // namespace fastshield

#endif // FASTSHIELD_SECURE_ZERO_HPP
