#ifndef FASTSHIELD_RANDOM_HPP
#define FASTSHIELD_RANDOM_HPP

#include <cstddef>
#include <cstdint>

namespace fastshield {

void secureRandom(uint8_t* data, size_t size);

} // namespace fastshield

#endif // FASTSHIELD_RANDOM_HPP
