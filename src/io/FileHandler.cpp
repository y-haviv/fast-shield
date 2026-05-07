#include "io/FileHandler.hpp"

#ifdef _WIN32
#include "io/Win32FileHandler.hpp"
#else
#include "io/LinuxFileHandler.hpp"
#endif

namespace fastshield {

std::unique_ptr<FileHandler> makeFileHandler() {
#ifdef _WIN32
    return std::make_unique<Win32FileHandler>();
#else
    return std::make_unique<LinuxFileHandler>();
#endif
}

} // namespace fastshield
