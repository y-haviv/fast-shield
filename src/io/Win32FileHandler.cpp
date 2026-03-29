#include "io/Win32FileHandler.hpp"

#ifdef _WIN32

Win32FileHandler::Win32FileHandler(const std::string& filePath)
    : m_filePath(filePath), m_fileHandle(kInvalidHandle), m_fileSize(0) {
}

Win32FileHandler::~Win32FileHandler() {
    close();
}

void Win32FileHandler::openForReading() {
    close();
    // OPEN_EXISTING: Opens the file only if it exists.
    // FILE_FLAG_SEQUENTIAL_SCAN: Hints to Windows that we will read from start to end.
    m_fileHandle = CreateFileA(
        m_filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN, 
        NULL
    );

    if (m_fileHandle == kInvalidHandle) {
        throwLastError("opening file for reading");
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(m_fileHandle, &size)) {
        throwLastError("getting file size");
    }
    m_fileSize = static_cast<uint64_t>(size.QuadPart);
}

void Win32FileHandler::openForWriting(const std::string& outPath, bool overwrite) {
    close();
    m_filePath = outPath;

    // CREATE_ALWAYS overwrites existing files, CREATE_NEW fails if it exists.
    DWORD creation = overwrite ? CREATE_ALWAYS : CREATE_NEW;

    m_fileHandle = CreateFileA(
        m_filePath.c_str(),
        GENERIC_WRITE,
        0,
        NULL,
        creation,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        NULL
    );

    if (m_fileHandle == kInvalidHandle) {
        throwLastError("opening file for writing");
    }

    m_fileSize = 0;
}

void Win32FileHandler::close() {
    if (m_fileHandle != kInvalidHandle) {
        CloseHandle(m_fileHandle);
        m_fileHandle = kInvalidHandle;
    }
}

void* Win32FileHandler::allocateAlignedBuffer(size_t size) {
    /**
     * VirtualAlloc is used instead of malloc/new.
     * This allows us to request memory that is aligned to page boundaries,
     * which is crucial for direct-to-disk I/O performance.
     */
    void* ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ptr) {
        throwLastError("allocating aligned memory");
    }
    return ptr;
}

void Win32FileHandler::freeAlignedBuffer(void* ptr) {
    if (ptr) {
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
}

size_t Win32FileHandler::getFileSize() const {
    return m_fileSize;
}

size_t Win32FileHandler::read(void* buffer, size_t bytes) {
    if (m_fileHandle == kInvalidHandle) {
        throw std::runtime_error("File handle is not open for reading.");
    }

    // ReadFile may return fewer bytes at EOF.
    DWORD bytesRead = 0;
    if (!ReadFile(m_fileHandle, buffer, static_cast<DWORD>(bytes), &bytesRead, NULL)) {
        throwLastError("reading from file");
    }
    return static_cast<size_t>(bytesRead);
}

void Win32FileHandler::readExact(void* buffer, size_t bytes) {
    size_t total = 0;
    uint8_t* out = static_cast<uint8_t*>(buffer);
    while (total < bytes) {
        size_t readNow = read(out + total, bytes - total);
        if (readNow == 0) {
            throw std::runtime_error("Unexpected end of file while reading.");
        }
        total += readNow;
    }
}

void Win32FileHandler::write(const void* buffer, size_t bytes) {
    if (m_fileHandle == kInvalidHandle) {
        throw std::runtime_error("File handle is not open for writing.");
    }

    // WriteFile should either write fully or fail; short writes are treated as errors.
    DWORD bytesWritten = 0;
    if (!WriteFile(m_fileHandle, buffer, static_cast<DWORD>(bytes), &bytesWritten, NULL)) {
        throwLastError("writing to file");
    }
    if (bytesWritten != bytes) {
        throw std::runtime_error("Short write detected.");
    }
}

void Win32FileHandler::writeExact(const void* buffer, size_t bytes) {
    const uint8_t* in = static_cast<const uint8_t*>(buffer);
    size_t total = 0;
    while (total < bytes) {
        size_t toWrite = bytes - total;
        DWORD bytesWritten = 0;
        if (!WriteFile(m_fileHandle, in + total, static_cast<DWORD>(toWrite), &bytesWritten, NULL)) {
            throwLastError("writing to file");
        }
        if (bytesWritten == 0) {
            throw std::runtime_error("Write failed, zero bytes written.");
        }
        total += static_cast<size_t>(bytesWritten);
    }
}

void Win32FileHandler::seek(uint64_t offset, DWORD moveMethod) {
    LARGE_INTEGER li;
    li.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(m_fileHandle, li, NULL, moveMethod)) {
        throwLastError("seeking in file");
    }
}

void Win32FileHandler::setFileSize(uint64_t size) {
    if (m_fileHandle == kInvalidHandle) {
        throw std::runtime_error("File handle is not open.");
    }
    LARGE_INTEGER li;
    li.QuadPart = static_cast<LONGLONG>(size);
    if (!SetFilePointerEx(m_fileHandle, li, NULL, FILE_BEGIN)) {
        throwLastError("setting file pointer for size");
    }
    if (!SetEndOfFile(m_fileHandle)) {
        throwLastError("setting end of file");
    }
    m_fileSize = size;
}

HANDLE Win32FileHandler::handle() const {
    return m_fileHandle;
}

void Win32FileHandler::throwLastError(const std::string& action) {
    DWORD errorCode = GetLastError();
    LPSTR messageBuffer = nullptr;
    DWORD size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&messageBuffer),
        0,
        NULL);

    std::string message = (size && messageBuffer)
        ? std::string(messageBuffer, size)
        : "Unknown Win32 error.";

    if (messageBuffer) {
        LocalFree(messageBuffer);
    }

    throw std::runtime_error(
        "Error during " + action + ": " + message + " (Win32 Error " + std::to_string(errorCode) + ")");
}

#else

#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

Win32FileHandler::Win32FileHandler(const std::string& filePath)
    : m_filePath(filePath), m_fileHandle(kInvalidHandle), m_fileSize(0) {
}

Win32FileHandler::~Win32FileHandler() {
    close();
}

void Win32FileHandler::openForReading() {
    close();
    m_fileHandle = ::open(m_filePath.c_str(), O_RDONLY);
    if (m_fileHandle == kInvalidHandle) {
        throwLastError("opening file for reading");
    }

    struct stat st {};
    if (::fstat(m_fileHandle, &st) != 0) {
        throwLastError("getting file size");
    }
    m_fileSize = static_cast<uint64_t>(st.st_size);
}

void Win32FileHandler::openForWriting(const std::string& outPath, bool overwrite) {
    close();
    m_filePath = outPath;

    int flags = O_WRONLY | O_CREAT;
    if (overwrite) {
        flags |= O_TRUNC;
    } else {
        flags |= O_EXCL;
    }

    m_fileHandle = ::open(m_filePath.c_str(), flags, 0666);
    if (m_fileHandle == kInvalidHandle) {
        throwLastError("opening file for writing");
    }

    m_fileSize = 0;
}

void Win32FileHandler::close() {
    if (m_fileHandle != kInvalidHandle) {
        ::close(m_fileHandle);
        m_fileHandle = kInvalidHandle;
    }
}

void* Win32FileHandler::allocateAlignedBuffer(size_t size) {
    void* ptr = nullptr;
    if (::posix_memalign(&ptr, 4096, size) != 0) {
        throwLastError("allocating aligned memory");
    }
    return ptr;
}

void Win32FileHandler::freeAlignedBuffer(void* ptr) {
    std::free(ptr);
}

size_t Win32FileHandler::getFileSize() const {
    return m_fileSize;
}

size_t Win32FileHandler::read(void* buffer, size_t bytes) {
    if (m_fileHandle == kInvalidHandle) {
        throw std::runtime_error("File handle is not open for reading.");
    }

    ssize_t readNow = ::read(m_fileHandle, buffer, bytes);
    if (readNow < 0) {
        throwLastError("reading from file");
    }
    return static_cast<size_t>(readNow);
}

void Win32FileHandler::readExact(void* buffer, size_t bytes) {
    size_t total = 0;
    uint8_t* out = static_cast<uint8_t*>(buffer);
    while (total < bytes) {
        size_t readNow = read(out + total, bytes - total);
        if (readNow == 0) {
            throw std::runtime_error("Unexpected end of file while reading.");
        }
        total += readNow;
    }
}

void Win32FileHandler::write(const void* buffer, size_t bytes) {
    if (m_fileHandle == kInvalidHandle) {
        throw std::runtime_error("File handle is not open for writing.");
    }

    ssize_t written = ::write(m_fileHandle, buffer, bytes);
    if (written < 0) {
        throwLastError("writing to file");
    }
    if (static_cast<size_t>(written) != bytes) {
        throw std::runtime_error("Short write detected.");
    }
}

void Win32FileHandler::writeExact(const void* buffer, size_t bytes) {
    const uint8_t* in = static_cast<const uint8_t*>(buffer);
    size_t total = 0;
    while (total < bytes) {
        ssize_t written = ::write(m_fileHandle, in + total, bytes - total);
        if (written < 0) {
            throwLastError("writing to file");
        }
        if (written == 0) {
            throw std::runtime_error("Write failed, zero bytes written.");
        }
        total += static_cast<size_t>(written);
    }
}

void Win32FileHandler::seek(uint64_t offset, DWORD moveMethod) {
    if (m_fileHandle == kInvalidHandle) {
        throw std::runtime_error("File handle is not open.");
    }

    int whence = SEEK_SET;
    if (moveMethod == FILE_CURRENT) {
        whence = SEEK_CUR;
    } else if (moveMethod == FILE_END) {
        whence = SEEK_END;
    }

    if (::lseek(m_fileHandle, static_cast<off_t>(offset), whence) == static_cast<off_t>(-1)) {
        throwLastError("seeking in file");
    }
}

void Win32FileHandler::setFileSize(uint64_t size) {
    if (m_fileHandle == kInvalidHandle) {
        throw std::runtime_error("File handle is not open.");
    }

    if (::ftruncate(m_fileHandle, static_cast<off_t>(size)) != 0) {
        throwLastError("setting end of file");
    }

    if (::lseek(m_fileHandle, 0, SEEK_SET) == static_cast<off_t>(-1)) {
        throwLastError("setting file pointer for size");
    }

    m_fileSize = size;
}

HANDLE Win32FileHandler::handle() const {
    return m_fileHandle;
}

void Win32FileHandler::throwLastError(const std::string& action) {
    int errorCode = errno;
    const char* message = std::strerror(errorCode);
    throw std::runtime_error(
        "Error during " + action + ": " + (message ? message : "Unknown error.") +
        " (errno " + std::to_string(errorCode) + ")");
}

#endif
