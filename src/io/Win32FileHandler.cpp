#include "io/Win32FileHandler.hpp"

#include <stdexcept>

namespace fastshield {

#ifdef _WIN32

namespace {

DWORD toMoveMethod(SeekWhence whence) {
    switch (whence) {
    case SeekWhence::Begin:
        return FILE_BEGIN;
    case SeekWhence::Current:
        return FILE_CURRENT;
    case SeekWhence::End:
        return FILE_END;
    default:
        return FILE_BEGIN;
    }
}

} // namespace

Win32FileHandler::Win32FileHandler() {
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    m_alignment = static_cast<size_t>(info.dwPageSize == 0 ? 4096 : info.dwPageSize);
}

Win32FileHandler::~Win32FileHandler() {
    close();
}

void Win32FileHandler::openForReading(const std::string& path, const FileOpenOptions& options) {
    close();

    DWORD flags = FILE_FLAG_SEQUENTIAL_SCAN;
    if (options.directIo) {
        flags |= FILE_FLAG_NO_BUFFERING;
    }

    m_fileHandle = CreateFileA(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        flags,
        nullptr);

    if (m_fileHandle == INVALID_HANDLE_VALUE) {
        throwLastError("opening file for reading");
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(m_fileHandle, &size)) {
        throwLastError("getting file size");
    }

    m_fileSize = static_cast<uint64_t>(size.QuadPart);
    m_directIo = options.directIo;
}

void Win32FileHandler::openForWriting(const std::string& path, const FileOpenOptions& options) {
    close();

    DWORD createMode = options.overwrite ? CREATE_ALWAYS : CREATE_NEW;
    DWORD flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN;
    if (options.directIo) {
        flags |= FILE_FLAG_NO_BUFFERING;
    }

    m_fileHandle = CreateFileA(
        path.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        createMode,
        flags,
        nullptr);

    if (m_fileHandle == INVALID_HANDLE_VALUE) {
        throwLastError("opening file for writing");
    }

    m_fileSize = 0;
    m_directIo = options.directIo;
}

void Win32FileHandler::close() {
    if (m_fileHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(m_fileHandle);
        m_fileHandle = INVALID_HANDLE_VALUE;
    }
}

uint64_t Win32FileHandler::getFileSize() const {
    return m_fileSize;
}

size_t Win32FileHandler::read(void* buffer, size_t bytes) {
    if (m_fileHandle == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("File is not open for reading.");
    }

    DWORD readNow = 0;
    if (!ReadFile(m_fileHandle, buffer, static_cast<DWORD>(bytes), &readNow, nullptr)) {
        throwLastError("reading from file");
    }
    return static_cast<size_t>(readNow);
}

void Win32FileHandler::readExact(void* buffer, size_t bytes) {
    uint8_t* out = static_cast<uint8_t*>(buffer);
    size_t total = 0;
    while (total < bytes) {
        size_t got = read(out + total, bytes - total);
        if (got == 0) {
            throw std::runtime_error("Unexpected EOF while reading file.");
        }
        total += got;
    }
}

void Win32FileHandler::write(const void* buffer, size_t bytes) {
    if (m_fileHandle == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("File is not open for writing.");
    }

    DWORD written = 0;
    if (!WriteFile(m_fileHandle, buffer, static_cast<DWORD>(bytes), &written, nullptr)) {
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
        size_t toWrite = bytes - total;
        DWORD written = 0;
        if (!WriteFile(m_fileHandle, in + total, static_cast<DWORD>(toWrite), &written, nullptr)) {
            throwLastError("writing to file");
        }
        if (written == 0) {
            throw std::runtime_error("Write failed with zero bytes written.");
        }
        total += static_cast<size_t>(written);
    }
}

void Win32FileHandler::seek(int64_t offset, SeekWhence whence) {
    if (m_fileHandle == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("File is not open.");
    }

    LARGE_INTEGER move{};
    move.QuadPart = offset;
    if (!SetFilePointerEx(m_fileHandle, move, nullptr, toMoveMethod(whence))) {
        throwLastError("seeking in file");
    }
}

void Win32FileHandler::setFileSize(uint64_t size) {
    if (m_fileHandle == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("File is not open.");
    }

    LARGE_INTEGER target{};
    target.QuadPart = static_cast<LONGLONG>(size);
    if (!SetFilePointerEx(m_fileHandle, target, nullptr, FILE_BEGIN)) {
        throwLastError("setting file pointer for resize");
    }
    if (!SetEndOfFile(m_fileHandle)) {
        throwLastError("resizing output file");
    }
    m_fileSize = size;
}

void Win32FileHandler::flush() {
    if (m_fileHandle != INVALID_HANDLE_VALUE && !FlushFileBuffers(m_fileHandle)) {
        throwLastError("flushing file");
    }
}

size_t Win32FileHandler::requiredAlignment() const {
    return m_alignment;
}

bool Win32FileHandler::directIoEnabled() const {
    return m_directIo;
}

void Win32FileHandler::throwLastError(const std::string& action) const {
    DWORD errorCode = GetLastError();
    LPSTR messageBuffer = nullptr;

    DWORD size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&messageBuffer),
        0,
        nullptr);

    std::string message = (size > 0 && messageBuffer != nullptr)
        ? std::string(messageBuffer, size)
        : std::string("Unknown Win32 error");

    if (messageBuffer) {
        LocalFree(messageBuffer);
    }

    throw std::runtime_error(
        "Error during " + action + ": " + message +
        " (Win32 error " + std::to_string(errorCode) + ").");
}

#else

Win32FileHandler::Win32FileHandler() = default;
Win32FileHandler::~Win32FileHandler() = default;

void Win32FileHandler::openForReading(const std::string&, const FileOpenOptions&) {
    throw std::runtime_error("Win32FileHandler is only available on Windows.");
}

void Win32FileHandler::openForWriting(const std::string&, const FileOpenOptions&) {
    throw std::runtime_error("Win32FileHandler is only available on Windows.");
}

void Win32FileHandler::close() {}
uint64_t Win32FileHandler::getFileSize() const { return 0; }
size_t Win32FileHandler::read(void*, size_t) { throw std::runtime_error("Unsupported platform."); }
void Win32FileHandler::readExact(void*, size_t) { throw std::runtime_error("Unsupported platform."); }
void Win32FileHandler::write(const void*, size_t) { throw std::runtime_error("Unsupported platform."); }
void Win32FileHandler::writeExact(const void*, size_t) { throw std::runtime_error("Unsupported platform."); }
void Win32FileHandler::seek(int64_t, SeekWhence) { throw std::runtime_error("Unsupported platform."); }
void Win32FileHandler::setFileSize(uint64_t) { throw std::runtime_error("Unsupported platform."); }
void Win32FileHandler::flush() {}
size_t Win32FileHandler::requiredAlignment() const { return 4096; }
bool Win32FileHandler::directIoEnabled() const { return false; }
void Win32FileHandler::throwLastError(const std::string&) const {}

#endif

} // namespace fastshield
