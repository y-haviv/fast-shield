/**
 * @file Win32FileHandler.hpp
 * @brief Low-level Windows file manipulation using Win32 API.
 * * This class handles high-performance file I/O operations by interfacing 
 * directly with the Windows kernel, ensuring memory alignment and 
 * efficient buffer management.
 */

#ifndef WIN32_FILE_HANDLER_HPP
#define WIN32_FILE_HANDLER_HPP

#include <string>
#include <vector>
#include <stdexcept>
#include <cstdint>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
using DWORD = uint32_t;
using HANDLE = int;
constexpr DWORD FILE_BEGIN = 0;
constexpr DWORD FILE_CURRENT = 1;
constexpr DWORD FILE_END = 2;
#endif

class Win32FileHandler {
public:
    // Constructor and Destructor
    explicit Win32FileHandler(const std::string& filePath);
    ~Win32FileHandler();

    // Prevent copying to avoid multiple handles to the same file
    Win32FileHandler(const Win32FileHandler&) = delete;
    Win32FileHandler& operator=(const Win32FileHandler&) = delete;

    // Core Operations
    /// Open the file for sequential reading.
    void openForReading();
    /// Create or overwrite an output file for sequential writing.
    void openForWriting(const std::string& outPath, bool overwrite = true);
    /// Close the underlying Win32 handle.
    void close();
    /// Get the cached file size (valid after openForReading or setFileSize).
    uint64_t getFileSize() const;

    /// Read up to `bytes` into buffer. Returns number of bytes read.
    size_t read(void* buffer, size_t bytes);
    /// Read exactly `bytes` or throw on EOF.
    void readExact(void* buffer, size_t bytes);
    /// Write buffer to disk (single call).
    void write(const void* buffer, size_t bytes);
    /// Write exactly `bytes` or throw.
    void writeExact(const void* buffer, size_t bytes);
    /// Move file pointer to an absolute or relative position.
    void seek(uint64_t offset, DWORD moveMethod = FILE_BEGIN);
    /// Resize file to `size` bytes.
    void setFileSize(uint64_t size);
    /// Access the raw Win32 handle (use with caution).
    HANDLE handle() const;

    /**
     * @brief Allocates memory aligned to the system's page size.
     * Required for high-performance O_DIRECT-style I/O on Windows.
     */
    void* allocateAlignedBuffer(size_t size);
    void freeAlignedBuffer(void* ptr);

private:
    std::string m_filePath;
    HANDLE m_fileHandle;
    uint64_t m_fileSize;

#ifdef _WIN32
    static constexpr HANDLE kInvalidHandle = INVALID_HANDLE_VALUE;
#else
    static constexpr HANDLE kInvalidHandle = -1;
#endif

    // Helper to throw detailed Windows error messages
    void throwLastError(const std::string& action);
};

#endif // WIN32_FILE_HANDLER_HPP
