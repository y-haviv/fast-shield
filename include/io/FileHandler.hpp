#ifndef FASTSHIELD_FILE_HANDLER_HPP
#define FASTSHIELD_FILE_HANDLER_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace fastshield {

enum class SeekWhence {
    Begin,
    Current,
    End
};

struct FileOpenOptions {
    bool overwrite = false;
    bool directIo = false;
};

class FileHandler {
public:
    virtual ~FileHandler() = default;

    virtual void openForReading(const std::string& path, const FileOpenOptions& options) = 0;
    virtual void openForWriting(const std::string& path, const FileOpenOptions& options) = 0;
    virtual void close() = 0;
    virtual uint64_t getFileSize() const = 0;

    virtual size_t read(void* buffer, size_t bytes) = 0;
    virtual void readExact(void* buffer, size_t bytes) = 0;
    virtual void write(const void* buffer, size_t bytes) = 0;
    virtual void writeExact(const void* buffer, size_t bytes) = 0;
    virtual void seek(int64_t offset, SeekWhence whence) = 0;
    virtual void setFileSize(uint64_t size) = 0;
    virtual void flush() = 0;

    virtual size_t requiredAlignment() const = 0;
    virtual bool directIoEnabled() const = 0;
};

std::unique_ptr<FileHandler> makeFileHandler();

} // namespace fastshield

#endif // FASTSHIELD_FILE_HANDLER_HPP
