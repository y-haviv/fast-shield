#ifndef FASTSHIELD_LINUX_FILE_HANDLER_HPP
#define FASTSHIELD_LINUX_FILE_HANDLER_HPP

#include "io/FileHandler.hpp"

#include <cstdint>
#include <string>

namespace fastshield {

class LinuxFileHandler final : public FileHandler {
public:
    LinuxFileHandler();
    ~LinuxFileHandler() override;

    LinuxFileHandler(const LinuxFileHandler&) = delete;
    LinuxFileHandler& operator=(const LinuxFileHandler&) = delete;

    void openForReading(const std::string& path, const FileOpenOptions& options) override;
    void openForWriting(const std::string& path, const FileOpenOptions& options) override;
    void close() override;
    uint64_t getFileSize() const override;
    size_t read(void* buffer, size_t bytes) override;
    void readExact(void* buffer, size_t bytes) override;
    void write(const void* buffer, size_t bytes) override;
    void writeExact(const void* buffer, size_t bytes) override;
    void seek(int64_t offset, SeekWhence whence) override;
    void setFileSize(uint64_t size) override;
    void flush() override;
    size_t requiredAlignment() const override;
    bool directIoEnabled() const override;

private:
    void throwErrno(const std::string& action) const;

    int m_fd = -1;
    uint64_t m_fileSize = 0;
    bool m_directIo = false;
    size_t m_alignment = 4096;
};

} // namespace fastshield

#endif // FASTSHIELD_LINUX_FILE_HANDLER_HPP
