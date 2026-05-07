#include "io/LinuxFileHandler.hpp"

#ifndef _WIN32

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef FASTSHIELD_HAS_IO_URING
#include <liburing.h>
#endif

namespace fastshield {

namespace {

off_t toOffT(int64_t value) {
    if (value < 0) {
        throw std::runtime_error("Negative file offset is invalid.");
    }
    return static_cast<off_t>(value);
}

int toWhence(SeekWhence whence) {
    switch (whence) {
    case SeekWhence::Begin:
        return SEEK_SET;
    case SeekWhence::Current:
        return SEEK_CUR;
    case SeekWhence::End:
        return SEEK_END;
    default:
        return SEEK_SET;
    }
}

} // namespace

LinuxFileHandler::LinuxFileHandler() = default;

LinuxFileHandler::~LinuxFileHandler() {
    close();
}

void LinuxFileHandler::openForReading(const std::string& path, const FileOpenOptions& options) {
    close();

    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_DIRECT
    if (options.directIo) {
        flags |= O_DIRECT;
    }
#endif

    m_fd = ::open(path.c_str(), flags);
    if (m_fd < 0) {
        throwErrno("opening file for reading");
    }

    struct stat st {};
    if (::fstat(m_fd, &st) != 0) {
        throwErrno("getting file size");
    }
    m_fileSize = static_cast<uint64_t>(st.st_size);
    m_directIo = options.directIo;

    long page = ::sysconf(_SC_PAGESIZE);
    m_alignment = page <= 0 ? 4096u : static_cast<size_t>(page);
}

void LinuxFileHandler::openForWriting(const std::string& path, const FileOpenOptions& options) {
    close();

    int flags = O_WRONLY | O_CREAT;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_DIRECT
    if (options.directIo) {
        flags |= O_DIRECT;
    }
#endif
    if (options.overwrite) {
        flags |= O_TRUNC;
    } else {
        flags |= O_EXCL;
    }

    m_fd = ::open(path.c_str(), flags, 0666);
    if (m_fd < 0) {
        throwErrno("opening file for writing");
    }

    m_fileSize = 0;
    m_directIo = options.directIo;
    long page = ::sysconf(_SC_PAGESIZE);
    m_alignment = page <= 0 ? 4096u : static_cast<size_t>(page);
}

void LinuxFileHandler::close() {
    if (m_fd >= 0) {
        ::close(m_fd);
        m_fd = -1;
    }
}

uint64_t LinuxFileHandler::getFileSize() const {
    return m_fileSize;
}

size_t LinuxFileHandler::read(void* buffer, size_t bytes) {
    if (m_fd < 0) {
        throw std::runtime_error("File is not open for reading.");
    }

#ifdef FASTSHIELD_HAS_IO_URING
    io_uring ring{};
    if (::io_uring_queue_init(1, &ring, 0) == 0) {
        io_uring_sqe* sqe = ::io_uring_get_sqe(&ring);
        off_t current = ::lseek(m_fd, 0, SEEK_CUR);
        if (sqe && current >= 0) {
            ::io_uring_prep_read(sqe, m_fd, buffer, static_cast<unsigned>(bytes), current);
            if (::io_uring_submit(&ring) < 0) {
                ::io_uring_queue_exit(&ring);
            } else {
                io_uring_cqe* cqe = nullptr;
                if (::io_uring_wait_cqe(&ring, &cqe) == 0 && cqe) {
                    int result = cqe->res;
                    ::io_uring_cqe_seen(&ring, cqe);
                    ::io_uring_queue_exit(&ring);
                    if (result < 0) {
                        errno = -result;
                        throwErrno("reading from file (io_uring)");
                    }
                    if (::lseek(m_fd, current + result, SEEK_SET) < 0) {
                        throwErrno("advancing file offset");
                    }
                    return static_cast<size_t>(result);
                }
            }
        }
        ::io_uring_queue_exit(&ring);
    }
#endif

    ssize_t result = ::read(m_fd, buffer, bytes);
    if (result < 0) {
        throwErrno("reading from file");
    }
    return static_cast<size_t>(result);
}

void LinuxFileHandler::readExact(void* buffer, size_t bytes) {
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

void LinuxFileHandler::write(const void* buffer, size_t bytes) {
    if (m_fd < 0) {
        throw std::runtime_error("File is not open for writing.");
    }

#ifdef FASTSHIELD_HAS_IO_URING
    io_uring ring{};
    if (::io_uring_queue_init(1, &ring, 0) == 0) {
        io_uring_sqe* sqe = ::io_uring_get_sqe(&ring);
        off_t current = ::lseek(m_fd, 0, SEEK_CUR);
        if (sqe && current >= 0) {
            ::io_uring_prep_write(sqe, m_fd, buffer, static_cast<unsigned>(bytes), current);
            if (::io_uring_submit(&ring) >= 0) {
                io_uring_cqe* cqe = nullptr;
                if (::io_uring_wait_cqe(&ring, &cqe) == 0 && cqe) {
                    int result = cqe->res;
                    ::io_uring_cqe_seen(&ring, cqe);
                    ::io_uring_queue_exit(&ring);
                    if (result < 0) {
                        errno = -result;
                        throwErrno("writing to file (io_uring)");
                    }
                    if (static_cast<size_t>(result) != bytes) {
                        throw std::runtime_error("Short write detected.");
                    }
                    if (::lseek(m_fd, current + result, SEEK_SET) < 0) {
                        throwErrno("advancing file offset");
                    }
                    return;
                }
            }
        }
        ::io_uring_queue_exit(&ring);
    }
#endif

    ssize_t result = ::write(m_fd, buffer, bytes);
    if (result < 0) {
        throwErrno("writing to file");
    }
    if (static_cast<size_t>(result) != bytes) {
        throw std::runtime_error("Short write detected.");
    }
}

void LinuxFileHandler::writeExact(const void* buffer, size_t bytes) {
    const uint8_t* in = static_cast<const uint8_t*>(buffer);
    size_t total = 0;
    while (total < bytes) {
        size_t chunk = bytes - total;
        write(in + total, chunk);
        total += chunk;
    }
}

void LinuxFileHandler::seek(int64_t offset, SeekWhence whence) {
    if (m_fd < 0) {
        throw std::runtime_error("File is not open.");
    }

    if (::lseek(m_fd, toOffT(offset), toWhence(whence)) == static_cast<off_t>(-1)) {
        throwErrno("seeking in file");
    }
}

void LinuxFileHandler::setFileSize(uint64_t size) {
    if (m_fd < 0) {
        throw std::runtime_error("File is not open.");
    }

    if (::ftruncate(m_fd, static_cast<off_t>(size)) != 0) {
        throwErrno("setting file size");
    }
    m_fileSize = size;
}

void LinuxFileHandler::flush() {
    if (m_fd >= 0 && ::fsync(m_fd) != 0) {
        throwErrno("flushing file");
    }
}

size_t LinuxFileHandler::requiredAlignment() const {
    return m_alignment;
}

bool LinuxFileHandler::directIoEnabled() const {
    return m_directIo;
}

void LinuxFileHandler::throwErrno(const std::string& action) const {
    int code = errno;
    const char* message = std::strerror(code);
    throw std::runtime_error(
        "Error during " + action + ": " + (message ? message : "Unknown error") +
        " (errno " + std::to_string(code) + ").");
}

} // namespace fastshield

#endif
