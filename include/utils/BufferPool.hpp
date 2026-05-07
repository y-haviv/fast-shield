#ifndef FASTSHIELD_BUFFER_POOL_HPP
#define FASTSHIELD_BUFFER_POOL_HPP

#include "utils/SecureZero.hpp"

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <stdexcept>

namespace fastshield {

size_t systemPageSize();
void* allocateAlignedPages(size_t size);
void freeAlignedPages(void* ptr);

class BufferPool;

class PooledBuffer {
public:
    PooledBuffer() = default;
    ~PooledBuffer() { reset(); }

    PooledBuffer(const PooledBuffer&) = delete;
    PooledBuffer& operator=(const PooledBuffer&) = delete;

    PooledBuffer(PooledBuffer&& other) noexcept { moveFrom(std::move(other)); }
    PooledBuffer& operator=(PooledBuffer&& other) noexcept {
        if (this != &other) {
            reset();
            moveFrom(std::move(other));
        }
        return *this;
    }

    uint8_t* data() { return m_ptr; }
    const uint8_t* data() const { return m_ptr; }

    size_t capacity() const { return m_capacity; }
    size_t size() const { return m_size; }
    void setSize(size_t size) {
        if (size > m_capacity) {
            throw std::runtime_error("Buffer size exceeds capacity.");
        }
        m_size = size;
    }

    explicit operator bool() const { return m_ptr != nullptr; }

    void reset();

private:
    friend class BufferPool;

    PooledBuffer(BufferPool* owner, uint8_t* ptr, size_t capacity)
        : m_owner(owner), m_ptr(ptr), m_capacity(capacity), m_size(0) {}

    void moveFrom(PooledBuffer&& other) {
        m_owner = other.m_owner;
        m_ptr = other.m_ptr;
        m_capacity = other.m_capacity;
        m_size = other.m_size;
        other.m_owner = nullptr;
        other.m_ptr = nullptr;
        other.m_capacity = 0;
        other.m_size = 0;
    }

    BufferPool* m_owner = nullptr;
    uint8_t* m_ptr = nullptr;
    size_t m_capacity = 0;
    size_t m_size = 0;
};

class BufferPool {
public:
    BufferPool(size_t bufferSize, size_t initialCount);
    ~BufferPool();

    BufferPool(const BufferPool&) = delete;
    BufferPool& operator=(const BufferPool&) = delete;

    PooledBuffer acquire();
    void release(uint8_t* ptr, size_t bytesUsed);
    void shutdown();

    size_t bufferSize() const { return m_bufferSize; }
    size_t alignment() const { return m_alignment; }

private:
    size_t m_bufferSize;
    size_t m_alignment;
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<uint8_t*> m_free;
    bool m_shutdown = false;
};

} // namespace fastshield

#endif // FASTSHIELD_BUFFER_POOL_HPP
