#include "utils/BufferPool.hpp"

#include <algorithm>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cstdlib>
#include <unistd.h>
#endif

namespace fastshield {

size_t systemPageSize() {
#ifdef _WIN32
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    return static_cast<size_t>(info.dwPageSize == 0 ? 4096 : info.dwPageSize);
#else
    long value = ::sysconf(_SC_PAGESIZE);
    return value <= 0 ? 4096u : static_cast<size_t>(value);
#endif
}

void* allocateAlignedPages(size_t size) {
#ifdef _WIN32
    void* ptr = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ptr) {
        throw std::runtime_error("VirtualAlloc failed while allocating pooled buffer.");
    }
    return ptr;
#else
    void* ptr = nullptr;
    if (::posix_memalign(&ptr, systemPageSize(), size) != 0 || ptr == nullptr) {
        throw std::runtime_error("posix_memalign failed while allocating pooled buffer.");
    }
    return ptr;
#endif
}

void freeAlignedPages(void* ptr) {
    if (!ptr) {
        return;
    }
#ifdef _WIN32
    VirtualFree(ptr, 0, MEM_RELEASE);
#else
    std::free(ptr);
#endif
}

void PooledBuffer::reset() {
    if (m_owner && m_ptr) {
        m_owner->release(m_ptr, m_size);
    }
    m_owner = nullptr;
    m_ptr = nullptr;
    m_capacity = 0;
    m_size = 0;
}

BufferPool::BufferPool(size_t bufferSize, size_t initialCount)
    : m_bufferSize(bufferSize), m_alignment(systemPageSize()) {
    if (bufferSize == 0 || initialCount == 0) {
        throw std::runtime_error("BufferPool requires non-zero buffer size and count.");
    }

    size_t alignedSize = ((bufferSize + m_alignment - 1) / m_alignment) * m_alignment;
    m_bufferSize = alignedSize;

    try {
        for (size_t i = 0; i < initialCount; ++i) {
            m_free.push_back(static_cast<uint8_t*>(allocateAlignedPages(m_bufferSize)));
        }
    } catch (...) {
        for (uint8_t* ptr : m_free) {
            freeAlignedPages(ptr);
        }
        m_free.clear();
        throw;
    }
}

BufferPool::~BufferPool() {
    shutdown();
    for (uint8_t* ptr : m_free) {
        secureZero(ptr, m_bufferSize);
        freeAlignedPages(ptr);
    }
    m_free.clear();
}

PooledBuffer BufferPool::acquire() {
    std::unique_lock<std::mutex> lock(m_mutex);
    m_cv.wait(lock, [&]() { return m_shutdown || !m_free.empty(); });
    if (m_shutdown) {
        throw std::runtime_error("BufferPool is shut down.");
    }

    uint8_t* ptr = m_free.front();
    m_free.pop_front();
    return PooledBuffer(this, ptr, m_bufferSize);
}

void BufferPool::release(uint8_t* ptr, size_t bytesUsed) {
    if (!ptr) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        size_t wipe = std::min(bytesUsed, m_bufferSize);
        if (wipe > 0) {
            secureZero(ptr, wipe);
        }
        m_free.push_back(ptr);
    }
    m_cv.notify_one();
}

void BufferPool::shutdown() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_shutdown = true;
    }
    m_cv.notify_all();
}

} // namespace fastshield
