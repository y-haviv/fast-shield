#ifndef FASTSHIELD_BLOCKING_QUEUE_HPP
#define FASTSHIELD_BLOCKING_QUEUE_HPP

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <utility>

namespace fastshield {

template <typename T>
class BlockingQueue {
public:
    /// Create a queue with an optional bounded capacity (0 = unbounded).
    explicit BlockingQueue(size_t capacity = 0)
        : m_capacity(capacity), m_closed(false) {}

    BlockingQueue(const BlockingQueue&) = delete;
    BlockingQueue& operator=(const BlockingQueue&) = delete;

    /// Push an item into the queue. Returns false if the queue is closed.
    bool push(T item) {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_notFull.wait(lock, [&]() {
            return m_closed || m_capacity == 0 || m_queue.size() < m_capacity;
        });
        if (m_closed) {
            return false;
        }
        m_queue.emplace_back(std::move(item));
        m_notEmpty.notify_one();
        return true;
    }

    /// Pop an item from the queue. Returns false if closed and empty.
    bool pop(T& out) {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_notEmpty.wait(lock, [&]() { return m_closed || !m_queue.empty(); });
        if (m_queue.empty()) {
            return false;
        }
        out = std::move(m_queue.front());
        m_queue.pop_front();
        m_notFull.notify_one();
        return true;
    }

    /// Close the queue and wake all waiting threads.
    void close() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_closed = true;
        m_notEmpty.notify_all();
        m_notFull.notify_all();
    }

    /// True if close() has been called.
    bool closed() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_closed;
    }

private:
    size_t m_capacity;
    mutable std::mutex m_mutex;
    std::condition_variable m_notEmpty;
    std::condition_variable m_notFull;
    std::deque<T> m_queue;
    bool m_closed;
};

} // namespace fastshield

#endif // FASTSHIELD_BLOCKING_QUEUE_HPP
