#include "core/FastShield.hpp"

#include "core/ChaCha20Poly1305.hpp"
#include "core/CryptoEngine.hpp"
#include "core/FileFormat.hpp"
#include "io/FileHandler.hpp"
#include "utils/BlockingQueue.hpp"
#include "utils/BufferPool.hpp"
#include "utils/Logger.hpp"
#include "utils/Random.hpp"
#include "utils/SecureZero.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <exception>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace fastshield {

namespace {

struct Chunk {
    uint64_t index = 0;
    PooledBuffer buffer;
    std::array<uint8_t, CryptoEngine::kTagSize> tag{};
};

constexpr uint32_t kDefaultChunkSize = 4 * 1024 * 1024;
constexpr uint32_t kMaxChunkSize = 256 * 1024 * 1024;

unsigned int resolveThreads(unsigned int requested) {
    if (requested > 0) {
        return requested;
    }
    unsigned int hc = std::thread::hardware_concurrency();
    return hc == 0 ? 4 : hc;
}

uint32_t resolveChunkSize(uint32_t requested) {
    uint32_t size = requested == 0 ? kDefaultChunkSize : requested;
    if (size > kMaxChunkSize) {
        std::ostringstream oss;
        oss << "Chunk size too large. Maximum is " << kMaxChunkSize << " bytes.";
        throw std::runtime_error(oss.str());
    }
    return size;
}

std::array<uint8_t, 16> buildChunkAad(uint64_t chunkIndex, uint64_t chunkSize) {
    std::array<uint8_t, 16> aad{};
    for (size_t i = 0; i < 8; ++i) {
        aad[i] = static_cast<uint8_t>((chunkIndex >> (i * 8)) & 0xffu);
        aad[8 + i] = static_cast<uint8_t>((chunkSize >> (i * 8)) & 0xffu);
    }
    return aad;
}

class OutputGuard {
public:
    explicit OutputGuard(const std::string& path)
        : m_path(path), m_active(false) {}

    void arm() { m_active = true; }
    void release() { m_active = false; }

    ~OutputGuard() {
        if (m_active) {
            std::error_code ec;
            std::filesystem::remove(m_path, ec);
        }
    }

private:
    std::string m_path;
    bool m_active;
};

class ProgressBar {
public:
    ProgressBar(const char* label, uint64_t totalBytes)
        : m_label(label), m_totalBytes(totalBytes) {
        if (m_totalBytes == 0) {
            m_enabled = false;
            return;
        }
        render(0, 0);
    }

    void update(uint64_t processedBytes) {
        if (!m_enabled) {
            return;
        }

        uint64_t clamped = std::min(processedBytes, m_totalBytes);
        uint32_t percent = static_cast<uint32_t>((clamped * 100) / m_totalBytes);
        if (percent == m_lastPercent && clamped < m_totalBytes && clamped < (m_lastBytes + kMinBytesStep)) {
            return;
        }

        render(percent, clamped);
        m_lastPercent = percent;
        m_lastBytes = clamped;
    }

    void finish() {
        if (!m_enabled) {
            return;
        }
        render(100, m_totalBytes);
        std::cout << "\n";
        std::cout.flush();
    }

private:
    static constexpr uint64_t kMinBytesStep = 4ULL * 1024ULL * 1024ULL;
    static constexpr size_t kBarWidth = 30;

    void render(uint32_t percent, uint64_t processedBytes) {
        size_t filled = static_cast<size_t>((percent * kBarWidth) / 100);
        std::string bar(kBarWidth, '-');
        std::fill(bar.begin(), bar.begin() + static_cast<std::ptrdiff_t>(filled), '#');

        std::cout << '\r' << m_label << " [" << bar << "] "
                  << std::setw(3) << percent << "% ("
                  << processedBytes << "/" << m_totalBytes << " bytes)";
        std::cout.flush();
    }

    const char* m_label;
    uint64_t m_totalBytes = 0;
    uint64_t m_lastBytes = 0;
    uint32_t m_lastPercent = 0;
    bool m_enabled = true;
};

template <typename ArrayT>
class ArrayWiper {
public:
    explicit ArrayWiper(ArrayT& array) : m_array(array) {}
    ~ArrayWiper() { secureZero(m_array.data(), m_array.size()); }

private:
    ArrayT& m_array;
};

class KeyWiper {
public:
    explicit KeyWiper(KeyMaterial& keys) : m_keys(keys) {}
    ~KeyWiper() {
        secureZero(m_keys.aeadKey.data(), m_keys.aeadKey.size());
    }

private:
    KeyMaterial& m_keys;
};

struct ErrorState {
    std::mutex mutex;
    std::exception_ptr error;
    std::atomic<bool> stop{false};

    void fail(
        std::exception_ptr ep,
        BlockingQueue<Chunk>& inQueue,
        BlockingQueue<Chunk>& outQueue,
        BufferPool& pool) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (!error) {
                error = ep;
            }
        }
        stop.store(true);
        inQueue.close();
        outQueue.close();
        pool.shutdown();
    }
};

uint64_t chunkPlainSize(const FileHeader& header, uint64_t chunkIndex) {
    uint64_t chunkOffset = chunkIndex * static_cast<uint64_t>(header.chunkSize);
    if (chunkOffset >= header.originalSize) {
        return 0;
    }
    return std::min<uint64_t>(header.chunkSize, header.originalSize - chunkOffset);
}

} // namespace

void encryptFile(
    const std::string& inputPath,
    const std::string& outputPath,
    const std::string& password,
    const Options& options) {
    Logger::setVerbose(options.verbose);

    auto input = makeFileHandler();
    input->openForReading(inputPath, FileOpenOptions{false, options.directIo});
    uint64_t fileSize = input->getFileSize();

    uint32_t chunkSize = resolveChunkSize(options.chunkSize);
    std::array<uint8_t, CryptoEngine::kSaltSize> salt{};
    std::array<uint8_t, CryptoEngine::kNonceSize> nonce{};
    ArrayWiper saltWiper(salt);
    ArrayWiper nonceWiper(nonce);
    secureRandom(salt.data(), salt.size());
    secureRandom(nonce.data(), nonce.size());

    uint32_t flags = options.directIo ? kFlagDirectIoRequested : 0u;
    FileHeader header = makeHeader(
        fileSize,
        chunkSize,
        CryptoEngine::kDefaultIterations,
        flags,
        salt.data(),
        nonce.data());

    KeyMaterial keys = CryptoEngine::deriveKey(password, salt.data(), salt.size(), header.kdfIterations);
    KeyWiper keyWiper(keys);

    uint64_t finalSize = sizeof(FileHeader) + fileSize +
        (header.chunkCount * static_cast<uint64_t>(CryptoEngine::kTagSize));

    OutputGuard outputGuard(outputPath);
    auto output = makeFileHandler();
    output->openForWriting(outputPath, FileOpenOptions{options.overwrite, false});
    output->setFileSize(finalSize);
    output->seek(0, SeekWhence::Begin);
    output->writeExact(&header, sizeof(header));
    outputGuard.arm();

    unsigned int threads = resolveThreads(options.threads);
    size_t queueCapacity = std::max<size_t>(4, threads * 2);

    BufferPool pool(chunkSize, std::max<size_t>(queueCapacity, threads + 2));
    BlockingQueue<Chunk> toProcess(queueCapacity);
    BlockingQueue<Chunk> toWrite(queueCapacity);
    ErrorState errorState;

    std::thread reader([&]() {
        try {
            uint64_t offset = 0;
            uint64_t index = 0;
            while (offset < fileSize && !errorState.stop.load()) {
                size_t toRead = static_cast<size_t>(std::min<uint64_t>(chunkSize, fileSize - offset));
                Chunk chunk;
                chunk.index = index;
                chunk.buffer = pool.acquire();
                chunk.buffer.setSize(toRead);
                size_t readNow = input->read(chunk.buffer.data(), toRead);
                if (readNow != toRead) {
                    throw std::runtime_error("Short read detected while encrypting.");
                }

                if (!toProcess.push(std::move(chunk))) {
                    break;
                }

                offset += readNow;
                ++index;
            }
        } catch (...) {
            errorState.fail(std::current_exception(), toProcess, toWrite, pool);
        }
        toProcess.close();
    });

    std::vector<std::thread> workers;
    workers.reserve(threads);
    for (unsigned int i = 0; i < threads; ++i) {
        workers.emplace_back([&]() {
            try {
                Chunk chunk;
                while (!errorState.stop.load() && toProcess.pop(chunk)) {
                    auto chunkNonce = CryptoEngine::nonceForChunk(nonce, chunk.index);
                    auto aad = buildChunkAad(chunk.index, chunk.buffer.size());
                    chunk.tag = ChaCha20Poly1305::encrypt(
                        chunk.buffer.data(),
                        chunk.buffer.size(),
                        keys.aeadKey,
                        chunkNonce,
                        aad.data(),
                        aad.size());
                    if (!toWrite.push(std::move(chunk))) {
                        break;
                    }
                }
            } catch (...) {
                errorState.fail(std::current_exception(), toProcess, toWrite, pool);
            }
        });
    }

    std::thread writer([&]() {
        try {
            uint64_t nextIndex = 0;
            uint64_t writtenBytes = 0;
            std::map<uint64_t, Chunk> pending;
            ProgressBar progress("Encrypting", fileSize);

            Chunk chunk;
            while (toWrite.pop(chunk)) {
                pending.emplace(chunk.index, std::move(chunk));
                auto it = pending.find(nextIndex);
                while (it != pending.end()) {
                    Chunk& ready = it->second;
                    output->writeExact(ready.buffer.data(), ready.buffer.size());
                    output->writeExact(ready.tag.data(), ready.tag.size());
                    writtenBytes += ready.buffer.size();
                    progress.update(writtenBytes);
                    pending.erase(it);
                    ++nextIndex;
                    it = pending.find(nextIndex);
                }
            }

            if (!pending.empty() && !errorState.stop.load()) {
                throw std::runtime_error("Writer queue closed with pending encrypted chunks.");
            }
            progress.finish();
        } catch (...) {
            errorState.fail(std::current_exception(), toProcess, toWrite, pool);
        }
    });

    reader.join();
    for (auto& worker : workers) {
        worker.join();
    }
    toWrite.close();
    writer.join();

    if (errorState.error) {
        std::rethrow_exception(errorState.error);
    }

    output->flush();
    outputGuard.release();
    Logger::info("Encryption complete.");
}

void decryptFile(
    const std::string& inputPath,
    const std::string& outputPath,
    const std::string& password,
    const Options& options) {
    Logger::setVerbose(options.verbose);

    auto input = makeFileHandler();
    input->openForReading(inputPath, FileOpenOptions{});

    uint64_t fileSize = input->getFileSize();
    if (fileSize < sizeof(FileHeader)) {
        throw std::runtime_error("Input file is too small to be a FastShield archive.");
    }

    FileHeader header{};
    input->readExact(&header, sizeof(header));
    if (!validateHeader(header)) {
        throw std::runtime_error("Invalid FastShield V2 header.");
    }

    uint64_t expectedPayload = header.originalSize +
        (header.chunkCount * static_cast<uint64_t>(CryptoEngine::kTagSize));
    uint64_t expectedFileSize = sizeof(FileHeader) + expectedPayload;
    if (fileSize != expectedFileSize) {
        throw std::runtime_error("Encrypted file size does not match header metadata.");
    }

    uint32_t chunkSize = resolveChunkSize(options.chunkSize == 0 ? header.chunkSize : options.chunkSize);

    std::array<uint8_t, CryptoEngine::kNonceSize> nonce{};
    ArrayWiper nonceWiper(nonce);
    std::copy(std::begin(header.nonce), std::end(header.nonce), nonce.begin());

    KeyMaterial keys = CryptoEngine::deriveKey(password, header.salt, CryptoEngine::kSaltSize, header.kdfIterations);
    KeyWiper keyWiper(keys);

    OutputGuard outputGuard(outputPath);
    auto output = makeFileHandler();
    output->openForWriting(outputPath, FileOpenOptions{options.overwrite, options.directIo});

    if (output->directIoEnabled()) {
        size_t align = output->requiredAlignment();
        if ((chunkSize % align) != 0 || (header.originalSize % align) != 0) {
            throw std::runtime_error(
                "Direct I/O requires chunk size and output size to be aligned to device page size.");
        }
    }

    output->setFileSize(header.originalSize);
    output->seek(0, SeekWhence::Begin);
    outputGuard.arm();

    unsigned int threads = resolveThreads(options.threads);
    size_t queueCapacity = std::max<size_t>(4, threads * 2);
    BufferPool pool(chunkSize, std::max<size_t>(queueCapacity, threads + 2));
    BlockingQueue<Chunk> toProcess(queueCapacity);
    BlockingQueue<Chunk> toWrite(queueCapacity);
    ErrorState errorState;

    std::thread reader([&]() {
        try {
            for (uint64_t chunkIndex = 0; chunkIndex < header.chunkCount && !errorState.stop.load(); ++chunkIndex) {
                uint64_t plainSize = chunkPlainSize(header, chunkIndex);
                if (plainSize == 0) {
                    break;
                }

                Chunk chunk;
                chunk.index = chunkIndex;
                chunk.buffer = pool.acquire();
                chunk.buffer.setSize(static_cast<size_t>(plainSize));
                input->readExact(chunk.buffer.data(), chunk.buffer.size());
                input->readExact(chunk.tag.data(), chunk.tag.size());

                if (!toProcess.push(std::move(chunk))) {
                    break;
                }
            }
        } catch (...) {
            errorState.fail(std::current_exception(), toProcess, toWrite, pool);
        }
        toProcess.close();
    });

    std::vector<std::thread> workers;
    workers.reserve(threads);
    for (unsigned int i = 0; i < threads; ++i) {
        workers.emplace_back([&]() {
            try {
                Chunk chunk;
                while (!errorState.stop.load() && toProcess.pop(chunk)) {
                    auto chunkNonce = CryptoEngine::nonceForChunk(nonce, chunk.index);
                    auto aad = buildChunkAad(chunk.index, chunk.buffer.size());
                    bool ok = ChaCha20Poly1305::decryptAndVerify(
                        chunk.buffer.data(),
                        chunk.buffer.size(),
                        keys.aeadKey,
                        chunkNonce,
                        aad.data(),
                        aad.size(),
                        chunk.tag);
                    if (!ok) {
                        throw std::runtime_error("AEAD verification failed. Wrong password or corrupted file.");
                    }

                    if (!toWrite.push(std::move(chunk))) {
                        break;
                    }
                }
            } catch (...) {
                errorState.fail(std::current_exception(), toProcess, toWrite, pool);
            }
        });
    }

    std::thread writer([&]() {
        try {
            uint64_t nextIndex = 0;
            uint64_t writtenBytes = 0;
            std::map<uint64_t, Chunk> pending;
            ProgressBar progress("Decrypting", header.originalSize);

            Chunk chunk;
            while (toWrite.pop(chunk)) {
                pending.emplace(chunk.index, std::move(chunk));
                auto it = pending.find(nextIndex);
                while (it != pending.end()) {
                    Chunk& ready = it->second;
                    output->writeExact(ready.buffer.data(), ready.buffer.size());
                    writtenBytes += ready.buffer.size();
                    progress.update(writtenBytes);
                    pending.erase(it);
                    ++nextIndex;
                    it = pending.find(nextIndex);
                }
            }

            if (!pending.empty() && !errorState.stop.load()) {
                throw std::runtime_error("Writer queue closed with pending decrypted chunks.");
            }
            progress.finish();
        } catch (...) {
            errorState.fail(std::current_exception(), toProcess, toWrite, pool);
        }
    });

    reader.join();
    for (auto& worker : workers) {
        worker.join();
    }
    toWrite.close();
    writer.join();

    if (errorState.error) {
        std::rethrow_exception(errorState.error);
    }

    output->flush();
    outputGuard.release();
    Logger::info("Decryption complete.");
}

} // namespace fastshield
