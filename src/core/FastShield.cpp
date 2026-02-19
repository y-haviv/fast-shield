#include "core/FastShield.hpp"

#include "core/CryptoEngine.hpp"
#include "core/FileFormat.hpp"
#include "core/HmacSha256.hpp"
#include "io/Win32FileHandler.hpp"
#include "utils/BlockingQueue.hpp"
#include "utils/Logger.hpp"
#include "utils/Random.hpp"
#include "utils/SecureZero.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <exception>
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
    uint64_t offset = 0;
    std::vector<uint8_t> data;
};

// Default chunk size used when none is provided.
constexpr uint32_t kDefaultChunkSize = 4 * 1024 * 1024;
// Upper bound to avoid excessive memory usage per chunk.
constexpr uint32_t kMaxChunkSize = 256 * 1024 * 1024;

// Resolve the number of worker threads to use.
unsigned int resolveThreads(unsigned int requested) {
    if (requested > 0) {
        return requested;
    }
    unsigned int hc = std::thread::hardware_concurrency();
    return hc == 0 ? 4 : hc;
}

// Resolve and validate the chunk size.
uint32_t resolveChunkSize(uint32_t requested) {
    uint32_t size = requested == 0 ? kDefaultChunkSize : requested;
    if (size > kMaxChunkSize) {
        std::ostringstream oss;
        oss << "Chunk size too large. Maximum is " << kMaxChunkSize << " bytes.";
        throw std::runtime_error(oss.str());
    }
    return size;
}

struct ErrorState {
    std::mutex mutex;
    std::exception_ptr error;
    std::atomic<bool> stop{false};

    // Capture the first error, stop other threads, and close queues.
    void fail(std::exception_ptr ep,
              BlockingQueue<Chunk>& inQueue,
              BlockingQueue<Chunk>& outQueue) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (!error) {
                error = ep;
            }
        }
        stop.store(true);
        inQueue.close();
        outQueue.close();
    }
};

bool constantTimeEqual(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

class OutputGuard {
public:
    explicit OutputGuard(const std::string& path)
        : m_path(path), m_active(false) {}

    void arm() { m_active = true; }
    void release() { m_active = false; }

    ~OutputGuard() {
        if (m_active) {
            DeleteFileA(m_path.c_str());
        }
    }

private:
    std::string m_path;
    bool m_active;
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
        secureZero(m_keys.encKey.data(), m_keys.encKey.size());
        secureZero(m_keys.macKey.data(), m_keys.macKey.size());
    }

private:
    KeyMaterial& m_keys;
};

} // namespace

void encryptFile(
    const std::string& inputPath,
    const std::string& outputPath,
    const std::string& password,
    const Options& options) {
    Logger::setVerbose(options.verbose);
    Logger::info("Opening input file.");

    Win32FileHandler input(inputPath);
    input.openForReading();
    uint64_t fileSize = input.getFileSize();

    if (fileSize > CryptoEngine::kMaxBytes) {
        throw std::runtime_error("Input file exceeds ChaCha20 maximum stream size (256 GiB).");
    }

    Logger::info("Preparing output file.");
    OutputGuard outputGuard(outputPath);
    Win32FileHandler output(outputPath);
    output.openForWriting(outputPath, options.overwrite);
    uint64_t finalSize = sizeof(FileHeader) + fileSize + CryptoEngine::kMacSize;
    output.setFileSize(finalSize);
    output.seek(0, FILE_BEGIN);
    outputGuard.arm();

    std::array<uint8_t, CryptoEngine::kSaltSize> salt{};
    std::array<uint8_t, CryptoEngine::kNonceSize> nonce{};
    ArrayWiper saltWiper(salt);
    ArrayWiper nonceWiper(nonce);
    secureRandom(salt.data(), salt.size());
    secureRandom(nonce.data(), nonce.size());

    uint32_t chunkSize = resolveChunkSize(options.chunkSize);
    // The header is written unencrypted and authenticated via HMAC.
    FileHeader header = makeHeader(
        fileSize,
        chunkSize,
        CryptoEngine::kDefaultIterations,
        salt.data(),
        nonce.data());

    KeyMaterial keys = CryptoEngine::deriveKey(
        password,
        salt.data(),
        salt.size(),
        header.kdfIterations);
    KeyWiper keyWiper(keys);

    // HMAC covers header + ciphertext.
    HmacSha256 hmac(keys.macKey.data(), keys.macKey.size());
    hmac.update(reinterpret_cast<const uint8_t*>(&header), sizeof(header));

    output.writeExact(&header, sizeof(header));

    unsigned int threads = resolveThreads(options.threads);
    size_t queueCapacity = std::max<size_t>(4, threads * 2);
    BlockingQueue<Chunk> toEncrypt(queueCapacity);
    BlockingQueue<Chunk> toWrite(queueCapacity);
    ErrorState errorState;

    // Reader: pull chunks from disk and enqueue for workers.
    std::thread reader([&]() {
        try {
            uint64_t offset = 0;
            uint64_t index = 0;
            while (offset < fileSize && !errorState.stop.load()) {
                size_t toRead = static_cast<size_t>(
                    std::min<uint64_t>(chunkSize, fileSize - offset));
                Chunk chunk;
                chunk.index = index;
                chunk.offset = offset;
                chunk.data.resize(toRead);
                size_t readNow = input.read(chunk.data.data(), toRead);
                if (readNow != toRead) {
                    throw std::runtime_error("Short read detected.");
                }
                if (!toEncrypt.push(std::move(chunk))) {
                    break;
                }
                offset += readNow;
                ++index;
            }
        } catch (...) {
            errorState.fail(std::current_exception(), toEncrypt, toWrite);
        }
        toEncrypt.close();
    });

    // Workers: encrypt chunks in parallel.
    std::vector<std::thread> workers;
    workers.reserve(threads);
    for (unsigned int i = 0; i < threads; ++i) {
        workers.emplace_back([&]() {
            try {
                Chunk chunk;
                while (!errorState.stop.load() && toEncrypt.pop(chunk)) {
                    CryptoEngine::cryptBuffer(
                        chunk.data.data(),
                        chunk.data.size(),
                        keys,
                        nonce,
                        chunk.offset);
                    if (!toWrite.push(std::move(chunk))) {
                        break;
                    }
                }
            } catch (...) {
                errorState.fail(std::current_exception(), toEncrypt, toWrite);
            }
        });
    }

    // Writer: restore order, update HMAC, and write ciphertext.
    std::thread writer([&]() {
        try {
            uint64_t nextIndex = 0;
            std::map<uint64_t, Chunk> pending;
            Chunk chunk;
            while (toWrite.pop(chunk)) {
                pending.emplace(chunk.index, std::move(chunk));
                auto it = pending.find(nextIndex);
                while (it != pending.end()) {
                    Chunk& ready = it->second;
                    hmac.update(ready.data.data(), ready.data.size());
                    output.writeExact(ready.data.data(), ready.data.size());
                    pending.erase(it);
                    ++nextIndex;
                    it = pending.find(nextIndex);
                }
            }

            if (!pending.empty() && !errorState.stop.load()) {
                throw std::runtime_error("Write queue closed with pending chunks.");
            }
        } catch (...) {
            errorState.fail(std::current_exception(), toEncrypt, toWrite);
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

    // Append the MAC after all ciphertext is written.
    auto mac = hmac.final();
    output.writeExact(mac.data(), mac.size());
    outputGuard.release();
    Logger::info("Encryption complete.");
}

void decryptFile(
    const std::string& inputPath,
    const std::string& outputPath,
    const std::string& password,
    const Options& options) {
    Logger::setVerbose(options.verbose);
    Logger::info("Opening input file.");

    Win32FileHandler input(inputPath);
    input.openForReading();
    uint64_t fileSize = input.getFileSize();

    if (fileSize < sizeof(FileHeader) + CryptoEngine::kMacSize) {
        throw std::runtime_error("Input file is too small to be a FastShield archive.");
    }

    FileHeader header{};
    // Read and validate the file header.
    input.readExact(&header, sizeof(header));
    if (!validateHeader(header)) {
        throw std::runtime_error("Invalid FastShield header.");
    }

    uint64_t cipherSize = fileSize - sizeof(FileHeader) - CryptoEngine::kMacSize;
    if (cipherSize != header.originalSize) {
        throw std::runtime_error("Ciphertext size does not match header metadata.");
    }

    if (cipherSize > CryptoEngine::kMaxBytes) {
        throw std::runtime_error("Encrypted payload exceeds ChaCha20 maximum stream size (256 GiB).");
    }

    // Read the expected MAC from the end of the file.
    std::array<uint8_t, CryptoEngine::kMacSize> expectedMac{};
    input.seek(static_cast<uint64_t>(fileSize - CryptoEngine::kMacSize), FILE_BEGIN);
    input.readExact(expectedMac.data(), expectedMac.size());

    input.seek(sizeof(FileHeader), FILE_BEGIN);

    // Derive keys from password and stored salt.
    KeyMaterial keys = CryptoEngine::deriveKey(
        password,
        header.salt,
        CryptoEngine::kSaltSize,
        header.kdfIterations);
    KeyWiper keyWiper(keys);

    // Nonce is stored in the header.
    std::array<uint8_t, CryptoEngine::kNonceSize> nonce{};
    ArrayWiper nonceWiper(nonce);
    std::copy(std::begin(header.nonce), std::end(header.nonce), nonce.begin());

    // Recompute HMAC while streaming ciphertext.
    HmacSha256 hmac(keys.macKey.data(), keys.macKey.size());
    hmac.update(reinterpret_cast<const uint8_t*>(&header), sizeof(header));

    Logger::info("Preparing output file.");
    OutputGuard outputGuard(outputPath);
    Win32FileHandler output(outputPath);
    output.openForWriting(outputPath, options.overwrite);
    output.setFileSize(header.originalSize);
    output.seek(0, FILE_BEGIN);
    outputGuard.arm();

    uint32_t chunkSize = resolveChunkSize(options.chunkSize == 0 ? header.chunkSize : options.chunkSize);
    unsigned int threads = resolveThreads(options.threads);
    size_t queueCapacity = std::max<size_t>(4, threads * 2);
    BlockingQueue<Chunk> toDecrypt(queueCapacity);
    BlockingQueue<Chunk> toWrite(queueCapacity);
    ErrorState errorState;

    // Reader: read ciphertext chunks and update HMAC.
    std::thread reader([&]() {
        try {
            uint64_t offset = 0;
            uint64_t index = 0;
            while (offset < cipherSize && !errorState.stop.load()) {
                size_t toRead = static_cast<size_t>(
                    std::min<uint64_t>(chunkSize, cipherSize - offset));
                Chunk chunk;
                chunk.index = index;
                chunk.offset = offset;
                chunk.data.resize(toRead);
                size_t readNow = input.read(chunk.data.data(), toRead);
                if (readNow != toRead) {
                    throw std::runtime_error("Short read detected.");
                }
                hmac.update(chunk.data.data(), chunk.data.size());
                if (!toDecrypt.push(std::move(chunk))) {
                    break;
                }
                offset += readNow;
                ++index;
            }
        } catch (...) {
            errorState.fail(std::current_exception(), toDecrypt, toWrite);
        }
        toDecrypt.close();
    });

    // Workers: decrypt chunks in parallel.
    std::vector<std::thread> workers;
    workers.reserve(threads);
    for (unsigned int i = 0; i < threads; ++i) {
        workers.emplace_back([&]() {
            try {
                Chunk chunk;
                while (!errorState.stop.load() && toDecrypt.pop(chunk)) {
                    CryptoEngine::cryptBuffer(
                        chunk.data.data(),
                        chunk.data.size(),
                        keys,
                        nonce,
                        chunk.offset);
                    if (!toWrite.push(std::move(chunk))) {
                        break;
                    }
                }
            } catch (...) {
                errorState.fail(std::current_exception(), toDecrypt, toWrite);
            }
        });
    }

    // Writer: restore order and write plaintext.
    std::thread writer([&]() {
        try {
            uint64_t nextIndex = 0;
            std::map<uint64_t, Chunk> pending;
            Chunk chunk;
            while (toWrite.pop(chunk)) {
                pending.emplace(chunk.index, std::move(chunk));
                auto it = pending.find(nextIndex);
                while (it != pending.end()) {
                    Chunk& ready = it->second;
                    output.writeExact(ready.data.data(), ready.data.size());
                    pending.erase(it);
                    ++nextIndex;
                    it = pending.find(nextIndex);
                }
            }

            if (!pending.empty() && !errorState.stop.load()) {
                throw std::runtime_error("Write queue closed with pending chunks.");
            }
        } catch (...) {
            errorState.fail(std::current_exception(), toDecrypt, toWrite);
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

    // Compare expected MAC with computed MAC.
    auto actualMac = hmac.final();
    if (!constantTimeEqual(actualMac.data(), expectedMac.data(), actualMac.size())) {
        output.close();
        throw std::runtime_error("HMAC verification failed. Wrong password or corrupted file.");
    }

    outputGuard.release();
    Logger::info("Decryption complete.");
}

} // namespace fastshield
