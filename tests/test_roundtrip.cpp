#include "core/ChaCha20Poly1305.hpp"
#include "core/CryptoEngine.hpp"
#include "core/FastShield.hpp"
#include "core/FileFormat.hpp"

#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::string uniquePath(const std::string& suffix) {
    auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    auto dir = std::filesystem::temp_directory_path();
    return (dir / ("fastshield_v2_test_" + std::to_string(now) + "_" + suffix)).string();
}

std::vector<uint8_t> loadFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open file for reading: " + path);
    }
    in.seekg(0, std::ios::end);
    std::streamsize size = in.tellg();
    in.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(static_cast<size_t>(size));
    if (size > 0) {
        in.read(reinterpret_cast<char*>(data.data()), size);
    }
    return data;
}

void writeFile(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("Failed to open file for writing: " + path);
    }
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

void cleanup(const std::vector<std::string>& paths) {
    for (const auto& path : paths) {
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
}

void testRoundTripAead() {
    std::string input = uniquePath("input.bin");
    std::string encrypted = uniquePath("encrypted.fs");
    std::string decrypted = uniquePath("decrypted.bin");

    std::vector<uint8_t> data(2 * 1024 * 1024 + 333);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<uint8_t>((i * 131) % 251);
    }
    writeFile(input, data);

    fastshield::Options options;
    options.chunkSize = 256 * 1024;
    options.threads = 3;
    options.overwrite = true;

    const std::string password = "test-password";
    fastshield::encryptFile(input, encrypted, password, options);
    fastshield::decryptFile(encrypted, decrypted, password, options);

    auto restored = loadFile(decrypted);
    if (restored != data) {
        throw std::runtime_error("Round-trip data mismatch for AEAD pipeline.");
    }

    auto encryptedRaw = loadFile(encrypted);
    if (encryptedRaw.size() < sizeof(fastshield::FileHeader)) {
        throw std::runtime_error("Encrypted archive too small for header.");
    }

    fastshield::FileHeader header{};
    std::memcpy(&header, encryptedRaw.data(), sizeof(header));
    if (header.version != fastshield::kFormatVersion) {
        throw std::runtime_error("Header version mismatch (expected V2).");
    }
    if (header.tagSize != fastshield::CryptoEngine::kTagSize) {
        throw std::runtime_error("Header tag size mismatch.");
    }

    cleanup({input, encrypted, decrypted});
}

void testTamperChunkTagFailure() {
    std::string input = uniquePath("tamper_input.bin");
    std::string encrypted = uniquePath("tamper_encrypted.fs");
    std::string decrypted = uniquePath("tamper_decrypted.bin");

    std::vector<uint8_t> data(512 * 1024, 0x5a);
    writeFile(input, data);

    fastshield::Options options;
    options.chunkSize = 64 * 1024;
    options.threads = 2;
    options.overwrite = true;

    const std::string password = "test-password";
    fastshield::encryptFile(input, encrypted, password, options);

    std::fstream tamper(encrypted, std::ios::binary | std::ios::in | std::ios::out);
    if (!tamper) {
        throw std::runtime_error("Failed to open encrypted file for tampering.");
    }

    const std::streamoff offset = static_cast<std::streamoff>(sizeof(fastshield::FileHeader) + 1024);
    tamper.seekg(offset);
    char byte = 0;
    tamper.read(&byte, 1);
    tamper.clear();
    tamper.seekp(offset);
    byte ^= static_cast<char>(0xA5);
    tamper.write(&byte, 1);
    tamper.close();

    bool failed = false;
    try {
        fastshield::decryptFile(encrypted, decrypted, password, options);
    } catch (const std::exception&) {
        failed = true;
    }

    if (!failed) {
        throw std::runtime_error("Tampered archive unexpectedly decrypted successfully.");
    }
    if (std::filesystem::exists(decrypted)) {
        throw std::runtime_error("Partial decrypted output was not deleted after authentication failure.");
    }

    cleanup({input, encrypted, decrypted});
}

void testDirectIoAlignedPath() {
    std::string input = uniquePath("dio_input.bin");
    std::string encrypted = uniquePath("dio_encrypted.fs");
    std::string decrypted = uniquePath("dio_decrypted.bin");

    const size_t alignedSize = 4096 * 32;
    std::vector<uint8_t> data(alignedSize);
    std::mt19937 rng(7);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<uint8_t>(rng() & 0xff);
    }
    writeFile(input, data);

    fastshield::Options options;
    options.chunkSize = 4096;
    options.threads = 2;
    options.overwrite = true;
    options.directIo = true;

    const std::string password = "test-password";
    fastshield::encryptFile(input, encrypted, password, options);
    fastshield::decryptFile(encrypted, decrypted, password, options);

    auto restored = loadFile(decrypted);
    if (restored != data) {
        throw std::runtime_error("Direct I/O round-trip mismatch.");
    }

    cleanup({input, encrypted, decrypted});
}

void testLargeChunkIndexNonceBehavior() {
    std::array<uint8_t, fastshield::CryptoEngine::kNonceSize> baseNonce{};
    for (size_t i = 0; i < baseNonce.size(); ++i) {
        baseNonce[i] = static_cast<uint8_t>(i + 1);
    }

    const uint64_t largeIndex = 0x1'0000'0005ULL;
    auto nonceA = fastshield::CryptoEngine::nonceForChunk(baseNonce, largeIndex);
    auto nonceB = fastshield::CryptoEngine::nonceForChunk(baseNonce, largeIndex + 1);
    if (nonceA == nonceB) {
        throw std::runtime_error("Chunk nonce derivation collision at large index.");
    }

    std::array<uint8_t, 32> key{};
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(0x10 + i);
    }

    std::vector<uint8_t> payload(4096, 0x42);
    auto aad = std::array<uint8_t, 16>{};
    for (size_t i = 0; i < 8; ++i) {
        aad[i] = static_cast<uint8_t>((largeIndex >> (i * 8)) & 0xffu);
        aad[8 + i] = static_cast<uint8_t>((payload.size() >> (i * 8)) & 0xffu);
    }

    auto tag = fastshield::ChaCha20Poly1305::encrypt(
        payload.data(), payload.size(), key, nonceA, aad.data(), aad.size());

    bool ok = fastshield::ChaCha20Poly1305::decryptAndVerify(
        payload.data(), payload.size(), key, nonceA, aad.data(), aad.size(), tag);
    if (!ok) {
        throw std::runtime_error("Large-index AEAD verification failed.");
    }
}

} // namespace

int main() {
    try {
        testRoundTripAead();
        testTamperChunkTagFailure();
        testDirectIoAlignedPath();
        testLargeChunkIndexNonceBehavior();
        std::cout << "FastShield V2 tests passed.\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "FastShield V2 tests failed: " << ex.what() << "\n";
        return 1;
    }
}
