#include "core/FastShield.hpp"
#include "core/FileFormat.hpp"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <sstream>
#include <iomanip>

namespace {

std::string uniquePath(const std::string& suffix) {
    auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::filesystem::path dir = std::filesystem::temp_directory_path();
    std::string name = "fastshield_test_" + std::to_string(now) + "_" + suffix;
    return (dir / name).string();
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

std::string generatePassword(size_t len = 16) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(dist(gen));
    }
    return ss.str();
}

void testRoundTrip() {
    std::string input = uniquePath("input.bin");
    std::string encrypted = uniquePath("encrypted.fs");
    std::string decrypted = uniquePath("decrypted.bin");

    std::vector<uint8_t> data(1024 * 1024);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<uint8_t>(i % 251);
    }
    writeFile(input, data);

    fastshield::Options options;
    options.chunkSize = 256 * 1024;
    options.threads = 2;
    options.overwrite = true;

    std::string testPassword = generatePassword();
    fastshield::encryptFile(input, encrypted, testPassword, options);
    fastshield::decryptFile(encrypted, decrypted, testPassword, options);

    auto restored = loadFile(decrypted);
    if (restored != data) {
        throw std::runtime_error("Round-trip data mismatch.");
    }

    std::filesystem::remove(input);
    std::filesystem::remove(encrypted);
    std::filesystem::remove(decrypted);
}

void testTamper() {
    std::string input = uniquePath("input2.bin");
    std::string encrypted = uniquePath("encrypted2.fs");
    std::string decrypted = uniquePath("decrypted2.bin");

    std::vector<uint8_t> data(128 * 1024, 0x5a);
    writeFile(input, data);

    fastshield::Options options;
    options.chunkSize = 64 * 1024;
    options.threads = 2;
    options.overwrite = true;

    std::string testPassword = generatePassword();
    fastshield::encryptFile(input, encrypted, testPassword, options);

    std::fstream tamper(encrypted, std::ios::binary | std::ios::in | std::ios::out);
    if (!tamper) {
        throw std::runtime_error("Failed to open encrypted file for tampering.");
    }
    tamper.seekg(sizeof(fastshield::FileHeader) + 10, std::ios::beg);
    char byte = 0;
    tamper.read(&byte, 1);
    tamper.clear();
    tamper.seekp(sizeof(fastshield::FileHeader) + 10, std::ios::beg);
    byte ^= 0xFF;
    tamper.write(&byte, 1);
    tamper.close();

    bool failed = false;
    try {
        fastshield::decryptFile(encrypted, decrypted, "test-password", options);
    } catch (const std::exception&) {
        failed = true;
    }

    if (!failed) {
        throw std::runtime_error("Tamper test did not fail as expected.");
    }

    std::filesystem::remove(input);
    std::filesystem::remove(encrypted);
    std::filesystem::remove(decrypted);
}

} // namespace

int main() {
    try {
        testRoundTrip();
        testTamper();
        std::cout << "FastShield tests passed.\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "FastShield tests failed: " << ex.what() << "\n";
        return 1;
    }
}
