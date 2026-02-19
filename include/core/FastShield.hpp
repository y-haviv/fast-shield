#ifndef FASTSHIELD_FASTSHIELD_HPP
#define FASTSHIELD_FASTSHIELD_HPP

#include <cstdint>
#include <string>

namespace fastshield {

struct Options {
    uint32_t chunkSize = 0;
    unsigned int threads = 0;
    bool overwrite = false;
    bool verbose = false;
};

/// Encrypt a file to the FastShield format.
void encryptFile(
    const std::string& inputPath,
    const std::string& outputPath,
    const std::string& password,
    const Options& options);

/// Decrypt a FastShield file back to plaintext.
void decryptFile(
    const std::string& inputPath,
    const std::string& outputPath,
    const std::string& password,
    const Options& options);

} // namespace fastshield

#endif // FASTSHIELD_FASTSHIELD_HPP
