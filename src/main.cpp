#include "core/FastShield.hpp"
#include "utils/Logger.hpp"
#include "utils/SecureZero.hpp"
#include "utils/SizeParser.hpp"

#include <iostream>
#include <stdexcept>
#include <string>

#ifndef FASTSHIELD_VERSION
#define FASTSHIELD_VERSION "dev"
#endif

namespace {

struct PasswordGuard {
    explicit PasswordGuard(std::string& value) : password(value) {}
    ~PasswordGuard() {
        if (!password.empty()) {
            fastshield::secureZero(password.data(), password.size());
        }
    }
    std::string& password;
};

void printUsage() {
    std::cout
        << "FastShield - High-speed file encryption for Windows\n"
        << "\n"
        << "Usage:\n"
        << "  fastshield encrypt -i <input> -o <output> -p <password> [options]\n"
        << "  fastshield decrypt -i <input> -o <output> -p <password> [options]\n"
        << "\n"
        << "Options:\n"
        << "  -i, --input <path>        Input file path\n"
        << "  -o, --output <path>       Output file path\n"
        << "  -p, --password <text>     Password (use with care)\n"
        << "  --password-stdin          Read password from stdin\n"
        << "  --threads <n>             Worker threads (default: auto)\n"
        << "  --chunk-size <size>       Chunk size (e.g. 4M, 16M)\n"
        << "  --overwrite               Allow overwriting the output file\n"
        << "  --verbose                 Enable debug logging\n"
        << "  -h, --help                Show this help text\n"
        << "  --version                 Show version\n"
        << "\n";
}

void printVersion() {
    std::cout << "FastShield version " << FASTSHIELD_VERSION << "\n";
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        // Basic CLI routing and validation.
        if (argc < 2) {
            printUsage();
            return 1;
        }

        std::string command = argv[1];
        if (command == "--help" || command == "-h") {
            printUsage();
            return 0;
        }
        if (command == "--version") {
            printVersion();
            return 0;
        }

        fastshield::Options options;
        std::string inputPath;
        std::string outputPath;
        std::string password;
        PasswordGuard passwordGuard(password);
        bool passwordFromStdin = false;

        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "-i" || arg == "--input") {
                if (i + 1 >= argc) {
                    throw std::runtime_error("Missing value for --input.");
                }
                inputPath = argv[++i];
            } else if (arg == "-o" || arg == "--output") {
                if (i + 1 >= argc) {
                    throw std::runtime_error("Missing value for --output.");
                }
                outputPath = argv[++i];
            } else if (arg == "-p" || arg == "--password") {
                if (i + 1 >= argc) {
                    throw std::runtime_error("Missing value for --password.");
                }
                password = argv[++i];
            } else if (arg == "--password-stdin") {
                passwordFromStdin = true;
            } else if (arg == "--threads") {
                if (i + 1 >= argc) {
                    throw std::runtime_error("Missing value for --threads.");
                }
                options.threads = static_cast<unsigned int>(std::stoul(argv[++i]));
            } else if (arg == "--chunk-size") {
                if (i + 1 >= argc) {
                    throw std::runtime_error("Missing value for --chunk-size.");
                }
                uint64_t size = fastshield::parseSize(argv[++i]);
                if (size > 0xFFFFFFFFu) {
                    throw std::runtime_error("Chunk size exceeds 4 GiB.");
                }
                options.chunkSize = static_cast<uint32_t>(size);
            } else if (arg == "--overwrite") {
                options.overwrite = true;
            } else if (arg == "--verbose") {
                options.verbose = true;
            } else if (arg == "--help" || arg == "-h") {
                printUsage();
                return 0;
            } else if (arg == "--version") {
                printVersion();
                return 0;
            } else {
                throw std::runtime_error("Unknown argument: " + arg);
            }
        }

        if (passwordFromStdin) {
            // Read the password from stdin to avoid shell history leaks.
            std::getline(std::cin, password);
        }

        if (command != "encrypt" && command != "decrypt") {
            throw std::runtime_error("First argument must be 'encrypt' or 'decrypt'.");
        }

        if (inputPath.empty()) {
            throw std::runtime_error("Input path is required.");
        }
        if (outputPath.empty()) {
            throw std::runtime_error("Output path is required.");
        }
        if (password.empty()) {
            throw std::runtime_error("Password is required.");
        }

        if (command == "encrypt") {
            fastshield::encryptFile(inputPath, outputPath, password, options);
        } else {
            fastshield::decryptFile(inputPath, outputPath, password, options);
        }
        return 0;
    } catch (const std::exception& ex) {
        fastshield::Logger::error(ex.what());
        return 1;
    }
}
