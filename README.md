# FastShield

FastShield is a Windows-focused CLI tool that encrypts and decrypts large files with high throughput (up to 256 GiB per stream). It streams data from disk, processes chunks in parallel, and avoids unnecessary copying to keep performance high while preserving integrity.

## Key Goals
- Fast, streaming encryption and decryption for large files.
- Parallel processing across CPU cores.
- Reliable, verified output with HMAC integrity checks.
- Clean, organized architecture that is easy to extend.

## Architecture (Layered)
1. Driver/OS Layer (Win32): `Win32FileHandler` wraps CreateFile/ReadFile/WriteFile and file sizing.
2. Core Logic Layer: ChaCha20 stream cipher, PBKDF2-HMAC-SHA256 key derivation, HMAC-SHA256 integrity.
3. Orchestrator Layer: Pipeline that reads, encrypts/decrypts, and writes in parallel.
4. Interface Layer: CLI entry point in `src/main.cpp`.

## File Format
FastShield writes a compact header followed by ciphertext, and ends with an HMAC.

Layout:
- 64-byte header (magic, version, chunk size, original size, salt, nonce)
- Ciphertext payload (same size as plaintext)
- 32-byte HMAC-SHA256 (header + ciphertext)

## Build (Windows, CMake)
Requirements:
- CMake 3.21+
- Visual Studio 2022 (MSVC) or another C++20-capable compiler

Steps:
1. Configure:
   - `cmake -S . -B build`
2. Build:
   - `cmake --build build --config Release`

The resulting executable is `build/Release/fastshield.exe` (or `build/fastshield.exe` for single-config generators).

## Usage
Encrypt:
- `fastshield encrypt -i input.bin -o output.fs -p "your-password"`

Decrypt:
- `fastshield decrypt -i output.fs -o restored.bin -p "your-password"`

Optional flags:
- `--threads <n>`: number of worker threads (default: auto)
- `--chunk-size <size>`: chunk size like `4M` or `16M` (default: 4M)
- `--overwrite`: allow overwriting the output file
- `--password-stdin`: read the password from stdin (avoids leaving it in shell history)

## Testing
Tests are built by default:
- `cmake --build build --config Release`
- `ctest --test-dir build --config Release`

## Security Notes
- Key derivation uses PBKDF2-HMAC-SHA256 with a random salt.
- Encryption uses ChaCha20 with a random nonce per file.
- Integrity uses HMAC-SHA256 (header + ciphertext).
- HMAC comparison uses constant-time equality.
- Output files are deleted on failure to avoid partial artifacts.
- Key material is wiped from memory on exit (best effort).
- Maximum file size for a single stream is 256 GiB due to ChaCha20's 32-bit counter.

## Project Structure
```
FastShield/
|-- bin/
|-- build/
|-- docs/
|   |-- building.md
|   |-- cli_reference.md
|   |-- concurrency_model.md
|   |-- performance_report.md
|   |-- security_notes.md
|   `-- technical_spec.md
|-- include/
|   |-- core/
|   |-- io/
|   `-- utils/
|-- src/
|   |-- core/
|   |-- io/
|   `-- main.cpp
|-- tests/
|-- CMakeLists.txt
`-- README.md
```

## Documentation
See the `docs/` folder for deeper technical detail:
- `docs/technical_spec.md`
- `docs/concurrency_model.md`
- `docs/performance_report.md`
- `docs/building.md`
- `docs/cli_reference.md`
- `docs/security_notes.md`

## Roadmap Ideas
- Optional direct I/O mode (`FILE_FLAG_NO_BUFFERING`) with explicit alignment.
- Memory-mapped or overlapped I/O for additional throughput.
- Authenticated encryption format (ChaCha20-Poly1305).
- Implement a Buffer Pool / Object Pool for chunks to eliminate dynamic memory allocation overhead during the pipeline execution.

## Contributing & Learning
This project was developed with a focus on clean architecture, thread-safe pipelines, and Windows API integration. It can serve as a learning resource for applying C++20 in data-streaming applications. If you're interested in improving the performance (e.g., implementing memory-mapped I/O or a buffer pool) or adding features, pull requests and ideas are highly welcome! Check out the docs/ folder for a deep dive into the architecture.




