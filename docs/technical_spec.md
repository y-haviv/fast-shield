FastShield Technical Specification
==================================

Overview
--------
FastShield is a Windows CLI program that encrypts and decrypts files in a streaming, multi-threaded pipeline. It is designed for high throughput on large files while preserving integrity with HMAC verification.

Core Requirements
-----------------
- Windows 10+ (Win32 APIs and BCrypt RNG)
- CMake 3.21+ and a C++20 compiler
- No external third-party crypto dependencies

Modules
-------
1. IO Layer
   - `Win32FileHandler` wraps CreateFile/ReadFile/WriteFile.
   - Sequential scan hint is used to improve disk cache behavior.

2. Core Crypto
   - `ChaCha20` for encryption and decryption.
   - `PBKDF2-HMAC-SHA256` for password-based key derivation.
   - `HMAC-SHA256` for integrity.

3. Orchestrator
   - Reader thread reads chunks from disk.
   - Worker threads encrypt/decrypt chunks in parallel.
   - Writer thread outputs chunks in the original order.

4. CLI Interface
   - Commands: `encrypt`, `decrypt`
   - Options: `--threads`, `--chunk-size`, `--overwrite`, `--password-stdin`

File Format
-----------
Header is 64 bytes and written in little-endian.

Field layout:
- magic (8 bytes): `FSTSHLD\0`
- version (2 bytes): format version
- headerSize (2 bytes): always 64
- flags (4 bytes): reserved for future features
- chunkSize (4 bytes): chunk size used during encryption
- kdfIterations (4 bytes): PBKDF2 iteration count
- originalSize (8 bytes): plaintext size
- salt (16 bytes)
- nonce (12 bytes)
- reserved (4 bytes)

Payload:
- Ciphertext (same size as plaintext)
- HMAC-SHA256 (32 bytes) over header + ciphertext

Cryptographic Details
---------------------
- Key derivation: PBKDF2-HMAC-SHA256
- Default iterations: 200,000
- Salt size: 16 bytes (random per file)
- Encryption: ChaCha20 (IETF variant, 96-bit nonce)
- Integrity: HMAC-SHA256 with a separate derived key
- HMAC comparison uses constant-time equality
- Key material is wiped from memory on exit (best effort)

Limits
------
- Maximum stream size: 256 GiB (ChaCha20 32-bit counter limit)
- Chunk size: 1 byte to 256 MiB (configurable)

Error Handling
--------------
- All critical failures throw exceptions.
- Output file is deleted if HMAC verification fails during decryption.
- Short reads/writes are treated as hard errors.
- Output files created during encryption/decryption are deleted on any failure.

Configuration
-------------
- `--threads`: 0 uses hardware_concurrency (auto).
- `--chunk-size`: affects throughput and memory usage.

Recommended Defaults
--------------------
- Chunk size: 4 MiB
- Threads: number of CPU cores
