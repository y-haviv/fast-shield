# FastShield V2

FastShield is a high-throughput CLI utility for streaming encryption and decryption of large files. V2 introduces a stronger authenticated format, reusable aligned buffers, optional direct I/O, and a cross-platform file layer prepared for Windows and Linux backends.

## What Is New in V2
- Chunked AEAD: ChaCha20-Poly1305 replaces Encrypt-then-MAC.
- Buffer pool: per-chunk heap allocations are removed from the pipeline.
- Direct I/O option: `--direct-io` enables direct file access for plaintext paths when alignment constraints are met.
- Cross-platform file abstraction: shared `FileHandler` interface with Windows backend and Linux backend.
- Linux `io_uring`: optional path compiled when `liburing` is available.
- Large file support: stream-size ceiling from a single global ChaCha20 counter is removed by independent per-chunk nonce derivation.

## Pipeline Architecture
FastShield keeps a three-stage concurrent pipeline:
1. Reader thread reads file chunks into aligned pooled buffers.
2. Worker pool encrypts/decrypts chunks in parallel and performs AEAD tagging/verification.
3. Writer thread restores order and emits output.

Backpressure is enforced through bounded blocking queues between stages.

## File Format (V2)
Layout:
- `FileHeader` (72 bytes)
- For each chunk in order:
  - ciphertext bytes (`chunk_plain_size`)
  - 16-byte Poly1305 tag

Header fields include format version, chunk size, KDF iterations, original size, chunk count, salt, base nonce, and tag size.

## Security Model
- KDF: PBKDF2-HMAC-SHA256 with per-file random salt.
- AEAD: ChaCha20-Poly1305 per chunk.
- Nonce safety: each chunk uses a unique nonce derived from a file nonce and chunk index.
- Associated data: chunk index + chunk plaintext size.
- Failure handling: auth failure aborts pipeline and deletes partial output.
- Sensitive memory: key material and pooled used bytes are wiped on release (best effort).

## Build
Requirements:
- CMake 3.21+
- C++20 compiler
- Windows: Visual Studio 2022 (or compatible toolchain)
- Linux: optional `liburing` for io_uring fast path

Configure:
```bash
cmake -S . -B build
```

Build:
```bash
cmake --build build --config Release
```

## CLI Usage
Encrypt:
```bash
fastshield encrypt -i input.bin -o archive.fs --password-stdin --chunk-size 4M --threads 8
```

Decrypt:
```bash
fastshield decrypt -i archive.fs -o restored.bin --password-stdin --chunk-size 4M --threads 8
```

Options:
- `-i, --input <path>` input file
- `-o, --output <path>` output file
- `-p, --password <text>` password literal
- `--password-stdin` read password from stdin
- `--threads <n>` worker count (`0` = auto)
- `--chunk-size <size>` chunk size (`K`, `M`, `G` suffixes)
- `--direct-io` attempt direct I/O on plaintext side (alignment dependent)
- `--overwrite` overwrite output path
- `--verbose` enable debug logs

## Testing
```bash
ctest --test-dir build --config Release --output-on-failure
```

Current suite covers:
- AEAD round trip
- tamper detection and cleanup behavior
- direct I/O aligned path
- large chunk-index nonce behavior

## Documentation
- `docs/building.md`
- `docs/cli_reference.md`
- `docs/concurrency_model.md`
- `docs/performance_report.md`
- `docs/security_notes.md`
- `docs/technical_spec.md`
