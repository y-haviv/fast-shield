# FastShield Technical Specification (V2)

## Scope
FastShield encrypts/decrypts large files through a streaming multi-threaded pipeline with authenticated chunk processing.

## Module Overview
1. `core`
- `FastShield.cpp`: pipeline orchestration
- `CryptoEngine`: KDF + chunk nonce derivation
- `ChaCha20`, `Poly1305`, `ChaCha20Poly1305`: crypto primitives
- `FileFormat`: V2 archive header

2. `io`
- `FileHandler` interface
- `Win32FileHandler` backend (`CreateFile`, optional `FILE_FLAG_NO_BUFFERING`)
- `LinuxFileHandler` backend (POSIX + optional `io_uring`)

3. `utils`
- `BufferPool`: aligned reusable chunk storage
- `BlockingQueue`: bounded producer/consumer queue
- `SecureZero`, `Random`, `Logger`

## Header Format
Packed struct size: 72 bytes.

Fields:
- `magic[8]`
- `version` (V2)
- `headerSize`
- `flags`
- `chunkSize`
- `kdfIterations`
- `originalSize`
- `chunkCount`
- `salt[16]`
- `nonce[12]`
- `tagSize`
- `reserved[3]`

## Payload Format
For each chunk in index order:
- ciphertext bytes (`<= chunkSize`)
- 16-byte tag

Total file size:
- `sizeof(FileHeader) + originalSize + chunkCount * 16`

## Concurrency
- Reader: reads chunks into pooled buffers
- Workers: AEAD encrypt/decrypt+verify
- Writer: stable ordering and output writes

Error propagation uses first-failure capture and cooperative shutdown.

## Direct I/O
`--direct-io` is optional. Backends attempt direct mode and enforce backend alignment constraints.

## Compatibility
V2 archives are not backward-compatible with V1 (HMAC trailer format).
