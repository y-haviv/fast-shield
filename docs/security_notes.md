# Security Notes (V2)

## Cryptography
- KDF: PBKDF2-HMAC-SHA256 with random per-file 16-byte salt.
- Encryption + integrity: ChaCha20-Poly1305 AEAD.
- Tag size: 16 bytes per chunk.

## Chunked AEAD Design
Each chunk is an independent AEAD message:
- nonce: derived from file nonce + chunk index
- AAD: chunk index + chunk plaintext size
- ciphertext and tag are stored together in stream order

Benefits:
- parallel processing without global AEAD state contention
- immediate detection of tampering or wrong password during decryption
- no single-stream 256 GiB counter ceiling from offset-based stream usage

## Memory Hygiene
- Derived keys are wiped after use.
- Used pooled bytes are wiped on release.
- Password string is wiped by CLI guard after command completion.

## Failure Handling
On authentication error or pipeline fault:
- all pipeline stages are signaled to stop
- queues are closed and joined
- partial output file is deleted

## Operational Guidance
- Prefer `--password-stdin` over inline passwords.
- Use strong passphrases.
- Keep backups; encryption cannot recover from forgotten passwords.
