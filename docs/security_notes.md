FastShield Security Notes
=========================

Design Intent
-------------
FastShield is designed for fast, streaming file encryption on Windows. It uses standard primitives and separates encryption and integrity keys derived from a single password.

Primitives
----------
- Key derivation: PBKDF2-HMAC-SHA256 with a per-file random salt.
- Encryption: ChaCha20 (IETF 96-bit nonce).
- Integrity: HMAC-SHA256 over header + ciphertext.

Integrity and Verification
--------------------------
- The header is authenticated, so tampering with metadata is detected.
- HMAC comparison is constant-time to reduce timing leakage.
- If verification fails, the output file is deleted.
- Derived keys and nonces are wiped from memory on exit (best effort).

Operational Guidance
--------------------
- Use `--password-stdin` to avoid leaving secrets in shell history.
- Keep passwords long and unique.
- Consider rotating passwords for high-value data.

Threat Model
------------
FastShield is intended for local file encryption and assumes the attacker does not have control of the running process. It is not audited and should not be used as the sole control for high-risk or regulated environments.
