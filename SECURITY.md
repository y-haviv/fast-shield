Reporting Security Issues
=========================

If you discover a security vulnerability in FastShield, please report it privately via GitHub Security Advisories if available, or open an issue and mark it as a security report. Avoid posting exploit details publicly until a fix is available.

Guidance for reporters:
- Provide a concise summary of the issue and steps to reproduce.
- Include affected versions and any proof-of-concept if possible.
- If you'd like private correspondence, use GitHub's private advisories or add a maintainer contact on the repository settings.

Disclaimer: 
FastShield is an experimental project built to explore high-throughput I/O, multi-threading pipelines, and stream cipher mechanics in modern C++. While the cryptographic primitives (ChaCha20, HMAC-SHA256) are implemented according to specification, this software has not undergone a formal security audit. Do not use it to encrypt highly sensitive or mission-critical data in production.