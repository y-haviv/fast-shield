Contributing to FastShield
==========================

Thank you for your interest in contributing to FastShield. Please follow these guidelines:

- Bug reports: open an issue with a clear, minimal reproduction and steps to reproduce.
- Feature requests: open an issue describing the problem and a suggested design.
- Pull requests: prefer small, focused PRs. Include tests and update documentation where applicable.
- Coding style: modern C++ (C++20), keep changes consistent with existing code style.
- Tests: new features/fixes should include tests that run on Windows with CMake.

Before submitting, run:

```bat
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build --config Release
```

We use `main` as the default branch. Thank you!
