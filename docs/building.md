# Building FastShield V2

## Requirements
- CMake 3.21+
- C++20 compiler
- Windows: Visual Studio 2022 or newer
- Linux: gcc/clang toolchain, optional `liburing` for io_uring backend acceleration

## Configure
```bash
cmake -S . -B build
```

## Build
Release:
```bash
cmake --build build --config Release
```

Debug:
```bash
cmake --build build --config Debug
```

## Tests
```bash
ctest --test-dir build --config Debug --output-on-failure
```

## Build Options
- `FASTSHIELD_BUILD_TESTS=ON|OFF`: enable/disable tests (default ON).

## Linux io_uring Notes
If `liburing` is found at configure time, CMake defines `FASTSHIELD_HAS_IO_URING=1` and links `liburing`. Without it, Linux backend falls back to POSIX syscalls.
