Building FastShield
===================

Prerequisites
-------------
- Windows 10 or later
- CMake 3.21+
- Visual Studio 2022 (MSVC) or another C++20 compiler

Configure
---------
From the project root:
- `cmake -S . -B build`

Build (Release)
---------------
- `cmake --build build --config Release`

Build (Debug)
-------------
- `cmake --build build --config Debug`

Run Tests
---------
Tests are enabled by default:
- `ctest --test-dir build --config Release`

Disable Tests
------------
If you want a lean build:
- `cmake -S . -B build -DFASTSHIELD_BUILD_TESTS=OFF`
