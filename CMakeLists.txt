cmake_minimum_required(VERSION 3.21)

project(FastShield VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(FASTSHIELD_BUILD_TESTS "Build FastShield tests" ON)

set(FASTSHIELD_SOURCES
    src/core/ChaCha20.cpp
    src/core/CryptoEngine.cpp
    src/core/FastShield.cpp
    src/core/HmacSha256.cpp
    src/core/Pbkdf2.cpp
    src/core/Sha256.cpp
    src/io/Win32FileHandler.cpp
    src/utils/Random.cpp
    src/utils/SecureZero.cpp
)

add_library(fastshield_lib ${FASTSHIELD_SOURCES})
target_include_directories(fastshield_lib PUBLIC include)
target_compile_definitions(fastshield_lib PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_definitions(fastshield_lib PUBLIC FASTSHIELD_VERSION="${PROJECT_VERSION}")
target_link_libraries(fastshield_lib PUBLIC bcrypt)

if (MSVC)
    target_compile_options(fastshield_lib PRIVATE /W4 /permissive- /EHsc)
else()
    target_compile_options(fastshield_lib PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(fastshield src/main.cpp)
target_link_libraries(fastshield PRIVATE fastshield_lib)

if (FASTSHIELD_BUILD_TESTS)
    enable_testing()
    add_executable(fastshield_tests tests/test_roundtrip.cpp)
    target_link_libraries(fastshield_tests PRIVATE fastshield_lib)
    add_test(NAME fastshield_tests COMMAND fastshield_tests)
endif()
