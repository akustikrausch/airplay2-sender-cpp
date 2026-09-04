# airplay 2 sender (c++): the crypto core, the sans-i/o sender, the bundled
# poll host, the airplay_send cli demo and the test suite. plain
# `cmake -B build && cmake --build build` builds all of it, no Qt anywhere.
cmake_minimum_required(VERSION 3.16)
project(airplay2_sender LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(AIRPLAY_BUILD_EXAMPLE "build the airplay_send cli demo"            ON)
option(AIRPLAY_BUILD_TESTS   "build + register the test suite (ctest)"    ON)
option(AIRPLAY_BUILD_QT_HOST "build the optional Qt6 host (RaopQtHost)"   OFF)
option(AIRPLAY_SANITIZE      "build with address + undefined sanitizers"  OFF)

include(FetchContent)

# --- Mbed TLS 3.6 (Apache-2.0): bignum, sha512, hkdf, chachapoly, drbg ---
# fatal warnings off: a bare `cmake --build` must not fail on a dependency's
# -Werror when a newer compiler learns a new warning.
set(ENABLE_PROGRAMS          OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING           OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS   OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON  CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
FetchContent_Declare(mbedtls
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG        2ca6c285a0dd3f33982dd57299012dacab1ff206   # v3.6.0, pinned by commit
    GIT_SHALLOW    TRUE)
FetchContent_MakeAvailable(mbedtls)

# --- orlp/ed25519 (zlib, vendored): the one primitive Mbed TLS lacks ---
# Drop seed.c and define ED25519_NO_SEED: ed25519_create_seed() is never called
# (all seeds come from Mbed TLS CTR-DRBG), so we don't pull in seed.c's
# CryptGenRandom/getrandom entropy path. Matches third_party/ed25519/SOURCE.md.
file(GLOB ED25519_SRC ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ed25519/src/*.c)
list(FILTER ED25519_SRC EXCLUDE REGEX "/seed\\.c$")
add_library(ed25519 STATIC ${ED25519_SRC})
target_compile_definitions(ed25519 PRIVATE ED25519_NO_SEED)
target_include_directories(ed25519 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ed25519/src)

# warnings for our own code only (the dependencies keep their flags).
function(airplay_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4)
        target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra)
    endif()
    if(AIRPLAY_SANITIZE AND NOT MSVC)
        target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    endif()
endfunction()

# --- the Qt-free AirPlay 2 crypto + wire-format core (the reusable part) ---
add_library(airplay_crypto STATIC src/airplay_crypto.cpp)
target_include_directories(airplay_crypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ed25519/src)
target_link_libraries(airplay_crypto PUBLIC mbedcrypto ed25519)
target_compile_features(airplay_crypto PUBLIC cxx_std_20)
airplay_warnings(airplay_crypto)

# --- the sender (sans-i/o state machine) + the bundled poll host (m1) ---
# raop_sender knows no socket; RaopLoop is the portable host that drives it.
# together they are the whole library: plain C++20 + airplay_crypto.
add_library(raop_sender STATIC
    src/raop_sender.cpp
    src/raop_loop.cpp)
target_include_directories(raop_sender PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(raop_sender PUBLIC airplay_crypto)
target_compile_features(raop_sender PUBLIC cxx_std_20)
airplay_warnings(raop_sender)
if(WIN32)
    target_link_libraries(raop_sender PUBLIC ws2_32)
endif()

# --- optional Qt host (OFF by default, never needed for the standalone build) ---
# an app that already runs a Qt event loop (FXChainPlayer) hands the sender a
# RaopQtHost instead of a RaopLoop and keeps its own loop.
if(AIRPLAY_BUILD_QT_HOST)
    find_package(Qt6 REQUIRED COMPONENTS Core Network)
    add_library(raop_sender_qt STATIC src/raop_qt_host.cpp)
    target_link_libraries(raop_sender_qt PUBLIC raop_sender Qt6::Core Qt6::Network)
    airplay_warnings(raop_sender_qt)
endif()

# --- airplay_send: the cli demo (m3) ---
if(AIRPLAY_BUILD_EXAMPLE)
    find_package(Threads REQUIRED)
    add_executable(airplay_send example/airplay_send.cpp)
    target_link_libraries(airplay_send PRIVATE raop_sender Threads::Threads)
    airplay_warnings(airplay_send)
endif()

# --- tests ---
# raop_core_tests: the protocol core against an in-process fake receiver, no
#   sockets: AP1 handshake + audio/sync/timing/retransmit, the full AP2 path
#   (transient pairing, pin pairing with credentials, pair-verify reconnect,
#   encrypted control channel, event channel keep-alive, encrypted ALAC
#   audio), strict receiver auth, the creds codec, the formatter.
# raop_loop_tests: the poll host against a real loopback receiver (connect,
#   refused connect, remote close + reconnect, udp replies to the source).
if(AIRPLAY_BUILD_TESTS)
    enable_testing()
    find_package(Threads REQUIRED)
    add_executable(raop_core_tests test/core_tests.cpp)
    target_link_libraries(raop_core_tests PRIVATE raop_sender)
    airplay_warnings(raop_core_tests)
    add_test(NAME raop_core_tests COMMAND raop_core_tests)

    add_executable(raop_loop_tests test/loop_tests.cpp)
    target_link_libraries(raop_loop_tests PRIVATE raop_sender Threads::Threads)
    airplay_warnings(raop_loop_tests)
    add_test(NAME raop_loop_tests COMMAND raop_loop_tests)
endif()
