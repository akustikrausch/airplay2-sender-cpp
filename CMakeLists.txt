# airplay 2 sender, build the Qt-free crypto + wire-format core.
#
# the reusable part (`airplay_crypto`) builds standalone. the AP2 SENDER
# (`src/raop_sender.*`) is reference source that still uses Qt networking +
# host glue and is NOT wired here yet, see ROADMAP.md.
cmake_minimum_required(VERSION 3.16)
project(airplay2_sender LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# --- Mbed TLS 3.6 (Apache-2.0): bignum, sha512, hkdf, chachapoly, drbg ---
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING  OFF CACHE BOOL "" FORCE)
FetchContent_Declare(mbedtls
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG        v3.6.0
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

# --- the Qt-free AirPlay 2 crypto + wire-format core (the reusable part) ---
add_library(airplay_crypto STATIC src/airplay_crypto.cpp)
target_include_directories(airplay_crypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ed25519/src)
target_link_libraries(airplay_crypto PUBLIC mbedcrypto ed25519)
target_compile_features(airplay_crypto PUBLIC cxx_std_20)

# --- the AirPlay 2 sender + the default Qt-free poll/select transport (m1) ---
# raop_sender is now plain C++: it drives all networking + timers through the
# ITransport seam (src/itransport.h) and the bundled PollTransport adapter, so
# it builds with NO Qt. the crypto + wire-format core (airplay_crypto) links in.
add_library(raop_sender STATIC
    src/raop_sender.cpp
    src/poll_transport.cpp)
target_include_directories(raop_sender PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(raop_sender PUBLIC airplay_crypto)
target_compile_features(raop_sender PUBLIC cxx_std_20)
if(WIN32)
    target_link_libraries(raop_sender PUBLIC ws2_32)
endif()

# --- optional thin Qt adapter (OFF by default) ---
# a host that already runs a Qt event loop (e.g. FXChainPlayer) can hand the
# sender a QtTransport instead of PollTransport and keep its own event loop.
# the default standalone build stays zero-Qt; this only pulls in Qt6 when asked.
option(AIRPLAY_BUILD_QT_ADAPTER "Build the thin Qt ITransport adapter" OFF)
if(AIRPLAY_BUILD_QT_ADAPTER)
    find_package(Qt6 REQUIRED COMPONENTS Core Network)
    add_library(raop_sender_qt STATIC src/qt_transport.cpp)
    target_link_libraries(raop_sender_qt PUBLIC raop_sender Qt6::Core Qt6::Network)
    target_compile_features(raop_sender_qt PUBLIC cxx_std_20)
endif()

# --- verification harness (OFF by default; CI turns it on) ---
# stands up a loopback "fake receiver" and drives the full AirPlay-1 handshake
# through PollTransport + RaopSender, then checks audio/sync/timing/retransmit;
# plus timer-restart, creds byte-compat, and UDP source-reply unit checks.
# POSIX sockets, so it is gated off Windows.
option(AIRPLAY_BUILD_TESTS "Build the transport verification harness" OFF)
if(AIRPLAY_BUILD_TESTS AND NOT WIN32)
    enable_testing()
    add_executable(m1_verify test/m1_verify.cpp)
    target_link_libraries(m1_verify PRIVATE raop_sender)
    add_test(NAME m1_verify COMMAND m1_verify)
endif()

# --- the airplay_send CLI demo (ROADMAP m3), OFF by default ---
# streams a WAV (or a test tone) to a real receiver through raop_sender +
# PollTransport. the runnable proof on your own couch.
option(AIRPLAY_BUILD_EXAMPLE "Build the airplay_send CLI demo" OFF)
if(AIRPLAY_BUILD_EXAMPLE)
    add_executable(airplay_send example/airplay_send.cpp)
    target_link_libraries(airplay_send PRIVATE raop_sender)
    find_package(Threads REQUIRED)
    target_link_libraries(airplay_send PRIVATE Threads::Threads)
endif()
