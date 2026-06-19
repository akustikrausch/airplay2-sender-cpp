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

# the sender + a CLI demo land here once the Qt-free transport interface from
# ROADMAP.md is in. for now, read src/raop_sender.* alongside the README recipe.
