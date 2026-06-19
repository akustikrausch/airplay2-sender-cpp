# Vendored orlp/ed25519 (zlib license) — Ed25519 sign/verify for AirPlay HAP
# pair-verify. See SOURCE.md for provenance + why Mbed TLS doesn't cover this.
#
# Qt-free, dependency-free standalone C. We DON'T compile seed.c (the platform
# entropy source) — ED25519_NO_SEED drops ed25519_create_seed; all randomness
# in the AirPlay path comes from Mbed TLS CTR-DRBG instead.

add_library(ed25519 STATIC
    src/add_scalar.c
    src/fe.c
    src/ge.c
    src/key_exchange.c
    src/keypair.c
    src/sc.c
    src/sha512.c
    src/sign.c
    src/verify.c
    src/x25519_raw.c)   # raw RFC-7748 X25519 for HAP pair-verify (see SOURCE.md)

target_include_directories(ed25519 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(ed25519 PUBLIC ED25519_NO_SEED)

# This is a C target — never inherit the project PCH (which is C++).
set_target_properties(ed25519 PROPERTIES
    C_STANDARD 99
    POSITION_INDEPENDENT_CODE ON)
if(MSVC)
    # The reference code is clean but uses classic C idioms; silence the
    # noise so it doesn't drown real warnings in the build log.
    target_compile_options(ed25519 PRIVATE /w)
endif()
