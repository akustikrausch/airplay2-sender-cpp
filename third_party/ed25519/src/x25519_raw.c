// Raw X25519 (RFC 7748) on top of the vendored orlp/ed25519 field arithmetic.
//
// WHY THIS EXISTS: orlp's own ed25519_key_exchange() expects an *Edwards*
// public key and converts Edwards->Montgomery internally. HomeKit (HAP)
// pair-verify uses *pure X25519* — the peer's public key is already a raw
// Curve25519 u-coordinate (little-endian, 32 bytes), so applying orlp's
// extra Edwards->Montgomery step would corrupt it. This function is the
// standard RFC 7748 X25519 scalar multiplication: it reads the raw u
// directly with fe_frombytes and runs the SAME constant-time Montgomery
// ladder orlp uses — just without the Edwards unpacking. The ladder body
// is the public-domain ref implementation (identical to orlp's, which is
// itself the ref10/donna lineage); reusing the audited fe.c keeps the
// field math in one vetted place.
//
// x25519_scalarmult(out, scalar, point):
//   out    = X25519(scalar, point)   (32 bytes)
//   scalar = our private key          (32 bytes, clamped here per RFC 7748)
//   point  = peer public u-coordinate (32 bytes, little-endian)
// For a base-point multiply (deriving our public key), pass the canonical
// base point u = 9 (i.e. {9,0,0,...}).

#include "fe.h"

#include <string.h>

void x25519_scalarmult(unsigned char *out,
                       const unsigned char *scalar,
                       const unsigned char *point) {
    unsigned char e[32];
    unsigned int i;

    fe x1, x2, z2, x3, z3, tmp0, tmp1;
    int pos;
    unsigned int swap;
    unsigned int b;

    for (i = 0; i < 32; ++i) {
        e[i] = scalar[i];
    }
    // RFC 7748 clamping.
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    // Read the peer u-coordinate DIRECTLY (no Edwards conversion).
    fe_frombytes(x1, point);

    fe_1(x2);
    fe_0(z2);
    fe_copy(x3, x1);
    fe_1(z3);

    swap = 0;
    for (pos = 254; pos >= 0; --pos) {
        b = e[pos / 8] >> (pos & 7);
        b &= 1;
        swap ^= b;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = b;

        fe_sub(tmp0, x3, z3);
        fe_sub(tmp1, x2, z2);
        fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);
        fe_mul(z3, tmp0, x2);
        fe_mul(z2, z2, tmp1);
        fe_sq(tmp0, tmp1);
        fe_sq(tmp1, x2);
        fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);
        fe_mul(x2, tmp1, tmp0);
        fe_sub(tmp1, tmp1, tmp0);
        fe_sq(z2, z2);
        fe_mul121666(z3, tmp1);
        fe_sq(x3, x3);
        fe_add(tmp0, tmp0, z3);
        fe_mul(z3, x1, z2);
        fe_mul(z2, tmp1, tmp0);
    }

    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(out, x2);
}

// Derive the X25519 public key from a private scalar (base point u = 9).
void x25519_base(unsigned char *out, const unsigned char *scalar) {
    unsigned char basepoint[32];
    memset(basepoint, 0, sizeof(basepoint));
    basepoint[0] = 9;
    x25519_scalarmult(out, scalar, basepoint);
}
