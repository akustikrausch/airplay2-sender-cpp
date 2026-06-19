#ifndef X25519_RAW_H
#define X25519_RAW_H

// Raw RFC 7748 X25519 (see x25519_raw.c for why orlp's ed25519_key_exchange
// can't be used for HomeKit pair-verify). All buffers are 32 bytes.
#ifdef __cplusplus
extern "C" {
#endif

void x25519_scalarmult(unsigned char *out,
                       const unsigned char *scalar,
                       const unsigned char *point);
void x25519_base(unsigned char *out, const unsigned char *scalar);

#ifdef __cplusplus
}
#endif

#endif
