// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// airplay_crypto.h -- the crypto + wire-format bytes airplay 2 pairing needs.
// ----------------------------------------------------------------------------
// the qt-free core. everything in here speaks `std::vector<uint8_t>` +
// `std::string` and nothing else, so you can lift it into anything and
// unit-test it on its own. this is the half of an AP2 sender that has no
// business knowing about sockets.
//
// what's inside, and what apple makes you do with it:
//   * SRP-6a, 3072-bit, SHA-512 -- HomeKit pair-setup. username is always
//     "Pair-Setup", password is the 4-digit on-screen PIN (apple tv) or the
//     fixed "3939" (transient homepod/macbook).
//   * X25519 ECDH + Ed25519 sign/verify -- HAP pair-verify.
//   * ChaCha20-Poly1305 AEAD -- the encrypted RTSP control channel, the event
//     channel, and the realtime audio payload. 8-byte LE counter nonce with a
//     4-zero-byte pad in front.
//   * HKDF-SHA512 -- every session key (Control-Write/Read, Events-Write/Read)
//     is HKDF over the pairing shared secret. the audio key is NOT (it's the
//     raw first 32 bytes -- see the README recipe).
//   * HomeKit TLV8 + a minimal `bplist00` -- the wire formats SETUP rides on.
//
// crypto backend: Mbed TLS 3.6 (Apache-2.0) for the bignum mod-exp / SHA-512 /
// HKDF / ChaCha20-Poly1305 / X25519 / CTR-DRBG, plus orlp's ed25519 (zlib,
// vendored) for the one thing Mbed TLS lacks: Ed25519. no GPL anywhere.
//
// clean-room: the exact byte sequences -- the SRP padding, the HKDF salt/info
// strings, the TLV8 nonce labels ("PS-Msg05" / "PV-Msg02" / …), the pair-verify
// signature layout -- were read out of pyatv (`hap_srp.py`) and cross-checked
// against ejurgensen/pair_ap (`pair_homekit.c`, the H_nn_pad convention) as a
// SPEC. not a line of their code is here, only the wire format they describe.

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace fxchain::airplay {

using Bytes = std::vector<uint8_t>;

// ── basic hashing / KDF (Mbed TLS) ───────────────────────────────────
Bytes sha512(const Bytes& data);
Bytes hmacSha512(const Bytes& key, const Bytes& data);
// RFC 5869 HKDF-SHA512. HAP always derives 32-byte keys.
Bytes hkdfSha512(const std::string& salt, const std::string& info,
                 const Bytes& ikm, size_t length = 32);

// Cryptographically-secure random bytes (CTR-DRBG seeded from the OS).
Bytes randomBytes(size_t n);

// ── ChaCha20-Poly1305 AEAD (HAP uses an 8-byte nonce, 4 zero bytes of
//    pad in front → 12-byte IETF nonce). Returns ciphertext||tag(16) on
//    encrypt; on decrypt, std::nullopt if the tag is invalid. ──────────
Bytes chacha20Poly1305Encrypt(const Bytes& key, const Bytes& nonce8,
                              const Bytes& plaintext, const Bytes& aad = {});
std::optional<Bytes> chacha20Poly1305Decrypt(const Bytes& key,
                                              const Bytes& nonce8,
                                              const Bytes& ciphertextAndTag,
                                              const Bytes& aad = {});
// Helper: build the 8-byte little-endian counter nonce HAP uses for the
// audio + control channels (the 4-byte zero pad is added internally).
Bytes counterNonce8(uint64_t counter);

// ── X25519 ECDH (Mbed TLS, curve25519) ───────────────────────────────
struct X25519KeyPair { Bytes pub; Bytes priv; };   // 32 bytes each
X25519KeyPair x25519Generate();
Bytes x25519SharedSecret(const Bytes& ourPriv32, const Bytes& theirPub32);

// ── Ed25519 sign / verify (orlp/ed25519) ─────────────────────────────
// `seed32` is the 32-byte long-term secret (== pyatv "ltsk"); the public
// key (== "ltpk") is derived from it. signWithSeed signs `msg`.
Bytes ed25519PublicFromSeed(const Bytes& seed32);
Bytes ed25519Sign(const Bytes& seed32, const Bytes& msg);
bool  ed25519Verify(const Bytes& pub32, const Bytes& msg, const Bytes& sig64);

// ── SRP-6a, 3072-bit, SHA-512, CLIENT side (HAP pair-setup) ──────────
//
// HomeKit pairing uses SRP-6a with N/g = RFC 5054 group 3072 (g = 5) and
// SHA-512. The username is always "Pair-Setup"; the password is the PIN
// ("3939" for transient HomePod pairing, the on-screen 4-digit code for
// Apple TV). The padding convention (k and u hashed over N-length
// zero-padded big-endian operands; salt/N/g hashed at natural length)
// matches pyatv's srptools AND pair_ap's H_nn_pad, both ends of this
// project's own test rig use it, so it is internally consistent and also
// what real Apple receivers expect.
class SrpClient {
public:
    SrpClient();
    ~SrpClient();
    SrpClient(const SrpClient&) = delete;
    SrpClient& operator=(const SrpClient&) = delete;

    // Choose the password (PIN). Generates the ephemeral secret `a` and
    // public `A = g^a mod N`.
    void start(const std::string& password);

    // Public client value A (big-endian, trimmed of leading zero bytes,
    // the wire form HAP TLV8 PublicKey carries).
    Bytes publicA() const;

    // Process the server's salt + public B. Computes the shared session
    // key K = SHA-512(S) and the client proof M1. Returns false if B ≡ 0
    // (mod N), a malicious/garbled server value.
    bool process(const Bytes& salt, const Bytes& serverB);

    Bytes proofM1() const;        // 64 bytes
    Bytes sessionKey() const;     // K, 64 bytes (the HKDF ikm)

    // Verify the server's proof M2 = H(A | M1 | K) against `serverM2`.
    bool verifyServerProof(const Bytes& serverM2) const;

private:
    struct Impl;
    Impl* d_;
};

// ── HomeKit TLV8 (type-length-value, 255-byte fragmenting) ────────────
//
// One level only (HAP never nests). A repeated tag whose value exceeds
// 255 bytes is split into consecutive same-tag chunks on write and
// re-joined on read, required for the 384-byte SRP PublicKey.
namespace tlv {

enum Type : uint8_t {
    Method        = 0x00,
    Identifier    = 0x01,
    Salt          = 0x02,
    PublicKey     = 0x03,
    Proof         = 0x04,
    EncryptedData = 0x05,
    State         = 0x06,   // SeqNo
    Error         = 0x07,
    Signature     = 0x0A,
    Permissions   = 0x0B,
    Name          = 0x11,
    Flags         = 0x13,
};

// Insertion-ordered map (HAP cares about order for some receivers).
using Map = std::vector<std::pair<uint8_t, Bytes>>;

Bytes encode(const Map& items);
Map   decode(const Bytes& data);
// Convenience: fetch the (joined) value for a tag, or nullopt.
std::optional<Bytes> get(const Map& m, uint8_t tag);

} // namespace tlv

// ── Apple binary property list (bplist00), minimal encoder/decoder ───
//
// Hand-framed in the spirit of cast_channel.cpp's protobuf: enough of the
// bplist grammar to round-trip the AirPlay 2 SETUP request/response
// dictionaries (dict / array / string / data / int / bool / real). NOT a
// general libplist replacement, it covers exactly the value types Apple
// receivers use for SETUP/SETUP-stream and nothing more.
namespace bplist {

// A tiny tagged-union value tree. We avoid std::variant gymnastics and
// use an explicit type tag so the encoder/decoder stay obvious.
struct Value;
using Array = std::vector<Value>;
using Dict  = std::vector<std::pair<std::string, Value>>;   // ordered

struct Value {
    enum class Type { Bool, Int, Real, Str, Data, Arr, Dict } type;
    bool        b = false;
    int64_t     i = 0;
    double      r = 0.0;
    std::string s;        // Str
    Bytes       data;     // Data
    Array       arr;
    Dict        dict;

    // Declared here, defined below the class: Dict holds pair<string, Value>,
    // and clang with libstdc++ 14 refuses to implicitly define these while
    // Value is still being completed (the pair needs a complete Value).
    Value();
    ~Value();
    Value(const Value&);
    Value(Value&&) noexcept;
    Value& operator=(const Value&);
    Value& operator=(Value&&) noexcept;

    static Value boolean(bool v)            { Value x; x.type=Type::Bool; x.b=v; return x; }
    static Value integer(int64_t v)         { Value x; x.type=Type::Int;  x.i=v; return x; }
    static Value real(double v)             { Value x; x.type=Type::Real; x.r=v; return x; }
    static Value str(std::string v)         { Value x; x.type=Type::Str;  x.s=std::move(v); return x; }
    static Value bytes(Bytes v)             { Value x; x.type=Type::Data; x.data=std::move(v); return x; }
    static Value array(Array v)             { Value x; x.type=Type::Arr;  x.arr=std::move(v); return x; }
    static Value object(Dict v)             { Value x; x.type=Type::Dict; x.dict=std::move(v); return x; }

    // Lookup helpers for decoded dicts (return nullptr if absent / wrong type).
    const Value* find(const std::string& key) const;
    int64_t      asInt(int64_t def = 0) const { return type==Type::Int ? i : def; }
    std::string  asStr(const std::string& def = {}) const { return type==Type::Str ? s : def; }
};

inline Value::Value() = default;
inline Value::~Value() = default;
inline Value::Value(const Value&) = default;
inline Value::Value(Value&&) noexcept = default;
inline Value& Value::operator=(const Value&) = default;
inline Value& Value::operator=(Value&&) noexcept = default;

Bytes                encode(const Value& root);
std::optional<Value> decode(const Bytes& data);

} // namespace bplist

// ── RFC 2617 MD5 digest auth (pw=true receivers) ──────────────────────
// Returns the value for the Authorization header given a parsed
// WWW-Authenticate realm+nonce and the user's password.
std::string digestAuthResponse(const std::string& method,
                               const std::string& uri,
                               const std::string& username,
                               const std::string& realm,
                               const std::string& password,
                               const std::string& nonce);

} // namespace fxchain::airplay
