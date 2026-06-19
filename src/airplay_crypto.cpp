//
// v0.66.x — AirPlay 2 / HomeKit crypto + wire-format primitives.
// See airplay_crypto.h for the design, the crypto-backend rationale, and
// the pyatv / pair_ap protocol attribution.
//

#include "airplay_crypto.h"

#include <mbedtls/bignum.h>
#include <mbedtls/chachapoly.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>

extern "C" {
#include "ed25519.h"
#include "x25519_raw.h"
}

#include <algorithm>
#include <cstring>
#include <mutex>
#include <stdexcept>

namespace fxchain::airplay {

namespace {

// ── one process-wide CTR-DRBG, lazily seeded from the OS entropy pool ──
// All AirPlay randomness (X25519 ephemerals, SRP `a`, Ed25519 seeds) flows
// through here. Guarded by a mutex because the pairing flow may touch it
// from the GUI thread while a re-pair is queued; the cost is irrelevant
// (pairing happens a handful of times, not per audio packet).
struct Drbg {
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr;
    std::mutex               mtx;
    bool                     ok = false;

    Drbg() {
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr);
        static const char pers[] = "fxchain-airplay";
        ok = mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy,
                                   reinterpret_cast<const unsigned char*>(pers),
                                   sizeof(pers)) == 0;
    }
    ~Drbg() {
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
    }
};

Drbg& drbg() {
    static Drbg g;   // Meyers singleton — thread-safe init since C++11.
    return g;
}

// RFC 5054 group 3072, g = 5. Big-endian hex (matches pair_ap / pyatv).
constexpr const char* kSrpN3072 =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183"
    "995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A"
    "85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7A"
    "BF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D"
    "87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E20"
    "8E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
constexpr int kSrpNBytes = 384;   // 3072 bits

void throwIf(int rc, const char* what) {
    if (rc != 0) throw std::runtime_error(std::string("airplay crypto: ") + what);
}

// ── mbedtls_mpi RAII wrapper (keeps the SRP math readable) ────────────
struct Mpi {
    mbedtls_mpi v;
    Mpi() { mbedtls_mpi_init(&v); }
    ~Mpi() { mbedtls_mpi_free(&v); }
    Mpi(const Mpi&) = delete;
    Mpi& operator=(const Mpi&) = delete;
    mbedtls_mpi* p() { return &v; }
    const mbedtls_mpi* p() const { return &v; }
};

Bytes mpiToBytes(const mbedtls_mpi& m) {
    const size_t n = mbedtls_mpi_size(&m);
    Bytes out(n == 0 ? 1 : n);
    throwIf(mbedtls_mpi_write_binary(&m, out.data(), out.size()),
            "mpi_write_binary");
    // Trim a single leading zero only if the value is genuinely zero-length.
    return out;
}

Bytes mpiToBytesPadded(const mbedtls_mpi& m, size_t len) {
    Bytes out(len);
    throwIf(mbedtls_mpi_write_binary(&m, out.data(), len), "mpi_write_binary pad");
    return out;
}

void bytesToMpi(Mpi& m, const Bytes& b) {
    throwIf(mbedtls_mpi_read_binary(m.p(), b.data(), b.size()), "mpi_read_binary");
}

} // namespace

// ── hashing / KDF ─────────────────────────────────────────────────────

Bytes sha512(const Bytes& data) {
    Bytes out(64);
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    throwIf(mbedtls_md(md, data.data(), data.size(), out.data()), "sha512");
    return out;
}

Bytes hmacSha512(const Bytes& key, const Bytes& data) {
    Bytes out(64);
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    throwIf(mbedtls_md_hmac(md, key.data(), key.size(),
                            data.data(), data.size(), out.data()),
            "hmac_sha512");
    return out;
}

Bytes hkdfSha512(const std::string& salt, const std::string& info,
                 const Bytes& ikm, size_t length) {
    Bytes out(length);
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    throwIf(mbedtls_hkdf(md,
                         reinterpret_cast<const unsigned char*>(salt.data()),
                         salt.size(),
                         ikm.data(), ikm.size(),
                         reinterpret_cast<const unsigned char*>(info.data()),
                         info.size(),
                         out.data(), out.size()),
            "hkdf_sha512");
    return out;
}

Bytes randomBytes(size_t n) {
    Bytes out(n);
    std::lock_guard<std::mutex> lk(drbg().mtx);
    throwIf(mbedtls_ctr_drbg_random(&drbg().ctr, out.data(), n), "ctr_drbg_random");
    return out;
}

// ── ChaCha20-Poly1305 ─────────────────────────────────────────────────

Bytes counterNonce8(uint64_t counter) {
    Bytes n(8);
    for (int i = 0; i < 8; ++i) n[i] = uint8_t((counter >> (8 * i)) & 0xFF);
    return n;   // little-endian, matches HAP / pyatv
}

namespace {
// HAP nonce: 4 zero bytes followed by the 8-byte (little-endian) value.
Bytes pad12(const Bytes& nonce8) {
    Bytes n(12, 0);
    std::copy(nonce8.begin(), nonce8.begin() + std::min<size_t>(8, nonce8.size()),
              n.begin() + 4);
    return n;
}
} // namespace

Bytes chacha20Poly1305Encrypt(const Bytes& key, const Bytes& nonce8,
                              const Bytes& plaintext, const Bytes& aad) {
    // setkey reads a fixed 32-byte key — guard against a short key (the
    // keys are HKDF-32 today, but this keeps it OOB-proof if ever misused).
    if (key.size() != 32) throw std::runtime_error("chacha key size");
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    throwIf(mbedtls_chachapoly_setkey(&ctx, key.data()), "chachapoly_setkey");
    const Bytes nonce = pad12(nonce8);
    Bytes out(plaintext.size() + 16);
    Bytes tag(16);
    const int rc = mbedtls_chachapoly_encrypt_and_tag(
        &ctx, plaintext.size(), nonce.data(),
        aad.data(), aad.size(),
        plaintext.data(), out.data(), tag.data());
    mbedtls_chachapoly_free(&ctx);
    throwIf(rc, "chachapoly_encrypt");
    std::copy(tag.begin(), tag.end(), out.begin() + plaintext.size());
    return out;
}

std::optional<Bytes> chacha20Poly1305Decrypt(const Bytes& key,
                                              const Bytes& nonce8,
                                              const Bytes& ct, const Bytes& aad) {
    if (ct.size() < 16 || key.size() != 32) return std::nullopt;
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    if (mbedtls_chachapoly_setkey(&ctx, key.data()) != 0) {
        mbedtls_chachapoly_free(&ctx);
        return std::nullopt;
    }
    const Bytes nonce = pad12(nonce8);
    const size_t plen = ct.size() - 16;
    Bytes out(plen);
    const unsigned char* tag = ct.data() + plen;
    const int rc = mbedtls_chachapoly_auth_decrypt(
        &ctx, plen, nonce.data(),
        aad.data(), aad.size(),
        tag, ct.data(), out.data());
    mbedtls_chachapoly_free(&ctx);
    if (rc != 0) return std::nullopt;   // bad tag → caller treats as auth failure
    return out;
}

// ── X25519 (raw, via the vendored ladder) ─────────────────────────────

X25519KeyPair x25519Generate() {
    X25519KeyPair kp;
    kp.priv = randomBytes(32);
    // Clamping is applied inside x25519_base; we also clamp the stored copy
    // so a later scalarmult with the same private is consistent.
    kp.priv[0]  &= 248;
    kp.priv[31] &= 127;
    kp.priv[31] |= 64;
    kp.pub.resize(32);
    x25519_base(kp.pub.data(), kp.priv.data());
    return kp;
}

Bytes x25519SharedSecret(const Bytes& ourPriv32, const Bytes& theirPub32) {
    // x25519_scalarmult reads a FIXED 32 bytes from each operand; theirPub32
    // is attacker-controlled (a receiver's TLV PublicKey), so a short value
    // would OOB-read. Reject anything but 32 bytes.
    if (ourPriv32.size() != 32 || theirPub32.size() != 32) return {};
    Bytes out(32);
    x25519_scalarmult(out.data(), ourPriv32.data(), theirPub32.data());
    // Reject an all-zero shared secret: a low-order receiver public key forces a
    // known (zero) secret -> predictable session keys. A legitimate receiver
    // never yields this. Constant-time OR over all 32 bytes.
    uint8_t acc = 0;
    for (uint8_t b : out) acc = uint8_t(acc | b);
    if (acc == 0) return {};
    return out;
}

// ── Ed25519 (orlp/ed25519) ────────────────────────────────────────────

Bytes ed25519PublicFromSeed(const Bytes& seed32) {
    Bytes pub(32), priv(64);
    ed25519_create_keypair(pub.data(), priv.data(), seed32.data());
    return pub;
}

Bytes ed25519Sign(const Bytes& seed32, const Bytes& msg) {
    Bytes pub(32), priv(64), sig(64);
    ed25519_create_keypair(pub.data(), priv.data(), seed32.data());
    ed25519_sign(sig.data(), msg.data(), msg.size(), pub.data(), priv.data());
    return sig;
}

bool ed25519Verify(const Bytes& pub32, const Bytes& msg, const Bytes& sig64) {
    if (pub32.size() != 32 || sig64.size() != 64) return false;
    return ed25519_verify(sig64.data(), msg.data(), msg.size(), pub32.data()) != 0;
}

// ── SRP-6a 3072 SHA-512, client side ──────────────────────────────────

struct SrpClient::Impl {
    Mpi N, g, a, A, B, k, u, x, S, v;
    Bytes salt;
    Bytes K;           // session key = SHA512(S)
    Bytes M1;
    std::string password;
    bool processed = false;

    Impl() {
        throwIf(mbedtls_mpi_read_string(N.p(), 16, kSrpN3072), "read N");
        throwIf(mbedtls_mpi_lset(g.p(), 5), "set g");
    }
};

// SHA-512 over two N-byte-padded big-integers (HAP k and u). Mirrors
// pair_ap H_nn_pad: both operands zero-extended to kSrpNBytes on the left.
static Bytes hashTwoPadded(const mbedtls_mpi& a, const mbedtls_mpi& b) {
    Bytes buf;
    buf.reserve(2 * kSrpNBytes);
    Bytes pa = mpiToBytesPadded(a, kSrpNBytes);
    Bytes pb = mpiToBytesPadded(b, kSrpNBytes);
    buf.insert(buf.end(), pa.begin(), pa.end());
    buf.insert(buf.end(), pb.begin(), pb.end());
    return sha512(buf);
}

SrpClient::SrpClient() : d_(new Impl) {}
SrpClient::~SrpClient() { delete d_; }

void SrpClient::start(const std::string& password) {
    d_->password = password;
    // Ephemeral secret a (256 bits, like pair_ap's bnum_random(a, 256)).
    Bytes aBytes = randomBytes(32);
    bytesToMpi(d_->a, aBytes);
    // A = g^a mod N
    throwIf(mbedtls_mpi_exp_mod(d_->A.p(), d_->g.p(), d_->a.p(), d_->N.p(), nullptr),
            "A = g^a");
}

Bytes SrpClient::publicA() const {
    return mpiToBytes(d_->A.v);
}

bool SrpClient::process(const Bytes& salt, const Bytes& serverB) {
    d_->salt = salt;
    bytesToMpi(d_->B, serverB);

    // Reject B ≡ 0 (mod N) (RFC 5054 safety check).
    {
        Mpi tmp;
        throwIf(mbedtls_mpi_mod_mpi(tmp.p(), d_->B.p(), d_->N.p()), "B mod N");
        if (mbedtls_mpi_cmp_int(tmp.p(), 0) == 0) return false;
    }

    // k = H(N | g)  (both padded to N length)
    bytesToMpi(d_->k, hashTwoPadded(d_->N.v, d_->g.v));
    // u = H(A | B)  (both padded to N length)
    bytesToMpi(d_->u, hashTwoPadded(d_->A.v, d_->B.v));

    // x = H(salt | H(username ":" password)); username is always "Pair-Setup".
    {
        Bytes inner;
        const std::string up = std::string("Pair-Setup:") + d_->password;
        inner.assign(up.begin(), up.end());
        Bytes ucpHash = sha512(inner);
        Bytes saltAndHash = salt;
        saltAndHash.insert(saltAndHash.end(), ucpHash.begin(), ucpHash.end());
        bytesToMpi(d_->x, sha512(saltAndHash));
    }

    // S = (B - k * g^x) ^ (a + u * x) mod N
    Mpi gx, kgx, base, ux, exp;
    throwIf(mbedtls_mpi_exp_mod(gx.p(), d_->g.p(), d_->x.p(), d_->N.p(), nullptr),
            "g^x");
    throwIf(mbedtls_mpi_mul_mpi(kgx.p(), d_->k.p(), gx.p()), "k*g^x");
    throwIf(mbedtls_mpi_mod_mpi(kgx.p(), kgx.p(), d_->N.p()), "k*g^x mod N");
    throwIf(mbedtls_mpi_sub_mpi(base.p(), d_->B.p(), kgx.p()), "B - k*g^x");
    // Keep base positive mod N (B - kgx can go negative).
    throwIf(mbedtls_mpi_mod_mpi(base.p(), base.p(), d_->N.p()), "base mod N");
    throwIf(mbedtls_mpi_mul_mpi(ux.p(), d_->u.p(), d_->x.p()), "u*x");
    throwIf(mbedtls_mpi_add_mpi(exp.p(), d_->a.p(), ux.p()), "a + u*x");
    throwIf(mbedtls_mpi_exp_mod(d_->S.p(), base.p(), exp.p(), d_->N.p(), nullptr),
            "S");

    // K = SHA512(S)  (S at natural byte length, like pair_ap hash_num)
    d_->K = sha512(mpiToBytes(d_->S.v));

    // M1 = H( H(N) XOR H(g) | H(I) | salt | A | B | K )
    {
        Bytes hN = sha512(mpiToBytes(d_->N.v));
        Bytes hg = sha512(mpiToBytes(d_->g.v));
        Bytes hXor(64);
        for (int i = 0; i < 64; ++i) hXor[i] = hN[i] ^ hg[i];
        const std::string I = "Pair-Setup";
        Bytes hI = sha512(Bytes(I.begin(), I.end()));

        Bytes m1in;
        m1in.insert(m1in.end(), hXor.begin(), hXor.end());
        m1in.insert(m1in.end(), hI.begin(), hI.end());
        m1in.insert(m1in.end(), salt.begin(), salt.end());
        Bytes aB = mpiToBytes(d_->A.v);
        Bytes bB = mpiToBytes(d_->B.v);
        m1in.insert(m1in.end(), aB.begin(), aB.end());
        m1in.insert(m1in.end(), bB.begin(), bB.end());
        m1in.insert(m1in.end(), d_->K.begin(), d_->K.end());
        d_->M1 = sha512(m1in);
    }

    d_->processed = true;
    return true;
}

Bytes SrpClient::proofM1() const { return d_->M1; }
Bytes SrpClient::sessionKey() const { return d_->K; }

bool SrpClient::verifyServerProof(const Bytes& serverM2) const {
    if (!d_->processed) return false;
    // M2 = H(A | M1 | K)
    Bytes in;
    Bytes aB = mpiToBytes(d_->A.v);
    in.insert(in.end(), aB.begin(), aB.end());
    in.insert(in.end(), d_->M1.begin(), d_->M1.end());
    in.insert(in.end(), d_->K.begin(), d_->K.end());
    Bytes m2 = sha512(in);
    // Constant-time compare (it's a proof, compared against a network value).
    if (m2.size() != serverM2.size()) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < m2.size(); ++i)
        diff = uint8_t(diff | (m2[i] ^ serverM2[i]));
    return diff == 0;
}

// ── HomeKit TLV8 ──────────────────────────────────────────────────────

namespace tlv {

Bytes encode(const Map& items) {
    Bytes out;
    for (const auto& [tag, value] : items) {
        size_t pos = 0;
        // Fragment values > 255 into consecutive same-tag chunks. An empty
        // value still emits one zero-length record (HAP State/Method etc.).
        do {
            const size_t chunk = std::min<size_t>(255, value.size() - pos);
            out.push_back(tag);
            out.push_back(uint8_t(chunk));
            out.insert(out.end(), value.begin() + pos, value.begin() + pos + chunk);
            pos += chunk;
        } while (pos < value.size());
    }
    return out;
}

Map decode(const Bytes& data) {
    Map out;
    size_t i = 0;
    while (i + 2 <= data.size()) {
        const uint8_t tag = data[i];
        const uint8_t len = data[i + 1];
        if (i + 2 + len > data.size()) break;
        const Bytes chunk(data.begin() + i + 2, data.begin() + i + 2 + len);
        // Join a repeated tag that immediately follows (fragmented value).
        if (!out.empty() && out.back().first == tag)
            out.back().second.insert(out.back().second.end(),
                                     chunk.begin(), chunk.end());
        else
            out.emplace_back(tag, chunk);
        i += 2 + len;
    }
    return out;
}

std::optional<Bytes> get(const Map& m, uint8_t tag) {
    for (const auto& [t, v] : m)
        if (t == tag) return v;
    return std::nullopt;
}

} // namespace tlv

// ── binary plist ──────────────────────────────────────────────────────

namespace bplist {

const Value* Value::find(const std::string& key) const {
    if (type != Type::Dict) return nullptr;
    for (const auto& [k, v] : dict)
        if (k == key) return &v;
    return nullptr;
}

namespace {

// bplist object-table encoder. We collect every distinct object into a flat
// table, then emit it with a fixed 4-byte object-reference size (simpler and
// always valid for the small dictionaries AirPlay SETUP uses). The format is
// the canonical Apple bplist00: header "bplist00", object table, offset
// table, then a 32-byte trailer.
struct Encoder {
    std::vector<Bytes> objects;   // each object's encoded bytes (refs are 4-byte)

    // Recursively flatten `v` into the object table, returning its index.
    int add(const Value& v) {
        const int idx = int(objects.size());
        objects.emplace_back();   // reserve slot (recursion-safe ordering)
        Bytes obj;
        switch (v.type) {
        case Value::Type::Bool:
            obj.push_back(v.b ? 0x09 : 0x08);
            break;
        case Value::Type::Int:
            encodeInt(obj, v.i);
            break;
        case Value::Type::Real: {
            obj.push_back(0x23);   // double (8-byte)
            uint64_t bits; std::memcpy(&bits, &v.r, 8);
            for (int s = 7; s >= 0; --s) obj.push_back(uint8_t((bits >> (8*s)) & 0xFF));
            break;
        }
        case Value::Type::Str:
            encodeString(obj, v.s);
            break;
        case Value::Type::Data:
            encodeMarkerLen(obj, 0x40, v.data.size());
            obj.insert(obj.end(), v.data.begin(), v.data.end());
            break;
        case Value::Type::Arr: {
            // Child refs must be assigned AFTER the marker slot, so encode
            // children first into the table, then write the ref list.
            std::vector<int> refs;
            for (const auto& c : v.arr) refs.push_back(add(c));
            encodeMarkerLen(obj, 0xA0, refs.size());
            for (int r : refs) appendRef(obj, r);
            break;
        }
        case Value::Type::Dict: {
            std::vector<int> krefs, vrefs;
            for (const auto& [k, val] : v.dict) {
                Value kv = Value::str(k);
                krefs.push_back(add(kv));
                vrefs.push_back(add(val));
            }
            encodeMarkerLen(obj, 0xD0, v.dict.size());
            for (int r : krefs) appendRef(obj, r);
            for (int r : vrefs) appendRef(obj, r);
            break;
        }
        }
        objects[idx] = std::move(obj);
        return idx;
    }

    static void appendRef(Bytes& obj, int ref) {
        for (int s = 3; s >= 0; --s) obj.push_back(uint8_t((ref >> (8*s)) & 0xFF));
    }

    static void encodeMarkerLen(Bytes& obj, uint8_t marker, size_t len) {
        if (len < 15) {
            obj.push_back(marker | uint8_t(len));
        } else {
            obj.push_back(marker | 0x0F);
            encodeInt(obj, int64_t(len));   // length follows as an int object inline
        }
    }

    static void encodeString(Bytes& obj, const std::string& s) {
        // ASCII string (0x5x). AirPlay SETUP keys/values are all ASCII.
        encodeMarkerLen(obj, 0x50, s.size());
        obj.insert(obj.end(), s.begin(), s.end());
    }

    static void encodeInt(Bytes& obj, int64_t value) {
        // Choose the smallest power-of-two width that holds the value.
        if (value >= 0 && value <= 0xFF) {
            obj.push_back(0x10); obj.push_back(uint8_t(value));
        } else if (value >= 0 && value <= 0xFFFF) {
            obj.push_back(0x11);
            obj.push_back(uint8_t((value >> 8) & 0xFF));
            obj.push_back(uint8_t(value & 0xFF));
        } else if (value >= 0 && value <= 0xFFFFFFFFLL) {
            obj.push_back(0x12);
            for (int s = 3; s >= 0; --s) obj.push_back(uint8_t((value >> (8*s)) & 0xFF));
        } else {
            obj.push_back(0x13);
            for (int s = 7; s >= 0; --s) obj.push_back(uint8_t((value >> (8*s)) & 0xFF));
        }
    }
};

} // namespace

Bytes encode(const Value& root) {
    Encoder enc;
    enc.add(root);   // root is object 0

    Bytes out;
    const char hdr[] = "bplist00";
    out.insert(out.end(), hdr, hdr + 8);

    // Emit the object table, recording each object's byte offset.
    std::vector<uint64_t> offsets;
    offsets.reserve(enc.objects.size());
    for (const auto& o : enc.objects) {
        offsets.push_back(out.size());
        out.insert(out.end(), o.begin(), o.end());
    }

    // Offset table (use 4-byte offsets — generous for our small payloads).
    const uint64_t offsetTableStart = out.size();
    const uint8_t offsetSize = 4;
    for (uint64_t off : offsets)
        for (int s = 3; s >= 0; --s) out.push_back(uint8_t((off >> (8*s)) & 0xFF));

    // Trailer: 6 unused, offsetIntSize, objectRefSize, numObjects(8),
    // topObject(8), offsetTableOffset(8).
    Bytes trailer(32, 0);
    trailer[6] = offsetSize;
    trailer[7] = 4;   // object refs are 4-byte (matches appendRef)
    auto put64 = [&](int at, uint64_t v) {
        for (int s = 0; s < 8; ++s) trailer[at + s] = uint8_t((v >> (8*(7-s))) & 0xFF);
    };
    put64(8, enc.objects.size());
    put64(16, 0);   // top object index
    put64(24, offsetTableStart);
    out.insert(out.end(), trailer.begin(), trailer.end());
    return out;
}

namespace {

struct Decoder {
    const Bytes& d;
    uint8_t offsetSize = 0, refSize = 0;
    uint64_t numObjects = 0;
    uint64_t offsetTableStart = 0;
    std::vector<uint64_t> offsets;
    bool ok = true;

    explicit Decoder(const Bytes& data) : d(data) {}

    uint64_t readBE(uint64_t at, int n) {
        uint64_t v = 0;
        for (int i = 0; i < n; ++i) {
            if (at + i >= d.size()) { ok = false; return 0; }
            v = (v << 8) | d[at + i];
        }
        return v;
    }

    bool parseTrailer() {
        if (d.size() < 8 + 32) return false;
        if (std::memcmp(d.data(), "bplist00", 8) != 0) return false;
        const uint64_t tr = d.size() - 32;
        offsetSize = d[tr + 6];
        refSize    = d[tr + 7];
        numObjects = readBE(tr + 8, 8);
        offsetTableStart = readBE(tr + 24, 8);
        if (!ok) return false;
        // Validate the size fields ∈ {1,2,4,8} and bound numObjects against
        // the file (each object needs ≥1 byte) BEFORE any multiply, so a
        // crafted huge numObjects can't wrap the bounds check (a malicious
        // receiver could otherwise force a multi-exabyte offsets.resize()).
        auto validSize = [](uint64_t s) { return s==1||s==2||s==4||s==8; };
        if (!validSize(offsetSize) || !validSize(refSize)) return false;
        if (offsetTableStart > d.size()) return false;
        if (numObjects > d.size()) return false;            // ≥1 byte/object
        if (numObjects > (d.size() - offsetTableStart) / offsetSize) return false;
        offsets.resize(numObjects);
        for (uint64_t i = 0; i < numObjects; ++i)
            offsets[i] = readBE(offsetTableStart + i * offsetSize, offsetSize);
        return ok;
    }

    // Decode the object at table index `ref`. Bounded recursion via depth.
    std::optional<Value> object(uint64_t ref, int depth) {
        if (depth > 32 || ref >= numObjects) return std::nullopt;
        uint64_t pos = offsets[ref];
        if (pos >= d.size()) return std::nullopt;
        const uint8_t marker = d[pos++];
        const uint8_t hi = marker & 0xF0;
        const uint8_t lo = marker & 0x0F;

        auto readCount = [&](void) -> uint64_t {
            if (lo != 0x0F) return lo;
            // Count is an int object inline.
            if (pos >= d.size()) { ok = false; return 0; }
            const uint8_t im = d[pos++];
            const int n = 1 << (im & 0x0F);
            const uint64_t c = readBE(pos, n);
            pos += n;
            return c;
        };

        switch (hi) {
        case 0x00:   // bool / null / fill
            if (marker == 0x08) return Value::boolean(false);
            if (marker == 0x09) return Value::boolean(true);
            return Value::boolean(false);
        case 0x10: { // int
            const int n = 1 << lo;
            int64_t v = int64_t(readBE(pos, n));
            pos += n;
            return Value::integer(v);
        }
        case 0x20: { // real
            const int n = 1 << lo;
            uint64_t bits = readBE(pos, n);
            pos += n;
            double r = 0;
            if (n == 8) std::memcpy(&r, &bits, 8);
            else if (n == 4) { float f; uint32_t b32 = uint32_t(bits); std::memcpy(&f,&b32,4); r = f; }
            return Value::real(r);
        }
        case 0x40: { // data
            const uint64_t cnt = readCount();
            // Bound cnt FIRST: pos+cnt is uint64 and would WRAP for a crafted
            // near-2^64 cnt, sneaking past a bare pos+cnt check into an OOB
            // slice / huge alloc. (The array/dict cases already guard via
            // cnt>numObjects; data/ASCII lacked the bound.)
            if (cnt > d.size() || pos + cnt > d.size()) return std::nullopt;
            Bytes b(d.begin() + pos, d.begin() + pos + cnt);
            return Value::bytes(std::move(b));
        }
        case 0x50: { // ASCII string
            const uint64_t cnt = readCount();
            if (cnt > d.size() || pos + cnt > d.size()) return std::nullopt;
            return Value::str(std::string(d.begin() + pos, d.begin() + pos + cnt));
        }
        case 0x60: { // UTF-16 string — store the raw bytes' ASCII subset
            const uint64_t cnt = readCount();   // unit count
            std::string s;
            for (uint64_t i = 0; i < cnt; ++i) {
                const uint64_t at = pos + i * 2;
                if (at + 1 >= d.size()) break;
                s.push_back(char(d[at + 1]));   // low byte (ASCII range)
            }
            return Value::str(s);
        }
        case 0xA0: { // array
            const uint64_t cnt = readCount();
            // An array can't reference more objects than exist, and its ref
            // table must fit — bounds a crafted huge `cnt` (DoS hang).
            if (!ok || cnt > numObjects || pos + cnt * refSize > d.size())
                return std::nullopt;
            Array arr;
            for (uint64_t i = 0; i < cnt; ++i) {
                const uint64_t r = readBE(pos + i * refSize, refSize);
                auto child = object(r, depth + 1);
                if (!child) return std::nullopt;
                arr.push_back(std::move(*child));
            }
            return Value::array(std::move(arr));
        }
        case 0xD0: { // dict
            const uint64_t cnt = readCount();
            // key table + value table must both fit, and can't reference
            // more objects than exist (bounds a crafted huge `cnt`).
            if (!ok || cnt > numObjects || pos + 2 * cnt * refSize > d.size())
                return std::nullopt;
            Dict dd;
            for (uint64_t i = 0; i < cnt; ++i) {
                const uint64_t kr = readBE(pos + i * refSize, refSize);
                const uint64_t vr = readBE(pos + (cnt + i) * refSize, refSize);
                auto k = object(kr, depth + 1);
                auto val = object(vr, depth + 1);
                if (!k || !val) return std::nullopt;
                dd.emplace_back(k->asStr(), std::move(*val));
            }
            return Value::object(std::move(dd));
        }
        default:
            return std::nullopt;
        }
    }
};

} // namespace

std::optional<Value> decode(const Bytes& data) {
    Decoder dec(data);
    if (!dec.parseTrailer()) return std::nullopt;
    return dec.object(0, 0);
}

} // namespace bplist

// ── RFC 2617 MD5 digest auth ──────────────────────────────────────────

namespace {
std::string md5Hex(const std::string& s) {
    unsigned char out[16];
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
    mbedtls_md(md, reinterpret_cast<const unsigned char*>(s.data()), s.size(), out);
    static const char* hx = "0123456789abcdef";
    std::string r;
    r.reserve(32);
    for (unsigned char c : out) { r.push_back(hx[c >> 4]); r.push_back(hx[c & 0xF]); }
    return r;
}
} // namespace

std::string digestAuthResponse(const std::string& method, const std::string& uri,
                               const std::string& username, const std::string& realm,
                               const std::string& password, const std::string& nonce) {
    const std::string ha1 = md5Hex(username + ":" + realm + ":" + password);
    const std::string ha2 = md5Hex(method + ":" + uri);
    const std::string resp = md5Hex(ha1 + ":" + nonce + ":" + ha2);
    return "Digest username=\"" + username + "\", realm=\"" + realm +
           "\", nonce=\"" + nonce + "\", uri=\"" + uri +
           "\", response=\"" + resp + "\"";
}

} // namespace fxchain::airplay
