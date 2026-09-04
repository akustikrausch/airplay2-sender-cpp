// SPDX-License-Identifier: Apache-2.0
//
// core_tests.cpp -- the protocol core against an in-process fake receiver.
//
// no sockets, no threads, no real clock: RaopSender talks to a FakeIo that
// records every byte it sends, the test hands it the receiver's replies
// through onTcpData()/onUdpDatagram(), and a fake clock drives tick(). the
// fake receiver is a real (if minimal) AirPlay peer: it runs the SRP-6a
// server side, HAP pair-setup M1..M6, pair-verify with X25519 + Ed25519,
// the encrypted control channel, the event channel, and decrypts the ALAC
// audio, so every step of the README recipe is checked byte for byte.

#include "airplay_crypto.h"
#include "raop_creds.h"
#include "raop_log.h"
#include "raop_sender.h"
#include "ring_buffer.h"

#include <mbedtls/bignum.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace fxchain;
using airplay::Bytes;
using Clock = RaopSender::Clock;

// ── a tiny check harness ────────────────────────────────────────────

namespace {

int g_checks = 0;
int g_failures = 0;
const char* g_test = "";

bool checkImpl(bool ok, const char* what, int line) {
    ++g_checks;
    if (!ok) {
        ++g_failures;
        std::printf("  [FAIL] %s  (%s, line %d)\n", what, g_test, line);
    }
    return ok;
}
#define CHECK(cond, what) checkImpl(bool(cond), what, __LINE__)
#define REQUIRE(cond, what) do { if (!CHECK(cond, what)) return; } while (0)

Bytes bytesOf(std::string_view s) { return Bytes(s.begin(), s.end()); }
std::string strOf(const Bytes& b) { return std::string(b.begin(), b.end()); }
std::span<const uint8_t> spanOf(std::string_view s) {
    return std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}
std::string trim(std::string s) {
    while (!s.empty() && (s.back() == ' ' || s.back() == '\r' || s.back() == '\t')) s.pop_back();
    size_t b = 0;
    while (b < s.size() && (s[b] == ' ' || s[b] == '\t')) ++b;
    return s.substr(b);
}
std::string lower(std::string s) {
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = char(c + 32);
    return s;
}
uint16_t be16(const std::string& s, size_t o) { return uint16_t((uint8_t(s[o]) << 8) | uint8_t(s[o + 1])); }
uint32_t be32(const std::string& s, size_t o) {
    return (uint32_t(uint8_t(s[o])) << 24) | (uint32_t(uint8_t(s[o + 1])) << 16)
         | (uint32_t(uint8_t(s[o + 2])) << 8) | uint32_t(uint8_t(s[o + 3]));
}

// ── request parsing (what the receiver sees) ─────────────────────────

struct Request {
    std::string method, uri, version, raw, body;
    std::map<std::string, std::string> headers;   // lowercase keys
    std::string h(const char* k) const { auto it = headers.find(k); return it == headers.end() ? std::string() : it->second; }
};

// pull every complete request off `stream` (the incomplete tail stays).
std::vector<Request> parseRequests(std::string& stream) {
    std::vector<Request> out;
    for (;;) {
        const size_t headEnd = stream.find("\r\n\r\n");
        if (headEnd == std::string::npos) break;
        Request r;
        const std::string head = stream.substr(0, headEnd);
        size_t p = 0;
        bool first = true;
        size_t clen = 0;
        while (p <= head.size()) {
            const size_t nl = head.find('\n', p);
            const std::string line = trim(head.substr(p, nl == std::string::npos ? std::string::npos : nl - p));
            if (first) {
                first = false;
                const size_t s1 = line.find(' '), s2 = line.rfind(' ');
                r.method  = line.substr(0, s1);
                r.uri     = (s1 != std::string::npos && s2 != std::string::npos && s2 > s1) ? line.substr(s1 + 1, s2 - s1 - 1) : "";
                r.version = s2 != std::string::npos ? line.substr(s2 + 1) : "";
            } else {
                const size_t colon = line.find(':');
                if (colon != std::string::npos) {
                    const std::string k = lower(trim(line.substr(0, colon)));
                    const std::string v = trim(line.substr(colon + 1));
                    r.headers[k] = v;
                    if (k == "content-length") clen = size_t(std::atoi(v.c_str()));
                }
            }
            if (nl == std::string::npos) break;
            p = nl + 1;
        }
        const size_t total = headEnd + 4 + clen;
        if (stream.size() < total) break;
        r.raw  = stream.substr(0, total);
        r.body = stream.substr(headEnd + 4, clen);
        stream.erase(0, total);
        out.push_back(std::move(r));
    }
    return out;
}

// ── the fake host ────────────────────────────────────────────────────

struct FakeIo final : RaopIo {
    struct Connect { RaopTcp ch; std::string host; uint16_t port; };
    struct Datagram { RaopUdp s; RaopEndpoint to; std::string data; };

    std::vector<Connect> connects;
    std::string tcpOut[2];
    bool tcpOpen[2] = {false, false};
    int  tcpCloses[2] = {0, 0};
    int  tcpFlushCloses[2] = {0, 0};
    uint16_t udpPorts[3] = {40001, 40002, 40003};   // Audio, Control, Timing
    bool udpOpen[3] = {false, false, false};
    int  udpCloses[3] = {0, 0, 0};
    bool failBind = false;
    std::vector<Datagram> udpOut;

    void tcpConnect(RaopTcp ch, const std::string& host, uint16_t port) override {
        connects.push_back({ch, host, port});
        tcpOpen[size_t(ch)] = true;
    }
    void tcpSend(RaopTcp ch, std::span<const uint8_t> bytes) override {
        tcpOut[size_t(ch)].append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }
    void tcpClose(RaopTcp ch, bool flush) override {
        if (!tcpOpen[size_t(ch)]) return;
        tcpOpen[size_t(ch)] = false;
        ++tcpCloses[size_t(ch)];
        if (flush) ++tcpFlushCloses[size_t(ch)];
    }
    uint16_t udpBind(RaopUdp s) override {
        if (failBind) return 0;
        udpOpen[size_t(s)] = true;
        return udpPorts[size_t(s)];
    }
    void udpSend(RaopUdp s, const RaopEndpoint& to, std::span<const uint8_t> bytes) override {
        udpOut.push_back({s, to, std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size())});
    }
    void udpClose(RaopUdp s) override {
        if (!udpOpen[size_t(s)]) return;
        udpOpen[size_t(s)] = false;
        ++udpCloses[size_t(s)];
    }

    std::string takeTcp(RaopTcp ch) { std::string s; s.swap(tcpOut[size_t(ch)]); return s; }
    std::vector<Datagram> takeUdp() { std::vector<Datagram> v; v.swap(udpOut); return v; }
    bool anyUdpOpen() const { return udpOpen[0] || udpOpen[1] || udpOpen[2]; }
};

// ── HomeKit crypto on the receiver side ──────────────────────────────

// RFC 5054 group 3072 (g = 5), the SRP group HomeKit pair-setup uses.
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
constexpr size_t kSrpNBytes = 384;

struct Mpi {
    mbedtls_mpi v;
    Mpi() { mbedtls_mpi_init(&v); }
    ~Mpi() { mbedtls_mpi_free(&v); }
    Mpi(const Mpi&) = delete;
    Mpi& operator=(const Mpi&) = delete;
    Mpi(Mpi&& o) noexcept { mbedtls_mpi_init(&v); mbedtls_mpi_swap(&v, &o.v); }
    Mpi& operator=(Mpi&& o) noexcept { if (this != &o) mbedtls_mpi_swap(&v, &o.v); return *this; }
};
Bytes mpiBytes(const mbedtls_mpi& m) {
    const size_t n = mbedtls_mpi_size(&m);
    Bytes out(n == 0 ? 1 : n);
    mbedtls_mpi_write_binary(&m, out.data(), out.size());
    return out;
}
Bytes mpiBytesPadded(const mbedtls_mpi& m, size_t len) {
    Bytes out(len);
    mbedtls_mpi_write_binary(&m, out.data(), len);
    return out;
}
void mpiRead(Mpi& m, const Bytes& b) { mbedtls_mpi_read_binary(&m.v, b.data(), b.size()); }
Bytes cat(std::initializer_list<Bytes> parts) {
    Bytes out;
    for (const Bytes& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

// SRP-6a server (RFC 5054 3072 / SHA-512, HAP padding conventions).
struct SrpServer {
    Mpi N, g, v, b, B, A, u, S, k;
    Bytes salt, K, M1expected, M2;

    void start(const std::string& pin) {
        mbedtls_mpi_read_string(&N.v, 16, kSrpN3072);
        mbedtls_mpi_lset(&g.v, 5);
        salt = airplay::randomBytes(16);
        // x = H(salt | H("Pair-Setup:" + pin)); v = g^x
        const Bytes x = airplay::sha512(cat({salt, airplay::sha512(bytesOf("Pair-Setup:" + pin))}));
        Mpi xm;
        mpiRead(xm, x);
        mbedtls_mpi_exp_mod(&v.v, &g.v, &xm.v, &N.v, nullptr);
        mpiRead(b, airplay::randomBytes(32));
        // k = H(pad(N) | pad(g)); B = (k*v + g^b) mod N
        mpiRead(k, airplay::sha512(cat({mpiBytesPadded(N.v, kSrpNBytes), mpiBytesPadded(g.v, kSrpNBytes)})));
        Mpi kv, gb;
        mbedtls_mpi_mul_mpi(&kv.v, &k.v, &v.v);
        mbedtls_mpi_exp_mod(&gb.v, &g.v, &b.v, &N.v, nullptr);
        mbedtls_mpi_add_mpi(&B.v, &kv.v, &gb.v);
        mbedtls_mpi_mod_mpi(&B.v, &B.v, &N.v);
    }
    Bytes publicB() const { return mpiBytes(B.v); }
    // true when the client's proof M1 matches; fills K and M2.
    bool process(const Bytes& clientA, const Bytes& clientM1) {
        mpiRead(A, clientA);
        mpiRead(u, airplay::sha512(cat({mpiBytesPadded(A.v, kSrpNBytes), mpiBytesPadded(B.v, kSrpNBytes)})));
        Mpi vu, base;
        mbedtls_mpi_exp_mod(&vu.v, &v.v, &u.v, &N.v, nullptr);
        mbedtls_mpi_mul_mpi(&base.v, &A.v, &vu.v);
        mbedtls_mpi_mod_mpi(&base.v, &base.v, &N.v);
        mbedtls_mpi_exp_mod(&S.v, &base.v, &b.v, &N.v, nullptr);
        K = airplay::sha512(mpiBytes(S.v));
        const Bytes hN = airplay::sha512(mpiBytes(N.v)), hg = airplay::sha512(mpiBytes(g.v));
        Bytes hx(64);
        for (size_t i = 0; i < 64; ++i) hx[i] = uint8_t(hN[i] ^ hg[i]);
        M1expected = airplay::sha512(cat({hx, airplay::sha512(bytesOf("Pair-Setup")), salt,
                                          mpiBytes(A.v), mpiBytes(B.v), K}));
        M2 = airplay::sha512(cat({mpiBytes(A.v), M1expected, K}));
        return clientM1 == M1expected;
    }
};

// the HomeKit frame format both encrypted channels use.
std::string encryptFrames(const Bytes& key, uint64_t& ctr, const std::string& plain) {
    std::string out;
    size_t off = 0;
    while (off < plain.size()) {
        const size_t len = std::min<size_t>(1024, plain.size() - off);
        const unsigned char lp[2] = { static_cast<unsigned char>(len & 0xFF), static_cast<unsigned char>((len >> 8) & 0xFF) };
        const Bytes pt(plain.begin() + std::ptrdiff_t(off), plain.begin() + std::ptrdiff_t(off + len));
        const Bytes ct = airplay::chacha20Poly1305Encrypt(key, airplay::counterNonce8(ctr++), pt, Bytes(lp, lp + 2));
        out.append(reinterpret_cast<const char*>(lp), 2);
        out.append(reinterpret_cast<const char*>(ct.data()), ct.size());
        off += len;
    }
    return out;
}
// decrypt whole frames out of `buf` (partial tail stays); `bad` on an auth failure.
std::string decryptFrames(const Bytes& key, uint64_t& ctr, std::string& buf, bool& bad) {
    std::string plain;
    while (buf.size() >= 2) {
        const size_t len = size_t(uint8_t(buf[0])) | (size_t(uint8_t(buf[1])) << 8);
        if (buf.size() < 2 + len + 16) break;
        const unsigned char lp[2] = { static_cast<unsigned char>(buf[0]), static_cast<unsigned char>(buf[1]) };
        const Bytes ctTag(buf.begin() + 2, buf.begin() + std::ptrdiff_t(2 + len + 16));
        auto dec = airplay::chacha20Poly1305Decrypt(key, airplay::counterNonce8(ctr++), ctTag, Bytes(lp, lp + 2));
        if (!dec) { bad = true; buf.clear(); break; }
        plain += strOf(*dec);
        buf.erase(0, 2 + len + 16);
    }
    return plain;
}

// an uncompressed ALAC frame (the only kind the sender emits) -> pcm.
std::optional<std::vector<int16_t>> decodeAlacUncompressed(const std::string& frame, int nFrames) {
    size_t bit = 0;
    auto get = [&](int bits) -> std::optional<uint32_t> {
        uint32_t v = 0;
        for (int i = 0; i < bits; ++i, ++bit) {
            if (bit / 8 >= frame.size()) return std::nullopt;
            v = (v << 1) | ((uint8_t(frame[bit / 8]) >> (7 - bit % 8)) & 1u);
        }
        return v;
    };
    if (get(3) != 1u) return std::nullopt;     // stereo channel-pair element
    if (get(4) != 0u) return std::nullopt;
    if (get(12) != 0u) return std::nullopt;
    if (get(1) != 0u) return std::nullopt;     // hasSize = 0
    if (get(2) != 0u) return std::nullopt;     // wastedBytes
    if (get(1) != 1u) return std::nullopt;     // isNotCompressed
    std::vector<int16_t> pcm;
    pcm.reserve(size_t(nFrames) * 2);
    for (int i = 0; i < nFrames * 2; ++i) {
        const auto s = get(16);
        if (!s) return std::nullopt;
        pcm.push_back(int16_t(uint16_t(*s)));
    }
    if (get(3) != 7u) return std::nullopt;     // END tag
    return pcm;
}

// ── the fake receiver ────────────────────────────────────────────────

struct FakeReceiver {
    enum class Mode { Ap1, Ap2Transient, Ap2Pin, Ap2Verify };
    Mode mode = Mode::Ap1;

    // what the receiver advertises back
    uint16_t serverPort = 6000, controlPort = 6001, timingPort = 6002;   // AP1 SETUP transport
    uint16_t eventPort = 7001, dataPort = 6100, ap2ControlPort = 6101;  // AP2 SETUP plists
    std::string pin = "3939";
    // failure injection
    bool badSrpProof = false;
    bool badVerifySignature = false;

    // receiver identity (pin / verify modes)
    Bytes srvLtsk, srvLtpk, srvId = bytesOf("AA:AA:AA:AA:AA:AA");
    // the client identity learned at M5 (or preset from stored creds)
    Bytes clientLtpk, clientId;
    bool  clientVerifyOk = false;

    // channel crypto
    bool     encrypted = false;
    Bytes    ctrlIn, ctrlOut;       // decrypt the sender's writes / encrypt our replies
    uint64_t ctrlInCtr = 0, ctrlOutCtr = 0;
    Bytes    evOut, evIn;           // encrypt our pushes / decrypt the sender's replies
    uint64_t evOutCtr = 0, evInCtr = 0;
    Bytes    sharedSecret, audioKey;

    std::string plainBuf, encBuf, eventReplyBuf;
    std::vector<Request> requests;   // everything received, in order
    bool sawTeardown = false;
    bool controlDecryptFailed = false;

    SrpServer srp;
    airplay::X25519KeyPair verifyKeys;

    FakeReceiver() {
        srvLtsk = airplay::randomBytes(32);
        srvLtpk = airplay::ed25519PublicFromSeed(srvLtsk);
    }

    const Request* last(const char* method, const char* uri = nullptr) const {
        for (auto it = requests.rbegin(); it != requests.rend(); ++it)
            if (it->method == method && (!uri || it->uri == uri)) return &*it;
        return nullptr;
    }
    int count(const char* method) const {
        int n = 0;
        for (const auto& r : requests) if (r.method == method) ++n;
        return n;
    }

    // bytes from the sender's control channel -> bytes the receiver answers.
    std::string onControlBytes(std::string_view in) {
        if (!encrypted) {
            plainBuf.append(in.data(), in.size());
        } else {
            encBuf.append(in.data(), in.size());
            plainBuf += decryptFrames(ctrlIn, ctrlInCtr, encBuf, controlDecryptFailed);
        }
        std::string out;
        for (Request& r : parseRequests(plainBuf)) {
            bool switchToEncrypted = false;
            const std::string reply = handle(r, switchToEncrypted);
            requests.push_back(std::move(r));
            out += encrypted ? encryptFrames(ctrlOut, ctrlOutCtr, reply) : reply;
            if (switchToEncrypted) encrypted = true;
        }
        return out;
    }

    // an event-channel push (encrypted with the Events-Write key).
    std::string pushEvent(const std::string& rtspRequest) {
        return encryptFrames(evOut, evOutCtr, rtspRequest);
    }
    // the sender's event-channel writes -> plaintext replies.
    std::string readEventReplies(std::string_view in) {
        eventReplyBuf.append(in.data(), in.size());
        bool bad = false;
        return decryptFrames(evIn, evInCtr, eventReplyBuf, bad);
    }

    // an audio datagram -> the pcm frames it carried (AP1 L16 / AP2 ALAC).
    std::optional<std::vector<int16_t>> decodeAudio(const std::string& pkt) {
        if (pkt.size() < 12) return std::nullopt;
        if (mode == Mode::Ap1) {
            if (pkt.size() != 12 + 352 * 4) return std::nullopt;
            std::vector<int16_t> pcm(352 * 2);
            for (size_t i = 0; i < pcm.size(); ++i) pcm[i] = int16_t(be16(pkt, 12 + i * 2));
            return pcm;
        }
        if (pkt.size() < 12 + 16 + 8) return std::nullopt;
        const Bytes aad(pkt.begin() + 4, pkt.begin() + 12);
        const Bytes nonce(pkt.end() - 8, pkt.end());
        const Bytes ctTag(pkt.begin() + 12, pkt.end() - 8);
        auto dec = airplay::chacha20Poly1305Decrypt(audioKey, nonce, ctTag, aad);
        if (!dec) return std::nullopt;
        return decodeAlacUncompressed(strOf(*dec), 352);
    }

private:
    static std::string cseqLine(const Request& r) {
        const std::string c = r.h("cseq");
        return c.empty() ? std::string() : "CSeq: " + c + "\r\n";
    }
    static std::string rtsp200(const Request& r, const std::string& extra = {},
                               const std::string& body = {}, const std::string& contentType = {}) {
        std::string s = "RTSP/1.0 200 OK\r\n" + cseqLine(r) + "Server: AirTunes/366.0\r\n" + extra;
        if (!contentType.empty()) s += "Content-Type: " + contentType + "\r\n";
        s += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
        return s;
    }
    static std::string http(const Request& r, int code, const char* text, const Bytes& body = {}) {
        std::string s = "HTTP/1.1 " + std::to_string(code) + " " + text + "\r\n" + cseqLine(r)
                      + "Content-Type: application/octet-stream\r\n"
                      + "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + strOf(body);
        return s;
    }
    static std::string tlvReply(const Request& r, const airplay::tlv::Map& m) {
        return http(r, 200, "OK", airplay::tlv::encode(m));
    }

    void deriveControlKeys() {
        ctrlIn  = airplay::hkdfSha512("Control-Salt", "Control-Write-Encryption-Key", sharedSecret, 32);
        ctrlOut = airplay::hkdfSha512("Control-Salt", "Control-Read-Encryption-Key",  sharedSecret, 32);
        ctrlInCtr = ctrlOutCtr = 0;
    }
    void deriveEventKeys() {
        evOut = airplay::hkdfSha512("Events-Salt", "Events-Write-Encryption-Key", sharedSecret, 32);
        evIn  = airplay::hkdfSha512("Events-Salt", "Events-Read-Encryption-Key",  sharedSecret, 32);
        evOutCtr = evInCtr = 0;
    }

    std::string handle(const Request& r, bool& switchToEncrypted) {
        using namespace airplay;
        if (r.version.rfind("HTTP/", 0) == 0) return handleHttp(r, switchToEncrypted);

        // RTSP methods (plaintext for AP1, encrypted for AP2)
        if (r.method == "OPTIONS")  return rtsp200(r, "Public: ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER, POST, GET\r\n");
        if (r.method == "ANNOUNCE") return rtsp200(r);
        if (r.method == "SETUP") {
            if (mode == Mode::Ap1) {
                return rtsp200(r, "Transport: RTP/AVP/UDP;unicast;mode=record;server_port=" + std::to_string(serverPort)
                                  + ";control_port=" + std::to_string(controlPort)
                                  + ";timing_port=" + std::to_string(timingPort) + "\r\nSession: 1\r\n");
            }
            auto root = bplist::decode(bytesOf(r.body));
            bplist::Dict d;
            if (root && root->find("streams")) {
                bplist::Dict s;
                s.emplace_back("dataPort", bplist::Value::integer(dataPort));
                s.emplace_back("controlPort", bplist::Value::integer(ap2ControlPort));
                s.emplace_back("type", bplist::Value::integer(0x60));
                bplist::Array arr;
                arr.push_back(bplist::Value::object(std::move(s)));
                d.emplace_back("streams", bplist::Value::array(std::move(arr)));
            } else {
                d.emplace_back("eventPort", bplist::Value::integer(eventPort));
                d.emplace_back("timingPort", bplist::Value::integer(timingPort));
            }
            const Bytes body = bplist::encode(bplist::Value::object(std::move(d)));
            return rtsp200(r, "", strOf(body), "application/x-apple-binary-plist");
        }
        if (r.method == "RECORD")   return rtsp200(r, "Audio-Latency: 11025\r\n");
        if (r.method == "GET")      return rtsp200(r);
        if (r.method == "SET_PARAMETER") return rtsp200(r);
        if (r.method == "POST")     return rtsp200(r);   // /feedback
        if (r.method == "FLUSH")    return rtsp200(r);
        if (r.method == "TEARDOWN") { sawTeardown = true; return rtsp200(r); }
        return "RTSP/1.0 501 Not Implemented\r\n" + cseqLine(r) + "Content-Length: 0\r\n\r\n";
    }

    std::string handleHttp(const Request& r, bool& switchToEncrypted) {
        using namespace airplay;
        if (r.uri == "/pair-pin-start") return http(r, 200, "OK");
        if (r.uri == "/auth-setup")     return http(r, 200, "OK");
        const tlv::Map m = tlv::decode(bytesOf(r.body));
        const auto state = tlv::get(m, tlv::State);
        const int st = (state && !state->empty()) ? int((*state)[0]) : -1;

        if (r.uri == "/pair-setup") {
            if (st == 1) {   // M1 -> M2
                srp.start(pin);
                return tlvReply(r, {{tlv::State, {0x02}}, {tlv::PublicKey, srp.publicB()}, {tlv::Salt, srp.salt}});
            }
            if (st == 3) {   // M3 -> M4
                const auto A = tlv::get(m, tlv::PublicKey), M1 = tlv::get(m, tlv::Proof);
                if (!A || !M1 || !srp.process(*A, *M1))
                    return tlvReply(r, {{tlv::State, {0x04}}, {tlv::Error, {0x02}}});   // kTLVError_Authentication
                Bytes proof = srp.M2;
                if (badSrpProof) proof[0] ^= 0xFF;
                if (mode == Mode::Ap2Transient) {
                    sharedSecret = srp.K;
                    deriveControlKeys();
                    audioKey = Bytes(sharedSecret.begin(), sharedSecret.begin() + 32);
                    switchToEncrypted = true;   // the very next request is encrypted
                }
                return tlvReply(r, {{tlv::State, {0x04}}, {tlv::Proof, proof}});
            }
            if (st == 5) {   // M5 -> M6
                const auto enc = tlv::get(m, tlv::EncryptedData);
                if (!enc) return tlvReply(r, {{tlv::State, {0x06}}, {tlv::Error, {0x01}}});
                const Bytes sessionKey = hkdfSha512("Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info", srp.K, 32);
                auto dec = chacha20Poly1305Decrypt(sessionKey, bytesOf("PS-Msg05"), *enc, {});
                if (!dec) return tlvReply(r, {{tlv::State, {0x06}}, {tlv::Error, {0x02}}});
                const tlv::Map sub = tlv::decode(*dec);
                const auto id = tlv::get(sub, tlv::Identifier), pk = tlv::get(sub, tlv::PublicKey), sig = tlv::get(sub, tlv::Signature);
                if (!id || !pk || !sig) return tlvReply(r, {{tlv::State, {0x06}}, {tlv::Error, {0x01}}});
                const Bytes x = hkdfSha512("Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info", srp.K, 32);
                if (!ed25519Verify(*pk, cat({x, *id, *pk}), *sig))
                    return tlvReply(r, {{tlv::State, {0x06}}, {tlv::Error, {0x02}}});
                clientId = *id;
                clientLtpk = *pk;
                // M6: our long-term identity, signed the HAP way.
                const Bytes ax = hkdfSha512("Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info", srp.K, 32);
                const Bytes srvSig = ed25519Sign(srvLtsk, cat({ax, srvId, srvLtpk}));
                const Bytes inner = tlv::encode({{tlv::Identifier, srvId}, {tlv::PublicKey, srvLtpk}, {tlv::Signature, srvSig}});
                return tlvReply(r, {{tlv::State, {0x06}},
                                    {tlv::EncryptedData, chacha20Poly1305Encrypt(sessionKey, bytesOf("PS-Msg06"), inner, {})}});
            }
            return http(r, 400, "Bad Request");
        }

        if (r.uri == "/pair-verify") {
            if (st == 1) {   // M1 -> M2
                const auto clientPub = tlv::get(m, tlv::PublicKey);
                if (!clientPub) return tlvReply(r, {{tlv::State, {0x02}}, {tlv::Error, {0x01}}});
                verifyKeys = x25519Generate();
                sharedSecret = x25519SharedSecret(verifyKeys.priv, *clientPub);
                const Bytes verifyKey = hkdfSha512("Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info", sharedSecret, 32);
                const Bytes signer = badVerifySignature ? randomBytes(32) : srvLtsk;
                const Bytes sig = ed25519Sign(signer, cat({verifyKeys.pub, srvId, *clientPub}));
                const Bytes inner = tlv::encode({{tlv::Identifier, srvId}, {tlv::Signature, sig}});
                clientVerifyPubForM3 = *clientPub;
                return tlvReply(r, {{tlv::State, {0x02}}, {tlv::PublicKey, verifyKeys.pub},
                                    {tlv::EncryptedData, chacha20Poly1305Encrypt(verifyKey, bytesOf("PV-Msg02"), inner, {})}});
            }
            if (st == 3) {   // M3 -> M4, then the channel goes encrypted
                const auto enc = tlv::get(m, tlv::EncryptedData);
                const Bytes verifyKey = hkdfSha512("Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info", sharedSecret, 32);
                auto dec = enc ? chacha20Poly1305Decrypt(verifyKey, bytesOf("PV-Msg03"), *enc, {}) : std::nullopt;
                if (!dec) return tlvReply(r, {{tlv::State, {0x04}}, {tlv::Error, {0x02}}});
                const tlv::Map sub = tlv::decode(*dec);
                const auto id = tlv::get(sub, tlv::Identifier), sig = tlv::get(sub, tlv::Signature);
                clientVerifyOk = id && sig && *id == clientId && !clientLtpk.empty()
                              && ed25519Verify(clientLtpk, cat({clientVerifyPubForM3, *id, verifyKeys.pub}), *sig);
                if (!clientVerifyOk) return tlvReply(r, {{tlv::State, {0x04}}, {tlv::Error, {0x02}}});
                deriveControlKeys();
                deriveEventKeys();
                audioKey = sharedSecret;   // 32 bytes from X25519
                switchToEncrypted = true;
                return tlvReply(r, {{tlv::State, {0x04}}});
            }
            return http(r, 400, "Bad Request");
        }
        return http(r, 404, "Not Found");
    }

    Bytes clientVerifyPubForM3;
};

// ── a test rig: sender + fake host + fake clock + captured events ──────

struct Rig {
    FakeIo io;
    Clock::time_point now = Clock::time_point(std::chrono::seconds(1000));
    std::vector<std::string> log;
    std::optional<bool> launchedOk;
    std::string launchedErr;
    int launchedCount = 0;
    int closedCount = 0;
    std::optional<std::string> pinDevice;
    std::optional<std::string> credsJson;
    std::string credsDeviceId;
    RingBuffer<int16_t> ring{1u << 16};
    std::unique_ptr<RaopSender> sender;
    FakeReceiver rx;
    const std::string localIp = "192.168.1.5";
    const std::string peerIp  = "192.168.1.20";

    Rig() {
        RaopEvents ev;
        ev.launched = [this](bool ok, const std::string& err) { launchedOk = ok; launchedErr = err; ++launchedCount; };
        ev.closed = [this] { ++closedCount; };
        ev.pinRequired = [this](const std::string& dev) { pinDevice = dev; };
        ev.credentialsObtained = [this](const std::string& dev, const std::string& json) { credsDeviceId = dev; credsJson = json; };
        sender = std::make_unique<RaopSender>(io, std::move(ev),
            [this](RaopLogLevel, const std::string& line) { log.push_back(line); });
        sender->setClock([this] { return now; });
        sender->attachRing(&ring);
        sender->setInputFormat(44100);
    }
    bool logHas(const char* needle) const {
        for (const auto& l : log) if (l.find(needle) != std::string::npos) return true;
        return false;
    }
    // the host completing the control connect
    void connectControl() {
        sender->onTcpConnected(RaopTcp::Control, {localIp, 50000}, {peerIp, 7000});
    }
    // ferry the sender's control bytes through the fake receiver and back
    void exchange() {
        for (int i = 0; i < 32; ++i) {   // a reply usually triggers the next request
            const std::string out = io.takeTcp(RaopTcp::Control);
            if (out.empty()) return;
            const std::string reply = rx.onControlBytes(out);
            if (reply.empty()) return;
            sender->onTcpData(RaopTcp::Control, spanOf(reply));
        }
    }
    void advance(int ms) {
        now += std::chrono::milliseconds(ms);
        sender->tick();
    }
    void fillRingRamp(size_t frames, int16_t seed = 0) {
        std::vector<int16_t> v(frames * 2);
        for (size_t i = 0; i < v.size(); ++i) v[i] = int16_t((seed + int(i) * 37) & 0x7FFF);
        ring.tryPush(std::span<const int16_t>(v.data(), v.size()));
    }
};

std::vector<int16_t> rampExpect(size_t samples, int16_t seed = 0) {
    std::vector<int16_t> v(samples);
    for (size_t i = 0; i < v.size(); ++i) v[i] = int16_t((seed + int(i) * 37) & 0x7FFF);
    return v;
}

// run a full AP2 session through the fake receiver in the given mode.
void runAp2Handshake(Rig& r, FakeReceiver::Mode mode, RaopDeviceInfo::Auth auth,
                     const std::string& creds = {}, const char* pin = nullptr) {
    r.rx.mode = mode;
    if (pin) r.rx.pin = pin;
    r.sender->setAuth(auth, true, "atv-1", creds, "");
    r.sender->start(r.peerIp, 7000, "Living Room");
    r.connectControl();
    r.exchange();
    if (r.pinDevice && r.sender->waitingForPin()) {
        r.sender->submitPin(r.rx.pin);
        r.exchange();
    }
}

// ── the tests ────────────────────────────────────────────────────────

void testFormatter() {
    g_test = "formatter";
    CHECK(raopFormat("{} of {}", 1, "two") == "1 of two", "positional {} substitution");
    CHECK(raopFormat("a{{b}}c {}", 5) == "a{b}c 5", "{{ }} escapes");
    CHECK(raopFormat("{} {}", uint8_t(7), true) == "7 true", "uint8 prints as a number, bool as text");
    CHECK(raopFormat("{}", std::string("s")) == "s", "std::string");
    CHECK(raopFormat("no args {}") == "no args {}", "missing argument leaves the text");
    CHECK(raopFormat("{}", 1, 2) == "1", "surplus arguments are ignored");
}

void testCredsCodec() {
    g_test = "creds codec";
    RaopCreds c;
    c.ltsk = {0x01, 0x02, 0x03};
    c.ltpk = {0xab, 0xcd};
    c.atvId = {0x41, 0x42};
    c.clientId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    const std::string json = raopCredsToJson(c);
    // byte-identical to QJsonDocument(QJsonObject{...}).toJson(Compact): sorted keys, no spaces
    CHECK(json == "{\"atvId\":\"4142\",\"clientId\":\"a1b2c3d4-e5f6-7890-abcd-ef1234567890\",\"ltpk\":\"abcd\",\"ltsk\":\"010203\"}",
          "writer matches the Qt compact json byte for byte");
    const auto back = raopCredsFromJson(json);
    CHECK(back && back->ltsk == c.ltsk && back->ltpk == c.ltpk && back->atvId == c.atvId && back->clientId == c.clientId,
          "round trip");
    const auto old = raopCredsFromJson(" { \"ltsk\" : \"00FF\", \"extra\": {\"x\":[1,2]}, \"clientId\":\"X\\u0041\", \"ltpk\":\"11\" , \"atvId\":\"22\" } ");
    CHECK((old && old->ltsk == Bytes{0x00, 0xff} && old->clientId == "XA" && old->ltpk == Bytes{0x11}),
          "reader tolerates whitespace, order, unknown keys, escapes, uppercase hex");
    CHECK(!raopCredsFromJson("{\"ltsk\":\"zz\",\"ltpk\":\"\",\"atvId\":\"\",\"clientId\":\"\"}"), "bad hex rejected");
    CHECK(!raopCredsFromJson("{\"ltsk\":\"00\"}"), "missing fields rejected");
    CHECK(!raopCredsFromJson("not json"), "garbage rejected");
    CHECK(!raopHexDecode("abc"), "odd hex length rejected");
}

void testAp1Session() {
    g_test = "ap1 session";
    Rig r;
    r.sender->setAuth(RaopDeviceInfo::Auth::None, false, "box", "", "");
    r.sender->start(r.peerIp, 5000, "FakeBox");
    REQUIRE(r.io.connects.size() == 1 && r.io.connects[0].ch == RaopTcp::Control
            && r.io.connects[0].host == r.peerIp && r.io.connects[0].port == 5000, "start() asks the host for the control connect");
    CHECK(r.io.udpOpen[0] && r.io.udpOpen[1] && r.io.udpOpen[2], "the udp trio is bound before the handshake");
    CHECK(r.io.takeTcp(RaopTcp::Control).empty(), "nothing is sent before the connect completes");
    CHECK(r.sender->nextDeadline().has_value(), "the handshake watchdog is armed");

    r.sender->onTcpConnected(RaopTcp::Control, {r.localIp, 50000}, {r.peerIp, 5000});
    // OPTIONS: check the exact header set + order
    std::string out = r.io.takeTcp(RaopTcp::Control);
    std::string stream = out;
    auto reqs = parseRequests(stream);
    REQUIRE(reqs.size() == 1 && reqs[0].method == "OPTIONS", "OPTIONS goes out on connect");
    const std::string dacp = reqs[0].h("dacp-id"), ar = reqs[0].h("active-remote");
    CHECK(!dacp.empty() && dacp == reqs[0].h("client-instance"), "DACP-ID == Client-Instance");
    CHECK(out == "OPTIONS * RTSP/1.0\r\nCSeq: 0\r\nUser-Agent: AirPlay/550.10\r\nDACP-ID: " + dacp
                 + "\r\nActive-Remote: " + ar + "\r\nClient-Instance: " + dacp
                 + "\r\nX-Apple-Client-Name: airplay2-sender-cpp\r\n\r\n",
          "OPTIONS request is byte-identical to the verified form");

    // reply one byte at a time: the response parser must reassemble it
    const std::string optReply = "RTSP/1.0 200 OK\r\nCSeq: 0\r\nPublic: ANNOUNCE, SETUP, RECORD\r\n\r\n";
    for (size_t i = 0; i + 1 < optReply.size(); ++i) {
        r.sender->onTcpData(RaopTcp::Control, spanOf(std::string_view(optReply).substr(i, 1)));
        if (!r.io.tcpOut[0].empty()) break;
    }
    CHECK(r.io.tcpOut[0].empty(), "no request before the reply is complete");
    r.sender->onTcpData(RaopTcp::Control, spanOf(std::string_view(optReply).substr(optReply.size() - 1)));
    out = r.io.takeTcp(RaopTcp::Control);
    stream = out;
    reqs = parseRequests(stream);
    REQUIRE(reqs.size() == 1 && reqs[0].method == "ANNOUNCE", "ANNOUNCE follows the OPTIONS 200");
    const std::string uri = reqs[0].uri;
    const std::string sid = uri.substr(uri.rfind('/') + 1);
    CHECK(uri == "rtsp://" + r.localIp + "/" + sid && !sid.empty(), "rtsp uri = our address as the receiver sees it + session id");
    CHECK(reqs[0].h("content-type") == "application/sdp", "ANNOUNCE content type");
    CHECK(reqs[0].body == "v=0\r\no=iTunes " + sid + " 0 IN IP4 " + r.localIp + "\r\ns=iTunes\r\nc=IN IP4 " + r.peerIp
                          + "\r\nt=0 0\r\nm=audio 0 RTP/AVP 96\r\na=rtpmap:96 L16/44100/2\r\n"
                          "a=fmtp:96 352 0 16 40 10 14 2 255 0 0 44100\r\n",
          "SDP body is byte-identical");
    CHECK(reqs[0].h("content-length") == std::to_string(reqs[0].body.size()), "Content-Length matches the body");
    r.rx.requests.push_back(reqs[0]);

    // let the fake receiver answer from here on
    r.sender->onTcpData(RaopTcp::Control, spanOf(std::string_view("RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")));
    out = r.io.takeTcp(RaopTcp::Control);
    stream = out;
    reqs = parseRequests(stream);
    REQUIRE(reqs.size() == 1 && reqs[0].method == "SETUP", "SETUP follows the ANNOUNCE 200");
    CHECK(reqs[0].h("transport") == "RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port=40002;timing_port=40003",
          "SETUP advertises our control + timing ports");
    r.sender->onTcpData(RaopTcp::Control, spanOf(r.rx.onControlBytes(out)));
    out = r.io.takeTcp(RaopTcp::Control);
    stream = out;
    reqs = parseRequests(stream);
    REQUIRE(reqs.size() == 1 && reqs[0].method == "RECORD", "RECORD follows the SETUP 200");
    const uint16_t firstSeq = uint16_t(std::atoi(reqs[0].h("rtp-info").c_str() + 4));
    CHECK(reqs[0].h("range") == "npt=0-" && reqs[0].h("session") == "1", "RECORD carries Range + Session");
    CHECK(reqs[0].h("rtp-info") == "seq=" + std::to_string(firstSeq) + ";rtptime=66150", "RTP-Info announces seq + rtptime = latency");
    CHECK(out.find("Range: npt=0-\r\nRTP-Info: ") != std::string::npos && out.find("\r\nSession: 1\r\n") != std::string::npos,
          "RECORD header order: Range, RTP-Info, Session");
    CHECK(!r.launchedOk.has_value(), "not launched before the RECORD reply");

    r.sender->onTcpData(RaopTcp::Control, spanOf(r.rx.onControlBytes(out)));
    REQUIRE(r.launchedOk && *r.launchedOk, "RECORD 200 -> launched(true)");
    CHECK(r.sender->active(), "active while streaming");
    auto dgs = r.io.takeUdp();
    REQUIRE(dgs.size() == 1, "exactly the first sync packet went out on launch");
    CHECK(dgs[0].s == RaopUdp::Control && dgs[0].to.ip == r.peerIp && dgs[0].to.port == 6001, "sync goes to the receiver's control port");
    REQUIRE(dgs[0].data.size() == 20, "sync packet is 20 bytes");
    CHECK(uint8_t(dgs[0].data[0]) == 0x90 && uint8_t(dgs[0].data[1]) == 0xD4 && be16(dgs[0].data, 2) == 7, "first sync: marker + type 0xD4 + seq 7");
    CHECK(be32(dgs[0].data, 4) == 0 && be32(dgs[0].data, 16) == 66150, "sync: now-latency = 0, now = latency");
    CHECK(be32(dgs[0].data, 8) != 0, "sync carries wall-clock ntp seconds");
    out = r.io.takeTcp(RaopTcp::Control);
    stream = out;
    reqs = parseRequests(stream);
    REQUIRE(reqs.size() == 1 && reqs[0].method == "POST" && reqs[0].uri == "/feedback" && reqs[0].version == "RTSP/1.0",
            "AP1 sends one POST /feedback probe (RTSP/1.0) on launch");
    CHECK(reqs[0].h("content-length").empty(), "the probe has no body");
    r.sender->onTcpData(RaopTcp::Control, spanOf(r.rx.onControlBytes(out)));

    // audio: the pacer's token bucket, one packet per 8 ms
    r.fillRingRamp(352 * 8);
    r.advance(8);
    dgs = r.io.takeUdp();
    REQUIRE(dgs.size() == 1 && dgs[0].s == RaopUdp::Audio, "8 ms -> one audio packet");
    CHECK(dgs[0].to.ip == r.peerIp && dgs[0].to.port == 6000, "audio goes to server_port");
    const std::string& pkt = dgs[0].data;
    REQUIRE(pkt.size() == 12 + 1408, "AP1 packet = 12 B header + 1408 B L16");
    CHECK(uint8_t(pkt[0]) == 0x80 && uint8_t(pkt[1]) == 0xE0, "first packet: v2 + marker + type 0x60");
    CHECK(be16(pkt, 2) == firstSeq, "first seq == the RECORD RTP-Info seq");
    CHECK(be32(pkt, 4) == 66150, "first rtptime == latency");
    CHECK(be32(pkt, 8) == uint32_t(std::strtoul(sid.c_str(), nullptr, 10)), "SSRC == session id");
    auto pcm = r.rx.decodeAudio(pkt);
    CHECK(pcm && *pcm == rampExpect(704), "L16 payload is the ring's pcm, big-endian");
    const std::string firstPacket = pkt;
    r.advance(8);
    dgs = r.io.takeUdp();
    REQUIRE(dgs.size() == 1, "next 8 ms -> next packet");
    CHECK(uint8_t(dgs[0].data[1]) == 0x60 && be16(dgs[0].data, 2) == uint16_t(firstSeq + 1) && be32(dgs[0].data, 4) == 66150 + 352,
          "second packet: no marker, seq+1, rtptime+352");
    pcm = r.rx.decodeAudio(dgs[0].data);
    CHECK(pcm && *pcm == rampExpect(704, int16_t(704 * 37)), "second packet continues the ring");
    // a stalled host catches up in a burst, capped at 16 packets
    r.advance(1000);
    dgs = r.io.takeUdp();
    int audio = 0, sync = 0;
    for (const auto& d : dgs) { if (d.s == RaopUdp::Audio) ++audio; else ++sync; }
    CHECK(audio == 16, "a 1 s stall is repaid at most 16 packets per tick");
    CHECK(sync == 1 && dgs.front().s == RaopUdp::Control && uint8_t(dgs.front().data[0]) == 0x80,
          "the 1 Hz sync fired first (no marker)");
    // the ring held 8 packets; 2 went out before, so 6 of the burst carry pcm
    // and the rest is silence: the timeline keeps running when the tap is dry
    int withPcm = 0, silent = 0;
    for (const auto& d : dgs) {
        if (d.s != RaopUdp::Audio) continue;
        pcm = r.rx.decodeAudio(d.data);
        if (!pcm) continue;
        if (std::all_of(pcm->begin(), pcm->end(), [](int16_t v) { return v == 0; })) ++silent; else ++withPcm;
    }
    CHECK(withPcm == 6 && silent == 10, "dry ring -> silent packets, timeline alive");

    // retransmit request from the receiver's control port -> reply to the SOURCE
    std::string rr(8, '\0');
    rr[0] = char(0x80); rr[1] = char(0xD5);
    rr[4] = char(firstSeq >> 8); rr[5] = char(firstSeq & 0xFF); rr[7] = 1;
    r.sender->onUdpDatagram(RaopUdp::Control, spanOf(rr), {r.peerIp, 6001});
    dgs = r.io.takeUdp();
    REQUIRE(dgs.size() == 1 && dgs[0].s == RaopUdp::Control, "retransmit request -> one reply");
    CHECK(dgs[0].to.ip == r.peerIp && dgs[0].to.port == 6001, "retransmit reply goes to the datagram source");
    CHECK(dgs[0].data == std::string("\x80\xD6") + char(firstSeq >> 8) + char(firstSeq & 0xFF) + firstPacket,
          "retransmit reply = 0x80 0xD6 + seq + the original packet");
    rr[4] = char(0x7F); rr[5] = char(0xFF);   // a seq we never sent
    r.sender->onUdpDatagram(RaopUdp::Control, spanOf(rr), {r.peerIp, 6001});
    CHECK(r.io.takeUdp().empty(), "unknown seq -> no reply");

    // timing request -> reply echoes the request's send time as reftime
    std::string tq(32, '\0');
    tq[0] = char(0x80); tq[1] = char(0xD2); tq[3] = 7;
    for (int i = 24; i < 32; ++i) tq[size_t(i)] = char('A' + i);
    r.sender->onUdpDatagram(RaopUdp::Timing, spanOf(tq), {r.peerIp, 6002});
    dgs = r.io.takeUdp();
    REQUIRE(dgs.size() == 1 && dgs[0].s == RaopUdp::Timing && dgs[0].data.size() == 32, "timing request -> 32 B reply");
    CHECK(dgs[0].to.ip == r.peerIp && dgs[0].to.port == 6002, "timing reply goes to the datagram source");
    CHECK(uint8_t(dgs[0].data[0]) == 0x80 && uint8_t(dgs[0].data[1]) == 0xD3 && be16(dgs[0].data, 2) == 7, "timing reply header");
    CHECK(dgs[0].data.substr(4, 4) == std::string(4, '\0'), "4 padding bytes");
    CHECK(dgs[0].data.substr(8, 8) == tq.substr(24, 8), "reftime = the request's sendtime");
    CHECK(be32(dgs[0].data, 16) != 0 && dgs[0].data.substr(16, 8) == dgs[0].data.substr(24, 8),
          "recvtime == sendtime = ntp now (one clock read)");
    r.sender->onUdpDatagram(RaopUdp::Timing, spanOf(tq.substr(0, 31)), {r.peerIp, 6002});
    CHECK(r.io.takeUdp().empty(), "short timing request ignored");

    // volume + metadata while streaming, two replies in one chunk
    r.sender->setVolume(100.0);
    r.sender->setNowPlaying("Song", "Artist", "Album", "JPEGBYTES", "image/jpeg");
    out = r.io.takeTcp(RaopTcp::Control);
    stream = out;
    reqs = parseRequests(stream);
    REQUIRE(reqs.size() == 3, "volume + dmap + cover = three SET_PARAMETERs");
    CHECK(reqs[0].method == "SET_PARAMETER" && reqs[0].h("content-type") == "text/parameters" && reqs[0].body == "volume: 0.000000"
          && reqs[0].h("session") == "1", "100 % -> volume: 0.000000 with Session");
    CHECK(reqs[1].h("content-type") == "application/x-dmap-tagged" && reqs[1].h("rtp-info").rfind("seq=", 0) == 0, "dmap metadata with RTP-Info");
    CHECK(reqs[1].body == std::string("mlit\0\0\0\x27", 8) + std::string("minm\0\0\0\x04", 8) + "Song"
                          + std::string("asal\0\0\0\x05", 8) + "Album" + std::string("asar\0\0\0\x06", 8) + "Artist",
          "dmap: mlit{minm, asal, asar} with big-endian lengths");
    CHECK(reqs[2].h("content-type") == "image/jpeg" && reqs[2].body == "JPEGBYTES", "cover art as raw image bytes");
    std::string replies;
    for (const auto& q : reqs) replies += r.rx.onControlBytes(q.raw);
    r.sender->onTcpData(RaopTcp::Control, spanOf(replies));
    CHECK(r.sender->active() && r.io.takeTcp(RaopTcp::Control).empty(), "three replies in one chunk consumed quietly");
    r.sender->setVolume(0.0);
    stream = r.io.takeTcp(RaopTcp::Control);
    reqs = parseRequests(stream);
    CHECK(reqs.size() == 1 && reqs[0].body == "volume: -144.000000", "0 % -> the mute sentinel");
    r.sender->onTcpData(RaopTcp::Control, spanOf(r.rx.onControlBytes(reqs[0].raw)));

    // AP1 keep-alive: the probe's 200 armed a 25 s feedback timer
    r.advance(23000);   // the probe's 200 armed the timer ~1 s ago (fake clock)
    stream = r.io.takeTcp(RaopTcp::Control);
    CHECK(parseRequests(stream).empty(), "no feedback before 25 s");
    r.advance(1100);
    stream = r.io.takeTcp(RaopTcp::Control);
    reqs = parseRequests(stream);
    CHECK(reqs.size() == 1 && reqs[0].method == "POST" && reqs[0].uri == "/feedback", "POST /feedback every 25 s");
    r.io.takeUdp();

    // stop: TEARDOWN with the session, flushed before the socket closes
    r.sender->stop();
    stream = r.io.takeTcp(RaopTcp::Control);
    reqs = parseRequests(stream);
    REQUIRE(reqs.size() == 1 && reqs[0].method == "TEARDOWN", "stop() sends TEARDOWN");
    CHECK(reqs[0].h("session") == "1" && reqs[0].uri == uri, "TEARDOWN carries Session on the session uri");
    CHECK(r.io.tcpFlushCloses[0] == 1 && r.io.tcpCloses[0] == 1, "control socket closed with flush");
    CHECK(!r.io.anyUdpOpen() && r.io.udpCloses[0] == 1 && r.io.udpCloses[1] == 1 && r.io.udpCloses[2] == 1, "udp trio released");
    CHECK(!r.sender->active() && !r.sender->nextDeadline().has_value(), "idle: no timers armed");
    CHECK(r.closedCount == 0, "our own stop() does not report closed()");
    r.advance(30000);
    CHECK(r.io.takeUdp().empty() && r.io.takeTcp(RaopTcp::Control).empty(), "nothing fires after stop()");
}

void testAp2Transient() {
    g_test = "ap2 transient (mac / homepod)";
    Rig r;
    runAp2Handshake(r, FakeReceiver::Mode::Ap2Transient, RaopDeviceInfo::Auth::HapTransient);

    REQUIRE(r.launchedOk && *r.launchedOk, std::string("transient pairing reaches streaming: " + r.launchedErr).c_str());
    CHECK(!r.pinDevice && !r.credsJson, "transient: no pin, no credentials");
    const auto& reqs = r.rx.requests;
    REQUIRE(reqs.size() >= 6, "the whole request sequence arrived");
    CHECK(reqs[0].method == "POST" && reqs[0].uri == "/pair-setup" && reqs[0].version == "HTTP/1.1", "M1 is an HTTP/1.1 POST /pair-setup");
    CHECK(reqs[0].h("x-apple-hkp") == "4" && reqs[0].h("connection") == "keep-alive"
          && reqs[0].h("x-apple-client-name") == "airplay2-sender-cpp" && !reqs[0].h("client-instance").empty(),
          "M1 headers: HKP 4 (transient) + the identity headers the access gate wants");
    {
        const auto m1 = airplay::tlv::decode(bytesOf(reqs[0].body));
        const auto method = airplay::tlv::get(m1, airplay::tlv::Method), state = airplay::tlv::get(m1, airplay::tlv::State),
                   flags = airplay::tlv::get(m1, airplay::tlv::Flags);
        CHECK(method && *method == Bytes{0} && state && *state == Bytes{1} && flags && *flags == Bytes{0x10},
              "M1 tlv: method 0, state 1, flags 0x10 (transient)");
    }
    CHECK(reqs[1].uri == "/pair-setup", "M3");
    {
        const auto m3 = airplay::tlv::decode(bytesOf(reqs[1].body));
        const auto state = airplay::tlv::get(m3, airplay::tlv::State), proof = airplay::tlv::get(m3, airplay::tlv::Proof);
        CHECK(state && *state == Bytes{3} && proof && proof->size() == 64, "M3 tlv: state 3 + a 64-byte proof");
        CHECK(*proof == r.rx.srp.M1expected, "the client's SRP proof M1 verifies against the server's math");
    }
    CHECK(r.rx.encrypted && !r.rx.controlDecryptFailed, "the control channel switched to ChaCha20-Poly1305 right after M4");
    CHECK(r.logHas("control channel now ENCRYPTED"), "sender logs the switch");
    CHECK(reqs[2].method == "GET" && reqs[2].uri == "/info" && reqs[2].version == "RTSP/1.0", "GET /info precedes SETUP (encrypted)");
    CHECK(reqs[2].h("x-apple-client-name") == "airplay2-sender-cpp", "identity header on the rtsp methods too");
    // session SETUP plist
    CHECK(reqs[3].method == "SETUP" && reqs[3].h("content-type") == "application/x-apple-binary-plist"
          && reqs[3].h("x-apple-streamid") == "1", "session SETUP is an RTSP method with a bplist body + X-Apple-StreamID");
    const std::string uri = reqs[3].uri;
    const uint32_t sid = uint32_t(std::strtoul(uri.substr(uri.rfind('/') + 1).c_str(), nullptr, 10));
    {
        auto root = airplay::bplist::decode(bytesOf(reqs[3].body));
        REQUIRE(root, "session SETUP body decodes");
        auto s = [&](const char* k) { auto* v = root->find(k); return v ? v->asStr() : std::string("<missing>"); };
        auto i = [&](const char* k) { auto* v = root->find(k); return v ? v->asInt(-1) : int64_t(-1); };
        CHECK(s("deviceID") == "AA:BB:CC:DD:EE:FF" && s("macAddress") == "AA:BB:CC:DD:EE:FF", "deviceID/macAddress default identity");
        CHECK(s("name") == "airplay2-sender-cpp" && s("model") == "iPhone14,3", "name + model identity");
        CHECK(s("timingProtocol") == "NTP" && i("timingPort") == 40003, "NTP timing on our timing port");
        CHECK(s("sessionUUID").size() == 36 && s("sessionUUID") == [&] { std::string u = s("sessionUUID"); for (char& c : u) if (c >= 'a' && c <= 'z') c = char(c - 32); return u; }(),
              "sessionUUID is an uppercase uuid");
        CHECK(s("osName") == "iPhone OS" && s("osVersion") == "16.5" && s("osBuildVersion") == "20F66" && s("sourceVersion") == "690.7.1",
              "os identity fields");
        auto* b = root->find("isMultiSelectAirPlay");
        CHECK(b && b->type == airplay::bplist::Value::Type::Bool && b->b, "isMultiSelectAirPlay true");
    }
    // event channel opened to the port from the session SETUP reply, before RECORD
    REQUIRE(r.io.connects.size() == 2 && r.io.connects[1].ch == RaopTcp::Event, "event channel connect requested");
    CHECK(r.io.connects[1].host == r.peerIp && r.io.connects[1].port == 7001, "event channel -> the receiver's eventPort");
    CHECK(reqs[4].method == "RECORD", "RECORD between session and stream SETUP");
    CHECK(reqs[5].method == "SETUP", "stream SETUP");
    {
        auto root = airplay::bplist::decode(bytesOf(reqs[5].body));
        REQUIRE(root, "stream SETUP body decodes");
        auto* streams = root->find("streams");
        REQUIRE(streams && streams->type == airplay::bplist::Value::Type::Arr && streams->arr.size() == 1, "one stream");
        const auto& st = streams->arr[0];
        auto i = [&](const char* k) { auto* v = st.find(k); return v ? v->asInt(-1) : int64_t(-1); };
        CHECK(i("audioFormat") == 0x40000 && i("ct") == 2 && i("type") == 0x60 && i("spf") == 352 && i("sr") == 44100,
              "realtime ALAC stream: audioFormat 0x40000, ct 2, type 0x60, spf 352, sr 44100");
        CHECK(i("controlPort") == 40002 && i("latencyMin") == 11025 && i("latencyMax") == 88200, "our control port + latency window");
        CHECK(i("streamConnectionID") == int64_t(sid), "streamConnectionID == the rtsp session id");
        auto* shk = st.find("shk");
        CHECK(shk && shk->type == airplay::bplist::Value::Type::Data && shk->data.size() == 32
              && shk->data == Bytes(r.rx.srp.K.begin(), r.rx.srp.K.begin() + 32),
              "shk = the FIRST 32 bytes of the 64-byte SRP session key (the macOS clamp)");
    }
    // streaming: the default AP2 volume push, the first sync, feedback interval
    std::string stream;
    {
        const Request* vol = r.rx.last("SET_PARAMETER");
        REQUIRE(vol && r.rx.count("SET_PARAMETER") == 1, "one SET_PARAMETER after the stream SETUP");
        CHECK(vol->body == "volume: 0.000000" && vol->h("session").empty() && vol->h("content-type") == "text/parameters",
              "AP2 default volume 0 dB, no Session header");
        CHECK(r.io.takeTcp(RaopTcp::Control).empty(), "nothing else pending on the control channel");
    }
    auto dgs = r.io.takeUdp();
    REQUIRE(dgs.size() == 1 && dgs[0].s == RaopUdp::Control && dgs[0].to.port == 6101, "first sync to the AP2 control port");
    CHECK(uint8_t(dgs[0].data[0]) == 0x90 && uint8_t(dgs[0].data[1]) == 0xD4, "sync marker + type");

    // encrypted ALAC audio
    r.fillRingRamp(352 * 4);
    r.advance(8);
    dgs = r.io.takeUdp();
    REQUIRE(dgs.size() == 1 && dgs[0].s == RaopUdp::Audio && dgs[0].to.port == 6100, "one audio packet to dataPort");
    const std::string& pkt = dgs[0].data;
    CHECK(uint8_t(pkt[0]) == 0x80 && uint8_t(pkt[1]) == 0xE0 && be32(pkt, 8) == sid, "rtp header: marker on the first packet, SSRC = session id");
    CHECK(pkt.size() == 12 + 1412 + 16 + 8, "payload = uncompressed ALAC frame (1412 B) + tag + trailing nonce");
    auto pcm = r.rx.decodeAudio(pkt);
    CHECK(pcm && *pcm == rampExpect(704), "audio decrypts with the 32-byte key and decodes as uncompressed ALAC");
    CHECK(pkt.substr(pkt.size() - 8) == std::string(8, '\0'), "first nonce is counter 0");
    r.advance(8);
    dgs = r.io.takeUdp();
    REQUIRE(dgs.size() == 1, "second packet");
    CHECK(dgs[0].data.substr(dgs[0].data.size() - 8) == std::string("\x01") + std::string(7, '\0'), "nonce counts up little-endian");
    pcm = r.rx.decodeAudio(dgs[0].data);
    CHECK(pcm && *pcm == rampExpect(704, int16_t(704 * 37)), "second packet continues the ring");

    // the event channel exists but transient pairing has no event keys: pushes are drained, not answered
    r.sender->onTcpConnected(RaopTcp::Event, {r.localIp, 50001}, {r.peerIp, 7001});
    r.sender->onTcpData(RaopTcp::Event, spanOf(std::string_view("\x05\x00garbage-frame-bytes-here")));
    CHECK(r.io.takeTcp(RaopTcp::Event).empty() && r.sender->active(), "unkeyed event channel: drained quietly");

    // AP2 feedback every 2 s, as an RTSP/1.0 POST with the identity headers
    r.advance(1900);
    stream = r.io.takeTcp(RaopTcp::Control);
    CHECK(stream.empty(), "no feedback before 2 s");
    r.advance(200);
    stream = r.io.takeTcp(RaopTcp::Control);
    {
        bool bad = false;
        std::string plain = decryptFrames(r.rx.ctrlIn, r.rx.ctrlInCtr, stream, bad);
        auto fb = parseRequests(plain);
        REQUIRE(!bad && fb.size() == 1, "one feedback");
        CHECK(fb[0].method == "POST" && fb[0].uri == "/feedback" && fb[0].version == "RTSP/1.0" && fb[0].h("content-length") == "0"
              && !fb[0].h("dacp-id").empty() && !fb[0].h("active-remote").empty() && !fb[0].h("client-instance").empty(),
              "POST /feedback RTSP/1.0 with CSeq/DACP-ID/Active-Remote/Client-Instance, empty body");
        r.sender->onTcpData(RaopTcp::Control, spanOf(encryptFrames(r.rx.ctrlOut, r.rx.ctrlOutCtr, "RTSP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")));
        CHECK(r.sender->active(), "feedback 200 consumed");
    }
    r.io.takeUdp();

    // stop: a bare encrypted TEARDOWN (no Session header on AP2), flushed
    r.sender->stop();
    stream = r.io.takeTcp(RaopTcp::Control);
    {
        bool bad = false;
        std::string plain = decryptFrames(r.rx.ctrlIn, r.rx.ctrlInCtr, stream, bad);
        auto td = parseRequests(plain);
        REQUIRE(!bad && td.size() == 1 && td[0].method == "TEARDOWN", "encrypted TEARDOWN on stop()");
        CHECK(td[0].h("session").empty() && td[0].uri == uri, "AP2 TEARDOWN has no Session header");
    }
    CHECK(r.io.tcpFlushCloses[0] == 1 && r.io.tcpCloses[1] == 1 && !r.io.anyUdpOpen(), "control flushed + event + udp released");
}

void testAp2PinPairingThenStoredCredentials() {
    g_test = "ap2 pin pairing (apple tv)";
    Rig r;
    runAp2Handshake(r, FakeReceiver::Mode::Ap2Pin, RaopDeviceInfo::Auth::HapPin, "", "1234");
    REQUIRE(r.launchedOk && *r.launchedOk, std::string("pin pairing reaches streaming: " + r.launchedErr).c_str());
    const auto& reqs = r.rx.requests;
    REQUIRE(reqs.size() >= 10, "pin-start, M1, M3, M5, verify M1, verify M3, info, setup, record, setup");
    CHECK(reqs[0].method == "POST" && reqs[0].uri == "/pair-pin-start" && reqs[0].h("x-apple-hkp") == "3" && reqs[0].h("content-length") == "0",
          "/pair-pin-start first (HKP 3, empty body) so the apple tv shows its code");
    {
        const auto m1 = airplay::tlv::decode(bytesOf(reqs[1].body));
        CHECK(reqs[1].uri == "/pair-setup" && !airplay::tlv::get(m1, airplay::tlv::Flags), "M1 without the transient flag");
    }
    CHECK(r.pinDevice && *r.pinDevice == "Living Room", "pinRequired() named the receiver");
    CHECK(reqs[2].uri == "/pair-setup" && reqs[3].uri == "/pair-setup", "M3 then M5");
    CHECK(!r.rx.clientLtpk.empty() && r.rx.clientLtpk.size() == 32, "M5 carried our long-term public key, signature verified");
    REQUIRE(r.credsJson.has_value(), "credentialsObtained() fired after M6");
    CHECK(r.credsDeviceId == "atv-1", "credentials keyed by the device id we were given");
    const auto creds = raopCredsFromJson(*r.credsJson);
    REQUIRE(creds.has_value(), "credentials json parses");
    CHECK(creds->ltpk == r.rx.srvLtpk && creds->atvId == r.rx.srvId, "credentials store the receiver's ltpk + id from M6");
    CHECK(creds->ltsk.size() == 32 && airplay::ed25519PublicFromSeed(creds->ltsk) == r.rx.clientLtpk, "ltsk is the seed of the key we signed M5 with");
    CHECK(creds->clientId.size() == 36 && creds->clientId == strOf(r.rx.clientId), "clientId is our pairing uuid");
    CHECK(reqs[4].uri == "/pair-verify" && reqs[5].uri == "/pair-verify", "pair-verify M1 + M3 follow pair-setup");
    CHECK(r.rx.clientVerifyOk, "our pair-verify M3 signature verified with the ltpk from M5");
    CHECK(r.rx.encrypted && reqs[6].method == "GET" && reqs[6].uri == "/info", "encrypted GET /info after pair-verify");
    CHECK(reqs[7].method == "SETUP" && reqs[8].method == "RECORD" && reqs[9].method == "SETUP", "session SETUP, RECORD, stream SETUP");
    {
        auto root = airplay::bplist::decode(bytesOf(reqs[9].body));
        auto* shk = root ? root->find("streams")->arr[0].find("shk") : nullptr;
        CHECK(shk && shk->data == r.rx.sharedSecret && shk->data.size() == 32, "shk = the 32-byte X25519 secret from pair-verify");
    }
    CHECK(r.logHas("pairing complete, credentials stored") && r.logHas("pair-verify complete"), "log tells the story");
    r.io.takeTcp(RaopTcp::Control);
    r.io.takeUdp();

    // the event-channel keep-alive: decrypt each pushed request, answer a bare 200
    r.sender->onTcpConnected(RaopTcp::Event, {r.localIp, 50001}, {r.peerIp, 7001});
    const std::string ev1 = "POST /command RTSP/1.0\r\nCSeq: 7\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: 5\r\n\r\nhello";
    const std::string ev2 = "POST /command RTSP/1.0\r\nCSeq: 8\r\nContent-Length: 0\r\n\r\n";
    const std::string frames = r.rx.pushEvent(ev1 + ev2);
    // deliver in two odd-sized chunks: frame reassembly + two requests in one frame
    r.sender->onTcpData(RaopTcp::Event, spanOf(std::string_view(frames).substr(0, 7)));
    CHECK(r.io.takeTcp(RaopTcp::Event).empty(), "no reply on a partial frame");
    r.sender->onTcpData(RaopTcp::Event, spanOf(std::string_view(frames).substr(7)));
    {
        const std::string replies = r.rx.readEventReplies(r.io.takeTcp(RaopTcp::Event));
        CHECK(replies == "RTSP/1.0 200 OK\r\nServer: AirTunes/550.10\r\nCSeq: 7\r\n\r\n"
                         "RTSP/1.0 200 OK\r\nServer: AirTunes/550.10\r\nCSeq: 8\r\n\r\n",
              "each event is answered with the minimal 200 (Server + CSeq only, no Content-Length)");
    }
    r.sender->onTcpData(RaopTcp::Event, spanOf(r.rx.pushEvent("POST /command RTSP/1.0\r\nContent-Length: 0\r\n\r\n")));
    CHECK(r.rx.readEventReplies(r.io.takeTcp(RaopTcp::Event)) == "RTSP/1.0 200 OK\r\nServer: AirTunes/550.10\r\n\r\n",
          "no CSeq in -> no CSeq out");
    CHECK(r.sender->active(), "still streaming");

    // audio with the pair-verify key
    r.fillRingRamp(352 * 2);
    r.advance(8);
    auto dgs = r.io.takeUdp();
    REQUIRE(dgs.size() == 1 && dgs[0].s == RaopUdp::Audio, "audio packet");
    auto pcm = r.rx.decodeAudio(dgs[0].data);
    CHECK(pcm && *pcm == rampExpect(704), "audio encrypted with the 32-byte pair-verify secret");

    // the event channel dropping is logged, not fatal
    r.sender->onTcpClosed(RaopTcp::Event, "");
    CHECK(r.sender->active() && r.logHas("event channel closed"), "event channel close: logged, session continues");
    r.sender->stop();

    // ── reconnect with the stored credentials: straight to pair-verify ──
    g_test = "ap2 stored credentials (pair-verify only)";
    Rig r2;
    r2.rx.srvLtsk = r.rx.srvLtsk;
    r2.rx.srvLtpk = r.rx.srvLtpk;
    r2.rx.clientLtpk = r.rx.clientLtpk;
    r2.rx.clientId = r.rx.clientId;
    runAp2Handshake(r2, FakeReceiver::Mode::Ap2Verify, RaopDeviceInfo::Auth::HapPin, *r.credsJson);
    REQUIRE(r2.launchedOk && *r2.launchedOk, std::string("stored creds reach streaming: " + r2.launchedErr).c_str());
    CHECK(!r2.pinDevice && !r2.credsJson, "no pin, no new credentials");
    REQUIRE(r2.rx.requests.size() >= 6, "verify M1, M3, info, setup, record, setup");
    CHECK(r2.rx.requests[0].uri == "/pair-verify" && r2.rx.requests[1].uri == "/pair-verify", "first request is pair-verify M1");
    CHECK(r2.rx.clientVerifyOk, "the stored ltsk signs a verifiable M3");
    CHECK(r2.rx.requests[2].method == "GET" && r2.rx.encrypted, "then the encrypted SETUP sequence");
    r2.sender->stop();

    // ── unusable stored credentials fall back to a fresh pin pairing ──
    g_test = "ap2 unusable stored credentials";
    Rig r3;
    runAp2Handshake(r3, FakeReceiver::Mode::Ap2Pin, RaopDeviceInfo::Auth::HapPin,
                    "{\"atvId\":\"41\",\"clientId\":\"x\",\"ltpk\":\"\",\"ltsk\":\"00\"}", "5555");
    CHECK(r3.launchedOk && *r3.launchedOk && r3.rx.requests[0].uri == "/pair-pin-start" && r3.credsJson,
          "short ltsk -> pair afresh with the pin, new credentials");
    CHECK(r3.logHas("stored AirPlay credentials unusable"), "and say so in the log");
    r3.sender->stop();
}

void testStrictReceiverAuth() {
    g_test = "receiver auth: default logs and continues";
    {
        Rig r;
        r.rx.badSrpProof = true;
        runAp2Handshake(r, FakeReceiver::Mode::Ap2Transient, RaopDeviceInfo::Auth::HapTransient);
        CHECK(r.launchedOk && *r.launchedOk, "bad SRP proof, default mode: session still launches");
        CHECK(r.logHas("server proof mismatch (continuing)"), "but the mismatch is logged");
        r.sender->stop();
    }
    {
        Rig r;
        r.rx.badVerifySignature = true;
        runAp2Handshake(r, FakeReceiver::Mode::Ap2Pin, RaopDeviceInfo::Auth::HapPin, "", "1234");
        CHECK(r.launchedOk && *r.launchedOk, "bad pair-verify signature, default mode: session still launches");
        CHECK(r.logHas("pair-verify signature mismatch (continuing)"), "logged");
        r.sender->stop();
    }
    g_test = "receiver auth: strict fails closed";
    {
        Rig r;
        r.rx.badSrpProof = true;
        r.sender->setStrictReceiverAuth(true);
        runAp2Handshake(r, FakeReceiver::Mode::Ap2Transient, RaopDeviceInfo::Auth::HapTransient);
        CHECK(r.launchedOk && !*r.launchedOk && r.launchedErr.find("not authenticated") != std::string::npos,
              "bad SRP proof, strict: launched(false, ...not authenticated)");
        CHECK(!r.sender->active() && r.closedCount == 1 && !r.io.anyUdpOpen() && r.io.tcpCloses[0] == 1, "torn down cleanly");
        CHECK(r.rx.count("GET") == 0, "nothing was sent over the channel after the failed proof");
    }
    {
        Rig r;
        r.rx.badVerifySignature = true;
        r.sender->setStrictReceiverAuth(true);
        runAp2Handshake(r, FakeReceiver::Mode::Ap2Pin, RaopDeviceInfo::Auth::HapPin, "", "1234");
        CHECK(r.launchedOk && !*r.launchedOk && r.launchedErr.find("not authenticated") != std::string::npos,
              "bad pair-verify signature, strict: launched(false)");
        CHECK(r.rx.count("GET") == 0 && !r.sender->active(), "no SETUP sequence after the failed signature");
    }
    {
        Rig r;
        r.sender->setStrictReceiverAuth(true);
        runAp2Handshake(r, FakeReceiver::Mode::Ap2Pin, RaopDeviceInfo::Auth::HapPin, "", "1234");
        CHECK(r.launchedOk && *r.launchedOk, "strict mode with an honest receiver launches");
        r.sender->stop();
    }
}

void testFailurePaths() {
    g_test = "connect failure";
    {
        Rig r;
        r.sender->setAuth(RaopDeviceInfo::Auth::None, false, "box", "", "");
        r.sender->start(r.peerIp, 5000, "FakeBox");
        r.sender->onTcpConnectFailed(RaopTcp::Control, "connection refused");
        CHECK(r.launchedOk && !*r.launchedOk && r.launchedErr == "connection refused", "connect failure -> launched(false, reason)");
        CHECK(r.closedCount == 1 && !r.sender->active() && !r.io.anyUdpOpen(), "closed(), idle, udp released");
        CHECK(!r.sender->nextDeadline().has_value(), "no timers left armed");
    }
    g_test = "udp bind failure";
    {
        Rig r;
        r.io.failBind = true;
        r.sender->setAuth(RaopDeviceInfo::Auth::None, false, "box", "", "");
        r.sender->start(r.peerIp, 5000, "FakeBox");
        CHECK(r.launchedOk && !*r.launchedOk && r.launchedErr == "Could not bind UDP sockets", "bind failure reported");
        CHECK(r.io.connects.empty() && !r.sender->active(), "no connect attempted");
    }
    g_test = "handshake timeout";
    {
        Rig r;
        r.sender->setAuth(RaopDeviceInfo::Auth::None, false, "box", "", "");
        r.sender->start(r.peerIp, 5000, "FakeBox");
        r.connectControl();
        r.io.takeTcp(RaopTcp::Control);
        r.advance(9900);
        CHECK(r.sender->active() && !r.launchedOk, "9.9 s: still waiting");
        r.advance(200);
        CHECK(r.launchedOk && !*r.launchedOk && r.launchedErr == "Timed out waiting for the device", "10 s without a reply -> timeout");
        CHECK(r.logHas("handshake TIMEOUT, state=3 pairStage=0"), "the diag names where it stalled");
        CHECK(r.io.tcpCloses[0] == 1 && r.io.tcpFlushCloses[0] == 0, "aborted, not flushed");
    }
    g_test = "pin wait watchdog";
    {
        Rig r;
        r.rx.mode = FakeReceiver::Mode::Ap2Pin;
        r.sender->setAuth(RaopDeviceInfo::Auth::HapPin, true, "atv-1", "", "");
        r.sender->start(r.peerIp, 7000, "Living Room");
        r.connectControl();
        r.exchange();
        REQUIRE(r.pinDevice && r.sender->waitingForPin(), "waiting for the pin");
        r.advance(60000);
        CHECK(r.sender->active(), "the 10 s handshake watchdog is off while the user reads the code");
        r.advance(121000);
        CHECK(r.launchedOk && !*r.launchedOk && r.launchedErr.rfind("No PIN was entered", 0) == 0 && !r.sender->waitingForPin(),
              "3 min without a pin -> fail with a message naming the receiver");
        CHECK(r.launchedErr.find("Living Room") != std::string::npos, "message names the receiver");
    }
    g_test = "remote close";
    {
        Rig r;
        r.sender->setAuth(RaopDeviceInfo::Auth::None, false, "box", "", "");
        r.sender->start(r.peerIp, 5000, "FakeBox");
        r.sender->onTcpConnected(RaopTcp::Control, {r.localIp, 50000}, {r.peerIp, 5000});
        r.exchange();
        REQUIRE(r.launchedOk && *r.launchedOk, "streaming");
        r.sender->onTcpClosed(RaopTcp::Control, "");
        CHECK(r.closedCount == 1 && r.launchedCount == 1 && !r.sender->active(), "peer FIN -> closed() only (already launched)");
        CHECK(!r.io.anyUdpOpen() && r.io.udpCloses[0] == 1 && r.io.udpCloses[1] == 1 && r.io.udpCloses[2] == 1,
              "udp trio released on a remote close");
        CHECK(!r.sender->nextDeadline().has_value(), "timers off");
        // and a new session works: everything is re-bound and re-connected
        r.rx = FakeReceiver();
        r.launchedOk.reset();
        r.sender->start(r.peerIp, 5000, "FakeBox");
        CHECK(r.io.udpOpen[0] && r.io.udpOpen[1] && r.io.udpOpen[2] && r.io.connects.size() == 2, "second session binds + connects again");
        r.sender->onTcpConnected(RaopTcp::Control, {r.localIp, 50002}, {r.peerIp, 5000});
        r.exchange();
        CHECK(r.launchedOk && *r.launchedOk, "second session streams");
        r.sender->stop();
        r.rx.onControlBytes(r.io.takeTcp(RaopTcp::Control));
        CHECK(r.rx.sawTeardown, "TEARDOWN reached the receiver");
    }
    g_test = "remote close during the handshake";
    {
        Rig r;
        r.sender->setAuth(RaopDeviceInfo::Auth::None, false, "box", "", "");
        r.sender->start(r.peerIp, 5000, "FakeBox");
        r.connectControl();
        r.sender->onTcpClosed(RaopTcp::Control, "");
        CHECK(r.launchedOk && !*r.launchedOk && r.launchedErr == "Connection closed by the device" && r.closedCount == 1,
              "FIN before RECORD -> launched(false) + closed()");
        Rig e;
        e.sender->setAuth(RaopDeviceInfo::Auth::None, false, "box", "", "");
        e.sender->start(e.peerIp, 5000, "FakeBox");
        e.connectControl();
        e.sender->onTcpClosed(RaopTcp::Control, "connection reset by peer");
        CHECK(e.launchedOk && !*e.launchedOk && e.launchedErr == "connection reset by peer", "socket error text is passed through");
    }
    g_test = "receiver refuses";
    {
        Rig r;
        r.sender->setAuth(RaopDeviceInfo::Auth::None, false, "box", "", "");
        r.sender->start(r.peerIp, 5000, "FakeBox");
        r.connectControl();
        r.io.takeTcp(RaopTcp::Control);
        r.sender->onTcpData(RaopTcp::Control, spanOf(std::string_view("RTSP/1.0 453 Not Enough Bandwidth\r\nCSeq: 0\r\n\r\n")));
        CHECK(r.launchedOk && !*r.launchedOk && r.launchedErr == "Device refused OPTIONS (453)", "non-2xx during the handshake is fatal");
    }
    g_test = "oversized response";
    {
        Rig r;
        r.sender->setAuth(RaopDeviceInfo::Auth::None, false, "box", "", "");
        r.sender->start(r.peerIp, 5000, "FakeBox");
        r.connectControl();
        r.io.takeTcp(RaopTcp::Control);
        const std::string junk(1 << 20, 'x');
        for (int i = 0; i < 5 && r.sender->active(); ++i) r.sender->onTcpData(RaopTcp::Control, spanOf(junk));
        CHECK(r.launchedOk && !*r.launchedOk && r.launchedErr == "Oversized RTSP response from the receiver", "4 MB without a header end -> dropped");
    }
    g_test = "destructor tears a live session down";
    {
        FakeIo io;
        {
            RaopSender s(io, RaopEvents{});
            s.setAuth(RaopDeviceInfo::Auth::None, false, "box", "", "");
            s.start("192.168.1.20", 5000, "FakeBox");
            s.onTcpConnected(RaopTcp::Control, {"192.168.1.5", 1}, {"192.168.1.20", 5000});
        }
        CHECK(io.tcpCloses[0] == 1 && !io.anyUdpOpen(), "sockets released by the destructor");
    }
}

void testIdentityAndDigest() {
    g_test = "identity";
    {
        Rig r;
        RaopIdentity id;
        id.name = "My\r\nPlayer";
        id.deviceId = "11:22:33:44:55:66";
        id.model = "";
        r.sender->setIdentity(id);
        r.sender->setAuth(RaopDeviceInfo::Auth::None, false, "box", "", "");
        r.sender->start(r.peerIp, 5000, "FakeBox");
        r.connectControl();
        std::string stream = r.io.takeTcp(RaopTcp::Control);
        auto reqs = parseRequests(stream);
        REQUIRE(reqs.size() == 1, "OPTIONS");
        CHECK(reqs[0].h("x-apple-client-name") == "MyPlayer", "CR/LF stripped from the client name (no header injection)");
        r.sender->stop();
        Rig a;
        a.sender->setIdentity(id);
        runAp2Handshake(a, FakeReceiver::Mode::Ap2Transient, RaopDeviceInfo::Auth::HapTransient);
        REQUIRE(a.launchedOk && *a.launchedOk, "streams");
        auto root = airplay::bplist::decode(bytesOf(a.rx.requests[3].body));
        REQUIRE(root, "session setup");
        CHECK(root->find("name")->asStr() == "MyPlayer" && root->find("deviceID")->asStr() == "11:22:33:44:55:66"
              && root->find("macAddress")->asStr() == "11:22:33:44:55:66" && root->find("model")->asStr() == "iPhone14,3",
              "identity flows into the session SETUP; an empty model keeps the default");
        a.sender->stop();
    }
    g_test = "rtsp digest auth (pw=true)";
    {
        Rig r;
        r.sender->setAuth(RaopDeviceInfo::Auth::Password, false, "box", "", "secret");
        r.sender->start(r.peerIp, 5000, "FakeBox");
        r.connectControl();
        std::string stream = r.io.takeTcp(RaopTcp::Control);
        auto reqs = parseRequests(stream);
        REQUIRE(reqs.size() == 1 && reqs[0].method == "OPTIONS" && reqs[0].h("authorization").empty(), "first OPTIONS without auth");
        r.sender->onTcpData(RaopTcp::Control, spanOf(std::string_view(
            "RTSP/1.0 401 Unauthorized\r\nCSeq: 0\r\nWWW-Authenticate: Digest realm=\"AirPlay\", nonce=\"abc123\"\r\n\r\n")));
        stream = r.io.takeTcp(RaopTcp::Control);
        reqs = parseRequests(stream);
        REQUIRE(reqs.size() == 1 && reqs[0].method == "OPTIONS", "OPTIONS re-sent");
        const std::string auth = reqs[0].h("authorization");
        CHECK(auth == airplay::digestAuthResponse("OPTIONS", "*", "iTunes", "AirPlay", "secret", "abc123"), "with the RFC 2617 digest");
        CHECK(auth.find("username=\"iTunes\"") != std::string::npos && auth.find("nonce=\"abc123\"") != std::string::npos, "digest fields");
        r.sender->onTcpData(RaopTcp::Control, spanOf(std::string_view("RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n\r\n")));
        CHECK(r.launchedOk && !*r.launchedOk && r.launchedErr == "The password was not accepted by the device", "second 401 is final");
        Rig n;
        n.sender->setAuth(RaopDeviceInfo::Auth::Password, false, "box", "", "");
        n.sender->start(n.peerIp, 5000, "FakeBox");
        n.connectControl();
        n.io.takeTcp(RaopTcp::Control);
        n.sender->onTcpData(RaopTcp::Control, spanOf(std::string_view("RTSP/1.0 401 Unauthorized\r\nCSeq: 0\r\n\r\n")));
        CHECK(n.launchedOk && !*n.launchedOk && n.launchedErr == "The device requires a password", "401 without a password");
    }
    g_test = "mac fallback: 403 on pin-start -> transient";
    {
        Rig r;
        r.rx.mode = FakeReceiver::Mode::Ap2Pin;
        r.sender->setAuth(RaopDeviceInfo::Auth::HapPin, true, "mac", "", "");
        r.sender->start(r.peerIp, 7000, "MacBook");
        r.connectControl();
        std::string stream = r.io.takeTcp(RaopTcp::Control);
        auto reqs = parseRequests(stream);
        REQUIRE(reqs.size() == 1 && reqs[0].uri == "/pair-pin-start", "pin-start");
        r.sender->onTcpData(RaopTcp::Control, spanOf(std::string_view("HTTP/1.1 403 Forbidden\r\nCSeq: 0\r\nContent-Length: 0\r\n\r\n")));
        stream = r.io.takeTcp(RaopTcp::Control);
        reqs = parseRequests(stream);
        REQUIRE(reqs.size() == 1 && reqs[0].uri == "/pair-setup" && reqs[0].h("x-apple-hkp") == "4", "falls back to transient M1 (HKP 4)");
        const auto m1 = airplay::tlv::decode(bytesOf(reqs[0].body));
        CHECK(airplay::tlv::get(m1, airplay::tlv::Flags).has_value(), "with the transient flag");
        CHECK(r.logHas("refused /pair-pin-start (403)"), "logged");
        r.rx.mode = FakeReceiver::Mode::Ap2Transient;
        r.rx.requests.push_back(reqs[0]);
        r.sender->onTcpData(RaopTcp::Control, spanOf(r.rx.onControlBytes(reqs[0].raw)));
        r.exchange();
        CHECK(r.launchedOk && *r.launchedOk, "mac-style receiver streams via transient pairing");
        r.sender->stop();
    }
    g_test = "apple tv fallback: 470 on transient -> pin";
    {
        Rig r;
        r.rx.mode = FakeReceiver::Mode::Ap2Pin;
        r.sender->setAuth(RaopDeviceInfo::Auth::HapTransient, true, "atv", "", "");
        r.sender->start(r.peerIp, 7000, "Apple TV");
        r.connectControl();
        std::string stream = r.io.takeTcp(RaopTcp::Control);
        auto reqs = parseRequests(stream);
        REQUIRE(reqs.size() == 1 && reqs[0].uri == "/pair-setup" && reqs[0].h("x-apple-hkp") == "4", "transient M1");
        r.sender->onTcpData(RaopTcp::Control, spanOf(std::string_view("HTTP/1.1 470 Connection Authorization Required\r\nCSeq: 0\r\nContent-Length: 0\r\n\r\n")));
        stream = r.io.takeTcp(RaopTcp::Control);
        reqs = parseRequests(stream);
        REQUIRE(reqs.size() == 1 && reqs[0].uri == "/pair-pin-start" && reqs[0].h("x-apple-hkp") == "3", "470 -> /pair-pin-start with HKP 3");
        r.rx.requests.push_back(reqs[0]);
        r.sender->onTcpData(RaopTcp::Control, spanOf(r.rx.onControlBytes(reqs[0].raw)));
        r.exchange();
        REQUIRE(r.pinDevice.has_value(), "then the on-screen pin");
        r.sender->submitPin("3939");
        r.exchange();
        CHECK(r.launchedOk && *r.launchedOk && r.credsJson, "pin pairing completes with credentials");
        r.sender->stop();
    }
}

void testResampler() {
    g_test = "48 kHz input is resampled to 44.1 kHz";
    Rig r;
    r.sender->setInputFormat(48000);
    r.sender->setAuth(RaopDeviceInfo::Auth::None, false, "box", "", "");
    r.sender->start(r.peerIp, 5000, "FakeBox");
    r.connectControl();
    r.exchange();
    REQUIRE(r.launchedOk && *r.launchedOk, "streaming");
    r.io.takeUdp();
    // a constant signal must pass through the lerp unchanged
    std::vector<int16_t> flat(32000 * 2, 1000);
    CHECK(r.ring.tryPush(std::span<const int16_t>(flat.data(), flat.size())), "32000 frames fit the ring");
    r.advance(8);
    auto dgs = r.io.takeUdp();
    REQUIRE(dgs.size() == 1, "one packet");
    auto pcm = r.rx.decodeAudio(dgs[0].data);
    CHECK(pcm && std::all_of(pcm->begin(), pcm->end(), [](int16_t s) { return s == 1000; }), "constant input -> constant output");
    // 10 packets consume 3520 output frames ~ 3831 input frames
    for (int i = 0; i < 10; ++i) r.advance(8);
    dgs = r.io.takeUdp();
    CHECK(dgs.size() == 10, "steady 8 ms cadence");
    // the staging buffer holds 8192 input frames; 10 more packets advanced the
    // phase by 10 * 352 * 48000/44100 = 3831 input frames, refilled on the next call
    const size_t consumedInputFrames = (size_t(32000) * 2 - r.ring.availableRead()) / 2;
    const size_t expectDropped = size_t(10) * 352 * 48000 / 44100;
    CHECK(consumedInputFrames >= 8192 + expectDropped - 400 && consumedInputFrames <= 8192 + expectDropped + 400,
          "input consumed at the 48000/44100 ratio (plus the 8192-frame staging buffer)");
    r.sender->stop();
}

} // namespace

int main() {
    std::printf("== raop core tests (in-process fake receiver, no sockets) ==\n");
    testFormatter();
    testCredsCodec();
    testAp1Session();
    testAp2Transient();
    testAp2PinPairingThenStoredCredentials();
    testStrictReceiverAuth();
    testFailurePaths();
    testIdentityAndDigest();
    testResampler();
    std::printf("%s: %d/%d checks passed\n", g_failures == 0 ? "ALL PASS" : "FAILURES",
                g_checks - g_failures, g_checks);
    return g_failures == 0 ? 0 : 1;
}
