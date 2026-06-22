// SPDX-License-Identifier: Apache-2.0
//
// v0.66.x, RaopSender implementation (AirPlay-1 / RAOP audio sender).
//
// ATTRIBUTION: the RAOP protocol logic in this file, RTSP sequence,
// SDP ANNOUNCE payload, RTP/sync/timing/retransmit packet formats, the
// NTP<->timestamp conversions and the fixed-latency timeline model,
// is ported to C++ from pyatv (https://github.com/postlund/pyatv,
// Copyright (c) Pierre Stahl, MIT License; specifically
// pyatv/protocols/raop/{stream_client.py,packets.py,timing.py,
// protocols/airplayv1.py} and pyatv/support/rtsp.py). The MIT notice
// is reproduced in licenses/THIRD-PARTY-NOTICES.txt ("pyatv"). pyatv's
// timing routines in turn credit RAOP-Player by philippe44 for the
// NTP math (the formulas, not the GPL code, are used here).
//
// Wire-format notes verified against pyatv (2026-05 tree):
//  - ANNOUNCE advertises raw PCM: `a=rtpmap:96 L16/44100/2` with the
//    classic ALAC-style fmtp parameter list, every modern receiver
//    (Apple + shairport-sync) accepts uncompressed L16, which spares
//    us an ALAC encoder for Phase 1.
//  - Payload byte order is BIG-endian s16 (RFC 3551 L16 network order;
//    pyatv byteswaps its little-endian buffers before sending).
//  - All RTP-family packet fields are big-endian (pyatv defpacket ">").
//  - The timeline: start_ts = ntp2ts(ntp_now); the per-packet RTP
//    timestamp is head_ts - start_ts + latency (so it STARTS at
//    `latency` and advances 352/packet); sync packets carry
//    ts2ntp(head_ts) as wall-clock NTP so the receiver can correlate
//    our timeline with the answers our timing server gives it.
//
// Deviation from pyatv, documented: pyatv sends a bare RECORD followed
// by a FLUSH carrying Range/Session/RTP-Info (a leftover of its seek
// machinery). We send the classic iTunes/OwnTone form instead, ONE
// RECORD with Range + Session + RTP-Info, which is what RAOP receivers
// have parsed since 2004 and strictly more conventional.

#include "raop_sender.h"

#include "airplay_crypto.h"
#include "creds_json.h"
#include "ring_buffer.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <format>
#include <span>
#include <string>

namespace fxchain {

namespace {

constexpr int      kFramesPerPacket = 352;          // RAOP fixed
constexpr uint32_t kRaopRate        = 44100;        // RAOP fixed
constexpr int      kChannels        = 2;
constexpr int      kPayloadBytes    = kFramesPerPacket * kChannels * 2;
constexpr int      kBacklogSize     = 1024;         // power of two
constexpr int      kPacerMs         = 8;            // ~ 1 packet/tick
constexpr int      kMaxPacketsPerTick = 16;         // GUI-stall catch-up cap
constexpr int      kHandshakeTimeoutMs = 10000;
constexpr int      kPinWaitTimeoutMs  = 180000;     // 3 min, read a code off the TV
constexpr int      kFeedbackIntervalMs = 25000;     // pyatv KEEP_ALIVE_INTERVAL
// Cap the resampler's staging buffer (frames). ~0.2 s at 48 kHz, the
// engine ring itself is the deep buffer; this is just working set.
constexpr size_t   kInBufMaxFrames  = 8192;

// Big-endian appenders (RTP family is network byte order throughout).
// b8 takes a runtime uint8 so high-bit protocol constants (0x80/0xD4/...)
// don't trip MSVC C4310 (constant-value truncation in a char cast). std::string
// is a byte buffer here exactly like QByteArray was (signed char, += char).
void b8(std::string& out, uint8_t v) { out += char(v); }
void be16(std::string& out, uint16_t v) {
    out += char(v >> 8); out += char(v & 0xFF);
}
void be32(std::string& out, uint32_t v) {
    out += char(v >> 24); out += char((v >> 16) & 0xFF);
    out += char((v >> 8) & 0xFF); out += char(v & 0xFF);
}

// pyatv timing.py, NTP <-> RTP-timestamp conversion.
uint64_t ntp2ts(uint64_t ntp, uint32_t rate) {
    return ((ntp >> 16) * rate) >> 16;
}
uint64_t ts2ntp(uint64_t ts, uint32_t rate) {
    return ((ts << 16) / rate) << 16;
}

// std::string (the wire layer) <-> airplay::Bytes (the Qt-free crypto layer).
airplay::Bytes toBytes(const std::string& s) {
    return airplay::Bytes(reinterpret_cast<const uint8_t*>(s.data()),
                          reinterpret_cast<const uint8_t*>(s.data()) + s.size());
}
std::string toStr(const airplay::Bytes& b) {
    return std::string(reinterpret_cast<const char*>(b.data()), b.size());
}

// view a std::string as the const-byte span ITransport sends/receives.
std::span<const uint8_t> bytesOf(const std::string& s) {
    return std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

// drain every byte currently readable on a tcp socket into a string (the
// non-Qt equivalent of QTcpSocket::readAll). an EOF seen mid-loop is reported
// separately by the transport via onTcpDisconnected.
std::string readAllTcp(ITransport& t, SockHandle h) {
    std::string out;
    uint8_t buf[4096];
    int n;
    while ((n = t.tcpRecv(h, std::span<uint8_t>(buf, sizeof(buf)))) > 0)
        out.append(reinterpret_cast<const char*>(buf), size_t(n));
    return out;
}

// QByteArray helpers that have no one-to-one std::string method. semantics
// match Qt's so the parsing stays byte-identical.
std::vector<std::string> splitCh(const std::string& s, char sep) {
    std::vector<std::string> out;
    size_t start = 0;
    for (size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == sep) {
            out.push_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    return out;
}
std::string trimMed(const std::string& s) {
    auto ws = [](char c) {
        return c == ' ' || c == '\t' || c == '\n' ||
               c == '\v' || c == '\f' || c == '\r';
    };
    size_t b = 0, e = s.size();
    while (b < e && ws(s[b])) ++b;
    while (e > b && ws(s[e - 1])) --e;
    return s.substr(b, e - b);
}
std::string toLowerAscii(const std::string& s) {
    std::string o = s;
    for (char& c : o) if (c >= 'A' && c <= 'Z') c = char(c + 32);
    return o;
}
std::string headerValue(const std::unordered_map<std::string, std::string>& h,
                        const std::string& key, const std::string& def = {}) {
    const auto it = h.find(key);
    return it == h.end() ? def : it->second;
}
// QByteArray::toInt / toUInt: parse base-10 (leading ws + sign tolerated),
// ok = at least one digit consumed.
long parseLong(const std::string& s, bool& ok) {
    const char* p = s.c_str();
    const char* end = p + s.size();
    while (p < end && (*p == ' ' || *p == '\t')) ++p;
    bool neg = false;
    if (p < end && (*p == '+' || *p == '-')) { neg = (*p == '-'); ++p; }
    long v = 0; bool any = false;
    while (p < end && *p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); ++p; any = true; }
    ok = any;
    return neg ? -v : v;
}
int toInt(const std::string& s) { bool ok; return int(parseLong(s, ok)); }
int toInt(const std::string& s, bool& ok) { return int(parseLong(s, ok)); }
unsigned toUInt(const std::string& s) {
    bool ok; const long v = parseLong(s, ok);
    return v < 0 ? 0u : unsigned(v);
}

// CSPRNG-backed identifiers (was QRandomGenerator; randomBytes is the Qt-free
// CTR-DRBG already used for key material, so the SSRC/DACP-ID/seq are sourced
// from it too).
uint32_t rand32() {
    const auto b = airplay::randomBytes(4);
    return uint32_t(b[0]) | (uint32_t(b[1]) << 8)
         | (uint32_t(b[2]) << 16) | (uint32_t(b[3]) << 24);
}
uint64_t rand64() {
    const auto b = airplay::randomBytes(8);
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= uint64_t(b[size_t(i)]) << (8 * i);
    return v;
}
uint16_t rand16() {
    const auto b = airplay::randomBytes(2);
    return uint16_t(uint16_t(b[0]) | (uint16_t(b[1]) << 8));
}
// lowercase RFC 4122 v4 UUID string (was QUuid::createUuid().toString).
std::string genUuidLower() {
    auto b = airplay::randomBytes(16);
    b[6] = uint8_t((b[6] & 0x0F) | 0x40);   // version 4
    b[8] = uint8_t((b[8] & 0x3F) | 0x80);   // variant 1
    static constexpr char h[] = "0123456789abcdef";
    std::string s;
    s.reserve(36);
    for (int i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) s += '-';
        s += h[b[size_t(i)] >> 4];
        s += h[b[size_t(i)] & 0xF];
    }
    return s;
}
std::string toUpperAscii(std::string s) {
    for (char& c : s) if (c >= 'a' && c <= 'z') c = char(c - 32);
    return s;
}

// DMAP tag: 4-char ASCII code + 4-byte big-endian length + payload.
std::string dmapTag(const char code[5], const std::string& payload) {
    std::string t(code, 4);
    t += char((payload.size() >> 24) & 0xFF);
    t += char((payload.size() >> 16) & 0xFF);
    t += char((payload.size() >> 8) & 0xFF);
    t += char(payload.size() & 0xFF);
    t += payload;
    return t;
}

} // namespace

// -- v0.66.x Phase 2/3, AirPlay-2 pairing + encryption session state --
//
// Held by unique_ptr from RaopSender so the header stays free of the
// airplay_crypto types. Carries the SRP client, the controller's long-term
// Ed25519 identity (persisted as credentials), the pair-verify ECDH state,
// the derived control-channel keys, and the AP2 audio cipher counter.
struct RaopAp2State {
    using Bytes = airplay::Bytes;

    // Pair-setup (SRP).
    std::unique_ptr<airplay::SrpClient> srp;

    // Controller long-term identity (Ed25519 seed == ltsk, pub == ltpk) and
    // a stable pairing id (UUID). On a first pairing these are generated; on
    // a stored-creds reconnect they are loaded from credsJson.
    Bytes ltSeed;     // 32-byte Ed25519 seed (secret)
    Bytes ltPub;      // 32-byte Ed25519 public
    Bytes pairingId;  // our client identifier (UUID string bytes)

    // Accessory (receiver) identity learned at the end of pair-setup M6 /
    // used for pair-verify.
    Bytes accessoryId;
    Bytes accessoryLtpk;

    // pair-verify ephemeral X25519 + derived control keys.
    airplay::X25519KeyPair verifyKeys;
    Bytes sharedSecret;        // X25519 ECDH output (pair-verify) OR SRP K (transient)
    Bytes controlOut, controlIn;
    // #90/#109, AP2 event channel keys (encrypted TCP to eventPort). The
    // receiver pushes encrypted MediaRemote/Command events; we must decrypt +
    // 200-OK them or it tears down the session after ~25 s.
    Bytes eventOut, eventIn;

    // AP2 audio cipher: a single 32-byte shared key (derived from the
    // pairing) + a monotonically increasing 64-bit nonce counter.
    Bytes audioKey;
    uint64_t audioNonce = 0;
    bool encryptAudio = false;

    // AP2 SETUP bookkeeping.
    std::string sessionUuid;
    std::string streamConnId;
    uint16_t eventPort = 0;

    RaopAp2State() {
        sessionUuid  = toUpperAscii(genUuidLower());
        streamConnId = std::to_string(rand64());
    }
};

RaopSender::RaopSender(ITransport& transport, LogSink log,
                       LaunchedCb onLaunched, ClosedCb onClosed,
                       PinRequiredCb onPinRequired, CredsCb onCredsObtained)
    : transport_(transport),
      log_(std::move(log)),
      onLaunched_(std::move(onLaunched)),
      onClosed_(std::move(onClosed)),
      onPinRequired_(std::move(onPinRequired)),
      onCredsObtained_(std::move(onCredsObtained)) {
    backlog_.resize(kBacklogSize);
    backlogSeq_.assign(kBacklogSize, -1);

    // Timers are created up front (QTimer-shaped) and armed/disarmed per
    // session. 8 ms PRECISE pacer: a coarse timer's slack at 125 ticks/s would
    // wander audibly against the 44.1 kHz budget; the token bucket in
    // onPacerTick_ absorbs the remainder.
    pacerTimer_ = transport_.createTimer(kPacerMs, true, [this] { onPacerTick_(); });
    syncTimer_  = transport_.createTimer(1000, true, [this] { sendSyncPacket_(false); });

    timeoutTimer_ = transport_.createTimer(kHandshakeTimeoutMs, false, [this] {
        // v0.66.x, a PIN wait is user-driven; pinTimer_ guards that.
        if (waitingForPin_) return;
        if (state_ == State::Connecting || state_ == State::Pairing
            || state_ == State::Handshake) {
            // #150 diag, name WHERE the handshake stalled. The MacBook
            // (hap-transient, sf=0x4) stalls at stage Ap2Session: the session
            // SETUP gets no reply, while the Apple TV (hap-pin) proceeds.
            log_.warn("Cast: AirPlay handshake TIMEOUT, state={} pairStage={} "
                      "(receiver sent no usable reply)",
                      static_cast<int>(state_), static_cast<int>(pairStage_));
            fail_("Timed out waiting for the device");
        }
    });

    // v0.66.x, the on-screen-PIN wait gets its OWN (generous) watchdog so a
    // device that never shows a code (Apple TV asleep / TV on another input)
    // can't leave the session stuck on "waiting for code" forever.
    pinTimer_ = transport_.createTimer(kPinWaitTimeoutMs, false, [this] {
        if (!waitingForPin_) return;
        waitingForPin_ = false;
        fail_(std::format("No PIN was entered. Switch {} on and make sure its "
                          "screen shows the AirPlay code, then try again.", name_));
    });

    // 0 ms one-shot: a connect-init failure (tcpConnect returning kInvalidSock
    // on the poll adapter) is reported from the run loop, not synchronously
    // from start(), so callers see the same async failure the Qt path gave.
    deferredFailTimer_ = transport_.createTimer(0, false, [this] {
        fail_("Could not reach the device");
    });

    feedbackTimer_ = transport_.createTimer(kFeedbackIntervalMs, true, [this] {
        if (state_ != State::Streaming) return;
        if (airplay2_) {
            // #90/#109, AP2 keep-alive: a post-RECORD Apple TV closes the
            // session after ~30 s without a VALID feedback request. The control
            // channel is RTSP, not HTTP, owntone/pyatv send `POST /feedback
            // RTSP/1.0` with the standard RTSP identity headers. An `HTTP/1.1`
            // line is silently ignored by the receiver's RTSP parser, so its
            // liveness timer never resets and it drops at 30 s. Empty body; the
            // 200 reply is matched by FIFO + discarded.
            std::string req = "POST /feedback RTSP/1.0\r\n";
            req += "CSeq: " + std::to_string(cseq_++) + "\r\n";
            req += "User-Agent: AirPlay/550.10\r\n";
            req += "DACP-ID: " + dacpId_ + "\r\n";
            req += "Active-Remote: " + std::to_string(activeRemote_) + "\r\n";
            req += "Client-Instance: " + dacpId_ + "\r\n";
            req += "Content-Length: 0\r\n\r\n";
            pendingMethods_.push_back("FEEDBACK");
            pendingIsHttp_.push_back(false);   // ignored by handleResponse_
            writeRtsp_(req);
        } else {
            sendRequest_("POST", "/feedback", {}, {});
        }
    });
}

RaopSender::~RaopSender() {
    stop();
    transport_.destroyTimer(pacerTimer_);
    transport_.destroyTimer(syncTimer_);
    transport_.destroyTimer(timeoutTimer_);
    transport_.destroyTimer(pinTimer_);
    transport_.destroyTimer(feedbackTimer_);
    transport_.destroyTimer(deferredFailTimer_);
}

void RaopSender::setInputFormat(uint32_t sampleRate) {
    // 0 = no device open yet, assume the WASAPI default like the
    // PcmStreamServer does; the resampler handles any real rate.
    inputRate_ = sampleRate > 0 ? sampleRate : 48000;
}

void RaopSender::setAuth(RaopDeviceInfo::Auth auth, bool airplay2,
                         const std::string& deviceId, const std::string& credsJson,
                         const std::string& password) {
    authMethod_     = auth;
    airplay2_       = airplay2;
    deviceId_       = deviceId;
    credsJson_      = credsJson;
    digestPassword_ = password;
}

// pyatv timing.ntp_now(): microsecond wall clock in 64-bit NTP format
// (seconds since 1900 in the high word, 2^32-scaled fraction below).
uint64_t RaopSender::ntpNow_() {
    using namespace std::chrono;
    const uint64_t us = uint64_t(duration_cast<microseconds>(
        system_clock::now().time_since_epoch()).count());
    const uint64_t sec  = us / 1000000ULL;
    const uint64_t frac = us % 1000000ULL;
    return ((sec + 0x83AA7E80ULL) << 32) | ((frac << 32) / 1000000ULL);
}

uint32_t RaopSender::rtptime32_() const {
    // pyatv StreamContext.rtptime: head_ts - (start_ts - latency),
    // the huge NTP-derived base cancels, so this starts at `latency`
    // and advances one per frame sent. u32 wrap is the RTP norm.
    return uint32_t(uint64_t(latency_) + framesSent_);
}

void RaopSender::start(const std::string& host, uint16_t port, const std::string& name) {
    stop();
    host_   = host;
    name_   = name;
    hostIp_ = host;   // mDNS hands us a resolved dotted-quad

    // Fresh session identity (pyatv: random session id reused as the
    // RTSP URI path AND the RTP SSRC; DACP-ID/Active-Remote identify
    // us to remote-control-capable receivers).
    sessionId_    = rand32();
    dacpId_       = std::format("{:X}", rand64());   // uppercase hex, like number(x,16).toUpper()
    activeRemote_ = rand32();
    seq_          = rand16();
    cseq_ = 0;
    rxBuf_.clear();
    // #90, fresh connection starts with a PLAINTEXT control channel; it flips
    // to encrypted in afterAuthOk_ once pair-verify keys the channel.
    controlEncrypted_ = false;
    ctrlSendCtr_ = 0;
    ctrlRecvCtr_ = 0;
    rtspEncBuf_.clear();
    eventSendCtr_ = 0;
    eventRecvCtr_ = 0;
    eventEncBuf_.clear();
    eventPlainBuf_.clear();
    pendingMethods_.clear();
    rtspSession_.clear();
    framesSent_ = 0;
    firstAudio_ = true;
    srcPhase_ = 0.0;
    inBuf_.clear();
    inReadFrames_ = 0;
    backlogSeq_.assign(kBacklogSize, -1);
    pendingVolumeDb_ = kNoVolume;   // never carry volume between devices
    feedbackActive_ = false;

    // v0.66.x Phase 2/3, reset auth/AP2 state for the new session.
    ap2_.reset();
    pairStage_       = PairStage::None;   // never carry a stale stage in
    waitingForPin_   = false;
    triedTransientAfterPin403_ = false;
    inHttpMode_      = false;
    pendingIsHttp_.clear();
    digestRealm_.clear();
    digestNonce_.clear();
    pendingDigestMethod_.clear();
    pendingDigestUri_.clear();
    digestRetried_   = false;

    // Bind the UDP trio BEFORE SETUP, the request advertises our
    // control/timing ports so the receiver can reach them. AnyIPv4 so
    // the receiver's unicast packets arrive regardless of which local
    // interface routes to it. (First real-device run: if the receiver
    // never clock-syncs, check the Windows-Firewall inbound rule for
    // the app, these are unsolicited inbound UDP datagrams.)
    timingSock_  = transport_.udpBind(0);
    controlSock_ = transport_.udpBind(0);
    audioSock_   = transport_.udpBind(0);
    if (timingSock_ == kInvalidSock || controlSock_ == kInvalidSock
        || audioSock_ == kInvalidSock) {
        log_.warn("Cast: RAOP UDP bind failed");
        if (onLaunched_) onLaunched_(false, "Could not bind UDP sockets");
        return;
    }
    transport_.onUdpReadable(controlSock_, [this] { onControlDatagram_(); });
    transport_.onUdpReadable(timingSock_,  [this] { onTimingDatagram_(); });

    state_ = State::Connecting;
    transport_.startTimer(timeoutTimer_);
    log_.info("Cast: RAOP connecting to {}:{} ('{}')", host, port, name);

    rtspSock_ = transport_.tcpConnect(host, port);
    if (rtspSock_ == kInvalidSock) {
        // defer so start() returns before the failure callbacks fire; the Qt
        // connectToHost path reported connect errors asynchronously too.
        transport_.startTimer(deferredFailTimer_);
        return;
    }
    rtspConnected_ = false;
    transport_.onTcpConnected(rtspSock_, [this, port](bool ok) {
        if (!ok) { if (state_ != State::Idle) fail_("Connection failed"); return; }
        if (state_ != State::Connecting) return;
        rtspConnected_ = true;
        log_.info("Cast: RAOP RTSP connected to {}:{}", host_, port);
        // v0.66.x Phase 2/3, run the auth/pairing chain first; for plain
        // Phase-1 receivers it falls straight through to OPTIONS.
        beginAuthChain_();
    });
    transport_.onTcpReadable(rtspSock_, [this] { onRtspReadyRead_(); });
    transport_.onTcpDisconnected(rtspSock_, [this] {
        if (state_ == State::Idle) return;   // our own stop(), quiet
        const bool wasStarting = state_ != State::Streaming;
        state_ = State::Idle;
        rtspConnected_ = false;
        transport_.stopTimer(pacerTimer_);  transport_.stopTimer(syncTimer_);
        transport_.stopTimer(timeoutTimer_); transport_.stopTimer(pinTimer_);
        transport_.stopTimer(feedbackTimer_); feedbackActive_ = false;
        if (wasStarting && onLaunched_)
            onLaunched_(false, "Connection closed by the device");
        if (onClosed_) onClosed_();
    });
    transport_.onTcpError(rtspSock_, [this](std::string e) {
        if (state_ != State::Idle) fail_(e);
    });
}

void RaopSender::stop() {
    if (state_ == State::Idle) return;
    transport_.stopTimer(pacerTimer_);
    transport_.stopTimer(syncTimer_);
    transport_.stopTimer(timeoutTimer_);
    transport_.stopTimer(pinTimer_);
    transport_.stopTimer(feedbackTimer_);
    transport_.stopTimer(deferredFailTimer_);   // cancel any pending connect-init failure
    feedbackActive_ = false;
    if (rtspConnected_ && (!rtspSession_.empty() || airplay2_)) {
        // v0.66.x, AP2 has no RTSP Session header (no RTSP SETUP), so send
        // a bare TEARDOWN; AP1 carries the Session it got from SETUP.
        std::vector<std::pair<std::string, std::string>> extra;
        if (!rtspSession_.empty())
            extra.push_back({"Session", rtspSession_});
        sendRequest_("TEARDOWN", rtspUri_(), {}, {}, extra);
        // Make sure the TEARDOWN actually leaves this machine before the
        // socket goes away (tcpDisconnect flushes then half-closes), otherwise
        // the receiver keeps the session open for minutes.
    }
    state_ = State::Idle;   // BEFORE disconnect -> the handler stays quiet
    if (rtspSock_ != kInvalidSock) {
        transport_.tcpDisconnect(rtspSock_);   // flush + FIN
        rtspSock_ = kInvalidSock;
    }
    rtspConnected_ = false;
    if (audioSock_   != kInvalidSock) { transport_.udpClose(audioSock_);   audioSock_   = kInvalidSock; }
    if (controlSock_ != kInvalidSock) { transport_.udpClose(controlSock_); controlSock_ = kInvalidSock; }
    if (timingSock_  != kInvalidSock) { transport_.udpClose(timingSock_);  timingSock_  = kInvalidSock; }
    if (eventSock_   != kInvalidSock) { transport_.tcpClose(eventSock_);   eventSock_   = kInvalidSock; }   // #90, AP2 event channel
    // Free the backlog payloads (~1.4 MB when full).
    for (auto& b : backlog_) b.clear();
    backlogSeq_.assign(kBacklogSize, -1);
    log_.info("Cast: RAOP session stopped");
}

void RaopSender::fail_(const std::string& why) {
    log_.warn("Cast: RAOP error, {}", why);
    const bool wasStarting = state_ != State::Streaming;
    state_ = State::Idle;
    transport_.stopTimer(pacerTimer_);
    transport_.stopTimer(syncTimer_);
    transport_.stopTimer(timeoutTimer_);
    transport_.stopTimer(pinTimer_);
    transport_.stopTimer(feedbackTimer_);
    feedbackActive_ = false;
    rtspConnected_ = false;
    if (rtspSock_    != kInvalidSock) { transport_.tcpClose(rtspSock_);    rtspSock_    = kInvalidSock; }
    if (audioSock_   != kInvalidSock) { transport_.udpClose(audioSock_);   audioSock_   = kInvalidSock; }
    if (controlSock_ != kInvalidSock) { transport_.udpClose(controlSock_); controlSock_ = kInvalidSock; }
    if (timingSock_  != kInvalidSock) { transport_.udpClose(timingSock_);  timingSock_  = kInvalidSock; }
    if (eventSock_   != kInvalidSock) { transport_.tcpClose(eventSock_);   eventSock_   = kInvalidSock; }   // #90, don't leak the AP2 event-channel auto-responder
    if (wasStarting && onLaunched_) onLaunched_(false, why);
    if (onClosed_) onClosed_();
}

void RaopSender::setVolume(double pct) {
    pct = std::clamp(pct, 0.0, 100.0);
    // pyatv pct_to_dbfs: 0 % is the AirPlay mute sentinel -144, the
    // rest maps linearly onto the -30..0 dBFS attenuation range.
    const double dbfs = (pct < 0.01) ? -144.0 : (-30.0 + 0.3 * pct);
    pendingVolumeDb_ = dbfs;
    if (state_ == State::Streaming) {
        const std::string body = "volume: " + std::format("{:.6f}", dbfs);
        std::vector<std::pair<std::string, std::string>> vh;
        if (!rtspSession_.empty())
            vh.push_back({"Session", rtspSession_});
        sendRequest_("SET_PARAMETER", rtspUri_(), "text/parameters", body, vh);
    }
}

void RaopSender::submitPin(const std::string& code) {
    if (!waitingForPin_) return;
    waitingForPin_ = false;
    transport_.stopTimer(pinTimer_);
    transport_.startTimer(timeoutTimer_);   // re-arm the handshake watchdog
    log_.info("Cast: AirPlay PIN entered, continuing pairing");
    // HAP normal PIN, run SRP M3 with the user's code. (Legacy "Fruit"
    // PIN never reaches here: it fails fast in beginAuthChain_.)
    sendPairSetupM3_(code);
}

void RaopSender::setNowPlaying(const std::string& title, const std::string& artist,
                               const std::string& album,
                               const std::string& cover,
                               const std::string& coverMime) {
    const bool changed = (title != npTitle_) || (artist != npArtist_)
                         || (album != npAlbum_) || (cover != npCover_)
                         || (coverMime != npCoverMime_);
    npTitle_ = title; npArtist_ = artist; npAlbum_ = album;
    npCover_ = cover; npCoverMime_ = coverMime;
    // While streaming, push the new track to the receiver right away;
    // otherwise it's stored and sent once RECORD/SETUP completes.
    if (state_ == State::Streaming && changed) sendMetadata_();
}

void RaopSender::sendMetadata_() {
    if (state_ != State::Streaming) return;
    if (npTitle_.empty() && npArtist_.empty() && npAlbum_.empty()
        && npCover_.empty())
        return;
    // RTP-Info ties the metadata to the audio timeline (pyatv form:
    // "seq=<rtpseq>;rtptime=<rtptime>"). Session present for AP1; for
    // AP2 it may be empty (the receiver tolerates its absence).
    const std::string rtpInfo =
        "seq=" + std::to_string(seq_) + ";rtptime="
        + std::to_string(rtptime32_());
    std::vector<std::pair<std::string, std::string>> hdr;
    if (!rtspSession_.empty())
        hdr.push_back({"Session", rtspSession_});
    hdr.push_back({"RTP-Info", rtpInfo});

    // DMAP-tagged text metadata: mlit{ minm(title) asal(album) asar(artist) }
    // (pyatv tag order). Empty fields are omitted entirely.
    std::string inner;
    if (!npTitle_.empty())  inner += dmapTag("minm", npTitle_);
    if (!npAlbum_.empty())  inner += dmapTag("asal", npAlbum_);
    if (!npArtist_.empty()) inner += dmapTag("asar", npArtist_);
    if (!inner.empty()) {
        const std::string body = dmapTag("mlit", inner);
        sendRequest_("SET_PARAMETER", rtspUri_(),
                     "application/x-dmap-tagged", body, hdr);
    }

    // Cover artwork as raw image bytes (pyatv: image/jpeg; PNG honoured).
    // Cap matches CastBridge's 8 MB cover read so nothing is silently
    // dropped between the two stages.
    bool coverSent = false;
    if (!npCover_.empty()) {
        if (npCover_.size() <= 8 * 1024 * 1024) {
            const std::string mime = npCoverMime_.empty()
                ? std::string("image/jpeg") : npCoverMime_;
            sendRequest_("SET_PARAMETER", rtspUri_(), mime, npCover_, hdr);
            coverSent = true;
        } else {
            log_.info("Cast: RAOP cover not sent, {} bytes exceeds the 8 MB cap",
                      npCover_.size());
        }
    }
    log_.info("Cast: RAOP now-playing pushed, '{}' / '{}'{}",
              npTitle_, npArtist_, coverSent ? " + cover" : "");
}

// -- RTSP plumbing -------------------------------------------------

std::string RaopSender::rtspUri_() const {
    // pyatv: rtsp://<our ip as the receiver sees it>/<session id>.
    return "rtsp://" + transport_.tcpLocalAddr(rtspSock_).ip + "/"
         + std::to_string(sessionId_);
}

void RaopSender::sendRequest_(const std::string& method, const std::string& uri,
                              const std::string& contentType,
                              const std::string& body,
                              const std::vector<std::pair<std::string, std::string>>& extra) {
    std::string req = method + " " + uri + " RTSP/1.0\r\n";
    req += "CSeq: " + std::to_string(cseq_++) + "\r\n";
    req += "User-Agent: AirPlay/550.10\r\n";          // pyatv's UA string
    req += "DACP-ID: " + dacpId_ + "\r\n";
    req += "Active-Remote: " + std::to_string(activeRemote_) + "\r\n";
    req += "Client-Instance: " + dacpId_ + "\r\n";
    req += "X-Apple-Client-Name: FXChainPlayer\r\n";   // AirPlay-bug fix, owntone parity
    // v0.66.x, RTSP digest auth for pw=true receivers: once a 401 has
    // told us realm+nonce, every subsequent request carries Authorization.
    if (!digestNonce_.empty() && !digestPassword_.empty()) {
        const std::string ah = airplay::digestAuthResponse(
            method, uri, "iTunes", digestRealm_, digestPassword_, digestNonce_);
        req += "Authorization: " + ah + "\r\n";
    }
    for (const auto& h : extra)
        req += h.first + ": " + h.second + "\r\n";
    if (!contentType.empty())
        req += "Content-Type: " + contentType + "\r\n";
    if (!body.empty())
        req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    req += "\r\n";
    req += body;
    pendingMethods_.push_back(method);
    pendingIsHttp_.push_back(false);       // RTSP reply
    // Remember the last handshake request so a 401 can re-issue it with auth.
    pendingDigestMethod_ = method;
    pendingDigestUri_    = uri;
    writeRtsp_(req);
    if (state_ == State::Handshake || state_ == State::Pairing)
        transport_.startTimer(timeoutTimer_);   // fresh window per handshake step
}

// AP2 encrypted control channel (#90), frame the request bytes
// [2-byte LE len][cipher][16-byte tag], chunked at 1024, Control-Write key +
// 8-byte LE per-frame counter; plaintext before pair-verify completes.
void RaopSender::writeRtsp_(const std::string& data) {
    if (!controlEncrypted_ || !ap2_) { transport_.tcpSend(rtspSock_, bytesOf(data)); return; }
    std::string out;
    int off = 0;
    const int n = int(data.size());
    while (off < n) {
        const int len = std::min(1024, n - off);
        const unsigned char lp[2] = {
            static_cast<unsigned char>(len & 0xFF),
            static_cast<unsigned char>((len >> 8) & 0xFF) };
        airplay::Bytes nonce8(8);
        for (int i = 0; i < 8; ++i)
            nonce8[size_t(i)] = static_cast<uint8_t>((ctrlSendCtr_ >> (8 * i)) & 0xFF);
        ++ctrlSendCtr_;
        const auto* p = reinterpret_cast<const uint8_t*>(data.data() + off);
        const airplay::Bytes pt(p, p + len);
        const airplay::Bytes aad(lp, lp + 2);
        const airplay::Bytes ct =
            airplay::chacha20Poly1305Encrypt(ap2_->controlOut, nonce8, pt, aad);
        out.append(reinterpret_cast<const char*>(lp), 2);
        out.append(reinterpret_cast<const char*>(ct.data()), ct.size());
        off += len;
    }
    transport_.tcpSend(rtspSock_, bytesOf(out));
}

// #90/#109, AP2 event channel. The receiver pushes encrypted RTSP requests
// (POST /command updateInfo, sendMediaRemoteCommand, ...); we MUST decrypt each
// and answer "RTSP/1.0 200 OK" or the Apple TV tears the session down at ~25 s.
// Same HomeKit frame format as the control channel ([2-byte LE len][cipher]
// [16-byte tag], AAD = the 2 length bytes, nonce = 4 zero + 8-byte LE counter),
// keyed with the Events keys + independent per-direction counters (eventIn
// decrypts, eventOut encrypts, swapped because it's a reverse connection).
void RaopSender::onEventReadyRead_() {
    if (state_ == State::Idle) { readAllTcp(transport_, eventSock_); return; }  // dead session, drain, don't auto-answer
    if (!ap2_ || ap2_->eventIn.size() != 32 || ap2_->eventOut.size() != 32) {
        readAllTcp(transport_, eventSock_);   // not keyed yet, drain
        return;
    }
    eventEncBuf_ += readAllTcp(transport_, eventSock_);
    while (eventEncBuf_.size() >= 2) {
        const int len = static_cast<unsigned char>(eventEncBuf_[0])
            | (static_cast<int>(static_cast<unsigned char>(eventEncBuf_[1])) << 8);
        const int need = 2 + len + 16;
        if (int(eventEncBuf_.size()) < need) break;   // frame still arriving
        const unsigned char lp[2] = {
            static_cast<unsigned char>(eventEncBuf_[0]),
            static_cast<unsigned char>(eventEncBuf_[1]) };
        airplay::Bytes nonce8(8);
        for (int i = 0; i < 8; ++i)
            nonce8[size_t(i)] = static_cast<uint8_t>((eventRecvCtr_ >> (8 * i)) & 0xFF);
        ++eventRecvCtr_;
        const auto* cipher =
            reinterpret_cast<const uint8_t*>(eventEncBuf_.data() + 2);
        const airplay::Bytes ctTag(cipher, cipher + len + 16);
        const airplay::Bytes aad(lp, lp + 2);
        auto dec = airplay::chacha20Poly1305Decrypt(ap2_->eventIn, nonce8, ctTag, aad);
        if (!dec) {
            log_.warn("Cast: AirPlay 2 event-channel decrypt failed, dropping");
            eventEncBuf_.clear();
            return;
        }
        eventPlainBuf_.append(reinterpret_cast<const char*>(dec->data()), dec->size());
        eventEncBuf_.erase(0, size_t(need));
    }
    // Answer each complete RTSP request with an encrypted 200 OK.
    for (;;) {
        const auto headEnd = eventPlainBuf_.find("\r\n\r\n");
        if (headEnd == std::string::npos) break;
        int contentLen = 0;
        std::string cseq;
        for (const std::string& line : splitCh(eventPlainBuf_.substr(0, headEnd), '\n')) {
            const std::string t = trimMed(line);
            const auto colon = t.find(':');
            if (colon == std::string::npos || colon == 0) continue;
            const std::string k = trimMed(toLowerAscii(t.substr(0, colon)));
            const std::string v = trimMed(t.substr(colon + 1));
            if (k == "content-length") contentLen = toInt(v);
            else if (k == "cseq")      cseq = v;
        }
        const size_t total = headEnd + 4 + (contentLen > 0 ? size_t(contentLen) : 0);
        if (eventPlainBuf_.size() < total) break;   // body still arriving
        eventPlainBuf_.erase(0, total);
        // Encrypted 200 OK, owntone's respond() sends a BARE 200 (just Server),
        // no Content-Length/Audio-Latency (those can corrupt the receiver's
        // realtime timeline). Echo CSeq when the request carried one.
        std::string resp = "RTSP/1.0 200 OK\r\n";
        resp += "Server: AirTunes/550.10\r\n";
        if (!cseq.empty()) resp += "CSeq: " + cseq + "\r\n";
        resp += "\r\n";
        const int rlen = int(resp.size());
        const unsigned char rlp[2] = {
            static_cast<unsigned char>(rlen & 0xFF),
            static_cast<unsigned char>((rlen >> 8) & 0xFF) };
        airplay::Bytes wnonce(8);
        for (int i = 0; i < 8; ++i)
            wnonce[size_t(i)] = static_cast<uint8_t>((eventSendCtr_ >> (8 * i)) & 0xFF);
        ++eventSendCtr_;
        const airplay::Bytes rpt(
            reinterpret_cast<const uint8_t*>(resp.data()),
            reinterpret_cast<const uint8_t*>(resp.data()) + rlen);
        const airplay::Bytes raad(rlp, rlp + 2);
        const airplay::Bytes rct =
            airplay::chacha20Poly1305Encrypt(ap2_->eventOut, wnonce, rpt, raad);
        std::string out;
        out.append(reinterpret_cast<const char*>(rlp), 2);
        out.append(reinterpret_cast<const char*>(rct.data()), rct.size());
        transport_.tcpSend(eventSock_, bytesOf(out));
    }
}

void RaopSender::onRtspReadyRead_() {
    if (!controlEncrypted_ || !ap2_) {
        rxBuf_ += readAllTcp(transport_, rtspSock_);
    } else {
        // AP2 encrypted control channel (#90), decrypt whole frames
        // [2-byte LE len][cipher][16-byte tag] into the plaintext rxBuf_.
        const std::string encChunk = readAllTcp(transport_, rtspSock_);
        if (!encChunk.empty())   // #150 diag, does the receiver reply at all?
            log_.info("Cast: AirPlay 2 control rx +{} enc byte(s)", int(encChunk.size()));
        rtspEncBuf_ += encChunk;
        while (rtspEncBuf_.size() >= 2) {
            const int len = static_cast<unsigned char>(rtspEncBuf_[0])
                | (static_cast<int>(static_cast<unsigned char>(rtspEncBuf_[1])) << 8);
            const int need = 2 + len + 16;
            if (int(rtspEncBuf_.size()) < need) break;   // frame still arriving
            const unsigned char lp[2] = {
                static_cast<unsigned char>(rtspEncBuf_[0]),
                static_cast<unsigned char>(rtspEncBuf_[1]) };
            airplay::Bytes nonce8(8);
            for (int i = 0; i < 8; ++i)
                nonce8[size_t(i)] = static_cast<uint8_t>((ctrlRecvCtr_ >> (8 * i)) & 0xFF);
            ++ctrlRecvCtr_;
            const auto* cipher =
                reinterpret_cast<const uint8_t*>(rtspEncBuf_.data() + 2);
            const airplay::Bytes ctTag(cipher, cipher + len + 16);
            const airplay::Bytes aad(lp, lp + 2);
            auto dec = airplay::chacha20Poly1305Decrypt(ap2_->controlIn, nonce8, ctTag, aad);
            if (!dec) {
                fail_("Encrypted control channel authentication failed");
                return;
            }
            rxBuf_.append(reinterpret_cast<const char*>(dec->data()), dec->size());
            rtspEncBuf_.erase(0, size_t(need));
        }
    }
    // Audit fix, a hostile/buggy receiver that dribbles a never-terminating
    // head (or a huge Content-Length) could grow rxBuf_ unbounded. RTSP control
    // responses are tiny; cap the buffer and drop the session if exceeded.
    if (rxBuf_.size() > 4 * 1024 * 1024) {
        fail_("Oversized RTSP response from the receiver");
        return;
    }
    for (;;) {
        const auto headEnd = rxBuf_.find("\r\n\r\n");
        if (headEnd == std::string::npos) return;
        // Parse the head: status line + headers (lower-cased keys).
        const std::string head = rxBuf_.substr(0, headEnd);
        const std::vector<std::string> lines = splitCh(head, '\n');
        std::unordered_map<std::string, std::string> headers;
        for (size_t i = 1; i < lines.size(); ++i) {
            const std::string line = trimMed(lines[i]);
            const auto colon = line.find(':');
            if (colon == std::string::npos || colon == 0) continue;
            headers[trimMed(toLowerAscii(line.substr(0, colon)))] =
                trimMed(line.substr(colon + 1));
        }
        bool clOk = false;
        int contentLen = toInt(headerValue(headers, "content-length", "0"), clOk);
        if (!clOk || contentLen < 0) contentLen = 0;   // audit fix, reject bad/negative length
        if (rxBuf_.size() < headEnd + 4 + size_t(contentLen)) return;   // body pending
        const std::string statusLine = trimMed(lines.empty() ? std::string{} : lines[0]);
        // v0.66.x, pairing + AP2 plists need the body, so capture it now.
        const std::string body = rxBuf_.substr(headEnd + 4, size_t(contentLen));
        rxBuf_.erase(0, headEnd + 4 + size_t(contentLen));

        const bool isRtsp = statusLine.starts_with("RTSP/");
        const bool isHttp = statusLine.starts_with("HTTP/");
        if (!isRtsp && !isHttp) {
            // A server->client RTSP request (rare; some receivers push
            // events). We don't act on any, consume + log.
            log_.info("Cast: RAOP ignoring server request '{}'", statusLine);
            continue;
        }
        const std::vector<std::string> parts = splitCh(statusLine, ' ');
        const int code = toInt(parts.size() > 1 ? parts[1] : std::string{});
        if (pendingMethods_.empty()) {
            log_.warn("Cast: RAOP unexpected response (code {})", code);
            continue;
        }
        const std::string method = pendingMethods_.front();
        pendingMethods_.pop_front();
        const bool replyIsHttp = pendingIsHttp_.empty()
                                     ? false : (pendingIsHttp_.front());
        if (!pendingIsHttp_.empty()) pendingIsHttp_.pop_front();

        // v0.66.x Phase 2/3, route HTTP-mode replies (pairing / AP2
        // plists) to the pairing dispatcher; everything else is RTSP.
        if (replyIsHttp) {
            onPairingResponse_(code, headers, body);
        } else {
            handleResponse_(method, code, headers);
        }
        if (state_ == State::Idle) return;   // fail_ during dispatch
    }
}

void RaopSender::handleResponse_(const std::string& method, int code,
                                 const std::unordered_map<std::string, std::string>& headers) {
    // Streaming-time auxiliaries first, failures are non-fatal there.
    if (method == "SET_PARAMETER") {
        if (code != 200)
            log_.warn("Cast: RAOP SET_PARAMETER rejected ({})", code);
        return;
    }
    if (method == "POST") {   // /feedback keep-alive probe (AP1)
        if (code == 200) {
            if (!feedbackActive_) { transport_.startTimer(feedbackTimer_); feedbackActive_ = true; }
        } else {
            transport_.stopTimer(feedbackTimer_); feedbackActive_ = false;
            log_.info("Cast: RAOP /feedback not supported ({}), "
                      "keep-alive disabled", code);
        }
        return;
    }
    if (method == "FEEDBACK") return;   // AP2 keep-alive, reply ignored
    if (method == "TEARDOWN") return;

    // v0.66.x, RTSP digest auth for pw=true receivers (RFC 2617 MD5).
    if (code == 401) {
        if (digestPassword_.empty()) {
            fail_("The device requires a password");
            return;
        }
        if (digestRetried_) {
            fail_("The password was not accepted by the device");
            return;
        }
        // WWW-Authenticate: Digest realm="AirPlay", nonce="..."
        const std::string wa = headerValue(headers, "www-authenticate");
        auto extractQuoted = [&](const char* key) -> std::string {
            const auto k = wa.find(key);
            if (k == std::string::npos) return {};
            const auto q1 = wa.find('"', k);
            if (q1 == std::string::npos) return {};
            const auto q2 = wa.find('"', q1 + 1);
            if (q2 == std::string::npos) return {};
            return wa.substr(q1 + 1, q2 - q1 - 1);
        };
        digestRealm_ = extractQuoted("realm=");
        digestNonce_ = extractQuoted("nonce=");
        if (digestNonce_.empty()) {
            fail_("The device password challenge could not be parsed");
            return;
        }
        digestRetried_ = true;
        log_.info("Cast: RAOP digest challenge, re-sending '{}' with auth", method);
        // Re-issue the request that was rejected. sendRequest_ now attaches
        // the Authorization header (digestNonce_ is set).
        if (method == "OPTIONS")       sendOptions_();
        else if (method == "ANNOUNCE") sendAnnounce_();
        else if (method == "SETUP")    sendSetup_();
        else if (method == "RECORD")   sendRecord_();
        else fail_("The device password was required at an unexpected step");
        return;
    }
    if (code < 200 || code >= 300) {
        // AP2 sends RECORD + FLUSH fire-and-forget AFTER streaming has already
        // begun. Some Apple TVs reject RECORD on the encrypted realtime channel
        // (500), that is NON-fatal: the FLUSH timeline anchor + the sync
        // packets drive playback. Only a handshake-phase (pre-Streaming)
        // failure aborts the session.
        if (state_ == State::Streaming && (method == "RECORD" || method == "FLUSH")) {
            log_.info("Cast: RAOP {} not accepted ({}), non-fatal (AP2 realtime)",
                      method, code);
            return;
        }
        fail_(std::format("Device refused {} ({})", method, code));
        return;
    }

    if (method == "OPTIONS") {
        sendAnnounce_();
    } else if (method == "ANNOUNCE") {
        sendSetup_();
    } else if (method == "SETUP") {
        // Transport: RTP/AVP/UDP;unicast;mode=record;server_port=N;
        //            control_port=N;timing_port=N
        const std::string transport = headerValue(headers, "transport");
        serverPort_ = controlPort_ = timingPort_ = 0;
        for (const std::string& opt : splitCh(transport, ';')) {
            const auto eq = opt.find('=');
            if (eq == std::string::npos || eq == 0) continue;
            const std::string key = trimMed(opt.substr(0, eq));
            const uint16_t val = uint16_t(toUInt(trimMed(opt.substr(eq + 1))));
            if      (key == "server_port")  serverPort_  = val;
            else if (key == "control_port") controlPort_ = val;
            else if (key == "timing_port")  timingPort_  = val;
        }
        rtspSession_ = headerValue(headers, "session");
        if (rtspSession_.empty()) rtspSession_ = "1";
        if (serverPort_ == 0) {
            fail_("SETUP reply carried no server_port");
            return;
        }
        log_.info("Cast: RAOP remote ports, server={} control={} timing={}",
                  serverPort_, controlPort_, timingPort_);
        sendRecord_();
    } else if (method == "RECORD") {
        // The receiver may report its buffer depth; informational only,
        // like pyatv we keep the fixed 22050+44100-frame latency model.
        const std::string lat = headerValue(headers, "audio-latency");
        if (!lat.empty())
            log_.info("Cast: RAOP receiver Audio-Latency={} frames", lat);
        // AP1: RECORD's reply is the trigger to begin streaming. AP2: RECORD
        // is sent fire-and-forget from WITHIN startStreaming_ (already
        // Streaming), so a late reply must NOT re-init the stream.
        if (state_ != State::Streaming)
            startStreaming_();
    } else if (method == "FLUSH") {
        // AP2 fire-and-forget timeline anchor, reply (if any) is informational.
    }
}

// -- Handshake steps -----------------------------------------------

void RaopSender::sendOptions_() {
    // Traditional session opener (iTunes sends it; every receiver
    // answers). pyatv skips it, but it doubles as a cheap liveness
    // probe before we commit the ANNOUNCE.
    sendRequest_("OPTIONS", "*", {}, {});
}

void RaopSender::sendAnnounce_() {
    // pyatv ANNOUNCE_PAYLOAD: raw PCM (L16) with the classic fmtp
    // parameter list (352 frames/packet, 16-bit, 2 ch, 44100 Hz).
    const std::string localIp  = transport_.tcpLocalAddr(rtspSock_).ip;
    const std::string remoteIp = hostIp_;
    std::string sdp;
    sdp += "v=0\r\n";
    sdp += "o=iTunes " + std::to_string(sessionId_) + " 0 IN IP4 "
         + localIp + "\r\n";
    sdp += "s=iTunes\r\n";
    sdp += "c=IN IP4 " + remoteIp + "\r\n";
    sdp += "t=0 0\r\n";
    sdp += "m=audio 0 RTP/AVP 96\r\n";
    sdp += "a=rtpmap:96 L16/44100/2\r\n";
    sdp += "a=fmtp:96 352 0 16 40 10 14 2 255 0 0 44100\r\n";
    sendRequest_("ANNOUNCE", rtspUri_(), "application/sdp", sdp);
}

void RaopSender::sendSetup_() {
    const std::string transport =
        "RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port="
        + std::to_string(transport_.udpLocalPort(controlSock_)) + ";timing_port="
        + std::to_string(transport_.udpLocalPort(timingSock_));
    sendRequest_("SETUP", rtspUri_(), {}, {}, {{"Transport", transport}});
}

void RaopSender::sendRecord_() {
    // Classic single-RECORD form (see the deviation note up top):
    // RTP-Info announces the seq + rtptime of the FIRST audio packet.
    const std::string rtpInfo = "seq=" + std::to_string(seq_)
        + ";rtptime=" + std::to_string(rtptime32_());
    std::vector<std::pair<std::string, std::string>> hdr = {
        {"Range",    "npt=0-"},
        {"RTP-Info", rtpInfo}};
    // AP1 carries the RTSP Session id; AP2 has no RTSP Session header (it keys
    // off the rtsp://host/sessionId URI), so only send it when we actually got
    // one from a Transport-mode SETUP.
    if (!rtspSession_.empty())
        hdr.push_back({"Session", rtspSession_});
    sendRequest_("RECORD", rtspUri_(), {}, {}, hdr);
}

void RaopSender::startStreaming_() {
    state_ = State::Streaming;
    transport_.stopTimer(timeoutTimer_);
    // pyatv StreamContext.reset(): anchor the timeline on wall-clock
    // NTP so sync-packet NTP values and our timing-server replies share
    // one epoch (the receiver correlates the two for clock recovery).
    startTs_ = ntp2ts(ntpNow_(), kRaopRate);
    framesSent_ = 0;
    firstAudio_ = true;
    clockStart_ = Clock::now();
    sendSyncPacket_(true);   // first sync carries the marker bit
    transport_.startTimer(syncTimer_);
    // #90, RECORD already ran between session + stream SETUP (owntone order),
    // so streaming just needs sync + volume + the RTP loop here.
    // Volume requested before the session was up? Apply it now. pyatv
    // uses the SAME SET_PARAMETER volume for AP1 AND AP2 (no separate AP2
    // surface), over the encrypted channel it just rides the same RTSP
    // connection.
    // #90, an AP2 receiver can sit at its own (possibly muted) default until
    // told otherwise, which reads as "connected but silent". If the user never
    // set a cast volume, push 0 dB (no attenuation; the TV/AVR's own volume
    // still governs the actual loudness) so audio is audible by default.
    if (airplay2_ && pendingVolumeDb_ <= kNoVolume + 1.0)
        pendingVolumeDb_ = 0.0;
    if (pendingVolumeDb_ > kNoVolume + 1.0) {
        const std::string body = "volume: " + std::format("{:.6f}", pendingVolumeDb_);
        std::vector<std::pair<std::string, std::string>> vh;
        if (!rtspSession_.empty())
            vh.push_back({"Session", rtspSession_});
        sendRequest_("SET_PARAMETER", rtspUri_(), "text/parameters", body, vh);
    }
    transport_.startTimer(pacerTimer_);   // audio RTP loop starts LAST (after RECORD/FLUSH/volume)
    if (airplay2_) {
        // AP2: feedback is an HTTP POST /feedback every 2 s (pyatv
        // FEEDBACK_INTERVAL).
        transport_.setTimerInterval(feedbackTimer_, 2000);
        transport_.startTimer(feedbackTimer_);
        feedbackActive_ = true;
    } else {
        // Keep-alive probe (pyatv start_feedback): one POST /feedback; a
        // 200 arms the 25 s timer, anything else disables it for good.
        sendRequest_("POST", "/feedback", {}, {});
    }
    // Push the current track's metadata + cover to the receiver now that
    // the stream is live (track changes during playback re-push via
    // setNowPlaying -> sendMetadata_).
    sendMetadata_();
    log_.info("Cast: RAOP streaming to '{}', RTP {} frames/packet @ {} Hz{}",
              name_, kFramesPerPacket, kRaopRate,
              (ap2_ && ap2_->encryptAudio) ? " (encrypted)" : "");
    if (onLaunched_) onLaunched_(true, "");
}

// -- v0.66.x Phase 2/3, auth + pairing + AirPlay 2 --------------------

void RaopSender::httpPost_(const std::string& uri, const std::string& contentType,
                           const std::string& body) {
    // POST over the SAME TCP socket as RTSP. Real receivers parse both an
    // RTSP and an HTTP request line on this connection (pyatv uses one
    // multiplexed HttpConnection); we send a proper HTTP/1.1 request and
    // route the reply back to onPairingResponse_ via pendingIsHttp_.
    std::string req = "POST " + uri + " HTTP/1.1\r\n";
    req += "CSeq: " + std::to_string(cseq_++) + "\r\n";
    req += "User-Agent: AirPlay/550.10\r\n";
    req += "Connection: keep-alive\r\n";
    req += "X-Apple-HKP: " +
           std::to_string(authMethod_ == RaopDeviceInfo::Auth::HapTransient ? 4 : 3) + "\r\n";
    req += "DACP-ID: " + dacpId_ + "\r\n";
    req += "Active-Remote: " + std::to_string(activeRemote_) + "\r\n";
    // owntone stamps Client-Instance + X-Apple-Client-Name on EVERY pairing
    // request (request_headers_add). Our pairing builder omitted both, a
    // macOS/Apple-TV receiver's access-control gate inspects the sender
    // identity headers before the TLV, and their absence is a documented 403
    // cause. Mirror owntone (Client-Instance == DACP-ID value).
    req += "Client-Instance: " + dacpId_ + "\r\n";
    req += "X-Apple-Client-Name: FXChainPlayer\r\n";
    if (!contentType.empty())
        req += "Content-Type: " + contentType + "\r\n";
    req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    req += "\r\n";
    req += body;
    pendingMethods_.push_back("POST");
    pendingIsHttp_.push_back(true);
    writeRtsp_(req);
    if (!waitingForPin_) transport_.startTimer(timeoutTimer_);
}

void RaopSender::beginAuthChain_() {
    state_ = State::Pairing;
    using Auth = RaopDeviceInfo::Auth;
    switch (authMethod_) {
    case Auth::None:
        // Plain Phase-1 receiver, go straight to the RTSP handshake.
        state_ = State::Handshake;
        sendOptions_();
        return;
    case Auth::Password:
        // Digest auth is reactive (triggered by a 401), so just start the
        // normal handshake; the first 401 arms the Authorization header.
        state_ = State::Handshake;
        sendOptions_();
        return;
    case Auth::AuthSetup:
        sendAuthSetup_();   // MFiSAP one-shot, then OPTIONS
        return;
    case Auth::LegacyPin:
        // Pre-HomeKit "Fruit" pairing (SRP-2048 + AES), only the oldest
        // Apple TVs that DON'T also advertise HAP land here (modern ATV4+
        // route to the tested HapPin/HapTransient paths). Rather than run a
        // doomed unencrypted handshake the device will reject, fail with a
        // clear, actionable message. (The full legacy SRP-2048 flow needs a
        // real legacy device to verify; not implemented yet.)
        fail_(std::format("{} uses an older AirPlay pairing that isn't supported "
                          "yet. Update the device's software, or use an AirPlay-2 "
                          "receiver (HomePod, Apple TV 4K, or a modern AirPlay "
                          "speaker).", name_));
        return;
    case Auth::HapTransient:
        // HomePod / AP2, fixed-PIN 3939 transient pairing, no UI.
        ap2_ = std::make_unique<RaopAp2State>();
        sendPairSetupM1_();
        return;
    case Auth::HapPin:
        // Apple TV 4+, stored creds -> pair-verify; else on-screen PIN.
        ap2_ = std::make_unique<RaopAp2State>();
        if (!credsJson_.empty()) {
            // Load stored long-term identity + the accessory's ltpk/id.
            if (auto cf = credsFromJson(credsJson_)) {
                ap2_->ltSeed        = cf->ltsk;
                ap2_->pairingId     = toBytes(cf->clientId);
                ap2_->accessoryId   = cf->atvId;
                ap2_->accessoryLtpk = cf->ltpk;
                if (ap2_->ltSeed.size() == 32 && !ap2_->accessoryLtpk.empty()) {
                    ap2_->ltPub = airplay::ed25519PublicFromSeed(ap2_->ltSeed);
                    sendPairVerifyM1_();
                    return;
                }
            }
        }
        sendPairPinStart_();  // first pairing (PIN), make the code appear, then M1
        return;
    }
}

void RaopSender::onPairingResponse_(int code,
                                    const std::unordered_map<std::string, std::string>& headers,
                                    const std::string& body) {
    (void)headers;
    if (state_ == State::Idle) return;

    // Once we're streaming the handshake is done; a late/duplicate
    // pairing-stage reply (e.g. a misbehaving receiver) must NOT be re-parsed
    // as a SETUP plist and tear down the live stream. Ignore it.
    if (state_ == State::Streaming) {
        log_.info("Cast: RAOP ignoring a late pairing reply ({}) while streaming",
                  code);
        return;
    }

    // auth-setup: response is ignored (pyatv does exactly this).
    if (authMethod_ == RaopDeviceInfo::Auth::AuthSetup &&
        ap2_ == nullptr && pairStage_ == PairStage::AuthSetup) {
        pairStage_ = PairStage::Done;
        afterAuthOk_();
        return;
    }

    // #90, the RECORD reply (between session + stream SETUP). A modern Apple TV
    // with the event channel open should answer 200; if it still rejects RECORD
    // (e.g. it wants PTP timing) we log the code and proceed to the stream SETUP
    // anyway so the stream is at least established. Handled before the generic
    // non-2xx abort below so a RECORD 500 doesn't kill the session.
    if (pairStage_ == PairStage::Ap2Record) {
        log_.info("Cast: AirPlay 2 RECORD reply ({}){}, proceeding to stream SETUP",
                  code, (code >= 200 && code < 300) ? " OK" : " (not accepted)");
        sendAp2SetupStream_();
        return;
    }

    if (code < 200 || code >= 300) {
        // HTTP 470 (RTSP_CONNECTION_AUTH_REQUIRED) on a transient pair-setup
        // means the receiver won't do PIN-less transient pairing, it wants
        // real (one-time / HomeKit) pairing. Switch to HapPin and run the
        // normal sequence: /pair-pin-start (which makes the Apple TV DISPLAY
        // its 4-digit code) THEN /pair-setup M1 without the transient flag.
        // (owntone returns AIRPLAY_SEQ_PIN_START on 470; pyatv posts
        // /pair-pin-start before M1.) One-shot, gated on the transient M1
        // stage so it can't loop.
        if (code == 470 && authMethod_ == RaopDeviceInfo::Auth::HapTransient
            && pairStage_ == PairStage::SetupM2) {
            log_.info("Cast: '{}' refused transient pairing (470), falling "
                      "back to on-screen PIN pairing", name_);
            authMethod_ = RaopDeviceInfo::Auth::HapPin;
            ap2_ = std::make_unique<RaopAp2State>();   // fresh pairing state
            // v0.66.x, /pair-pin-start (HKP 3) FIRST so the Apple TV shows
            // its code, THEN M1. Sending M1 alone returns salt+B but never
            // displays a code (the user's "waiting for code" hang).
            sendPairPinStart_();
            return;
        }
        // A 403 to /pair-pin-start is the Mac case: a macOS AirPlay receiver
        // does NOT display an on-screen PIN (it gates by access control), so
        // it rejects the pin-start. When access is "Anyone on the Same
        // Network" the Mac still accepts PIN-LESS TRANSIENT pairing, so try
        // that once before giving up. (One-shot, so a genuine "Current User"
        // Mac, which 403s transient too, falls through to the message.)
        if (code == 403 && pairStage_ == PairStage::PinStart
            && !triedTransientAfterPin403_) {
            log_.info("Cast: '{}' refused /pair-pin-start (403), no on-screen "
                      "PIN (Mac-style); trying transient pairing", name_);
            triedTransientAfterPin403_ = true;
            authMethod_ = RaopDeviceInfo::Auth::HapTransient;
            ap2_ = std::make_unique<RaopAp2State>();
            sendPairSetupM1_();
            return;
        }
        // Any other pairing failure at the HTTP layer. 403 on a HomeKit
        // receiver is almost always an ACCESS-CONTROL rejection, the
        // device only accepts senders it's configured to allow.
        if (code == 403) {
            // 403 = the receiver's access-control policy refused us (not a
            // protocol error). On a Mac: System Settings -> General -> AirDrop &
            // Handoff -> AirPlay Receiver -> "Allow AirPlay for: Everyone" AND
            // turn Require Password OFF. Note that a macOS AirPlay Receiver may
            // only accept Apple devices regardless of this setting, an Apple TV
            // or HomePod is the reliable target. On an Apple TV: Settings ->
            // AirPlay & HomeKit -> Allow Access -> "Anyone on the Same Network".
            fail_(std::format("{} refused pairing. On a Mac, set System Settings "
                     "-> AirDrop & Handoff -> AirPlay Receiver -> \"Allow AirPlay "
                     "for: Everyone\" and turn off Require Password, though a "
                     "Mac may only accept Apple devices. An Apple TV or HomePod "
                     "(Allow Access -> \"Anyone on the Same Network\") is the "
                     "reliable target.", name_));
        } else if (code == 470) {
            fail_(std::format("{} needs to be paired with a PIN, but it didn't "
                     "show one. On the Apple TV / Mac set AirPlay access to "
                     "\"Anyone on the Same Network\" and try again.", name_));
        } else {
            fail_(std::format("Pairing with {} failed (HTTP {})", name_, code));
        }
        return;
    }

    // HAP pair-setup / pair-verify TLV8 flow. The on-screen-PIN path begins
    // with /pair-pin-start (PairStage::PinStart) so the Apple TV displays its
    // code; transient + pair-verify go straight to their first message.
    switch (pairStage_) {
    case PairStage::PinStart:
        // /pair-pin-start acknowledged, the device's 4-digit code is now on
        // screen. Begin the SRP handshake (M1, no transient flag).
        log_.info("Cast: AirPlay /pair-pin-start OK, Apple TV should now "
                  "show its code");
        sendPairSetupM1_();
        break;
    case PairStage::SetupM2: handlePairSetupM2_(body); break;
    case PairStage::SetupM4: handlePairSetupM4_(body); break;
    case PairStage::SetupM6: handlePairSetupM6_(body); break;
    case PairStage::VerifyM2: handlePairVerifyM2_(body); break;
    case PairStage::VerifyDone:
        // pair-verify M3 acknowledged -> the control channel is now keyed.
        log_.info("Cast: AirPlay pair-verify complete");
        pairStage_ = PairStage::Done;
        afterAuthOk_();
        break;
    case PairStage::Ap2Info:
        // GET /info acknowledged (device-capability plist; we don't need its
        // contents for realtime audio), proceed to the session SETUP.
        log_.info("Cast: AirPlay 2 GET /info ok, starting SETUP");
        sendAp2SetupSession_();
        break;
    case PairStage::Ap2Session: handleAp2SetupSession_(body); break;
    case PairStage::Ap2Stream: handleAp2SetupStream_(body); break;
    default:
        log_.warn("Cast: AirPlay pairing reply at unexpected stage");
        break;
    }
}

void RaopSender::afterAuthOk_() {
    // Auth/pairing succeeded. For AP2 (encrypted) devices we go to the
    // binary-plist SETUP; for AP1 (auth-setup / legacy-PIN / password) we
    // run the classic RTSP handshake (audio stays unencrypted).
    digestRetried_ = false;   // reset for the handshake's own auth
    if (airplay2_) {
        // #90, pair-verify is done; from here the RTSP control channel is
        // ChaCha20-Poly1305 encrypted (Control-Write/Read keys derived during
        // pair-verify). The very next request (/setup) is already encrypted,
        // and an Apple TV REQUIRES this, sending /setup plaintext made it drop
        // the connection right after pair-verify.
        if (ap2_ && ap2_->controlOut.size() == 32 && ap2_->controlIn.size() == 32) {
            controlEncrypted_ = true;
            ctrlSendCtr_ = 0;
            ctrlRecvCtr_ = 0;
            rtspEncBuf_.clear();
            log_.info("Cast: AirPlay 2 control channel now ENCRYPTED (post pair-verify)");
        }
        state_ = State::Handshake;
        sendAp2Info_();
    } else {
        state_ = State::Handshake;
        sendOptions_();
    }
}

// -- auth-setup (MFiSAP / AirPort Express gen 2) -----------------------

void RaopSender::sendAuthSetup_() {
    // pyatv: a single 0x01 mode byte (unencrypted) + a static curve25519
    // public key. The receiver's reply is ignored entirely.
    pairStage_ = PairStage::AuthSetup;
    static const uint8_t kCurve25519Pub[33] = {
        0x01,   // mode = unencrypted
        0x59,0x02,0xed,0xe9,0x0d,0x4e,0xf2,0xbd,
        0x4c,0xb6,0x8a,0x63,0x30,0x03,0x82,0x07,
        0xa9,0x4d,0xbd,0x50,0xd8,0xaa,0x46,0x5b,
        0x5d,0x8c,0x01,0x2a,0x0c,0x7e,0x1d,0x4e};
    httpPost_("/auth-setup", "application/octet-stream",
              std::string(reinterpret_cast<const char*>(kCurve25519Pub), 33));
}

// -- HAP pair-setup (SRP) ----------------------------------------------

void RaopSender::sendPairPinStart_() {
    // v0.66.x, the on-screen-PIN trigger. A tvOS Apple TV only RENDERS its
    // 4-digit code when it receives POST /pair-pin-start; the subsequent
    // /pair-setup M1 just returns SRP material (salt+B) without displaying
    // anything. owntone (payload_make_pin_start) and pyatv (start_pairing)
    // both send this BEFORE M1 for normal HomeKit pairing. httpPost_ already
    // stamps the required `X-Apple-HKP: 3` header for the non-transient
    // (HapPin) path. Empty body. On the 200 reply we proceed to M1.
    //
    // NOTE: an earlier refactor removed this, blaming it for the MacBook's
    // HTTP 403, but that 403 is a SEPARATE access gate (the Mac receiver in
    // "Current User" mode refusing pairing wholesale), not /pair-pin-start.
    pairStage_ = PairStage::PinStart;
    httpPost_("/pair-pin-start", "application/octet-stream", std::string());
}

void RaopSender::sendPairSetupM1_() {
    using namespace airplay;
    // HAP pair-setup M1 to /pair-setup. On the PIN path this is sent AFTER
    // /pair-pin-start (see sendPairPinStart_) so the device's code is already
    // on screen. M1 carries State=1 + Method=0(PairSetup); the transient
    // fast-path additionally sets Flags=0x10 (kPairingFlag_Transient).
    tlv::Map m = {
        {tlv::Method, {0x00}},
        {tlv::State, {0x01}},
    };
    if (authMethod_ == RaopDeviceInfo::Auth::HapTransient)
        m.push_back({tlv::Flags, {0x10}});   // TransientPairing
    pairStage_ = PairStage::SetupM2;
    httpPost_("/pair-setup", "application/octet-stream", toStr(tlv::encode(m)));
}

void RaopSender::sendPairSetupM3_(const std::string& pin) {
    using namespace airplay;
    // Run SRP step1/step2 with the PIN against the stored salt+B.
    ap2_->srp = std::make_unique<SrpClient>();
    ap2_->srp->start(pin);
    if (!ap2_->srp->process(toBytes(srpSalt_), toBytes(srpServerB_))) {
        fail_("Pairing rejected the device's parameters");
        return;
    }
    tlv::Map m = {
        {tlv::State, {0x03}},
        {tlv::PublicKey, ap2_->srp->publicA()},
        {tlv::Proof, ap2_->srp->proofM1()},
    };
    pairStage_ = PairStage::SetupM4;
    httpPost_("/pair-setup", "application/octet-stream", toStr(tlv::encode(m)));
}

void RaopSender::handlePairSetupM2_(const std::string& body) {
    using namespace airplay;
    const tlv::Map m = tlv::decode(toBytes(body));
    if (auto err = tlv::get(m, tlv::Error)) {
        fail_(std::format("The device rejected pairing (error {})",
                          err->empty() ? 0 : int((*err)[0])));
        return;
    }
    auto salt = tlv::get(m, tlv::Salt);
    auto pub  = tlv::get(m, tlv::PublicKey);
    if (!salt || !pub) { fail_("Pairing setup response was incomplete"); return; }
    srpSalt_    = toStr(*salt);
    srpServerB_ = toStr(*pub);
    if (authMethod_ == RaopDeviceInfo::Auth::HapTransient) {
        // Transient: no user interaction, fixed PIN 3939.
        sendPairSetupM3_("3939");
    } else {
        // Normal HAP PIN, ask the UI for the on-screen code.
        waitingForPin_ = true;
        transport_.stopTimer(timeoutTimer_);
        transport_.startTimer(pinTimer_);   // bounded user-driven wait (see ctor)
        log_.info("Cast: AirPlay HAP PIN pairing, waiting for code");
        if (onPinRequired_) onPinRequired_(name_);
    }
}

void RaopSender::handlePairSetupM4_(const std::string& body) {
    using namespace airplay;
    const tlv::Map m = tlv::decode(toBytes(body));
    if (auto err = tlv::get(m, tlv::Error)) {
        fail_(std::format("Pairing PIN was not accepted (error {})",
                          err->empty() ? 0 : int((*err)[0])));
        return;
    }
    // M4 carries the server proof M5 (HAP "Proof"); verify it.
    if (auto proof = tlv::get(m, tlv::Proof)) {
        if (!ap2_->srp->verifyServerProof(*proof))
            log_.warn("Cast: AirPlay server proof mismatch (continuing)");
    }
    // Transient pairing stops at M4: derive the audio/control key from the
    // SRP shared secret and go straight to AP2 SETUP.
    if (authMethod_ == RaopDeviceInfo::Auth::HapTransient) {
        ap2_->sharedSecret = ap2_->srp->sessionKey();
        // Control-channel keys (read/write) per HAP.
        ap2_->controlOut = hkdfSha512("Control-Salt",
                                      "Control-Write-Encryption-Key",
                                      ap2_->sharedSecret, 32);
        ap2_->controlIn  = hkdfSha512("Control-Salt",
                                      "Control-Read-Encryption-Key",
                                      ap2_->sharedSecret, 32);
        pairStage_ = PairStage::Done;
        afterAuthOk_();
        return;
    }
    // Normal HAP pairing, exchange long-term keys (M5/M6).
    sendPairSetupM5_();
}

void RaopSender::sendPairSetupM5_() {
    using namespace airplay;
    // Generate our long-term Ed25519 identity (persisted as credentials).
    if (ap2_->ltSeed.empty()) ap2_->ltSeed = randomBytes(32);
    ap2_->ltPub = ed25519PublicFromSeed(ap2_->ltSeed);
    if (ap2_->pairingId.empty()) {
        const std::string id = genUuidLower();
        ap2_->pairingId = toBytes(id);
    }
    // session_key = HKDF(Pair-Setup-Encrypt) over K; the signed material is
    // HKDF(Pair-Setup-Controller-Sign) || pairingId || ltPub.
    const Bytes K = ap2_->srp->sessionKey();
    const Bytes sessionKey = hkdfSha512("Pair-Setup-Encrypt-Salt",
                                        "Pair-Setup-Encrypt-Info", K, 32);
    const Bytes iosDeviceX = hkdfSha512("Pair-Setup-Controller-Sign-Salt",
                                        "Pair-Setup-Controller-Sign-Info", K, 32);
    Bytes deviceInfo = iosDeviceX;
    deviceInfo.insert(deviceInfo.end(), ap2_->pairingId.begin(), ap2_->pairingId.end());
    deviceInfo.insert(deviceInfo.end(), ap2_->ltPub.begin(), ap2_->ltPub.end());
    const Bytes sig = ed25519Sign(ap2_->ltSeed, deviceInfo);

    tlv::Map inner = {
        {tlv::Identifier, ap2_->pairingId},
        {tlv::PublicKey, ap2_->ltPub},
        {tlv::Signature, sig},
    };
    // HAP setup messages use a STRING-label nonce ("PS-Msg05"), the 8
    // ASCII bytes sit in the low 8 of the 12-byte IETF nonce (the 4-byte
    // zero pad is added by chacha20Poly1305Encrypt).
    const Bytes nonceM5 = toBytes("PS-Msg05");
    const Bytes enc = chacha20Poly1305Encrypt(sessionKey, nonceM5,
                                              tlv::encode(inner), {});
    tlv::Map m = {
        {tlv::State, {0x05}},
        {tlv::EncryptedData, enc},
    };
    // Stash the M5 session key so M6 can decrypt the reply.
    pairSetupSessionKey_ = sessionKey;
    pairStage_ = PairStage::SetupM6;
    httpPost_("/pair-setup", "application/octet-stream", toStr(tlv::encode(m)));
}

void RaopSender::handlePairSetupM6_(const std::string& body) {
    using namespace airplay;
    const tlv::Map m = tlv::decode(toBytes(body));
    if (auto err = tlv::get(m, tlv::Error)) {
        fail_(std::format("Pairing finalisation failed (error {})",
                          err->empty() ? 0 : int((*err)[0])));
        return;
    }
    auto encrypted = tlv::get(m, tlv::EncryptedData);
    if (!encrypted) { fail_("Pairing M6 response was incomplete"); return; }
    const Bytes sessionKey = pairSetupSessionKey_;   // stashed in M5
    const Bytes nonceM6 = toBytes("PS-Msg06");
    auto dec = chacha20Poly1305Decrypt(sessionKey, nonceM6, *encrypted, {});
    if (!dec) { fail_("Pairing M6 could not be decrypted"); return; }
    const tlv::Map sub = tlv::decode(*dec);
    auto atvId  = tlv::get(sub, tlv::Identifier);
    auto atvLtpk = tlv::get(sub, tlv::PublicKey);
    if (!atvId || !atvLtpk) { fail_("Pairing M6 was missing device keys"); return; }
    ap2_->accessoryId   = *atvId;
    ap2_->accessoryLtpk = *atvLtpk;

    // Persist the long-term credentials so later connects skip the PIN.
    CredsFields cf;
    cf.ltsk     = ap2_->ltSeed;
    cf.ltpk     = *atvLtpk;
    cf.atvId    = *atvId;
    cf.clientId = toStr(ap2_->pairingId);
    const std::string creds = credsToJson(cf);
    if (onCredsObtained_) onCredsObtained_(deviceId_, creds);
    log_.info("Cast: AirPlay HAP pairing complete, credentials stored");

    // Now run pair-verify to derive the live session keys.
    pairSetupSessionKey_.clear();
    sendPairVerifyM1_();
}

// -- HAP pair-verify (X25519 + Ed25519) --------------------------------

void RaopSender::sendPairVerifyM1_() {
    using namespace airplay;
    ap2_->verifyKeys = x25519Generate();
    tlv::Map m = {
        {tlv::State, {0x01}},
        {tlv::PublicKey, ap2_->verifyKeys.pub},
    };
    pairStage_ = PairStage::VerifyM2;
    httpPost_("/pair-verify", "application/octet-stream", toStr(tlv::encode(m)));
}

void RaopSender::handlePairVerifyM2_(const std::string& body) {
    using namespace airplay;
    const tlv::Map m = tlv::decode(toBytes(body));
    if (auto err = tlv::get(m, tlv::Error)) {
        fail_(std::format("Pair-verify rejected (error {})",
                          err->empty() ? 0 : int((*err)[0])));
        return;
    }
    auto sessionPub = tlv::get(m, tlv::PublicKey);
    auto encrypted  = tlv::get(m, tlv::EncryptedData);
    if (!sessionPub || !encrypted) { fail_("Pair-verify response incomplete"); return; }

    // Shared secret + verify session key.
    ap2_->sharedSecret = x25519SharedSecret(ap2_->verifyKeys.priv, *sessionPub);
    if (ap2_->sharedSecret.empty()) {   // malformed/low-order sessionPub
        fail_("Pair-verify shared-secret derivation failed");
        return;
    }
    const Bytes verifyKey = hkdfSha512("Pair-Verify-Encrypt-Salt",
                                       "Pair-Verify-Encrypt-Info",
                                       ap2_->sharedSecret, 32);
    const Bytes nonce02 = toBytes("PV-Msg02");
    auto dec = chacha20Poly1305Decrypt(verifyKey, nonce02, *encrypted, {});
    if (!dec) { fail_("Pair-verify could not be decrypted"); return; }
    const tlv::Map sub = tlv::decode(*dec);
    auto atvId = tlv::get(sub, tlv::Identifier);
    auto atvSig = tlv::get(sub, tlv::Signature);
    if (!atvId || !atvSig) { fail_("Pair-verify was missing the device signature"); return; }

    // Verify the accessory's signature over sessionPub || atvId || ourPub.
    if (!ap2_->accessoryLtpk.empty()) {
        Bytes info = *sessionPub;
        info.insert(info.end(), atvId->begin(), atvId->end());
        info.insert(info.end(), ap2_->verifyKeys.pub.begin(),
                    ap2_->verifyKeys.pub.end());
        if (!ed25519Verify(ap2_->accessoryLtpk, info, *atvSig))
            log_.warn("Cast: AirPlay pair-verify signature mismatch (continuing)");
    }

    // Sign our half: ourPub || pairingId || sessionPub.
    Bytes deviceInfo = ap2_->verifyKeys.pub;
    deviceInfo.insert(deviceInfo.end(), ap2_->pairingId.begin(), ap2_->pairingId.end());
    deviceInfo.insert(deviceInfo.end(), sessionPub->begin(), sessionPub->end());
    const Bytes sig = ed25519Sign(ap2_->ltSeed, deviceInfo);
    tlv::Map innerOut = {
        {tlv::Identifier, ap2_->pairingId},
        {tlv::Signature, sig},
    };
    const Bytes nonce03 = toBytes("PV-Msg03");
    const Bytes enc = chacha20Poly1305Encrypt(verifyKey, nonce03,
                                              tlv::encode(innerOut), {});
    tlv::Map mOut = {
        {tlv::State, {0x03}},
        {tlv::EncryptedData, enc},
    };
    // After M3 the receiver enables encryption on the control channel; the
    // SETUP plist exchange proceeds. Derive the control keys now.
    ap2_->controlOut = hkdfSha512("Control-Salt",
                                  "Control-Write-Encryption-Key",
                                  ap2_->sharedSecret, 32);
    ap2_->controlIn  = hkdfSha512("Control-Salt",
                                  "Control-Read-Encryption-Key",
                                  ap2_->sharedSecret, 32);
    // #90/#109, event-channel keys (pyatv/owntone "Events-Salt"). The event
    // channel is a REVERSE connection, so the read/write keys are SWAPPED vs the
    // control channel: we DECRYPT the receiver's pushed events with the
    // "Events-Write" key and ENCRYPT our 200-OK responses with "Events-Read".
    ap2_->eventIn  = hkdfSha512("Events-Salt",
                                "Events-Write-Encryption-Key",
                                ap2_->sharedSecret, 32);
    ap2_->eventOut = hkdfSha512("Events-Salt",
                                "Events-Read-Encryption-Key",
                                ap2_->sharedSecret, 32);
    // Send M3, then (on its 200) proceed to AP2 SETUP. The next reply is
    // routed via the VerifyDone stage.
    pairStage_ = PairStage::VerifyDone;
    httpPost_("/pair-verify", "application/octet-stream", toStr(tlv::encode(mOut)));
}

// -- AirPlay 2 binary-plist SETUP --------------------------------------

// pyatv/owntone: after pair-verify the realtime SETUP sequence is, on the
// rtsp:// control channel, GET /info -> SETUP (session) -> SETUP (stream) ->
// RECORD -> SET_PARAMETER volume. Critically these are RTSP *methods*, not a
// `POST /setup` HTTP path (which 404s). The replies carry a binary-plist body,
// so they route through the body-capturing pairing dispatcher.
void RaopSender::sendAp2Rtsp_(const std::string& method, const std::string& uri,
                              const std::string& contentType,
                              const std::string& body) {
    std::string req = method + " " + uri + " RTSP/1.0\r\n";
    req += "CSeq: " + std::to_string(cseq_++) + "\r\n";
    req += "User-Agent: AirPlay/550.10\r\n";
    req += "DACP-ID: " + dacpId_ + "\r\n";
    req += "Active-Remote: " + std::to_string(activeRemote_) + "\r\n";
    req += "Client-Instance: " + dacpId_ + "\r\n";
    req += "X-Apple-Client-Name: FXChainPlayer\r\n";
    if (method == "SETUP")
        req += "X-Apple-StreamID: 1\r\n";        // owntone/pyatv parity
    if (!contentType.empty())
        req += "Content-Type: " + contentType + "\r\n";
    if (!body.empty())
        req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    req += "\r\n";
    req += body;
    pendingMethods_.push_back(method);
    pendingIsHttp_.push_back(true);   // reply has a plist body -> pairing dispatcher
    writeRtsp_(req);
    transport_.startTimer(timeoutTimer_);
}

void RaopSender::sendAp2Info_() {
    // GET /info (path GET on the RTSP control channel), required before SETUP.
    pairStage_ = PairStage::Ap2Info;
    sendAp2Rtsp_("GET", "/info", {}, {});
}

void RaopSender::sendAp2SetupSession_() {
    using namespace airplay::bplist;
    // Session-level SETUP: timing over NTP (no PTP/nqptp), event channel.
    Dict d;
    d.emplace_back("deviceID", Value::str("AA:BB:CC:DD:EE:FF"));
    d.emplace_back("sessionUUID", Value::str(ap2_->sessionUuid));
    d.emplace_back("timingPort", Value::integer(transport_.udpLocalPort(timingSock_)));
    d.emplace_back("timingProtocol", Value::str("NTP"));
    d.emplace_back("isMultiSelectAirPlay", Value::boolean(true));
    d.emplace_back("groupContainsGroupLeader", Value::boolean(false));
    d.emplace_back("macAddress", Value::str("AA:BB:CC:DD:EE:FF"));
    d.emplace_back("model", Value::str("iPhone14,3"));
    d.emplace_back("name", Value::str("FXChainPlayer"));
    d.emplace_back("osBuildVersion", Value::str("20F66"));
    d.emplace_back("osName", Value::str("iPhone OS"));
    d.emplace_back("osVersion", Value::str("16.5"));
    d.emplace_back("senderSupportsRelay", Value::boolean(false));
    d.emplace_back("sourceVersion", Value::str("690.7.1"));
    d.emplace_back("statsCollectionEnabled", Value::boolean(false));
    const auto body = airplay::bplist::encode(Value::object(std::move(d)));
    pairStage_ = PairStage::Ap2Session;
    sendAp2Rtsp_("SETUP", rtspUri_(),
                 "application/x-apple-binary-plist", toStr(body));
    // #150 diag, confirm the session SETUP went out; the MacBook stall shows
    // this line then silence (no "session SETUP ok", no control rx).
    log_.info("Cast: AirPlay 2 session SETUP sent ({} plist bytes), awaiting reply",
              int(body.size()));
}

void RaopSender::handleAp2SetupSession_(const std::string& body) {
    using namespace airplay::bplist;
    auto root = decode(toBytes(body));
    if (root) {
        if (auto* ep = root->find("eventPort"))
            ap2_->eventPort = uint16_t(ep->asInt());
    }
    log_.info("Cast: AirPlay 2 session SETUP ok, eventPort={}", ap2_->eventPort);
    // #90, a modern Apple TV needs the event-channel TCP connection OPEN and
    // RECORD accepted BEFORE the stream SETUP. Open the event channel, then
    // send RECORD; the stream SETUP follows on the RECORD reply.
    if (ap2_->eventPort != 0) {
        if (eventSock_ != kInvalidSock) { transport_.tcpClose(eventSock_); eventSock_ = kInvalidSock; }
        eventSock_ = transport_.tcpConnect(hostIp_, ap2_->eventPort);
        if (eventSock_ != kInvalidSock) {
            transport_.onTcpReadable(eventSock_, [this] { onEventReadyRead_(); });
            // Surface an event-channel drop instead of silently ignoring it
            // (a receiver that drops the event channel usually tears down).
            transport_.onTcpError(eventSock_, [this](std::string e) {
                if (state_ == State::Streaming || state_ == State::Handshake)
                    log_.warn("Cast: AirPlay 2 event channel error: {}", e);
            });
        }
        log_.info("Cast: AirPlay 2 opening event channel -> {}:{}",
                  host_, ap2_->eventPort);
    }
    sendAp2Record_();
}

void RaopSender::sendAp2Record_() {
    // owntone START_PLAYBACK order: RECORD (empty body, standard headers) comes
    // right after session SETUP, BEFORE the stream SETUP. The receiver enters
    // its RECORD state, required before it will render the realtime stream.
    pairStage_ = PairStage::Ap2Record;
    sendAp2Rtsp_("RECORD", rtspUri_(), {}, {});
}

void RaopSender::sendAp2SetupStream_() {
    using namespace airplay::bplist;
    // The audio shared key (shk) = the FIRST 32 bytes of the pairing shared
    // secret, used DIRECTLY as the ChaCha20-Poly1305 audio key (owntone:
    // session->shared_secret is both the `shk` plist value AND the cipher key,
    // with NO HKDF). #90: a modern Apple TV derives the audio key from the
    // shared secret, so encrypting with the derived Control-Write key produced
    // garbage (noise) on decode, the raw secret is the correct key.
    //
    // #150, the secret's LENGTH differs by pairing path:
    //   - pair-verify (Apple TV, HAP PIN, sf=0x644): X25519 ECDH = 32 bytes.
    //   - HAP transient (macOS/MacBook, sf=0x4): SRP session key K = SHA-512(S)
    //     = 64 bytes (transient stops at pair-setup M4, no pair-verify).
    // owntone airplay.c AIRPLAY_AUDIO_KEY_LEN: "for transient pairing the
    // key_len will be 64 bytes, but only 32 are used for audio payload
    // encryption", chacha_open() takes the FIRST 32, and `shk` carries the
    // same 32. Passing all 64 made chacha20Poly1305Encrypt throw on every
    // packet -> zero audio sent -> the MacBook dropped the (otherwise healthy)
    // session after its ~30 s no-audio timeout. The control/event keys stay
    // HKDF-SHA512 over the FULL K (size-independent, which is why pairing +
    // cover art already worked). Clamp the copy, not sharedSecret_ (the HKDF
    // keys are already derived).
    ap2_->audioKey = ap2_->sharedSecret;
    if (ap2_->audioKey.size() > 32) ap2_->audioKey.resize(32);  // first 32 B
    ap2_->audioNonce = 0;
    ap2_->encryptAudio = true;

    Dict stream;
    // #90, the realtime stream (type 0x60) is HARDCODED to ALAC on the
    // receiver (shairport-sync rtsp.c: type 96 -> ast_apple_lossless, ct is
    // ignored). We therefore ALAC-encode each packet (see encodeAlacFrame_).
    stream.emplace_back("audioFormat", Value::integer(0x40000));  // ALAC/44100/16/2
    stream.emplace_back("audioMode", Value::str("default"));
    stream.emplace_back("controlPort", Value::integer(transport_.udpLocalPort(controlSock_)));
    stream.emplace_back("ct", Value::integer(2));        // ALAC
    stream.emplace_back("isMedia", Value::boolean(true));
    stream.emplace_back("latencyMax", Value::integer(88200));
    stream.emplace_back("latencyMin", Value::integer(11025));
    stream.emplace_back("shk", Value::bytes(ap2_->audioKey));
    stream.emplace_back("spf", Value::integer(352));     // samples per frame
    stream.emplace_back("sr", Value::integer(44100));
    stream.emplace_back("type", Value::integer(0x60));   // realtime
    stream.emplace_back("supportsDynamicStreamID", Value::boolean(false));
    // owntone/pyatv: streamConnectionID is the numeric RTSP session id (uint),
    // not a separate random string.
    stream.emplace_back("streamConnectionID", Value::integer(int64_t(sessionId_)));
    Array streams;
    streams.push_back(Value::object(std::move(stream)));
    Dict d;
    d.emplace_back("streams", Value::array(std::move(streams)));
    const auto reqBody = airplay::bplist::encode(Value::object(std::move(d)));
    pairStage_ = PairStage::Ap2Stream;
    sendAp2Rtsp_("SETUP", rtspUri_(),
                 "application/x-apple-binary-plist", toStr(reqBody));
}

void RaopSender::handleAp2SetupStream_(const std::string& body) {
    using namespace airplay::bplist;
    auto root = decode(toBytes(body));
    serverPort_ = controlPort_ = 0;
    if (root) {
        if (auto* streams = root->find("streams")) {
            if (streams->type == Value::Type::Arr && !streams->arr.empty()) {
                const Value& s0 = streams->arr.front();
                if (auto* dp = s0.find("dataPort"))    serverPort_  = uint16_t(dp->asInt());
                if (auto* cp = s0.find("controlPort")) controlPort_ = uint16_t(cp->asInt());
            }
        }
    }
    if (serverPort_ == 0) {
        fail_("AirPlay 2 stream SETUP returned no data port");
        return;
    }
    // AP2 has no separate sync 'control_port' on the receiver in the AP1
    // sense; reuse the data path for sync if the receiver didn't give one.
    if (controlPort_ == 0) controlPort_ = serverPort_;
    timingPort_ = serverPort_;   // NTP timing rides the same host
    log_.info("Cast: AirPlay 2 stream SETUP ok, dataPort={} controlPort={}",
              serverPort_, controlPort_);
    // AP2 realtime does NOT use RTSP RECORD, the Apple TV never replies to it
    // (it anchors the timeline via the SYNC/NTP channel). Go straight to
    // streaming; startStreaming_ pushes the initial volume + sync + RTP.
    startStreaming_();
}

// -- per-session audio encryption hook ---------------------------------

std::string RaopSender::encryptAudioPayload_(const std::string& rtpHeader,
                                             const std::string& payload) {
    if (!ap2_ || !ap2_->encryptAudio) return payload;   // AP1 = identity
    // pyatv send_audio_packet: AAD = RTP header bytes 4..12 (8 bytes);
    // nonce = the 8-byte little-endian counter; the 8-byte nonce is
    // appended AFTER the ciphertext+tag.
    const airplay::Bytes nonce8 = airplay::counterNonce8(ap2_->audioNonce);
    airplay::Bytes aad(reinterpret_cast<const uint8_t*>(rtpHeader.data()) + 4,
                       reinterpret_cast<const uint8_t*>(rtpHeader.data()) + 12);
    airplay::Bytes pt(reinterpret_cast<const uint8_t*>(payload.data()),
                      reinterpret_cast<const uint8_t*>(payload.data()) + payload.size());
    airplay::Bytes ct = airplay::chacha20Poly1305Encrypt(
        ap2_->audioKey, nonce8, pt, aad);
    ++ap2_->audioNonce;
    std::string out = toStr(ct);
    out += toStr(nonce8);   // trailing 8-byte nonce
    return out;
}

// -- Streaming -----------------------------------------------------

void RaopSender::onPacerTick_() {
    // Token bucket: frames-on-the-wire must track wall clock at
    // 44100/s (pyatv paces identically off monotonic time). A GUI
    // stall is repaid in bursts, capped so we never flood the LAN,
    // the receiver buffers ~2 s, so a capped catch-up is inaudible.
    const uint64_t elapsedNs = uint64_t(std::chrono::duration_cast<std::chrono::nanoseconds>(
        Clock::now() - clockStart_).count());
    const uint64_t target = elapsedNs * kRaopRate / 1000000000ULL;
    int sentThisTick = 0;
    while (framesSent_ + kFramesPerPacket <= target
           && sentThisTick < kMaxPacketsPerTick) {
        sendAudioPacket_();
        ++sentThisTick;
    }
}

// #90, encode one frame of interleaved s16 stereo PCM as an UNCOMPRESSED ALAC
// frame, which is what a modern Apple TV's realtime path (hardcoded ALAC,
// frameLength 352 / 16-bit / 2ch) decodes. The ALAC bitstream is read MSB-first
// by the receiver (shairport-sync alac.c). Per-frame element layout:
//   3b channel tag = 1 (stereo CPE) . 4b unused=0 . 12b unknown=0 .
//   1b hasSize=0 (use cookie's default 352) . 2b wastedBytes=0 .
//   1b isNotCompressed=1 . then nFrames x {L16,R16} samples MSB-first .
//   3b end tag = 7 . zero-pad to a byte boundary.
std::string RaopSender::encodeAlacFrame_(const int16_t* frames, int nFrames) {
    std::string out;
    out.reserve(nFrames * kChannels * 2 + 8);
    uint8_t cur = 0;
    int filled = 0;   // bits currently in `cur` (0..7)
    auto put = [&](uint32_t value, int bits) {
        for (int i = bits - 1; i >= 0; --i) {
            cur = uint8_t((cur << 1) | ((value >> i) & 1u));
            if (++filled == 8) { out += char(cur); cur = 0; filled = 0; }
        }
    };
    put(1, 3);    // stereo channel-pair element
    put(0, 4);    // unused
    put(0, 12);   // unknown
    put(0, 1);    // hasSize = 0 -> default frame length (352) from the cookie
    put(0, 2);    // wastedBytes = 0
    put(1, 1);    // isNotCompressed = 1 (uncompressed escape)
    for (int i = 0; i < nFrames * kChannels; ++i)
        put(uint16_t(frames[i]), 16);   // 16-bit sample, MSB-first
    put(7, 3);    // END element tag
    if (filled > 0) { cur = uint8_t(cur << (8 - filled)); out += char(cur); }
    return out;
}

void RaopSender::sendAudioPacket_() {
    int16_t frames[kFramesPerPacket * kChannels];
    fillFrames_(frames, kFramesPerPacket);

    // 12-byte RTP header (big-endian, shared by AP1 + AP2).
    std::string header;
    header.reserve(12);
    b8(header, 0x80);
    b8(header, firstAudio_ ? 0xE0 : 0x60);   // marker on the first packet
    be16(header, seq_);
    be32(header, rtptime32_());
    be32(header, sessionId_);                 // SSRC = session id (pyatv)

    // Payload:
    //  - AP2 realtime (type 0x60) is HARDCODED ALAC on the receiver -> send an
    //    uncompressed-ALAC frame (#90).
    //  - AP1 RAOP announces L16 (RFC 3551) -> BIG-endian s16 raw PCM.
    std::string payload;
    if (ap2_ && ap2_->encryptAudio) {
        payload = encodeAlacFrame_(frames, kFramesPerPacket);
    } else {
        payload.reserve(kPayloadBytes);
        for (int i = 0; i < kFramesPerPacket * kChannels; ++i) {
            const uint16_t s = uint16_t(frames[i]);
            payload += char(s >> 8);
            payload += char(s & 0xFF);
        }
    }

    // v0.66.x Phase 3, AP2 receivers get the payload ChaCha20-Poly1305
    // encrypted (AAD = header[4..12], trailing 8-byte nonce). AP1 = identity.
    const std::string wirePayload = encryptAudioPayload_(header, payload);

    std::string pkt = header;
    pkt += wirePayload;
    transport_.udpSendTo(audioSock_, bytesOf(pkt), SockAddr{hostIp_, serverPort_});

    // Retransmit backlog (the receiver asks by seq via type 0x55).
    const int slot = seq_ & (kBacklogSize - 1);
    backlog_[slot] = pkt;
    backlogSeq_[slot] = seq_;

    firstAudio_ = false;
    seq_ = uint16_t(seq_ + 1);
    framesSent_ += kFramesPerPacket;
}

size_t RaopSender::fillFrames_(int16_t* dst, size_t want) {
    const size_t wantSamples = want * kChannels;
    if (!ring_) {
        std::memset(dst, 0, wantSamples * sizeof(int16_t));
        return 0;
    }

    if (inputRate_ == kRaopRate) {
        // Pass-through: pop what's there, pad the rest with silence
        // (player paused / ring priming, the timeline must keep
        // running or the receiver declares the stream dead).
        const size_t availFrames = ring_->availableRead() / kChannels;
        const size_t take = std::min(availFrames, want);
        if (take > 0)
            ring_->tryPop(std::span<int16_t>(dst, take * kChannels));
        if (take < want)
            std::memset(dst + take * kChannels, 0,
                        (want - take) * kChannels * sizeof(int16_t));
        return take;
    }

    // Linear-interpolation resample deviceRate -> 44100. Deliberately
    // simple (two-point lerp): the quality is fine for the cast path
    // and it is allocation-light; a windowed-sinc upgrade is the
    // documented Phase-2 refinement.
    const double step = double(inputRate_) / double(kRaopRate);

    // Top up the staging buffer from the ring (bounded working set).
    size_t bufFrames = inBuf_.size() / kChannels;
    const size_t room = kInBufMaxFrames > bufFrames
                            ? kInBufMaxFrames - bufFrames : 0;
    const size_t ringFrames = ring_->availableRead() / kChannels;
    const size_t pull = std::min(room, ringFrames);
    if (pull > 0) {
        const size_t old = inBuf_.size();
        inBuf_.resize(old + pull * kChannels);
        ring_->tryPop(std::span<int16_t>(inBuf_.data() + old,
                                         pull * kChannels));
        bufFrames += pull;
    }

    size_t produced = 0;
    while (produced < want) {
        const size_t i0 = size_t(srcPhase_);
        if (i0 + 1 >= bufFrames) break;   // need i0 and i0+1, starved
        const double frac = srcPhase_ - double(i0);
        const int16_t* a = inBuf_.data() + i0 * kChannels;
        const int16_t* b = a + kChannels;
        dst[produced * 2 + 0] =
            int16_t(a[0] + (b[0] - a[0]) * frac);
        dst[produced * 2 + 1] =
            int16_t(a[1] + (b[1] - a[1]) * frac);
        srcPhase_ += step;
        ++produced;
    }
    if (produced < want)
        std::memset(dst + produced * kChannels, 0,
                    (want - produced) * kChannels * sizeof(int16_t));

    // Compact: drop fully consumed frames (keep the one at floor(phase),
    // the lerp's left neighbour) and rebase the phase.
    const size_t keepFrom = size_t(srcPhase_);
    if (keepFrom > 0) {
        const size_t drop = std::min(keepFrom, bufFrames);
        inBuf_.erase(inBuf_.begin(),
                     inBuf_.begin() + std::ptrdiff_t(drop * kChannels));
        srcPhase_ -= double(drop);
    }
    return produced;
}

void RaopSender::sendSyncPacket_(bool first) {
    if (serverPort_ == 0 || controlPort_ == 0) return;
    // pyatv ControlClient._sync_task: maps "the frame we just wrote"
    // (head_ts == startTs_+framesSent_) onto NTP wall time; `now` is the
    // latency-shifted RTP time the audio headers carry, and
    // `now_without_latency` is where the receiver should be PLAYING.
    const uint64_t curNtp = ts2ntp(startTs_ + framesSent_, kRaopRate);
    const uint32_t now = rtptime32_();
    std::string pkt;
    pkt.reserve(20);
    b8(pkt, first ? 0x90 : 0x80);   // marker on the first sync
    b8(pkt, 0xD4);                  // type 0x54 | 0x80
    be16(pkt, 0x0007);
    be32(pkt, now - latency_);
    be32(pkt, uint32_t(curNtp >> 32));
    be32(pkt, uint32_t(curNtp & 0xFFFFFFFFULL));
    be32(pkt, now);
    transport_.udpSendTo(controlSock_, bytesOf(pkt), SockAddr{hostIp_, controlPort_});
}

void RaopSender::onControlDatagram_() {
    uint8_t buf[2048];
    SockAddr src;
    int n;
    while ((n = transport_.udpRecvFrom(controlSock_, std::span<uint8_t>(buf, sizeof(buf)), src)) > 0) {
        const std::string dg(reinterpret_cast<const char*>(buf), size_t(n));
        if (dg.size() < 8) continue;
        const uint8_t type = uint8_t(dg[1]) & 0x7F;
        if (type != 0x55) continue;   // only retransmit requests expected
        // RetransmitRequest: lost_seqno u16 @4, lost_packets u16 @6.
        const uint16_t lostSeq =
            uint16_t((uint8_t(dg[4]) << 8) | uint8_t(dg[5]));
        const uint16_t lostCount =
            uint16_t((uint8_t(dg[6]) << 8) | uint8_t(dg[7]));
        for (uint16_t i = 0; i < lostCount; ++i) {
            const uint16_t s = uint16_t(lostSeq + i);
            const int slot = s & (kBacklogSize - 1);
            if (backlogSeq_[slot] != s) continue;   // aged out of backlog
            // pyatv: 0x80 0xD6 + original seq + the FULL original packet.
            std::string resp;
            resp.reserve(4 + backlog_[slot].size());
            b8(resp, 0x80);
            b8(resp, 0xD6);
            be16(resp, s);
            resp += backlog_[slot];
            transport_.udpSendTo(controlSock_, bytesOf(resp), src);
        }
    }
}

void RaopSender::onTimingDatagram_() {
    uint8_t buf[2048];
    SockAddr src;
    int n;
    while ((n = transport_.udpRecvFrom(timingSock_, std::span<uint8_t>(buf, sizeof(buf)), src)) > 0) {
        const std::string dg(reinterpret_cast<const char*>(buf), size_t(n));
        if (dg.size() < 32) continue;   // TimingPacket is 32 bytes
        // pyatv TimingServer.datagram_received: echo the request's
        // sendtime as our reftime; receive + send time = NTP "now"
        // (one wall-clock read is plenty at this precision).
        const uint64_t now = ntpNow_();
        std::string resp;
        resp.reserve(32);
        resp += dg[0];                       // proto byte echoed
        b8(resp, 0xD3);                      // type 0x53 | 0x80
        be16(resp, 0x0007);
        be32(resp, 0);                       // padding
        resp += dg.substr(24, 8);            // reftime = request sendtime
        be32(resp, uint32_t(now >> 32));     // recvtime
        be32(resp, uint32_t(now & 0xFFFFFFFFULL));
        be32(resp, uint32_t(now >> 32));     // sendtime
        be32(resp, uint32_t(now & 0xFFFFFFFFULL));
        transport_.udpSendTo(timingSock_, bytesOf(resp), src);
    }
}

} // namespace fxchain
