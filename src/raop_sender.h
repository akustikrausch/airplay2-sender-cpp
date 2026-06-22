// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// raop_sender.h -- the airplay sender state machine. this IS the recipe.
// ----------------------------------------------------------------------------
// RAOP is a PUSH protocol. you don't hand the receiver a url like google cast;
// you drive the whole transport yourself. this class does both eras:
//
//   AirPlay 1 (the old, unencrypted way -- shairport-sync, apple tv 3, raop
//   speakers/avrs): plain RTSP OPTIONS -> ANNOUNCE (SDP L16/44100/2, 352
//   frames/packet) -> SETUP -> RECORD -> [SET_PARAMETER volume] -> TEARDOWN,
//   with the audio as RTP type 0x60 (big-endian L16), a 1 Hz SYNC mapping the
//   RTP timeline onto NTP wall time, our own timing + retransmit udp servers.
//
//   AirPlay 2 realtime (the modern apple tv 4K / homepod / macOS path -- the
//   one nobody published): HAP pairing, then EVERYTHING rides an encrypted
//   ChaCha20-Poly1305 RTSP control channel, the `SETUP rtsp://host/sessionId`
//   METHOD, an event channel opened before RECORD, a HARDCODED-ALAC realtime
//   stream, and a ~30 s keep-alive that IS the encrypted event channel. the
//   full seven-step order -- and the pair-verify-vs-transient audio-key story
//   that decides between "plays" and "shows the cover and is silent" -- is in
//   the README. this file is that recipe written as a state machine.
//
// pacing: a precise ~8 ms timer ticks a token bucket so frames-on-the-wire
// track wall clock at 44100/s (pyatv paces the same way off NTP); when the tap
// runs dry (player paused) we push silence to keep the receiver's timeline
// alive. audio is pulled from a lock-free spsc ring the host's audio thread
// feeds (see ring_buffer.h).
//
// clean-room: the protocol was reconstructed from pyatv / owntone /
// shairport-sync / emanuelecozzi's AP2 notes as a SPEC -- not a line of their
// code is here. see README + the .cpp for the per-section attribution.
//
// transport: networking + timers go through ITransport (see itransport.h), so
// the sender is plain C++ + airplay_crypto. the default PollTransport is a
// poll()/select() loop with no Qt; a host that already runs Qt can pass a
// QtTransport instead. discovery + the auth enum used to live in a host header
// (mdns_discovery.h); the enum is inlined in raop_device_auth.h and the caller
// passes an already-resolved host + the matching Auth value to setAuth().

#include "itransport.h"
#include "logging.h"
#include "raop_device_auth.h"

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace fxchain {

template <typename T> class RingBuffer;

// v0.66.x Phase 2/3, opaque pairing/crypto state lives in the .cpp so the
// header stays free of the airplay_crypto includes (the SrpClient / ChaCha
// cipher state). Forward-declared here.
struct RaopAp2State;

class RaopSender {
public:
    // Callbacks that replace the old Qt signals. All fire from the transport's
    // run loop (or the host's Qt event loop for the Qt adapter); they must not
    // block. Any may be left empty.
    using LaunchedCb = std::function<void(bool ok, std::string error)>;       // RECORD accepted / failed
    using ClosedCb   = std::function<void()>;                                 // session ended
    // The receiver shows a PIN; the host collects 4 digits and calls
    // submitPin(). `deviceName` is the friendly name.
    using PinRequiredCb = std::function<void(std::string deviceName)>;
    // A successful FIRST pairing produced long-term credentials the host should
    // persist for this device id (so later connects skip the PIN). `credsJson`
    // is opaque to the host.
    using CredsCb = std::function<void(std::string deviceId, std::string credsJson)>;

    // `transport` and the callbacks are borrowed; the transport must outlive
    // this object. Pass an empty `log` to silence logging.
    RaopSender(ITransport& transport, LogSink log,
               LaunchedCb onLaunched, ClosedCb onClosed,
               PinRequiredCb onPinRequired, CredsCb onCredsObtained);
    ~RaopSender();

    RaopSender(const RaopSender&) = delete;
    RaopSender& operator=(const RaopSender&) = delete;

    // The engine's network-tap ring (16-bit interleaved stereo at the
    // DEVICE sample rate). Same attach pattern as PcmStreamServer.
    void attachRing(RingBuffer<int16_t>* ring) { ring_ = ring; }

    // Sample rate of the PCM in the ring (engine device rate). 44100
    // passes through; anything else is linear-resampled to 44100.
    void setInputFormat(uint32_t sampleRate);

    // v0.66.x Phase 2/3, describe how the receiver must be reached BEFORE
    // start(). `auth` selects auth-setup / legacy-PIN / HAP-transient /
    // HAP-PIN / password / none; `airplay2` switches to the encrypted AP2
    // transport (bplist SETUP + ChaCha20 audio). `credsJson` carries stored
    // long-term credentials for a device we've paired before (empty = first
    // pairing). `password` is the RTSP digest password for pw=true devices.
    void setAuth(RaopDeviceInfo::Auth auth, bool airplay2,
                 const std::string& deviceId, const std::string& credsJson,
                 const std::string& password);

    // Connect + handshake + stream. One session at a time.
    void start(const std::string& host, uint16_t port, const std::string& name);
    void stop();   // TEARDOWN + close
    bool active() const { return state_ != State::Idle; }

    // v0.66.x Phase 2, supply the on-screen PIN the user typed (drives the
    // legacy/HAP PIN pairing). Only meaningful while waitingForPin() is true.
    void submitPin(const std::string& code);
    bool waitingForPin() const { return waitingForPin_; }

    // Receiver volume, 0..100 % -> AirPlay dBFS (-30..0; 0 % = -144 mute,
    // the pyatv pct_to_dbfs mapping). Not sent automatically at start so
    // the receiver keeps its own current volume.
    void setVolume(double pct);

    // Now-playing metadata pushed to the receiver via DMAP-tagged
    // SET_PARAMETER (title/artist/album) + the cover as image/jpeg|png.
    // Stored when not streaming and (re)sent on the next RECORD; sent
    // immediately on a track change while streaming. `cover`/`coverMime`
    // may be empty (no artwork sent then).
    void setNowPlaying(const std::string& title, const std::string& artist,
                       const std::string& album,
                       const std::string& cover = {},
                       const std::string& coverMime = {});

private:
    // v0.66.x, the handshake now has a pairing phase between Connecting
    // and the audio Setup/Record chain.
    enum class State { Idle, Connecting, Pairing, Handshake, Streaming };

    // RTSP plumbing (plain-text request/response over one TCP socket;
    // requests are answered in order, so a method FIFO routes replies).
    void sendRequest_(const std::string& method, const std::string& uri,
                      const std::string& contentType, const std::string& body,
                      const std::vector<std::pair<std::string, std::string>>& extra = {});
    std::string rtspUri_() const;
    // Write to the RTSP socket, ChaCha20-Poly1305-framing the bytes when the
    // AP2 control channel is encrypted (post pair-verify); plaintext otherwise.
    void writeRtsp_(const std::string& data);
    void onEventReadyRead_();   // #90/#109 decrypt + 200-OK the event channel
    void onRtspReadyRead_();
    void handleResponse_(const std::string& method, int code,
                         const std::unordered_map<std::string, std::string>& headers);
    void fail_(const std::string& why);

    // Handshake steps
    void sendOptions_();
    void sendAnnounce_();
    void sendSetup_();
    void sendRecord_();
    void startStreaming_();

    // -- v0.66.x Phase 2/3, auth + AP2 --------------------------------
    // After TCP connect, run the auth/pairing chain; on success continue
    // to the audio Setup/Record (AP1) or the AP2 bplist SETUP path.
    void beginAuthChain_();
    void onPairingResponse_(int code,
                            const std::unordered_map<std::string, std::string>& headers,
                            const std::string& body);
    void afterAuthOk_();          // -> AP1 ANNOUNCE or AP2 SETUP
    // auth-setup (MFiSAP), one POST, response ignored.
    void sendAuthSetup_();
    // HAP transient / PIN pair-setup state machine (M1..M6) + pair-verify.
    // v0.66.x, POST /pair-pin-start (header X-Apple-HKP: 3) BEFORE M1 on the
    // on-screen-PIN path. This is the request that makes a tvOS Apple TV
    // render its 4-digit code (owntone payload_make_pin_start / pyatv
    // start_pairing both do this). Without it the device silently returns
    // M2 (salt+B) and the user waits for a code that never appears.
    void sendPairPinStart_();
    void sendPairSetupM1_();
    void sendPairSetupM3_(const std::string& pin);
    void sendPairSetupM5_();
    void sendPairVerifyM1_();
    void handlePairSetupM2_(const std::string& body);
    void handlePairSetupM4_(const std::string& body);
    void handlePairSetupM6_(const std::string& body);
    void handlePairVerifyM2_(const std::string& body);
    // AP2 binary-plist SETUP (session + stream) and RECORD.
    void sendAp2Info_();
    // AP2 SETUP/RECORD etc. are RTSP methods on the rtsp://host/sessionId URI
    // (NOT a POST /setup path, that 404s), but their replies carry a
    // binary-plist body, so they route through the body-capturing pairing
    // dispatcher (pendingIsHttp_=true) just like the pairing POSTs.
    void sendAp2Rtsp_(const std::string& method, const std::string& uri,
                      const std::string& contentType, const std::string& body);
    void sendAp2SetupSession_();
    void handleAp2SetupSession_(const std::string& body);
    void sendAp2Record_();   // #90 RECORD between session + stream SETUP
    void sendAp2SetupStream_();
    void handleAp2SetupStream_(const std::string& body);
    // Generic HTTP POST over the RTSP socket (pairing + AP2 plists). The
    // reply is routed to onPairingResponse_ via the pending-method FIFO.
    void httpPost_(const std::string& uri, const std::string& contentType,
                   const std::string& body);
    // The per-session audio encryptor (AP2 ChaCha20-Poly1305; identity for
    // AP1). Hooked into sendAudioPacket_.
    std::string encryptAudioPayload_(const std::string& rtpHeader,
                                     const std::string& payload);

    // Streaming
    void onPacerTick_();
    void sendAudioPacket_();
    std::string encodeAlacFrame_(const int16_t* frames, int nFrames);   // #90 ALAC, one 352-frame packet
    size_t fillFrames_(int16_t* dst, size_t want); // ring -> 44.1 kHz frames
    void sendSyncPacket_(bool first);
    void onControlDatagram_();                     // retransmit requests
    void onTimingDatagram_();                      // timing requests
    uint32_t rtptime32_() const;                   // current RTP timestamp
    // Push DMAP now-playing metadata + cover via SET_PARAMETER (AP1+AP2).
    void sendMetadata_();

    static uint64_t ntpNow_();                     // 64-bit NTP wall time

    // -- collaborators (borrowed) -------------------------------------
    ITransport& transport_;
    Logger      log_;
    LaunchedCb    onLaunched_;
    ClosedCb      onClosed_;
    PinRequiredCb onPinRequired_;
    CredsCb       onCredsObtained_;

    // -- RTSP session -------------------------------------------------
    SockHandle rtspSock_ = kInvalidSock;
    bool       rtspConnected_ = false;   // tracks QAbstractSocket::ConnectedState
    std::string rxBuf_;
    // AirPlay 2 encrypted control channel (#90). After HAP pair-verify the
    // RTSP/HTTP control connection is ChaCha20-Poly1305 framed: every write is
    // [2-byte LE len][cipher][16-byte tag] chunked at 1024 B, keyed with the
    // Control-Write key + an 8-byte LE per-frame counter; reads use the
    // Control-Read key + an independent counter. rtspEncBuf_ accumulates raw
    // (still-encrypted) bytes until a whole frame is present to decrypt.
    bool        controlEncrypted_ = false;
    uint64_t    ctrlSendCtr_ = 0;
    uint64_t    ctrlRecvCtr_ = 0;
    std::string rtspEncBuf_;
    // #90/#109, AP2 event channel (encrypted, same HomeKit frame format as the
    // control channel but keyed with the Events keys + its own counters). The
    // receiver pushes RTSP requests we must decrypt and answer "200 OK" or it
    // tears down the session at ~25 s.
    uint64_t    eventSendCtr_ = 0;
    uint64_t    eventRecvCtr_ = 0;
    std::string eventEncBuf_;     // raw (still-encrypted) bytes from the receiver
    std::string eventPlainBuf_;   // decrypted RTSP request stream
    std::deque<std::string> pendingMethods_;   // FIFO: request -> response routing
    int         cseq_ = 0;
    uint32_t    sessionId_ = 0;          // RTSP URI id; doubles as RTP SSRC
    std::string dacpId_;                 // DACP-ID / Client-Instance header
    uint32_t    activeRemote_ = 0;
    std::string rtspSession_;            // Session: header from SETUP
    std::string host_, name_;
    std::string hostIp_;                 // resolved receiver IPv4 (dotted-quad)
    State       state_ = State::Idle;

    // #90, AP2 event channel: a modern Apple TV requires an (encrypted) TCP
    // connection to the session-SETUP `eventPort` to be OPEN before it will
    // accept RECORD. We don't transmit on it, the receiver pushes play/pause
    // events we ignore, so a plain connected socket satisfies the prerequisite.
    SockHandle eventSock_ = kInvalidSock;

    // -- UDP transport ------------------------------------------------
    SockHandle audioSock_   = kInvalidSock;  // -> receiver server_port (RTP audio)
    SockHandle controlSock_ = kInvalidSock;  // -> receiver control_port (sync); <-
                                             //   retransmit requests on OUR port
    SockHandle timingSock_  = kInvalidSock;  // <- timing requests on OUR port
    uint16_t   serverPort_  = 0;             // receiver's, from SETUP Transport
    uint16_t   controlPort_ = 0;
    uint16_t   timingPort_  = 0;

    // -- stream clock / RTP state -------------------------------------
    using Clock = std::chrono::steady_clock;
    TimerHandle pacerTimer_    = kInvalidTimer;  // 8 ms precise, token-bucket sender
    TimerHandle syncTimer_     = kInvalidTimer;  // 1 Hz sync packets
    TimerHandle timeoutTimer_  = kInvalidTimer;  // handshake watchdog
    TimerHandle pinTimer_      = kInvalidTimer;  // on-screen-PIN wait watchdog (user-driven)
    TimerHandle feedbackTimer_ = kInvalidTimer;  // /feedback keep-alive (if supported)
    // 0 ms one-shot, defers a connect-init failure so start() never fires a
    // callback synchronously (QTcpSocket::connectToHost was always async).
    TimerHandle deferredFailTimer_ = kInvalidTimer;
    bool        feedbackActive_ = false;         // replaces QTimer::isActive()
    Clock::time_point clockStart_;               // monotonic pacing reference
    uint64_t startTs_ = 0;       // NTP-derived start timestamp (pyatv model)
    uint64_t framesSent_ = 0;    // 44.1 kHz frames put on the wire
    uint32_t latency_ = 22050 + 44100;   // fixed RAOP latency (pyatv)
    uint16_t seq_ = 0;           // RTP sequence number
    bool     firstAudio_ = true; // marker bit on the first audio packet
    double   pendingVolumeDb_ = kNoVolume;   // setVolume before RECORD

    // -- input conditioning (device rate -> 44.1 kHz) -----------------
    RingBuffer<int16_t>* ring_ = nullptr;
    uint32_t inputRate_ = 44100;
    std::vector<int16_t> inBuf_;   // unconsumed input samples (interleaved)
    size_t   inReadFrames_ = 0;    // consumed frames at inBuf_'s front
    double   srcPhase_ = 0.0;      // fractional input-frame position

    // -- retransmit backlog (last 1024 packets, slot = seq & 0x3FF) ---
    std::vector<std::string> backlog_;
    std::vector<int32_t>     backlogSeq_;

    std::string npTitle_, npArtist_, npAlbum_;   // now-playing metadata
    std::string npCover_, npCoverMime_;          // cover art bytes + MIME

    // -- v0.66.x Phase 2/3, auth + AP2 state --------------------------
    // The pairing sub-state machine: which reply the next HTTP POST's
    // response corresponds to (the wire has no method tag we can rely on).
    enum class PairStage {
        None, AuthSetup,
        // v0.66.x, /pair-pin-start (HKP mode 3) precedes M1 on the on-screen
        // PIN path; it is what makes the Apple TV DISPLAY its 4-digit code.
        PinStart,
        SetupM2, SetupM4, SetupM6,
        VerifyM2, VerifyDone,
        Ap2Info, Ap2Session, Ap2Record, Ap2Stream,
        Done,
    };
    PairStage  pairStage_ = PairStage::None;
    RaopDeviceInfo::Auth authMethod_ = RaopDeviceInfo::Auth::None;
    bool        airplay2_   = false;
    std::string deviceId_;       // mDNS instance id (creds key)
    std::string credsJson_;      // stored long-term creds (empty = first pair)
    std::string digestPassword_; // pw=true RTSP digest password
    bool        waitingForPin_ = false;
    // One-shot: a Mac-style receiver 403s /pair-pin-start (Macs don't show an
    // on-screen AirPlay PIN), we then try PIN-less transient pairing once.
    bool        triedTransientAfterPin403_ = false;
    // SRP exchange scratch (server salt + B captured at M2 for M3).
    std::string srpSalt_, srpServerB_;
    // The HKDF(Pair-Setup-Encrypt) key, stashed at M5 to decrypt M6.
    std::vector<uint8_t> pairSetupSessionKey_;

    // The pairing/crypto state (SrpClient, ChaCha ciphers, X25519/Ed25519
    // keys, the derived control + shared keys). Heap-held so the header
    // never pulls in airplay_crypto.h.
    std::unique_ptr<RaopAp2State> ap2_;

    // HTTP-over-RTSP-socket reply routing (pairing + AP2 plists). When a
    // POST is in flight we capture its body and dispatch to the pairing
    // handlers instead of the RTSP handlers.
    bool        inHttpMode_ = false;     // current pending reply is HTTP not RTSP
    std::deque<bool> pendingIsHttp_;     // parallel to pendingMethods_

    // RTSP digest-auth retry state (pw=true): on a 401 we capture the
    // realm+nonce and re-send the failed request with an Authorization
    // header exactly once.
    std::string digestRealm_, digestNonce_;
    std::string pendingDigestMethod_, pendingDigestUri_;
    bool        digestRetried_ = false;

    static constexpr double kNoVolume = -1000.0;
};

} // namespace fxchain
