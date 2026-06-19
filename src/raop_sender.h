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
// pacing: a precise ~16 ms timer ticks a token bucket so frames-on-the-wire
// track wall clock at 44100/s (pyatv paces the same way off NTP); when the tap
// runs dry (player paused) we push silence to keep the receiver's timeline
// alive. audio is pulled from a lock-free spsc ring the host's audio thread
// feeds (see ring_buffer.h).
//
// clean-room: the protocol was reconstructed from pyatv / owntone /
// shairport-sync / emanuelecozzi's AP2 notes as a SPEC -- not a line of their
// code is here. see README + the .cpp for the per-section attribution.
//
// STATUS (honest): lifted out of FXChainPlayer, where it casts to a real apple
// tv 4K + a macbook daily. the networking here is still Qt (`QTcpSocket` /
// `QUdpSocket` / `QTimer`) and it pulls one host enum (`RaopDeviceInfo::Auth`
// from mdns_discovery.h). the Qt-free socket interface + a CLI demo are the
// roadmap (ROADMAP.md). the crypto half (airplay_crypto.*) already stands
// alone today.

#include <QElapsedTimer>
#include <QHash>
#include <QHostAddress>
#include <QList>
#include <QObject>
#include <QPair>
#include <QString>
#include <QTcpSocket>
#include <QTimer>
#include <QUdpSocket>

#include <cstdint>
#include <memory>
#include <vector>

#include "mdns_discovery.h"   // RaopDeviceInfo::Auth

namespace fxchain {

template <typename T> class RingBuffer;

// v0.66.x Phase 2/3, opaque pairing/crypto state lives in the .cpp so the
// header stays free of the airplay_crypto includes (the SrpClient / ChaCha
// cipher state). Forward-declared here.
struct RaopAp2State;

class RaopSender : public QObject {
    Q_OBJECT
public:
    explicit RaopSender(QObject* parent = nullptr);
    ~RaopSender() override;

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
                 const QByteArray& deviceId, const QString& credsJson,
                 const QString& password);

    // Connect + handshake + stream. One session at a time.
    void start(const QString& host, quint16 port, const QString& name);
    void stop();   // TEARDOWN + close
    bool active() const { return state_ != State::Idle; }

    // v0.66.x Phase 2, supply the on-screen PIN the user typed (drives the
    // legacy/HAP PIN pairing). Only meaningful while waitingForPin() is true.
    void submitPin(const QString& code);
    bool waitingForPin() const { return waitingForPin_; }

    // Receiver volume, 0..100 % → AirPlay dBFS (-30..0; 0 % = -144 mute,
    // the pyatv pct_to_dbfs mapping). Not sent automatically at start so
    // the receiver keeps its own current volume.
    void setVolume(double pct);

    // Now-playing metadata pushed to the receiver via DMAP-tagged
    // SET_PARAMETER (title/artist/album) + the cover as image/jpeg|png.
    // Stored when not streaming and (re)sent on the next RECORD; sent
    // immediately on a track change while streaming. `cover`/`coverMime`
    // may be empty (no artwork sent then).
    void setNowPlaying(const QString& title, const QString& artist,
                       const QString& album,
                       const QByteArray& cover = {},
                       const QByteArray& coverMime = {});

signals:
    void launched(bool ok, const QString& error);  // RECORD accepted / failed
    void closed();                                  // session ended
    // v0.66.x Phase 2, the receiver shows a PIN; the UI must collect 4
    // digits and call submitPin(). `deviceName` is the friendly name.
    void pinRequired(const QString& deviceName);
    // v0.66.x Phase 2, a successful FIRST pairing produced long-term
    // credentials the bridge should persist for this device id (so later
    // connects skip the PIN). `credsJson` is opaque to the bridge.
    void credentialsObtained(const QByteArray& deviceId,
                             const QString& credsJson);

private:
    // v0.66.x, the handshake now has a pairing phase between Connecting
    // and the audio Setup/Record chain.
    enum class State { Idle, Connecting, Pairing, Handshake, Streaming };

    // RTSP plumbing (plain-text request/response over one TCP socket;
    // requests are answered in order, so a method FIFO routes replies).
    void sendRequest_(const QByteArray& method, const QByteArray& uri,
                      const QByteArray& contentType, const QByteArray& body,
                      const QList<QPair<QByteArray, QByteArray>>& extra = {});
    QByteArray rtspUri_() const;
    // Write to the RTSP socket, ChaCha20-Poly1305-framing the bytes when the
    // AP2 control channel is encrypted (post pair-verify); plaintext otherwise.
    void writeRtsp_(const QByteArray& data);
    void onEventReadyRead_();   // #90/#109 decrypt + 200-OK the event channel
    void onRtspReadyRead_();
    void handleResponse_(const QByteArray& method, int code,
                         const QHash<QByteArray, QByteArray>& headers);
    void fail_(const QString& why);

    // Handshake steps
    void sendOptions_();
    void sendAnnounce_();
    void sendSetup_();
    void sendRecord_();
    void startStreaming_();

    // ── v0.66.x Phase 2/3, auth + AP2 ───────────────────────────────
    // After TCP connect, run the auth/pairing chain; on success continue
    // to the audio Setup/Record (AP1) or the AP2 bplist SETUP path.
    void beginAuthChain_();
    void onPairingResponse_(int code,
                            const QHash<QByteArray, QByteArray>& headers,
                            const QByteArray& body);
    void afterAuthOk_();          // → AP1 ANNOUNCE or AP2 SETUP
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
    void sendPairSetupM3_(const QString& pin);
    void sendPairSetupM5_();
    void sendPairVerifyM1_();
    void handlePairSetupM2_(const QByteArray& body);
    void handlePairSetupM4_(const QByteArray& body);
    void handlePairSetupM6_(const QByteArray& body);
    void handlePairVerifyM2_(const QByteArray& body);
    // AP2 binary-plist SETUP (session + stream) and RECORD.
    void sendAp2Info_();
    // AP2 SETUP/RECORD etc. are RTSP methods on the rtsp://host/sessionId URI
    // (NOT a POST /setup path, that 404s), but their replies carry a
    // binary-plist body, so they route through the body-capturing pairing
    // dispatcher (pendingIsHttp_=true) just like the pairing POSTs.
    void sendAp2Rtsp_(const QByteArray& method, const QByteArray& uri,
                      const QByteArray& contentType, const QByteArray& body);
    void sendAp2SetupSession_();
    void handleAp2SetupSession_(const QByteArray& body);
    void sendAp2Record_();   // #90 RECORD between session + stream SETUP
    void sendAp2SetupStream_();
    void handleAp2SetupStream_(const QByteArray& body);
    // Generic HTTP POST over the RTSP socket (pairing + AP2 plists). The
    // reply is routed to onPairingResponse_ via the pending-method FIFO.
    void httpPost_(const QByteArray& uri, const QByteArray& contentType,
                   const QByteArray& body);
    // The per-session audio encryptor (AP2 ChaCha20-Poly1305; identity for
    // AP1). Hooked into sendAudioPacket_.
    QByteArray encryptAudioPayload_(const QByteArray& rtpHeader,
                                    const QByteArray& payload);

    // Streaming
    void onPacerTick_();
    void sendAudioPacket_();
    QByteArray encodeAlacFrame_(const int16_t* frames, int nFrames);   // #90 ALAC                       // one 352-frame packet
    size_t fillFrames_(int16_t* dst, size_t want); // ring → 44.1 kHz frames
    void sendSyncPacket_(bool first);
    void onControlDatagram_();                     // retransmit requests
    void onTimingDatagram_();                      // timing requests
    quint32 rtptime32_() const;                    // current RTP timestamp
    // Push DMAP now-playing metadata + cover via SET_PARAMETER (AP1+AP2).
    void sendMetadata_();

    static quint64 ntpNow_();                      // 64-bit NTP wall time

    // ── RTSP session ─────────────────────────────────────────────
    QTcpSocket rtsp_;
    QByteArray rxBuf_;
    // AirPlay 2 encrypted control channel (#90). After HAP pair-verify the
    // RTSP/HTTP control connection is ChaCha20-Poly1305 framed: every write is
    // [2-byte LE len][cipher][16-byte tag] chunked at 1024 B, keyed with the
    // Control-Write key + an 8-byte LE per-frame counter; reads use the
    // Control-Read key + an independent counter. rtspEncBuf_ accumulates raw
    // (still-encrypted) bytes until a whole frame is present to decrypt.
    bool       controlEncrypted_ = false;
    quint64    ctrlSendCtr_ = 0;
    quint64    ctrlRecvCtr_ = 0;
    QByteArray rtspEncBuf_;
    // #90/#109, AP2 event channel (encrypted, same HomeKit frame format as the
    // control channel but keyed with the Events keys + its own counters). The
    // receiver pushes RTSP requests we must decrypt and answer "200 OK" or it
    // tears down the session at ~25 s.
    quint64    eventSendCtr_ = 0;
    quint64    eventRecvCtr_ = 0;
    QByteArray eventEncBuf_;     // raw (still-encrypted) bytes from the receiver
    QByteArray eventPlainBuf_;   // decrypted RTSP request stream
    QList<QByteArray> pendingMethods_;   // FIFO: request → response routing
    int        cseq_ = 0;
    quint32    sessionId_ = 0;           // RTSP URI id; doubles as RTP SSRC
    QByteArray dacpId_;                  // DACP-ID / Client-Instance header
    quint32    activeRemote_ = 0;
    QByteArray rtspSession_;             // Session: header from SETUP
    QString    host_, name_;
    QHostAddress hostAddr_;
    State      state_ = State::Idle;

    // #90, AP2 event channel: a modern Apple TV requires an (encrypted) TCP
    // connection to the session-SETUP `eventPort` to be OPEN before it will
    // accept RECORD. We don't transmit on it, the receiver pushes play/pause
    // events we ignore, so a plain connected socket satisfies the prerequisite.
    QTcpSocket eventSock_;

    // ── UDP transport ────────────────────────────────────────────
    QUdpSocket audioSock_;     // → receiver server_port (RTP audio)
    QUdpSocket controlSock_;   // → receiver control_port (sync); ←
                               //   retransmit requests on OUR port
    QUdpSocket timingSock_;    // ← timing requests on OUR port
    quint16    serverPort_  = 0;   // receiver's, from SETUP Transport
    quint16    controlPort_ = 0;
    quint16    timingPort_  = 0;

    // ── stream clock / RTP state ─────────────────────────────────
    QTimer        pacer_;        // 8 ms precise, token-bucket sender
    QTimer        syncTimer_;    // 1 Hz sync packets
    QTimer        timeout_;      // handshake watchdog
    QTimer        pinTimeout_;   // on-screen-PIN wait watchdog (user-driven)
    QTimer        feedbackTimer_;// 25 s /feedback keep-alive (if supported)
    QElapsedTimer clock_;        // monotonic pacing reference
    quint64  startTs_ = 0;       // NTP-derived start timestamp (pyatv model)
    quint64  framesSent_ = 0;    // 44.1 kHz frames put on the wire
    quint32  latency_ = 22050 + 44100;   // fixed RAOP latency (pyatv)
    quint16  seq_ = 0;           // RTP sequence number
    bool     firstAudio_ = true; // marker bit on the first audio packet
    double   pendingVolumeDb_ = kNoVolume;   // setVolume before RECORD

    // ── input conditioning (device rate → 44.1 kHz) ──────────────
    RingBuffer<int16_t>* ring_ = nullptr;
    uint32_t inputRate_ = 44100;
    std::vector<int16_t> inBuf_;   // unconsumed input samples (interleaved)
    size_t   inReadFrames_ = 0;    // consumed frames at inBuf_'s front
    double   srcPhase_ = 0.0;      // fractional input-frame position

    // ── retransmit backlog (last 1024 packets, slot = seq & 0x3FF) ─
    std::vector<QByteArray> backlog_;
    std::vector<qint32>     backlogSeq_;

    QString    npTitle_, npArtist_, npAlbum_;   // now-playing metadata
    QByteArray npCover_, npCoverMime_;          // cover art bytes + MIME

    // ── v0.66.x Phase 2/3, auth + AP2 state ─────────────────────────
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
    bool       airplay2_   = false;
    QByteArray deviceId_;        // mDNS instance id (creds key)
    QString    credsJson_;       // stored long-term creds (empty = first pair)
    QString    digestPassword_;  // pw=true RTSP digest password
    bool       waitingForPin_ = false;
    // One-shot: a Mac-style receiver 403s /pair-pin-start (Macs don't show an
    // on-screen AirPlay PIN), we then try PIN-less transient pairing once.
    bool       triedTransientAfterPin403_ = false;
    // SRP exchange scratch (server salt + B captured at M2 for M3).
    QByteArray srpSalt_, srpServerB_;
    // The HKDF(Pair-Setup-Encrypt) key, stashed at M5 to decrypt M6.
    std::vector<uint8_t> pairSetupSessionKey_;

    // The pairing/crypto state (SrpClient, ChaCha ciphers, X25519/Ed25519
    // keys, the derived control + shared keys). Heap-held so the header
    // never pulls in airplay_crypto.h.
    std::unique_ptr<RaopAp2State> ap2_;

    // HTTP-over-RTSP-socket reply routing (pairing + AP2 plists). When a
    // POST is in flight we capture its body and dispatch to the pairing
    // handlers instead of the RTSP handlers.
    bool       inHttpMode_ = false;     // current pending reply is HTTP not RTSP
    QList<bool> pendingIsHttp_;         // parallel to pendingMethods_

    // RTSP digest-auth retry state (pw=true): on a 401 we capture the
    // realm+nonce and re-send the failed request with an Authorization
    // header exactly once.
    QByteArray digestRealm_, digestNonce_;
    QByteArray pendingDigestMethod_, pendingDigestUri_;
    bool       digestRetried_ = false;

    static constexpr double kNoVolume = -1000.0;
};

} // namespace fxchain
