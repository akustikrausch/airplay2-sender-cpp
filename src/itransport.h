// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// itransport.h -- the Qt-free networking seam for the AirPlay sender.
// ----------------------------------------------------------------------------
// RaopSender used to talk to Qt directly (QTcpSocket / QUdpSocket / QTimer).
// ITransport is the small interface that dependency drops behind, so the
// sender becomes plain C++ + airplay_crypto and the only thing that knows
// about a concrete socket/timer backend is one adapter.
//
// two adapters ship:
//   * PollTransport  -- the default, a portable poll()/WSAPoll() loop, zero Qt.
//   * QtTransport     -- optional (off by default), for hosts that already run
//                        a Qt event loop (the original FXChainPlayer).
//
// the model is single-threaded and callback-driven, exactly like the Qt
// version was: the sender registers read / connect / timer callbacks and the
// adapter's run loop fires them. the ONLY cross-thread boundary is the audio
// ring buffer the host feeds (see ring_buffer.h), unchanged by this seam.

#include <cstdint>
#include <functional>
#include <span>
#include <string>

namespace fxchain {

// opaque integer handles into the backend. one space for tcp + udp sockets so
// a raw-fd backend needs no per-type bookkeeping. kInvalid* are the sentinels.
using SockHandle  = int;
using TimerHandle = int;
inline constexpr SockHandle  kInvalidSock  = -1;
inline constexpr TimerHandle kInvalidTimer = -1;

// an IPv4 endpoint (AirPlay is IPv4 in practice; the receiver is reached by a
// dotted-quad mDNS address). `ip` is dotted-decimal, e.g. "192.168.1.20".
struct SockAddr {
    std::string ip;
    uint16_t    port = 0;
};

class ITransport {
public:
    virtual ~ITransport() = default;

    // ── TCP ───────────────────────────────────────────────────────────
    // start a non-blocking connect and return a handle immediately, BEFORE
    // the connection completes (mirrors QTcpSocket::connectToHost). the
    // onTcpConnected callback fires later, from the run loop, with ok. on a
    // setup error (e.g. getaddrinfo) returns kInvalidSock.
    virtual SockHandle tcpConnect(const std::string& host, uint16_t port) = 0;
    // ok=false means the connect failed (SO_ERROR != 0). guaranteed to fire
    // from inside the run loop, never synchronously from tcpConnect, so the
    // caller can register every callback before the first event is delivered.
    virtual void onTcpConnected(SockHandle, std::function<void(bool ok)>) = 0;
    // queue bytes for sending; the adapter buffers any unwritten remainder
    // and drains it as the socket becomes writable (mirrors Qt's write()).
    // returns the number of bytes accepted, or -1 on a fatal error.
    virtual int  tcpSend(SockHandle, std::span<const uint8_t> data) = 0;
    // non-blocking read into buf: >0 bytes read, 0 if the peer closed (EOF),
    // -1 if nothing is pending right now or on error. loop from onTcpReadable
    // while it returns > 0; an EOF additionally drives onTcpDisconnected.
    virtual int  tcpRecv(SockHandle, std::span<uint8_t> buf) = 0;
    virtual void onTcpReadable(SockHandle, std::function<void()>) = 0;
    // the peer closed the connection (mirrors QTcpSocket::disconnected).
    virtual void onTcpDisconnected(SockHandle, std::function<void()>) = 0;
    // a socket-level error; the string is a human-readable description
    // (mirrors errorOccurred + errorString).
    virtual void onTcpError(SockHandle, std::function<void(std::string)>) = 0;
    // graceful shutdown: flush queued bytes, send FIN, then close once the
    // peer FINs or a short watchdog elapses (mirrors disconnectFromHost +
    // waitForDisconnected, but without blocking the loop).
    virtual void tcpDisconnect(SockHandle) = 0;
    // hard close now (mirrors abort()). safe on kInvalidSock.
    virtual void tcpClose(SockHandle) = 0;
    // the local address of a connected socket, as the receiver sees us. used
    // to build the rtsp:// URI and the SDP o=/c= lines. {"",0} if unknown.
    virtual SockAddr tcpLocalAddr(SockHandle) = 0;

    // ── UDP ───────────────────────────────────────────────────────────
    // bind a udp socket to all IPv4 interfaces on an ephemeral port (the OS
    // picks when port_hint is 0). kInvalidSock on error.
    virtual SockHandle udpBind(uint16_t port_hint = 0) = 0;
    // the OS-assigned local port, advertised to the receiver in the RTSP
    // SETUP Transport header (control_port=/timing_port=) and the AP2 plist.
    virtual uint16_t udpLocalPort(SockHandle) = 0;
    // send a datagram to an explicit destination. the audio/sync packets go
    // to the receiver's port; retransmit + NTP timing replies go back to the
    // DYNAMIC source captured by udpRecvFrom, not a pre-known peer.
    virtual int  udpSendTo(SockHandle, std::span<const uint8_t> data,
                           const SockAddr& dest) = 0;
    // receive one datagram and report its source in src_out. bytes read, 0 if
    // none pending, -1 on error. loop until <= 0 from onUdpReadable.
    virtual int  udpRecvFrom(SockHandle, std::span<uint8_t> buf,
                             SockAddr& src_out) = 0;
    virtual void onUdpReadable(SockHandle, std::function<void()>) = 0;
    virtual void udpClose(SockHandle) = 0;

    // ── timers ─────────────────────────────────────────────────────────
    // QTimer-shaped lifecycle so stop()/start() re-arm semantics are exact:
    //   createTimer  == new QTimer + setInterval + setSingleShot + connect
    //   startTimer   == start()   (arm / re-arm from now)
    //   stopTimer    == stop()    (disarm; safe if already stopped)
    //   setTimerInterval == setInterval() (takes effect on the next start)
    //   destroyTimer == ~QTimer
    // a one-shot stays alive after it fires so a later startTimer can re-arm
    // it (the handshake watchdog relies on stop-then-start). fn is invoked
    // from the run loop.
    virtual TimerHandle createTimer(int ms, bool repeating,
                                    std::function<void()> fn) = 0;
    virtual void startTimer(TimerHandle) = 0;
    virtual void stopTimer(TimerHandle) = 0;
    virtual void setTimerInterval(TimerHandle, int ms) = 0;
    virtual void destroyTimer(TimerHandle) = 0;

    // ── run loop ───────────────────────────────────────────────────────
    // block, dispatching socket + timer callbacks, until stopLoop() is
    // called. the poll adapter implements the poll() loop here; the Qt
    // adapter leaves these no-ops because Qt's own event loop drives it.
    virtual void runLoop() = 0;
    virtual void stopLoop() = 0;
};

} // namespace fxchain
