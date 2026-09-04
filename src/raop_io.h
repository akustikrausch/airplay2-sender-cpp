// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// raop_io.h -- the sender's outbound i/o seam (ROADMAP m1).
// ----------------------------------------------------------------------------
// RaopSender is sans-i/o: it owns no socket, no timer and no thread. it asks
// its host for exactly six things through this interface (tcp connect / send /
// close, udp bind / send / close) and gets everything else pushed INTO it by
// the host: bytes that arrived, datagrams that arrived, connect and close
// notifications, and tick() once a deadline it published is due.
//
// the host never registers a callback inside the sender and the sender never
// stores anything the host owns, so the two can be torn down in any order,
// there is no handle table to leak, and the whole protocol core can be driven
// by a fake host in a unit test without a single socket.
//
// hosts that ship: RaopLoop (poll()/WSAPoll(), zero dependencies, the default)
// and RaopQtHost (optional, for an app that already runs a Qt event loop).

#include <cstdint>
#include <span>
#include <string>

namespace fxchain {

// an ipv4 endpoint as dotted-quad text + port. the host reports the resolved
// peer address on connect, so the sender never parses a hostname itself.
struct RaopEndpoint {
    std::string ip;
    uint16_t    port = 0;
};

// the fixed set of sockets one session uses. fixed slots, no handle tables.
enum class RaopTcp : uint8_t {
    Control,   // the rtsp/http control connection (plaintext, then encrypted)
    Event,     // the ap2 event channel (reverse-direction encrypted requests)
};
enum class RaopUdp : uint8_t {
    Audio,     // rtp audio out
    Control,   // sync packets out; retransmit requests in (replied to source)
    Timing,    // ntp timing requests in (replied to source)
};

class RaopIo {
public:
    virtual ~RaopIo() = default;

    // start a non-blocking connect. completion is reported later by the host
    // through RaopSender::onTcpConnected() / onTcpConnectFailed(). a host may
    // report a failure from inside this call if it cannot even start the
    // attempt; the sender copes with that.
    virtual void tcpConnect(RaopTcp ch, const std::string& host, uint16_t port) = 0;
    // queue bytes; the host writes them out as the socket allows.
    virtual void tcpSend(RaopTcp ch, std::span<const uint8_t> bytes) = 0;
    // release the socket. flush=true asks for a graceful close: get the queued
    // bytes (the TEARDOWN) onto the wire first, then FIN. flush=false aborts.
    // must be a no-op when the slot is not open.
    virtual void tcpClose(RaopTcp ch, bool flush) = 0;

    // bind an ipv4 udp socket on all interfaces, ephemeral port. returns the
    // port (the sender advertises it to the receiver) or 0 on failure.
    virtual uint16_t udpBind(RaopUdp s) = 0;
    virtual void udpSend(RaopUdp s, const RaopEndpoint& to,
                         std::span<const uint8_t> bytes) = 0;
    virtual void udpClose(RaopUdp s) = 0;
};

} // namespace fxchain
