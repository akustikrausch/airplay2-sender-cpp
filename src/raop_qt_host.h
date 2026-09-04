// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// raop_qt_host.h -- the optional Qt host for RaopSender.
// ----------------------------------------------------------------------------
// for an application that already runs a Qt event loop (FXChainPlayer): hand
// the sender a RaopQtHost instead of a RaopLoop and Qt's own loop drives it,
// no second thread, no poll loop.
//
//   RaopQtHost host;
//   RaopSender sender(host, events, log);
//   host.drive(sender);          // socket signals push data in, a QTimer ticks
//   sender.start(ip, 7000, name);
//
// all Qt detail is behind a pimpl, so this header pulls in no Qt headers. every
// method must be called on the thread that owns the Qt event loop. built only
// with -DAIRPLAY_BUILD_QT_HOST=ON (Qt6 Core + Network); the standalone build
// never compiles it.

#include "raop_io.h"

#include <memory>

namespace fxchain {

class RaopSender;

class RaopQtHost final : public RaopIo {
public:
    RaopQtHost();
    ~RaopQtHost() override;
    RaopQtHost(const RaopQtHost&) = delete;
    RaopQtHost& operator=(const RaopQtHost&) = delete;

    // deliver socket events to `sender` and tick its deadlines from a precise
    // QTimer (4 ms while a session is active, 50 ms while idle).
    void drive(RaopSender& sender);
    // stop driving. call before the sender goes away if the host outlives it.
    void release();

    // RaopIo
    void tcpConnect(RaopTcp ch, const std::string& host, uint16_t port) override;
    void tcpSend(RaopTcp ch, std::span<const uint8_t> bytes) override;
    void tcpClose(RaopTcp ch, bool flush) override;
    uint16_t udpBind(RaopUdp s) override;
    void udpSend(RaopUdp s, const RaopEndpoint& to, std::span<const uint8_t> bytes) override;
    void udpClose(RaopUdp s) override;

private:
    struct Impl;
    std::unique_ptr<Impl> d_;
};

} // namespace fxchain
