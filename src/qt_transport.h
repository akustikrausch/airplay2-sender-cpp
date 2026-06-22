// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// qt_transport.h -- the optional Qt ITransport adapter.
// ----------------------------------------------------------------------------
// for hosts that already run a Qt event loop (e.g. FXChainPlayer): hand the
// sender a QtTransport instead of PollTransport and it drives QTcpSocket /
// QUdpSocket / QTimer under Qt's own loop, no second thread or poll loop. the
// default standalone build does NOT compile this (see the AIRPLAY_BUILD_QT_ADAPTER
// CMake option); it exists so the proven Qt integration keeps working.
//
// all Qt detail is behind a pimpl so this header pulls in no Qt headers. every
// method must be called from the Qt event-loop (GUI) thread. runLoop() spins a
// QEventLoop (a QCoreApplication must exist); a host that already calls exec()
// can ignore runLoop()/stopLoop() and just pump its own loop.

#include "itransport.h"

#include <memory>

namespace fxchain {

class QtTransport final : public ITransport {
public:
    QtTransport();
    ~QtTransport() override;
    QtTransport(const QtTransport&) = delete;
    QtTransport& operator=(const QtTransport&) = delete;

    SockHandle tcpConnect(const std::string& host, uint16_t port) override;
    void onTcpConnected(SockHandle, std::function<void(bool)>) override;
    int  tcpSend(SockHandle, std::span<const uint8_t> data) override;
    int  tcpRecv(SockHandle, std::span<uint8_t> buf) override;
    void onTcpReadable(SockHandle, std::function<void()>) override;
    void onTcpDisconnected(SockHandle, std::function<void()>) override;
    void onTcpError(SockHandle, std::function<void(std::string)>) override;
    void tcpDisconnect(SockHandle) override;
    void tcpClose(SockHandle) override;
    SockAddr tcpLocalAddr(SockHandle) override;

    SockHandle udpBind(uint16_t port_hint = 0) override;
    uint16_t udpLocalPort(SockHandle) override;
    int  udpSendTo(SockHandle, std::span<const uint8_t> data, const SockAddr&) override;
    int  udpRecvFrom(SockHandle, std::span<uint8_t> buf, SockAddr& src_out) override;
    void onUdpReadable(SockHandle, std::function<void()>) override;
    void udpClose(SockHandle) override;

    TimerHandle createTimer(int ms, bool repeating, std::function<void()>) override;
    void startTimer(TimerHandle) override;
    void stopTimer(TimerHandle) override;
    void setTimerInterval(TimerHandle, int ms) override;
    void destroyTimer(TimerHandle) override;

    void runLoop() override;
    void stopLoop() override;

private:
    struct Impl;
    std::unique_ptr<Impl> d_;
};

} // namespace fxchain
