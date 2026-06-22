// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// poll_transport.h -- the default, Qt-free ITransport.
// ----------------------------------------------------------------------------
// a single-threaded poll()/WSAPoll() event loop driving the sender's tcp +
// udp sockets and its timers. construct one, hand it to RaopSender, call
// start(), then runLoop() to pump events until stopLoop(). all platform and
// socket detail lives behind a pimpl so this header pulls in no system
// headers (no winsock leakage into callers).

#include "itransport.h"

#include <memory>

namespace fxchain {

// not `final`: it is used through ITransport& (calls are virtual regardless),
// and tests subclass it to inject a tcpConnect failure.
class PollTransport : public ITransport {
public:
    PollTransport();
    ~PollTransport() override;
    PollTransport(const PollTransport&) = delete;
    PollTransport& operator=(const PollTransport&) = delete;

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
