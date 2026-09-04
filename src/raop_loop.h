// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// raop_loop.h -- the bundled, dependency-free host for RaopSender.
// ----------------------------------------------------------------------------
// one thread, one poll()/WSAPoll() loop, five fixed socket slots (the two
// tcp channels + the udp trio a session uses). it implements the RaopIo
// seam and pushes everything that happens into the sender:
//
//   RaopLoop   loop;
//   RaopSender sender(loop, events, log);
//   sender.setAuth(...); sender.attachRing(&ring); sender.start(ip, 7000, name);
//   loop.run(sender);                    // until loop.requestStop()
//
// every sender callback (launched / closed / pinRequired / ...) fires from
// inside pump(), on the thread that calls it. sockets are released the moment
// a channel is closed by either side, so nothing outlives a session and
// nothing in the loop ever points back into the sender.
//
// portable: POSIX sockets (linux, macos, bsd) and Winsock 2 (msvc, mingw).

#include "raop_io.h"

#include <atomic>
#include <chrono>
#include <memory>

namespace fxchain {

class RaopSender;

class RaopLoop final : public RaopIo {
public:
    RaopLoop();
    ~RaopLoop() override;
    RaopLoop(const RaopLoop&) = delete;
    RaopLoop& operator=(const RaopLoop&) = delete;

    // Wait for socket activity (at most `maxWait`, or until the sender's next
    // deadline, whichever is first), deliver it to `sender`, then tick it.
    void pump(RaopSender& sender,
              std::chrono::milliseconds maxWait = std::chrono::milliseconds(50));
    // pump() until requestStop().
    void run(RaopSender& sender);
    // May be called from another thread or a signal handler (an atomic store;
    // run() notices within one pump).
    void requestStop() { stop_.store(true); }
    bool stopRequested() const { return stop_.load(); }
    void clearStopRequest() { stop_.store(false); }

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
    std::atomic<bool> stop_{false};
};

} // namespace fxchain
