// SPDX-License-Identifier: Apache-2.0
//
// transport_loopback.cpp -- drives PollTransport over a loopback socket with the
// AirPlay 2 handshake shape (several request/reply round-trips, a re-entrant send
// from inside onTcpReadable, segmented + multi-part replies, three idle UDP
// sockets in the poll set). cross-platform, so it also runs in the Windows CI.

#include "poll_transport.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  using raw_sock_t = SOCKET;
  static constexpr raw_sock_t kRawInvalid = INVALID_SOCKET;
  static void raw_close(raw_sock_t s) { ::closesocket(s); }
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <unistd.h>
  using raw_sock_t = int;
  static constexpr raw_sock_t kRawInvalid = -1;
  static void raw_close(raw_sock_t s) { ::close(s); }
#endif

using namespace fxchain;

namespace {

constexpr int kWarmups      = 4;     // pair-setup / pair-verify round-trips
constexpr int kWarmupReqLen = 200;
constexpr int kWarmupRepLen = 200;
constexpr int kReq1Len      = 100;   // GET /info analog
constexpr int kRep1Len      = 1431;
constexpr int kReq2Len      = 800;   // SETUP analog
constexpr int kRep2Len      = 310;

std::atomic<uint16_t> g_port{0};
std::atomic<bool>     g_ready{false};

bool sendN(raw_sock_t s, int n) {
    std::vector<char> buf(size_t(n), char(0xAB));
    int off = 0;
    while (off < n) {
        const int r = ::send(s, buf.data() + off, n - off, 0);
        if (r <= 0) return false;
        off += r;
    }
    return true;
}
bool sendSegmented(raw_sock_t s, int n, int seg, int sleepMs) {
    std::vector<char> buf(size_t(n), char(0xAB));
    int off = 0;
    while (off < n) {
        const int r = ::send(s, buf.data() + off, std::min(seg, n - off), 0);
        if (r <= 0) return false;
        off += r;
        if (off < n) std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
    }
    return true;
}
bool recvN(raw_sock_t s, int n) {
    std::vector<char> buf(static_cast<size_t>(n));
    int off = 0;
    while (off < n) {
        const int r = ::recv(s, buf.data() + off, n - off, 0);
        if (r <= 0) return false;
        off += r;
    }
    return true;
}

void serverThread() {
    raw_sock_t lfd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (lfd == kRawInvalid) return;
    int one = 1;
    ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&one), sizeof(one));
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;
    if (::bind(lfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) { raw_close(lfd); return; }
    ::listen(lfd, 1);
    sockaddr_in local{};
    socklen_t llen = sizeof(local);
    ::getsockname(lfd, reinterpret_cast<sockaddr*>(&local), &llen);
    g_port  = ntohs(local.sin_port);
    g_ready = true;

    raw_sock_t cfd = ::accept(lfd, nullptr, nullptr);
    if (cfd == kRawInvalid) { raw_close(lfd); return; }

    auto bail = [&] { raw_close(cfd); raw_close(lfd); };
    for (int i = 0; i < kWarmups; ++i)
        if (!recvN(cfd, kWarmupReqLen) || !sendN(cfd, kWarmupRepLen)) { bail(); return; }
    if (!recvN(cfd, kReq1Len) || !sendSegmented(cfd, kRep1Len, 100, 5)) { bail(); return; }
    if (!recvN(cfd, kReq2Len)) { bail(); return; }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));   // receiver processing time
    // reply 2 as three chunks, mirroring a ChaCha20 frame: [2B len][292B cipher][16B tag]
    if (!sendN(cfd, 2)) { bail(); return; }
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    if (!sendN(cfd, 292)) { bail(); return; }
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    if (!sendN(cfd, 16)) { bail(); return; }
    std::this_thread::sleep_for(std::chrono::seconds(2));
    bail();
}

} // namespace

int main() {
    PollTransport pt;
    std::thread srv(serverThread);
    while (!g_ready.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));

    enum class Phase { Warmup, Rep1, Rep2 };
    Phase phase = Phase::Warmup;
    int  warmupDone = 0, warmupRecv = 0, rep1 = 0, rep2 = 0;
    bool success = false;

    SockHandle h = pt.tcpConnect("127.0.0.1", g_port.load());
    if (h == kInvalidSock) { srv.detach(); std::printf("FAIL: connect\n"); return 1; }

    auto sendReq = [&](int len, uint8_t fill) {
        std::vector<uint8_t> r(size_t(len), fill);
        pt.tcpSend(h, r);
    };

    pt.onTcpConnected(h, [&](bool ok) {
        if (!ok) { pt.stopLoop(); return; }
        sendReq(kWarmupReqLen, 0x01);
    });

    pt.onTcpReadable(h, [&] {
        uint8_t buf[4096];
        for (;;) {
            const int n = pt.tcpRecv(h, std::span<uint8_t>(buf, sizeof(buf)));
            if (n <= 0) break;
            if (phase == Phase::Warmup) {
                warmupRecv += n;
                while (warmupRecv >= kWarmupRepLen) {
                    warmupRecv -= kWarmupRepLen;
                    if (++warmupDone < kWarmups) { sendReq(kWarmupReqLen, 0x01); return; }
                    phase = Phase::Rep1;
                    sendReq(kReq1Len, 0x01);
                    return;
                }
            } else if (phase == Phase::Rep1) {
                rep1 += n;
                if (rep1 >= kRep1Len) {
                    phase = Phase::Rep2;
                    sendReq(kReq2Len, 0x02);   // re-entrant SETUP-analog send, then await the reply
                    return;
                }
            } else {
                rep2 += n;
                if (rep2 >= kRep2Len) { success = true; pt.stopLoop(); return; }
            }
        }
    });

    pt.onTcpDisconnected(h, [&] { pt.stopLoop(); });
    pt.onTcpError(h, [&](std::string) { pt.stopLoop(); });

    // three idle UDP sockets in the poll set, as the live session has (audio has no callback)
    SockHandle ut = pt.udpBind(0), uc = pt.udpBind(0), ua = pt.udpBind(0);
    if (ut == kInvalidSock || uc == kInvalidSock || ua == kInvalidSock) {
        srv.detach(); std::printf("FAIL: udpBind\n"); return 1;
    }
    pt.onUdpReadable(ut, [] {});
    pt.onUdpReadable(uc, [] {});

    TimerHandle wd = pt.createTimer(8000, false, [&] { pt.stopLoop(); });
    pt.startTimer(wd);

    pt.runLoop();
    srv.detach();

    if (success) { std::printf("PASS\n"); return 0; }
    std::printf("FAIL: stall (phase=%d warmup=%d/%d rep1=%d/%d rep2=%d/%d)\n",
                int(phase), warmupDone, kWarmups, rep1, kRep1Len, rep2, kRep2Len);
    return 1;
}
