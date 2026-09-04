// SPDX-License-Identifier: Apache-2.0
//
// loop_tests.cpp -- RaopLoop (the poll host) against a real loopback receiver.
//
// the protocol itself is covered byte for byte by core_tests; this file
// checks the socket host: connect completion, refused / unresolvable
// connects reported asynchronously, a full AP1 session over real udp with
// the timing + retransmit replies landing at the datagram SOURCE, TEARDOWN
// reaching the receiver before the close, a receiver-initiated close with
// a clean reconnect, and that nothing leaks between sessions.

#include "raop_loop.h"
#include "raop_sender.h"
#include "ring_buffer.h"

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  using sock_t = SOCKET;
  static const sock_t kBad = INVALID_SOCKET;
  static void sockClose(sock_t s) { ::closesocket(s); }
  using buflen_t = int;
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/select.h>
  #include <sys/socket.h>
  #include <unistd.h>
  using sock_t = int;
  static const sock_t kBad = -1;
  static void sockClose(sock_t s) { ::close(s); }
  using buflen_t = size_t;
#endif

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace fxchain;

namespace {

int g_checks = 0, g_failures = 0;
const char* g_test = "";
bool checkImpl(bool ok, const char* what, int line) {
    ++g_checks;
    if (!ok) { ++g_failures; std::printf("  [FAIL] %s  (%s, line %d)\n", what, g_test, line); }
    return ok;
}
#define CHECK(cond, what) checkImpl(bool(cond), what, __LINE__)
#define REQUIRE(cond, what) do { if (!CHECK(cond, what)) return; } while (0)

// ── blocking-socket helpers for the fake receiver thread ──────────────

bool waitReadable(sock_t fd, int ms) {
    fd_set set;
    FD_ZERO(&set);
    FD_SET(fd, &set);
    timeval tv{ms / 1000, (ms % 1000) * 1000};
    return ::select(int(fd + 1), &set, nullptr, nullptr, &tv) > 0;
}
uint16_t localPort(sock_t fd) {
    sockaddr_in a{};
    socklen_t l = sizeof(a);
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&a), &l);
    return ntohs(a.sin_port);
}
sock_t udpLoopback() {
    const sock_t s = ::socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a));
    return s;
}
sock_t tcpListenLoopback() {
    const sock_t s = ::socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a));
    ::listen(s, 1);
    return s;
}
void udpSendTo(sock_t s, const std::string& d, uint16_t port) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    ::sendto(s, d.data(), buflen_t(d.size()), 0, reinterpret_cast<sockaddr*>(&a), sizeof(a));
}
int udpRecv(sock_t s, std::string& out, int ms) {
    if (!waitReadable(s, ms)) return -1;
    char buf[4096];
    const int n = int(::recvfrom(s, buf, buflen_t(sizeof(buf)), 0, nullptr, nullptr));
    if (n > 0) out.assign(buf, size_t(n));
    return n;
}
void sendAll(sock_t fd, const std::string& s) {
    size_t off = 0;
    while (off < s.size()) {
        const int n = int(::send(fd, s.data() + off, buflen_t(s.size() - off), 0));
        if (n <= 0) break;
        off += size_t(n);
    }
}
// one complete rtsp request (head + Content-Length body) or "" on EOF/timeout.
std::string recvRequest(sock_t fd, std::string& buf, std::string& method, int ms) {
    for (;;) {
        const size_t he = buf.find("\r\n\r\n");
        if (he != std::string::npos) {
            size_t clen = 0;
            const std::string head = buf.substr(0, he);
            for (size_t p = 0; p < head.size();) {
                const size_t nl = head.find('\n', p);
                std::string line = head.substr(p, nl == std::string::npos ? std::string::npos : nl - p);
                for (auto& c : line) c = char(tolower(static_cast<unsigned char>(c)));
                if (line.rfind("content-length:", 0) == 0) clen = size_t(std::atoi(line.c_str() + 15));
                if (nl == std::string::npos) break;
                p = nl + 1;
            }
            if (buf.size() >= he + 4 + clen) {
                const std::string full = buf.substr(0, he + 4 + clen);
                buf.erase(0, he + 4 + clen);
                method = full.substr(0, full.find(' '));
                return full;
            }
        }
        if (!waitReadable(fd, ms)) return {};
        char tmp[4096];
        const int n = int(::recv(fd, tmp, buflen_t(sizeof(tmp)), 0));
        if (n <= 0) return {};
        buf.append(tmp, size_t(n));
    }
}

// ── the fake AP1 receiver (its own thread, blocking sockets) ──────────

struct FakeResult {
    std::atomic<bool> handshakeDone{false};
    std::atomic<bool> sawTeardown{false};
    std::atomic<bool> sawEof{false};
    std::atomic<int>  audioPackets{0};
    std::atomic<int>  syncPackets{0};
    std::atomic<bool> timingReplyOk{false};
    std::atomic<bool> retransmitReplyOk{false};
    std::atomic<int>  firstPacketLen{0};
    std::atomic<int>  firstByte{-1};
    std::atomic<bool> announceSawLoopback{false};
};

// closeAfterRecord: hang up right after answering RECORD (remote-close test).
void fakeReceiver(sock_t listenFd, FakeResult* r, bool closeAfterRecord) {
    if (!waitReadable(listenFd, 5000)) return;
    const sock_t cli = ::accept(listenFd, nullptr, nullptr);
    if (cli == kBad) return;
    const sock_t srv = udpLoopback(), ctl = udpLoopback(), tim = udpLoopback();

    uint16_t senderCtl = 0, senderTim = 0;
    std::string buf, method;
    int cseq = 0;
    for (;;) {
        const std::string req = recvRequest(cli, buf, method, 5000);
        if (req.empty()) break;
        ++cseq;
        std::string reply = "RTSP/1.0 200 OK\r\nCSeq: " + std::to_string(cseq) + "\r\n";
        if (method == "ANNOUNCE" && req.find("c=IN IP4 127.0.0.1") != std::string::npos) r->announceSawLoopback = true;
        if (method == "SETUP") {
            auto grab = [&](const char* key) -> uint16_t {
                const size_t k = req.find(key);
                return k == std::string::npos ? 0 : uint16_t(std::atoi(req.c_str() + k + std::strlen(key)));
            };
            senderCtl = grab("control_port=");
            senderTim = grab("timing_port=");
            reply += "Session: 1\r\nTransport: RTP/AVP/UDP;unicast;mode=record;server_port=" + std::to_string(localPort(srv))
                   + ";control_port=" + std::to_string(localPort(ctl)) + ";timing_port=" + std::to_string(localPort(tim)) + "\r\n";
        }
        reply += "\r\n";
        sendAll(cli, reply);
        if (method == "RECORD" && closeAfterRecord) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            sockClose(cli);
            sockClose(srv); sockClose(ctl); sockClose(tim); sockClose(listenFd);
            return;
        }
        if (method == "POST") { r->handshakeDone = true; break; }   // the /feedback probe = handshake fully up
    }

    // collect some audio + a sync, remember a seq to ask back for
    uint16_t grabbedSeq = 0;
    bool haveSeq = false;
    std::string pkt;
    for (int i = 0; i < 80 && !(r->audioPackets > 8 && r->syncPackets > 0); ++i) {
        if (udpRecv(srv, pkt, 60) > 0) {
            if (r->audioPackets == 0) { r->firstPacketLen = int(pkt.size()); r->firstByte = uint8_t(pkt[0]); }
            ++r->audioPackets;
            if (!haveSeq && pkt.size() >= 4) { grabbedSeq = uint16_t((uint8_t(pkt[2]) << 8) | uint8_t(pkt[3])); haveSeq = true; }
        }
        if (udpRecv(ctl, pkt, 5) > 0 && pkt.size() >= 2 && uint8_t(pkt[1]) == 0xD4) ++r->syncPackets;
    }
    // timing probe: the reply must come back to THIS socket
    if (senderTim) {
        std::string q(32, '\0');
        q[0] = char(0x80); q[1] = char(0xD2);
        udpSendTo(tim, q, senderTim);
        std::string rep;
        if (udpRecv(tim, rep, 1000) == 32 && uint8_t(rep[1]) == 0xD3) r->timingReplyOk = true;
    }
    // retransmit probe
    if (senderCtl && haveSeq) {
        std::string q(8, '\0');
        q[0] = char(0x80); q[1] = char(0xD5);
        q[4] = char(grabbedSeq >> 8); q[5] = char(grabbedSeq & 0xFF); q[7] = 1;
        udpSendTo(ctl, q, senderCtl);
        for (int i = 0; i < 20; ++i) {
            std::string rep;
            if (udpRecv(ctl, rep, 200) <= 0) break;
            if (rep.size() >= 4 && uint8_t(rep[0]) == 0x80 && uint8_t(rep[1]) == 0xD6) { r->retransmitReplyOk = true; break; }
        }
    }
    // now wait for the TEARDOWN, then the FIN
    for (;;) {
        const std::string req = recvRequest(cli, buf, method, 5000);
        if (req.empty()) { r->sawEof = true; break; }
        ++cseq;
        sendAll(cli, "RTSP/1.0 200 OK\r\nCSeq: " + std::to_string(cseq) + "\r\n\r\n");
        if (method == "TEARDOWN") r->sawTeardown = true;
    }
    sockClose(cli);
    sockClose(srv); sockClose(ctl); sockClose(tim); sockClose(listenFd);
}

struct Session {
    RaopLoop loop;
    RingBuffer<int16_t> ring{1u << 16};
    std::optional<bool> launched;
    std::string error;
    int closed = 0;
    std::vector<std::string> log;
    std::unique_ptr<RaopSender> sender;
    bool inStart = false, syncCallback = false;

    Session() {
        RaopEvents ev;
        ev.launched = [this](bool ok, const std::string& e) { launched = ok; error = e; if (inStart) syncCallback = true; };
        ev.closed = [this] { ++closed; };
        sender = std::make_unique<RaopSender>(loop, std::move(ev),
            [this](RaopLogLevel, const std::string& l) { log.push_back(l); });
        sender->attachRing(&ring);
        sender->setInputFormat(44100);
        std::vector<int16_t> tone(44100 * 2);
        for (size_t i = 0; i < tone.size(); ++i) tone[i] = int16_t((i * 7) & 0x3FFF);
        ring.tryPush(std::span<const int16_t>(tone.data(), tone.size()));
    }
    void start(const std::string& host, uint16_t port) {
        sender->setAuth(RaopDeviceInfo::Auth::None, false, "box", "", "");
        inStart = true;
        sender->start(host, port, "FakeBox");
        inStart = false;
    }
    // pump until `done` or the timeout
    template <class F> bool pumpUntil(F&& done, int ms) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
        while (!done()) {
            if (std::chrono::steady_clock::now() > deadline) return false;
            loop.pump(*sender, std::chrono::milliseconds(20));
        }
        return true;
    }
};

void testFullSession() {
    g_test = "full ap1 session over loopback";
    const sock_t lfd = tcpListenLoopback();
    const uint16_t port = localPort(lfd);
    FakeResult res;
    std::thread rx(fakeReceiver, lfd, &res, false);

    Session s;
    s.start("127.0.0.1", port);
    CHECK(!s.launched.has_value(), "start() reports nothing synchronously");
    REQUIRE(s.pumpUntil([&] { return s.launched.has_value(); }, 5000), "launched within 5 s");
    CHECK(*s.launched, std::string("launched ok: " + s.error).c_str());
    CHECK(res.announceSawLoopback.load(), "SDP c= line carries the resolved peer address");
    // stream for a bit, until the receiver has probed us
    s.pumpUntil([&] { return res.retransmitReplyOk.load() || res.timingReplyOk.load(); }, 4000);
    s.pumpUntil([&] { return false; }, 300);
    CHECK(res.handshakeDone.load(), "OPTIONS/ANNOUNCE/SETUP/RECORD/feedback all arrived");
    CHECK(res.audioPackets.load() > 8, "rtp audio flows to server_port");
    CHECK(res.firstByte.load() == 0x80 && res.firstPacketLen.load() == 12 + 1408, "rtp v2 header + 1408 B L16");
    CHECK(res.syncPackets.load() > 0, "sync packets flow to control_port");
    CHECK(res.timingReplyOk.load(), "timing reply lands at the requesting socket");
    CHECK(res.retransmitReplyOk.load(), "retransmit reply lands at the requesting socket");
    s.sender->stop();
    rx.join();
    CHECK(res.sawTeardown.load(), "TEARDOWN reached the receiver before the socket closed");
    CHECK(res.sawEof.load(), "and the receiver saw our FIN");
    CHECK(!s.sender->active() && s.closed == 0, "idle after stop(), no closed() for our own stop");
}

void testConnectRefused() {
    g_test = "refused connect";
    // a listener we close immediately: the port is (almost certainly) dead
    const sock_t lfd = tcpListenLoopback();
    const uint16_t port = localPort(lfd);
    sockClose(lfd);
    Session s;
    s.start("127.0.0.1", port);
    CHECK(!s.launched.has_value() && !s.syncCallback, "nothing reported from inside start()");
    REQUIRE(s.pumpUntil([&] { return s.launched.has_value(); }, 5000), "reported within 5 s");
    CHECK(!*s.launched && !s.error.empty(), std::string("launched(false, '" + s.error + "')").c_str());
    CHECK(s.closed == 1 && !s.sender->active(), "closed() once, idle");
}

void testUnresolvableHost() {
    g_test = "unresolvable host";
    Session s;
    s.start("no-such-host.invalid", 7000);
    CHECK(!s.launched.has_value() && !s.syncCallback, "resolution failure is not reported from inside start()");
    REQUIRE(s.pumpUntil([&] { return s.launched.has_value(); }, 5000), "reported from pump()");
    CHECK(!*s.launched && s.error.find("resolve") != std::string::npos, "launched(false, cannot resolve ...)");
}

void testRemoteCloseThenReconnect() {
    g_test = "receiver closes, then a clean reconnect";
    const sock_t lfd = tcpListenLoopback();
    const uint16_t port = localPort(lfd);
    FakeResult res;
    std::thread rx(fakeReceiver, lfd, &res, true);
    Session s;
    s.start("127.0.0.1", port);
    REQUIRE(s.pumpUntil([&] { return s.launched.has_value(); }, 5000), "launched");
    CHECK(*s.launched, "streaming");
    REQUIRE(s.pumpUntil([&] { return s.closed > 0; }, 5000), "the receiver's hang-up is reported as closed()");
    CHECK(!s.sender->active(), "idle after the remote close");
    rx.join();

    // second session on a fresh receiver through the SAME loop + sender
    const sock_t lfd2 = tcpListenLoopback();
    const uint16_t port2 = localPort(lfd2);
    FakeResult res2;
    std::thread rx2(fakeReceiver, lfd2, &res2, false);
    s.launched.reset();
    s.start("127.0.0.1", port2);
    REQUIRE(s.pumpUntil([&] { return s.launched.has_value(); }, 5000), "second session launched");
    CHECK(*s.launched, "second session streams (no leaked slots)");
    s.pumpUntil([&] { return res2.timingReplyOk.load(); }, 4000);
    CHECK(res2.timingReplyOk.load(), "udp sockets of the second session work");
    s.sender->stop();
    rx2.join();
    CHECK(res2.sawTeardown.load(), "second session torn down properly");
}

void testStopFromCallbackAndRequestStop() {
    g_test = "run() + requestStop()";
    const sock_t lfd = tcpListenLoopback();
    const uint16_t port = localPort(lfd);
    FakeResult res;
    std::thread rx(fakeReceiver, lfd, &res, false);
    RaopLoop loop;
    RingBuffer<int16_t> ring{1u << 12};
    RaopEvents ev;
    ev.launched = [&](bool, const std::string&) { loop.requestStop(); };
    RaopSender sender(loop, std::move(ev));
    sender.attachRing(&ring);
    sender.setAuth(RaopDeviceInfo::Auth::None, false, "box", "", "");
    sender.start("127.0.0.1", port, "FakeBox");
    const auto t0 = std::chrono::steady_clock::now();
    loop.run(sender);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    CHECK(loop.stopRequested() && ms < 5000, "run() returns once requestStop() is called from a callback");
    sender.stop();
    rx.join();
    CHECK(res.sawTeardown.load(), "TEARDOWN delivered");
}

} // namespace

int main() {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    std::printf("== raop loop tests (real loopback sockets) ==\n");
    testFullSession();
    testConnectRefused();
    testUnresolvableHost();
    testRemoteCloseThenReconnect();
    testStopFromCallbackAndRequestStop();
    std::printf("%s: %d/%d checks passed\n", g_failures == 0 ? "ALL PASS" : "FAILURES",
                g_checks - g_failures, g_checks);
#ifdef _WIN32
    WSACleanup();
#endif
    return g_failures == 0 ? 0 : 1;
}
