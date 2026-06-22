// SPDX-License-Identifier: Apache-2.0
//
// m1_verify.cpp -- verification harness for the Qt-free transport refactor.
//
// not part of the shipped library. proves the poll transport + the ported
// RaopSender actually work end to end by standing up a loopback "fake RAOP
// receiver" and driving the full AirPlay-1 handshake through them, then
// checking that audio / sync flow and that the UDP timing + retransmit
// REPLIES go back to the datagram source (the #1 regression risk). also
// unit-checks the timer restart semantics, the creds JSON byte-compat, and
// the on-wire RTP header.

#include "raop_sender.h"
#include "poll_transport.h"
#include "creds_json.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace fxchain;

static int g_failures = 0;
static void check(bool ok, const char* what) {
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++g_failures;
}

// ── tiny blocking-socket helpers for the fake receiver ────────────────

static void setRcvTimeout(int fd, int ms) {
    timeval tv{ms / 1000, (ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}
static uint16_t localPortOf(int fd) {
    sockaddr_in a{}; socklen_t l = sizeof(a);
    getsockname(fd, reinterpret_cast<sockaddr*>(&a), &l);
    return ntohs(a.sin_port);
}
static int udpBindLoopback() {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a));
    return s;
}
static void udpSendTo(int fd, const std::string& data, uint16_t port) {
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons(port);
    sendto(fd, data.data(), data.size(), 0, reinterpret_cast<sockaddr*>(&a), sizeof(a));
}

// read exactly one RTSP/HTTP request (head + Content-Length body) off `fd`,
// carrying any over-read into `buf`. returns the request method, or "" on EOF.
static std::string recvRequest(int fd, std::string& buf, std::string& full) {
    for (;;) {
        const auto he = buf.find("\r\n\r\n");
        if (he != std::string::npos) {
            int clen = 0;
            const std::string head = buf.substr(0, he);
            size_t p = 0;
            while (true) {
                const auto nl = head.find('\n', p);
                const std::string line = head.substr(p, (nl == std::string::npos ? head.size() : nl) - p);
                auto c = line.find(':');
                if (c != std::string::npos) {
                    std::string k = line.substr(0, c);
                    for (auto& ch : k) ch = char(tolower((unsigned char)ch));
                    if (k == "content-length") clen = atoi(line.substr(c + 1).c_str());
                }
                if (nl == std::string::npos) break;
                p = nl + 1;
            }
            const size_t total = he + 4 + size_t(clen < 0 ? 0 : clen);
            if (buf.size() >= total) {
                full = buf.substr(0, total);
                buf.erase(0, total);
                return full.substr(0, full.find(' '));
            }
        }
        char tmp[4096];
        const ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0) return {};
        buf.append(tmp, size_t(n));
    }
}
static void sendAll(int fd, const std::string& s) {
    size_t off = 0;
    while (off < s.size()) {
        const ssize_t n = send(fd, s.data() + off, s.size() - off, 0);
        if (n <= 0) break;
        off += size_t(n);
    }
}

struct FakeResult {
    std::atomic<bool> handshakeDone{false};
    std::atomic<int>  audioPkts{0};
    std::atomic<int>  syncPkts{0};
    std::atomic<bool> timingReplyOk{false};
    std::atomic<bool> retransReplyOk{false};
    std::atomic<int>  firstAudioLen{0};
    std::atomic<int>  firstHeaderByte{-1};
};

// the fake AirPlay-1 receiver: accept, complete the RTSP handshake, then
// collect audio/sync and probe the timing + retransmit servers.
static void fakeReceiver(int listenFd, FakeResult* r) {
    int cli = accept(listenFd, nullptr, nullptr);
    if (cli < 0) return;
    setRcvTimeout(cli, 3000);

    int srvSock = udpBindLoopback();   // receives audio
    int ctlSock = udpBindLoopback();   // receives sync; sends retransmit req
    int timSock = udpBindLoopback();   // receives timing reply
    setRcvTimeout(srvSock, 200);
    setRcvTimeout(ctlSock, 50);
    setRcvTimeout(timSock, 600);
    const uint16_t srvPort = localPortOf(srvSock);
    const uint16_t ctlPort = localPortOf(ctlSock);
    const uint16_t timPort = localPortOf(timSock);

    uint16_t senderCtlPort = 0, senderTimPort = 0;
    std::string buf, full;
    int cseq = 0;
    for (;;) {
        const std::string method = recvRequest(cli, buf, full);
        if (method.empty()) break;
        ++cseq;
        std::string reply;
        if (method == "SETUP") {
            // learn the sender's control/timing ports from its Transport line
            auto grab = [&](const char* key) -> uint16_t {
                auto k = full.find(key);
                if (k == std::string::npos) return 0;
                return uint16_t(atoi(full.c_str() + k + strlen(key)));
            };
            senderCtlPort = grab("control_port=");
            senderTimPort = grab("timing_port=");
            reply = "RTSP/1.0 200 OK\r\nCSeq: " + std::to_string(cseq) +
                    "\r\nSession: 1\r\nTransport: RTP/AVP/UDP;unicast;mode=record;server_port=" +
                    std::to_string(srvPort) + ";control_port=" + std::to_string(ctlPort) +
                    ";timing_port=" + std::to_string(timPort) + "\r\n\r\n";
        } else {
            reply = "RTSP/1.0 200 OK\r\nCSeq: " + std::to_string(cseq) + "\r\n\r\n";
        }
        sendAll(cli, reply);
        if (method == "RECORD") { /* streaming begins; feedback POST follows */ }
        if (method == "POST") { r->handshakeDone = true; break; }   // /feedback probe = handshake fully up
    }

    // collect audio + sync for a budget, grabbing a seq to ask back for.
    uint16_t grabbedSeq = 0;
    bool haveSeq = false;
    for (int i = 0; i < 60; ++i) {
        unsigned char pkt[2048];
        sockaddr_in from{}; socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(srvSock, pkt, sizeof(pkt), 0, reinterpret_cast<sockaddr*>(&from), &fl);
        if (n > 0) {
            if (r->audioPkts == 0) { r->firstAudioLen = int(n); r->firstHeaderByte = pkt[0]; }
            ++r->audioPkts;
            if (!haveSeq && n >= 4) { grabbedSeq = uint16_t((pkt[2] << 8) | pkt[3]); haveSeq = true; }
        }
        n = recvfrom(ctlSock, pkt, sizeof(pkt), 0, nullptr, nullptr);
        if (n > 0 && n >= 2 && (unsigned char)pkt[1] == 0xD4) ++r->syncPkts;
        if (r->audioPkts > 8 && r->syncPkts > 0) break;
    }

    std::fprintf(stderr, "  fake: senderCtlPort=%u senderTimPort=%u audio=%d sync=%d haveSeq=%d\n",
                 senderCtlPort, senderTimPort, r->audioPkts.load(), r->syncPkts.load(), haveSeq);

    // timing server probe: send a 32-byte request, expect a 0xD3 reply.
    if (senderTimPort) {
        std::string req(32, '\0');
        req[0] = char(0x80); req[1] = char(0x52);
        udpSendTo(timSock, req, senderTimPort);
        unsigned char rep[64];
        const ssize_t n = recv(timSock, rep, sizeof(rep), 0);
        std::fprintf(stderr, "  fake: timing reply n=%zd b1=0x%02x\n", n, n >= 2 ? rep[1] : 0);
        if (n == 32 && (rep[1] & 0x7F) == 0x53) r->timingReplyOk = true;
    }

    // retransmit probe: ask for a seq we saw; expect a 0x80 0xD6 reply.
    if (senderCtlPort && haveSeq) {
        std::string req(8, '\0');
        req[0] = char(0x80); req[1] = char(0xD5);   // type 0x55 | 0x80
        req[4] = char(grabbedSeq >> 8); req[5] = char(grabbedSeq & 0xFF);
        req[6] = 0; req[7] = 1;                      // lost_count = 1
        udpSendTo(ctlSock, req, senderCtlPort);
        for (int i = 0; i < 8; ++i) {
            unsigned char rep[2048];
            const ssize_t n = recv(ctlSock, rep, sizeof(rep), 0);
            if (n <= 0) break;
            if (n >= 4 && rep[0] == 0x80 && rep[1] == 0xD6) { r->retransReplyOk = true; break; }
        }
        std::fprintf(stderr, "  fake: retransReplyOk=%d\n", r->retransReplyOk.load());
    }

    close(srvSock); close(ctlSock); close(timSock); close(cli);
}

// ── unit checks ───────────────────────────────────────────────────────

// directly exercises the PollTransport UDP path (bind, recvfrom-with-source,
// sendto-the-source, onUdpReadable) -- isolates Risk 1 from RaopSender.
static void testUdpEcho() {
    PollTransport t;
    SockHandle a = t.udpBind(0);
    SockHandle b = t.udpBind(0);
    const uint16_t portB = t.udpLocalPort(b);
    bool gotReply = false, srcOk = false;
    TimerHandle guard = t.createTimer(2000, false, [&] { t.stopLoop(); });

    t.onUdpReadable(b, [&] {
        uint8_t buf[64]; SockAddr src;
        int n = t.udpRecvFrom(b, std::span<uint8_t>(buf, sizeof(buf)), src);
        if (n > 0) {
            srcOk = (src.ip == "127.0.0.1") && (src.port != 0);
            const std::string pong = "pong";
            t.udpSendTo(b, std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(pong.data()), pong.size()), src);
        }
    });
    t.onUdpReadable(a, [&] {
        uint8_t buf[64]; SockAddr src;
        int n = t.udpRecvFrom(a, std::span<uint8_t>(buf, sizeof(buf)), src);
        if (n == 4 && std::string(reinterpret_cast<char*>(buf), 4) == "pong") {
            gotReply = true; t.stopLoop();
        }
    });

    const std::string ping = "ping";
    t.udpSendTo(a, std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(ping.data()), ping.size()),
        SockAddr{"127.0.0.1", portB});
    t.runLoop();
    t.destroyTimer(guard);
    check(srcOk, "PollTransport udpRecvFrom captures the datagram source addr");
    check(gotReply, "PollTransport udpSendTo replies to the captured source");
    t.udpClose(a); t.udpClose(b);
}

static void testCreds() {
    CredsFields c;
    c.ltsk  = {0x01, 0x02, 0x03};
    c.ltpk  = {0xab, 0xcd};
    c.atvId = {0x41, 0x42};
    c.clientId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    const std::string j = credsToJson(c);
    check(j == "{\"ltsk\":\"010203\",\"ltpk\":\"abcd\",\"atvId\":\"4142\","
               "\"clientId\":\"a1b2c3d4-e5f6-7890-abcd-ef1234567890\"}",
          "creds JSON byte-compatible with the Qt QJsonObject layout");
    auto back = credsFromJson(j);
    check(back && back->ltsk == c.ltsk && back->ltpk == c.ltpk &&
          back->atvId == c.atvId && back->clientId == c.clientId,
          "creds JSON round-trips ltsk/ltpk/atvId/clientId");
    // tolerate a pretty-printed / reordered blob (reader scans by key)
    auto pp = credsFromJson("{ \"clientId\":\"X\", \"ltsk\":\"00ff\", "
                            "\"ltpk\":\"11\", \"atvId\":\"22\" }");
    check(pp && pp->clientId == "X" && pp->ltsk == std::vector<uint8_t>{0x00, 0xff},
          "creds reader tolerates reordering + whitespace");
}

static void testTimerRestart() {
    PollTransport t;
    using clk = std::chrono::steady_clock;
    auto t0 = clk::now();
    long firedMs = -1;
    int  repeats = 0;

    TimerHandle one = t.createTimer(200, false, [&] {
        firedMs = std::chrono::duration_cast<std::chrono::milliseconds>(clk::now() - t0).count();
        t.stopLoop();
    });
    TimerHandle rep = t.createTimer(40, true, [&] { ++repeats; });
    // at +100ms, restart the one-shot: it must then fire ~300ms from t0, not 200.
    TimerHandle kick = t.createTimer(100, false, [&] { t.startTimer(one); });

    t.startTimer(one);
    t.startTimer(rep);
    t.startTimer(kick);
    t.runLoop();

    check(firedMs >= 280 && firedMs <= 360,
          "one-shot restart re-arms from now (fired ~300ms after a +100ms restart)");
    check(repeats >= 5, "repeating timer kept firing across the run");
    t.destroyTimer(one); t.destroyTimer(rep); t.destroyTimer(kick);
}

static void testBadHostFails() {
    PollTransport t;
    bool launched = false, ok = true;
    TimerHandle guard = t.createTimer(4000, false, [&] { t.stopLoop(); });
    RaopSender s(t, {},
        [&](bool good, std::string) { launched = true; ok = good; t.stopLoop(); },
        [] {}, [](std::string) {}, [](std::string, std::string) {});
    t.startTimer(guard);
    s.setAuth(RaopDeviceInfo::Auth::None, false, "dev", "", "");
    // 127.0.0.1:9 (discard) is almost never listening -> connection refused.
    s.start("127.0.0.1", 9, "nobody");
    t.runLoop();
    t.destroyTimer(guard);
    check(launched && !ok, "connect to a dead port reports launched(false)");
}

// forces tcpConnect to fail immediately (kInvalidSock), to deterministically
// exercise the deferred connect-init failure path (regression fix).
struct FailConnectTransport : PollTransport {
    SockHandle tcpConnect(const std::string&, uint16_t) override { return kInvalidSock; }
};

static void testDeferredConnectFail() {
    FailConnectTransport t;
    bool launched = false, ok = true, closed = false, syncDuringStart = false, inStart = false;
    RaopSender s(t, {},
        [&](bool good, std::string) { launched = true; ok = good; if (inStart) syncDuringStart = true; t.stopLoop(); },
        [&] { closed = true; }, [](std::string) {}, [](std::string, std::string) {});
    TimerHandle guard = t.createTimer(3000, false, [&] { t.stopLoop(); });
    t.startTimer(guard);
    s.setAuth(RaopDeviceInfo::Auth::None, false, "dev", "", "");
    inStart = true;
    s.start("10.255.255.1", 7000, "ghost");
    inStart = false;
    check(!launched && !syncDuringStart,
          "start() fires NO callback synchronously when tcpConnect fails (deferred)");
    t.runLoop();
    t.destroyTimer(guard);
    check(launched && !ok, "deferred connect-init failure reports launched(false) from the run loop");
    check(closed, "deferred connect-init failure also fires closed() (matches old async fail_)");
}

static void testFullHandshake() {
    int listenFd = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1; setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    bind(listenFd, reinterpret_cast<sockaddr*>(&a), sizeof(a));
    listen(listenFd, 1);
    const uint16_t port = localPortOf(listenFd);

    FakeResult r;
    std::thread fake(fakeReceiver, listenFd, &r);

    PollTransport t;
    bool launched = false, launchOk = false;
    TimerHandle guard = t.createTimer(8000, false, [&] { t.stopLoop(); });
    TimerHandle stopper = t.createTimer(3000, false, [&] { t.stopLoop(); });
    RaopSender s(t, {},
        [&](bool ok, std::string) { launched = true; launchOk = ok; t.startTimer(stopper); },
        [] {}, [](std::string) {}, [](std::string, std::string) {});
    t.startTimer(guard);
    s.setAuth(RaopDeviceInfo::Auth::None, false, "dev", "", "");
    s.start("127.0.0.1", port, "FakeBox");
    t.runLoop();

    fake.join();
    close(listenFd);
    t.destroyTimer(guard); t.destroyTimer(stopper);

    check(launched && launchOk, "AP1 handshake reaches Streaming -> launched(true)");
    check(r.handshakeDone.load(), "receiver saw OPTIONS/ANNOUNCE/SETUP/RECORD/feedback");
    check(r.audioPkts.load() > 5, "RTP audio packets flow to the receiver server_port");
    check(r.firstHeaderByte.load() == 0x80, "RTP header byte0 == 0x80 (V2)");
    check(r.firstAudioLen.load() == 12 + 352 * 2 * 2,
          "AP1 RTP packet == 12B header + 1408B L16 payload");
    check(r.syncPkts.load() > 0, "1 Hz SYNC packets (type 0xD4) flow to control_port");
    check(r.timingReplyOk.load(), "timing server replies to the datagram source (type 0xD3)");
    check(r.retransReplyOk.load(), "retransmit responder replies to the datagram source (0x80 0xD6)");
}

int main() {
    std::printf("== m1 Qt-free transport verification ==\n");
    testCreds();
    testTimerRestart();
    testUdpEcho();
    testBadHostFails();
    testDeferredConnectFail();
    testFullHandshake();
    std::printf("\n%s (%d failure%s)\n",
                g_failures == 0 ? "ALL PASS" : "FAILURES", g_failures,
                g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
