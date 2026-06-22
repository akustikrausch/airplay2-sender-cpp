// SPDX-License-Identifier: Apache-2.0
//
// poll_transport.cpp -- the default Qt-free ITransport (poll()/WSAPoll()).
//
// one thread, one event loop. sockets are non-blocking; the loop multiplexes
// them with a small set of timers (the ~8 ms pacer, 1 Hz sync, keep-alive,
// handshake/PIN watchdogs). callbacks fire from inside runLoop(), so the
// whole sender stays single-threaded exactly like the Qt version was.

#include "poll_transport.h"
#include "net_compat.h"

#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace fxchain {

namespace {

enum class TcpState { Connecting, Connected, Closed };

struct TcpEntry {
    socket_t                         fd    = INVALID_SOCK;
    TcpState                         state = TcpState::Connecting;
    std::function<void(bool)>        onConnected;
    std::function<void()>            onReadable;
    std::function<void()>            onDisconnected;
    std::function<void(std::string)> onError;
    std::vector<uint8_t>             sendBuf;
    size_t                           sendOff    = 0;
    bool                             eofPending = false;  // recv saw a peer FIN
};

struct UdpEntry {
    socket_t              fd = INVALID_SOCK;
    std::function<void()> onReadable;
};

struct TimerEntry {
    uint64_t              deadlineMs = 0;
    int                   intervalMs = 0;
    bool                  repeating  = false;
    bool                  active     = false;
    std::function<void()> cb;
};

// fill a sockaddr_in from a dotted-quad + port. returns false on a bad ip.
bool makeSockAddr(const std::string& ip, uint16_t port, sockaddr_in& out) {
    std::memset(&out, 0, sizeof(out));
    out.sin_family = AF_INET;
    out.sin_port   = htons(port);
    return inet_pton(AF_INET, ip.c_str(), &out.sin_addr) == 1;
}

void portableSleepMs(int ms) {
#ifdef _WIN32
    Sleep(ms < 0 ? 0 : DWORD(ms));
#else
    struct timespec ts;
    ts.tv_sec  = ms / 1000;
    ts.tv_nsec = long(ms % 1000) * 1000000L;
    nanosleep(&ts, nullptr);
#endif
}

} // namespace

struct PollTransport::Impl {
    std::unordered_map<int, TcpEntry>   tcp;
    std::unordered_map<int, UdpEntry>   udp;
    std::unordered_map<int, TimerEntry> timers;
    int  nextHandle = 1;
    bool running    = false;

    TcpEntry*   findTcp(int h)   { auto it = tcp.find(h);    return it == tcp.end()    ? nullptr : &it->second; }
    UdpEntry*   findUdp(int h)   { auto it = udp.find(h);    return it == udp.end()    ? nullptr : &it->second; }
    TimerEntry* findTimer(int h) { auto it = timers.find(h); return it == timers.end() ? nullptr : &it->second; }

    // try to push as much of e.sendBuf as the kernel takes, without blocking.
    // returns false on a fatal send error.
    bool drainSend(TcpEntry& e) {
        while (e.sendOff < e.sendBuf.size()) {
            const auto n = ::send(e.fd,
                reinterpret_cast<const char*>(e.sendBuf.data() + e.sendOff),
                int(e.sendBuf.size() - e.sendOff), 0);
            if (n > 0) {
                e.sendOff += size_t(n);
            } else {
                if (n < 0 && err_would_block(sock_errno())) return true;
                return false;
            }
        }
        e.sendBuf.clear();
        e.sendOff = 0;
        return true;
    }

    int32_t nextTimeoutMs() {
        const uint64_t now = now_ms();
        bool     any = false;
        uint64_t best = 0;
        for (auto& [h, t] : timers) {
            if (!t.active) continue;
            if (!any || t.deadlineMs < best) { best = t.deadlineMs; any = true; }
        }
        if (!any) return -1;
        if (best <= now) return 0;
        const uint64_t diff = best - now;
        return diff > INT32_MAX ? INT32_MAX : int32_t(diff);
    }

    void fireExpiredTimers() {
        std::vector<int> due;
        const uint64_t now = now_ms();
        for (auto& [h, t] : timers)
            if (t.active && t.deadlineMs <= now) due.push_back(h);
        for (int h : due) {
            TimerEntry* t = findTimer(h);
            if (!t || !t->active || t->deadlineMs > now_ms()) continue;
            if (t->repeating) {
                // advance by interval, skipping any slots missed under load
                // (the audio pacer's token bucket absorbs the jitter).
                do { t->deadlineMs += uint64_t(t->intervalMs); }
                while (t->deadlineMs <= now_ms());
            } else {
                t->active = false;   // one-shot: disarm but keep for re-arm
            }
            auto cb = t->cb;         // copy: the callback may destroy this timer
            if (cb) cb();
        }
    }
};

PollTransport::PollTransport() : d_(std::make_unique<Impl>()) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
}

PollTransport::~PollTransport() {
    for (auto& [h, e] : d_->tcp) if (e.fd != INVALID_SOCK) sock_close(e.fd);
    for (auto& [h, e] : d_->udp) if (e.fd != INVALID_SOCK) sock_close(e.fd);
#ifdef _WIN32
    WSACleanup();
#endif
}

// ── TCP ──────────────────────────────────────────────────────────────

SockHandle PollTransport::tcpConnect(const std::string& host, uint16_t port) {
    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res)
        return kInvalidSock;

    auto* a4 = reinterpret_cast<sockaddr_in*>(res->ai_addr);
    a4->sin_port = htons(port);
    sockaddr_in dst = *a4;
    ::freeaddrinfo(res);

    socket_t s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCK) return kInvalidSock;
    sock_set_nonblocking(s);
    int one = 1;
    ::setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
                 reinterpret_cast<const char*>(&one), sizeof(one));

    // non-blocking connect: success or in-progress are both fine; the loop
    // confirms completion via POLLOUT + SO_ERROR. anything else is fatal.
    const int rc = ::connect(s, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
    if (rc != 0 && !err_in_progress(sock_errno())) {
        sock_close(s);
        return kInvalidSock;
    }
    const int h = d_->nextHandle++;
    TcpEntry e;
    e.fd    = s;
    e.state = TcpState::Connecting;
    d_->tcp.emplace(h, std::move(e));
    return h;
}

void PollTransport::onTcpConnected(SockHandle h, std::function<void(bool)> cb) {
    if (auto* e = d_->findTcp(h)) e->onConnected = std::move(cb);
}
void PollTransport::onTcpReadable(SockHandle h, std::function<void()> cb) {
    if (auto* e = d_->findTcp(h)) e->onReadable = std::move(cb);
}
void PollTransport::onTcpDisconnected(SockHandle h, std::function<void()> cb) {
    if (auto* e = d_->findTcp(h)) e->onDisconnected = std::move(cb);
}
void PollTransport::onTcpError(SockHandle h, std::function<void(std::string)> cb) {
    if (auto* e = d_->findTcp(h)) e->onError = std::move(cb);
}

int PollTransport::tcpSend(SockHandle h, std::span<const uint8_t> data) {
    auto* e = d_->findTcp(h);
    if (!e || e->fd == INVALID_SOCK) return -1;
    e->sendBuf.insert(e->sendBuf.end(), data.begin(), data.end());
    if (e->state == TcpState::Connected && !d_->drainSend(*e)) return -1;
    return int(data.size());
}

int PollTransport::tcpRecv(SockHandle h, std::span<uint8_t> buf) {
    auto* e = d_->findTcp(h);
    if (!e || e->fd == INVALID_SOCK) return -1;
    const auto n = ::recv(e->fd, reinterpret_cast<char*>(buf.data()),
                          int(buf.size()), 0);
    if (n > 0)  return int(n);
    if (n == 0) { e->eofPending = true; return 0; }   // peer closed
    return -1;                                          // EAGAIN or error
}

void PollTransport::tcpDisconnect(SockHandle h) {
    auto* e = d_->findTcp(h);
    if (!e || e->fd == INVALID_SOCK) { d_->tcp.erase(h); return; }
    // flush any queued bytes (e.g. the final TEARDOWN) so they reach the wire
    // before the FIN, then half-close. bounded so a stuck peer can't hang us.
    // this is the non-Qt equivalent of waitForBytesWritten + disconnectFromHost.
    const uint64_t deadline = now_ms() + 500;
    while (e->sendOff < e->sendBuf.size() && now_ms() < deadline) {
        if (!d_->drainSend(*e)) break;
        if (e->sendOff >= e->sendBuf.size()) break;
        pollfd pfd{};
        pfd.fd     = e->fd;
        pfd.events = POLLOUT;
        const int left = int(deadline - now_ms());
        sock_poll(&pfd, 1, left > 0 ? left : 0);
    }
#ifdef _WIN32
    ::shutdown(e->fd, SD_SEND);
#else
    ::shutdown(e->fd, SHUT_WR);
#endif
    sock_close(e->fd);
    d_->tcp.erase(h);
}

void PollTransport::tcpClose(SockHandle h) {
    auto* e = d_->findTcp(h);
    if (!e) return;
    if (e->fd != INVALID_SOCK) sock_close(e->fd);
    d_->tcp.erase(h);
}

SockAddr PollTransport::tcpLocalAddr(SockHandle h) {
    SockAddr out;
    auto* e = d_->findTcp(h);
    if (!e || e->fd == INVALID_SOCK) return out;
    sockaddr_in local{};
    socklen_t len = sizeof(local);
    if (::getsockname(e->fd, reinterpret_cast<sockaddr*>(&local), &len) == 0) {
        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &local.sin_addr, ip, sizeof(ip));
        out.ip   = ip;
        out.port = ntohs(local.sin_port);
    }
    return out;
}

// ── UDP ──────────────────────────────────────────────────────────────

SockHandle PollTransport::udpBind(uint16_t port_hint) {
    socket_t s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCK) return kInvalidSock;
    int rcvbuf = 256 * 1024;
    ::setsockopt(s, SOL_SOCKET, SO_RCVBUF,
                 reinterpret_cast<const char*>(&rcvbuf), sizeof(rcvbuf));
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port_hint);
    if (::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        sock_close(s);
        return kInvalidSock;
    }
    sock_set_nonblocking(s);
    const int h = d_->nextHandle++;
    d_->udp.emplace(h, UdpEntry{s, {}});
    return h;
}

uint16_t PollTransport::udpLocalPort(SockHandle h) {
    auto* e = d_->findUdp(h);
    if (!e || e->fd == INVALID_SOCK) return 0;
    sockaddr_in local{};
    socklen_t len = sizeof(local);
    if (::getsockname(e->fd, reinterpret_cast<sockaddr*>(&local), &len) != 0)
        return 0;
    return ntohs(local.sin_port);
}

int PollTransport::udpSendTo(SockHandle h, std::span<const uint8_t> data,
                             const SockAddr& dest) {
    auto* e = d_->findUdp(h);
    if (!e || e->fd == INVALID_SOCK) return -1;
    sockaddr_in addr{};
    if (!makeSockAddr(dest.ip, dest.port, addr)) return -1;
    return int(::sendto(e->fd, reinterpret_cast<const char*>(data.data()),
                        int(data.size()), 0,
                        reinterpret_cast<sockaddr*>(&addr), sizeof(addr)));
}

int PollTransport::udpRecvFrom(SockHandle h, std::span<uint8_t> buf,
                               SockAddr& src_out) {
    auto* e = d_->findUdp(h);
    if (!e || e->fd == INVALID_SOCK) return -1;
    sockaddr_in peer{};
    socklen_t plen = sizeof(peer);
    const auto n = ::recvfrom(e->fd, reinterpret_cast<char*>(buf.data()),
                              int(buf.size()), 0,
                              reinterpret_cast<sockaddr*>(&peer), &plen);
    if (n > 0) {
        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
        src_out.ip   = ip;
        src_out.port = ntohs(peer.sin_port);
        return int(n);
    }
    return n == 0 ? 0 : -1;
}

void PollTransport::onUdpReadable(SockHandle h, std::function<void()> cb) {
    if (auto* e = d_->findUdp(h)) e->onReadable = std::move(cb);
}

void PollTransport::udpClose(SockHandle h) {
    auto* e = d_->findUdp(h);
    if (!e) return;
    if (e->fd != INVALID_SOCK) sock_close(e->fd);
    d_->udp.erase(h);
}

// ── timers ────────────────────────────────────────────────────────────

TimerHandle PollTransport::createTimer(int ms, bool repeating,
                                       std::function<void()> fn) {
    const int h = d_->nextHandle++;
    TimerEntry t;
    t.intervalMs = ms;
    t.repeating  = repeating;
    t.active     = false;
    t.cb         = std::move(fn);
    d_->timers.emplace(h, std::move(t));
    return h;
}
void PollTransport::startTimer(TimerHandle h) {
    if (auto* t = d_->findTimer(h)) {
        t->deadlineMs = now_ms() + uint64_t(t->intervalMs < 0 ? 0 : t->intervalMs);
        t->active     = true;
    }
}
void PollTransport::stopTimer(TimerHandle h) {
    if (auto* t = d_->findTimer(h)) t->active = false;
}
void PollTransport::setTimerInterval(TimerHandle h, int ms) {
    if (auto* t = d_->findTimer(h)) t->intervalMs = ms;
}
void PollTransport::destroyTimer(TimerHandle h) {
    d_->timers.erase(h);
}

// ── run loop ──────────────────────────────────────────────────────────

void PollTransport::runLoop() {
    d_->running = true;
    std::vector<pollfd> pfds;
    std::vector<int>    tcpOrder;
    std::vector<int>    udpOrder;

    while (d_->running) {
        pfds.clear();
        tcpOrder.clear();
        udpOrder.clear();

        for (auto& [h, e] : d_->tcp) {
            if (e.fd == INVALID_SOCK) continue;
            pollfd p{};
            p.fd     = e.fd;
            p.events = (e.state == TcpState::Connecting) ? POLLOUT : POLLIN;
            if (e.state == TcpState::Connected && e.sendOff < e.sendBuf.size())
                p.events = short(p.events | POLLOUT);
            pfds.push_back(p);
            tcpOrder.push_back(h);
        }
        for (auto& [h, e] : d_->udp) {
            if (e.fd == INVALID_SOCK) continue;
            pollfd p{};
            p.fd     = e.fd;
            p.events = POLLIN;
            pfds.push_back(p);
            udpOrder.push_back(h);
        }

        int32_t to = d_->nextTimeoutMs();
        if (to < 0 || to > 50) to = 50;   // wake at least every 50 ms for stopLoop

        if (pfds.empty()) {
            portableSleepMs(to);
        } else {
            const int rc = sock_poll(pfds.data(), poll_nfds_t(pfds.size()), to);
            if (rc < 0) {
#ifndef _WIN32
                if (sock_errno() == EINTR) { d_->fireExpiredTimers(); continue; }
#endif
                // transient; let the timers run and retry
            } else if (rc > 0) {
                // TCP first. snapshot order; callbacks may mutate the maps, so
                // re-resolve each handle and skip ones that vanished.
                for (size_t i = 0; i < tcpOrder.size(); ++i) {
                    const short re = pfds[i].revents;
                    if (!re) continue;
                    const int h = tcpOrder[i];
                    TcpEntry* e = d_->findTcp(h);
                    if (!e || e->fd == INVALID_SOCK) continue;

                    if (e->state == TcpState::Connecting) {
                        if (re & (POLLOUT | POLLERR | POLLHUP | POLLNVAL)) {
                            int err = 0;
                            socklen_t len = sizeof(err);
                            ::getsockopt(e->fd, SOL_SOCKET, SO_ERROR,
                                         reinterpret_cast<char*>(&err), &len);
                            if (re & (POLLERR | POLLNVAL)) err = err ? err : -1;
                            if (err == 0) {
                                e->state = TcpState::Connected;
                                if (!e->sendBuf.empty()) d_->drainSend(*e);
                                auto cb = e->onConnected;
                                if (cb) cb(true);
                            } else {
                                auto cb = e->onConnected;
                                sock_close(e->fd);
                                e->fd = INVALID_SOCK;
                                d_->tcp.erase(h);
                                if (cb) cb(false);
                            }
                        }
                        continue;
                    }

                    // connected socket
                    if (re & (POLLERR | POLLNVAL)) {
                        auto cb = e->onError;
                        if (cb) cb("socket error");
                        continue;
                    }
                    if (re & POLLOUT) {
                        // a fatal send error (EPIPE/ECONNRESET) must surface now,
                        // not wait for a later POLLERR (Qt raised it immediately).
                        if (!d_->drainSend(*e)) {
                            auto cb = e->onError;
                            if (cb) cb("send error");
                            continue;
                        }
                    }
                    if (re & (POLLIN | POLLHUP)) {
                        auto rd = e->onReadable;
                        if (rd) rd();
                        // onReadable drained via tcpRecv; an EOF seen there (or
                        // a bare POLLHUP) means the peer hung up.
                        e = d_->findTcp(h);
                        if (!e) continue;
                        if (e->eofPending || (re & POLLHUP)) {
                            auto cb = e->onDisconnected;
                            if (e->fd != INVALID_SOCK) sock_close(e->fd);
                            d_->tcp.erase(h);
                            if (cb) cb();
                        }
                    }
                }
                // UDP
                for (size_t i = 0; i < udpOrder.size(); ++i) {
                    const short re = pfds[tcpOrder.size() + i].revents;
                    if (!(re & (POLLIN | POLLERR | POLLHUP))) continue;
                    UdpEntry* e = d_->findUdp(udpOrder[i]);
                    if (!e || e->fd == INVALID_SOCK) continue;
                    auto rd = e->onReadable;
                    if (rd) rd();
                }
            }
        }

        d_->fireExpiredTimers();
    }
}

void PollTransport::stopLoop() {
    d_->running = false;
}

} // namespace fxchain
