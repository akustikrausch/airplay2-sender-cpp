// SPDX-License-Identifier: Apache-2.0
//
// raop_loop.cpp -- the bundled poll()/WSAPoll() host for RaopSender.
//
// design notes:
//   * five fixed slots, each carrying a generation counter. every callback
//     into the sender may open or close slots (a fail_() closes all of them,
//     the session SETUP reply opens the event channel), so after each call
//     the loop re-checks "is this still the socket I was handling?" by
//     (fd, generation) and never touches a slot that was recycled.
//   * nothing is reported to the sender from inside one of its own calls: a
//     connect that cannot even be started, or a send that fails, is parked
//     on the slot and delivered at the start of the next pump().
//   * errors close the socket first and report second, so no POLLERR can be
//     reported twice and the loop cannot spin on a dead descriptor.

#include "raop_loop.h"
#include "raop_sender.h"

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
  #include <errno.h>
  #include <fcntl.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <poll.h>
  #include <sys/socket.h>
  #include <unistd.h>
#endif

#include <algorithm>
#include <array>
#include <cstring>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace fxchain {

namespace {

#ifdef _WIN32
using sock_t   = SOCKET;
using pollfd_t = WSAPOLLFD;
using buflen_t = int;
constexpr sock_t kBadSock = INVALID_SOCKET;
constexpr short  kPollIn  = POLLRDNORM;
constexpr short  kPollOut = POLLWRNORM;
constexpr int    kSendFlags = 0;
constexpr int    kShutWrite = SD_SEND;
int  lastError()              { return WSAGetLastError(); }
bool wouldBlock(int e)        { return e == WSAEWOULDBLOCK; }
bool connectInProgress(int e) { return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS; }
void closeSocket(sock_t s)    { ::closesocket(s); }
bool setNonBlocking(sock_t s) { u_long one = 1; return ::ioctlsocket(s, FIONBIO, &one) == 0; }
int  pollSockets(pollfd_t* p, size_t n, int ms) { return ::WSAPoll(p, ULONG(n), ms); }
std::string errorText(int e)  { return "winsock error " + std::to_string(e); }
#else
using sock_t   = int;
using pollfd_t = pollfd;
using buflen_t = size_t;
constexpr sock_t kBadSock = -1;
constexpr short  kPollIn  = POLLIN;
constexpr short  kPollOut = POLLOUT;
#ifdef MSG_NOSIGNAL
constexpr int    kSendFlags = MSG_NOSIGNAL;
#else
constexpr int    kSendFlags = 0;
#endif
constexpr int    kShutWrite = SHUT_WR;
int  lastError()              { return errno; }
bool wouldBlock(int e)        { return e == EAGAIN || e == EWOULDBLOCK; }
bool connectInProgress(int e) { return e == EINPROGRESS || e == EAGAIN || e == EWOULDBLOCK; }
void closeSocket(sock_t s)    { ::close(s); }
bool setNonBlocking(sock_t s) {
    const int f = ::fcntl(s, F_GETFL, 0);
    return f >= 0 && ::fcntl(s, F_SETFL, f | O_NONBLOCK) == 0;
}
int  pollSockets(pollfd_t* p, size_t n, int ms) { return ::poll(p, nfds_t(n), ms); }
std::string errorText(int e)  { return std::strerror(e); }
#endif

// macOS has no MSG_NOSIGNAL; SO_NOSIGPIPE on the socket does the same job.
void disableSigpipe(sock_t s) {
#ifdef SO_NOSIGPIPE
    int one = 1;
    ::setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, reinterpret_cast<const char*>(&one), sizeof(one));
#else
    (void)s;
#endif
}

bool toSockAddr(const std::string& ip, uint16_t port, sockaddr_in& out) {
    std::memset(&out, 0, sizeof(out));
    out.sin_family = AF_INET;
    out.sin_port   = htons(port);
    return ::inet_pton(AF_INET, ip.c_str(), &out.sin_addr) == 1;
}

RaopEndpoint fromSockAddr(const sockaddr_in& a) {
    char buf[INET_ADDRSTRLEN] = {0};
    ::inet_ntop(AF_INET, const_cast<in_addr*>(&a.sin_addr), buf, sizeof(buf));
    return RaopEndpoint{buf, ntohs(a.sin_port)};
}

RaopEndpoint localOf(sock_t fd) {
    sockaddr_in a{};
    socklen_t len = sizeof(a);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&a), &len) != 0) return {};
    return fromSockAddr(a);
}

RaopEndpoint peerOf(sock_t fd) {
    sockaddr_in a{};
    socklen_t len = sizeof(a);
    if (::getpeername(fd, reinterpret_cast<sockaddr*>(&a), &len) != 0) return {};
    return fromSockAddr(a);
}

int socketError(sock_t fd) {
    int err = 0;
    socklen_t len = sizeof(err);
    ::getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len);
    return err;
}

struct TcpSlot {
    sock_t   fd  = kBadSock;
    uint32_t gen = 0;             // bumped on every open, see the header note
    bool     connecting = false;
    bool     connected  = false;
    std::vector<uint8_t> out;     // unsent bytes
    size_t   outOff = 0;
    // parked notifications, delivered at the start of the next pump():
    std::optional<std::string> failedToStart;   // -> onTcpConnectFailed
    std::optional<std::string> sendFailed;      // -> onTcpClosed

    void reset() {
        fd = kBadSock;
        connecting = connected = false;
        out.clear();
        outOff = 0;
        failedToStart.reset();
        sendFailed.reset();
    }
};

struct UdpSlot {
    sock_t   fd  = kBadSock;
    uint32_t gen = 0;
};

} // namespace

struct RaopLoop::Impl {
    std::array<TcpSlot, 2> tcp;
    std::array<UdpSlot, 3> udp;

    TcpSlot& t(RaopTcp ch) { return tcp[size_t(ch)]; }
    UdpSlot& u(RaopUdp s)  { return udp[size_t(s)]; }

    void closeTcp(TcpSlot& s) {
        if (s.fd != kBadSock) closeSocket(s.fd);
        s.reset();
    }
    void closeUdp(UdpSlot& s) {
        if (s.fd != kBadSock) closeSocket(s.fd);
        s.fd = kBadSock;
    }

    // push as much of the queued bytes as the kernel takes right now.
    // false = fatal error (err filled in).
    bool drain(TcpSlot& s, int& err) {
        while (s.outOff < s.out.size()) {
            const auto n = ::send(s.fd,
                                  reinterpret_cast<const char*>(s.out.data() + s.outOff),
                                  buflen_t(s.out.size() - s.outOff), kSendFlags);
            if (n > 0) { s.outOff += size_t(n); continue; }
            err = lastError();
            if (n < 0 && wouldBlock(err)) return true;
            return false;
        }
        s.out.clear();
        s.outOff = 0;
        return true;
    }
};

RaopLoop::RaopLoop() : d_(std::make_unique<Impl>()) {
#ifdef _WIN32
    WSADATA wsa;
    ::WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
}

RaopLoop::~RaopLoop() {
    for (auto& s : d_->tcp) d_->closeTcp(s);
    for (auto& s : d_->udp) d_->closeUdp(s);
#ifdef _WIN32
    ::WSACleanup();
#endif
}

// -- RaopIo: tcp -------------------------------------------------------

void RaopLoop::tcpConnect(RaopTcp ch, const std::string& host, uint16_t port) {
    TcpSlot& s = d_->t(ch);
    d_->closeTcp(s);
    ++s.gen;

    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) {
        s.failedToStart = "cannot resolve " + host;
        return;
    }
    sockaddr_in dst{};
    std::memcpy(&dst, res->ai_addr, std::min(sizeof(dst), size_t(res->ai_addrlen)));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(port);
    ::freeaddrinfo(res);

    const sock_t fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == kBadSock) {
        s.failedToStart = "socket: " + errorText(lastError());
        return;
    }
    setNonBlocking(fd);
    disableSigpipe(fd);
    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));

    // non-blocking connect: 0 (loopback can complete at once) or
    // in-progress are both "connecting"; pump() confirms via POLLOUT +
    // SO_ERROR and reports from there, never from here.
    const int rc = ::connect(fd, reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
    if (rc != 0 && !connectInProgress(lastError())) {
        const std::string why = errorText(lastError());
        closeSocket(fd);
        s.failedToStart = why;
        return;
    }
    s.fd = fd;
    s.connecting = true;
    s.connected  = false;
}

void RaopLoop::tcpSend(RaopTcp ch, std::span<const uint8_t> bytes) {
    TcpSlot& s = d_->t(ch);
    if (s.fd == kBadSock || bytes.empty()) return;
    s.out.insert(s.out.end(), bytes.begin(), bytes.end());
    if (!s.connected) return;   // flushed once the connect completes
    int err = 0;
    if (!d_->drain(s, err) && !s.sendFailed)
        s.sendFailed = "send failed: " + errorText(err);
}

void RaopLoop::tcpClose(RaopTcp ch, bool flush) {
    TcpSlot& s = d_->t(ch);
    if (s.fd == kBadSock) { s.reset(); return; }
    if (flush && s.connected && !s.sendFailed) {
        using namespace std::chrono;
        // the TEARDOWN must reach the wire before the FIN, otherwise the
        // receiver keeps the session open for minutes. bounded.
        const auto sendDeadline = steady_clock::now() + milliseconds(500);
        int err = 0;
        while (s.outOff < s.out.size() && steady_clock::now() < sendDeadline) {
            if (!d_->drain(s, err)) break;
            if (s.outOff >= s.out.size()) break;
            const auto left = duration_cast<milliseconds>(sendDeadline - steady_clock::now()).count();
            pollfd_t p{};
            p.fd = s.fd;
            p.events = kPollOut;
            pollSockets(&p, 1, int(std::max<long long>(1, left)));
        }
        ::shutdown(s.fd, kShutWrite);
        // give the peer up to 300 ms to answer our FIN with its own (the
        // old waitForDisconnected(300)); drain whatever it still says.
        const auto finDeadline = steady_clock::now() + milliseconds(300);
        char sink[1024];
        for (;;) {
            const auto left = duration_cast<milliseconds>(finDeadline - steady_clock::now()).count();
            if (left <= 0) break;
            pollfd_t p{};
            p.fd = s.fd;
            p.events = kPollIn;
            if (pollSockets(&p, 1, int(left)) <= 0) break;
            const auto n = ::recv(s.fd, sink, buflen_t(sizeof(sink)), 0);
            if (n > 0) continue;
            if (n < 0 && wouldBlock(lastError())) continue;
            break;   // FIN or error: done
        }
    }
    d_->closeTcp(s);
}

// -- RaopIo: udp -------------------------------------------------------

uint16_t RaopLoop::udpBind(RaopUdp which) {
    UdpSlot& u = d_->u(which);
    d_->closeUdp(u);
    ++u.gen;
    const sock_t fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == kBadSock) return 0;
    int rcvbuf = 256 * 1024;   // best effort, retransmit requests are bursty
    ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcvbuf), sizeof(rcvbuf));
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = 0;
    if (::bind(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        closeSocket(fd);
        return 0;
    }
    setNonBlocking(fd);
    const RaopEndpoint local = localOf(fd);
    if (local.port == 0) { closeSocket(fd); return 0; }
    u.fd = fd;
    return local.port;
}

void RaopLoop::udpSend(RaopUdp which, const RaopEndpoint& to, std::span<const uint8_t> bytes) {
    UdpSlot& u = d_->u(which);
    if (u.fd == kBadSock) return;
    sockaddr_in addr{};
    if (!toSockAddr(to.ip, to.port, addr)) return;
    ::sendto(u.fd, reinterpret_cast<const char*>(bytes.data()), buflen_t(bytes.size()),
             kSendFlags, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
}

void RaopLoop::udpClose(RaopUdp which) {
    d_->closeUdp(d_->u(which));
}

// -- the loop ----------------------------------------------------------

void RaopLoop::run(RaopSender& sender) {
    while (!stop_.load()) pump(sender);
}

void RaopLoop::pump(RaopSender& sender, std::chrono::milliseconds maxWait) {
    using namespace std::chrono;
    Impl& d = *d_;

    // 1. parked notifications first, outside of any sender call.
    for (size_t i = 0; i < d.tcp.size(); ++i) {
        TcpSlot& s = d.tcp[i];
        const auto ch = RaopTcp(i);
        if (s.failedToStart) {
            const std::string why = *s.failedToStart;
            d.closeTcp(s);
            sender.onTcpConnectFailed(ch, why);
        } else if (s.sendFailed) {
            const std::string why = *s.sendFailed;
            d.closeTcp(s);
            sender.onTcpClosed(ch, why);
        }
    }

    // 2. how long may we block: the sender's next deadline, capped.
    long long waitMs = maxWait.count();
    if (const auto dl = sender.nextDeadline()) {
        const auto left = *dl - RaopSender::Clock::now();
        // round UP so a deadline 0.3 ms away does not turn into a busy spin
        const long long ms = left.count() <= 0
            ? 0 : duration_cast<milliseconds>(left + microseconds(999)).count();
        waitMs = std::min(waitMs, ms);
    }
    if (waitMs < 0) waitMs = 0;

    // 3. snapshot the live sockets.
    struct Entry { bool tcp; size_t idx; sock_t fd; uint32_t gen; };
    std::vector<pollfd_t> pfds;
    std::vector<Entry>    entries;
    pfds.reserve(5);
    entries.reserve(5);
    for (size_t i = 0; i < d.tcp.size(); ++i) {
        const TcpSlot& s = d.tcp[i];
        if (s.fd == kBadSock) continue;
        pollfd_t p{};
        p.fd = s.fd;
        p.events = s.connecting ? kPollOut
                 : short(kPollIn | (s.outOff < s.out.size() ? kPollOut : 0));
        pfds.push_back(p);
        entries.push_back({true, i, s.fd, s.gen});
    }
    for (size_t i = 0; i < d.udp.size(); ++i) {
        const UdpSlot& u = d.udp[i];
        if (u.fd == kBadSock) continue;
        pollfd_t p{};
        p.fd = u.fd;
        p.events = kPollIn;
        pfds.push_back(p);
        entries.push_back({false, i, u.fd, u.gen});
    }

    // 4. wait.
    int ready = 0;
    if (pfds.empty()) {
        if (waitMs > 0) std::this_thread::sleep_for(milliseconds(waitMs));
    } else {
        ready = pollSockets(pfds.data(), pfds.size(), int(waitMs));
    }

    // 5. deliver. every sender call may close/open slots: re-validate by
    //    (fd, generation) before touching a slot again.
    for (size_t i = 0; ready > 0 && i < entries.size(); ++i) {
        const short re = pfds[i].revents;
        if (!re) continue;
        const Entry& e = entries[i];

        if (!e.tcp) {
            UdpSlot& u = d.udp[e.idx];
            if (u.fd != e.fd || u.gen != e.gen) continue;
            if (!(re & (kPollIn | POLLERR | POLLHUP))) continue;
            const auto which = RaopUdp(e.idx);
            uint8_t buf[4096];
            for (int burst = 0; burst < 64; ++burst) {
                sockaddr_in from{};
                socklen_t flen = sizeof(from);
                const auto n = ::recvfrom(u.fd, reinterpret_cast<char*>(buf), buflen_t(sizeof(buf)), 0,
                                          reinterpret_cast<sockaddr*>(&from), &flen);
                if (n > 0) {
                    const uint32_t gen = u.gen;
                    sender.onUdpDatagram(which, std::span<const uint8_t>(buf, size_t(n)), fromSockAddr(from));
                    if (u.fd != e.fd || u.gen != gen) break;   // the sender closed it
                    continue;
                }
                if (n == 0) continue;                      // empty datagram
                const int err = lastError();
                if (!wouldBlock(err)) (void)socketError(u.fd);   // clear a pending ICMP error
                break;
            }
            continue;
        }

        TcpSlot& s = d.tcp[e.idx];
        if (s.fd != e.fd || s.gen != e.gen) continue;
        const auto ch = RaopTcp(e.idx);

        if (s.connecting) {
            if (!(re & (kPollOut | POLLERR | POLLHUP))) continue;
            const int err = socketError(s.fd);
            if (err != 0 || (re & (POLLERR | POLLHUP))) {
                const std::string why = err ? errorText(err) : std::string("connection failed");
                d.closeTcp(s);
                sender.onTcpConnectFailed(ch, why);
                continue;
            }
            s.connecting = false;
            s.connected  = true;
            const uint32_t gen = s.gen;
            const RaopEndpoint local = localOf(s.fd), peer = peerOf(s.fd);
            sender.onTcpConnected(ch, local, peer);
            if (s.fd != e.fd || s.gen != gen) continue;
            int sendErr = 0;
            if (!d.drain(s, sendErr)) {
                d.closeTcp(s);
                sender.onTcpClosed(ch, "send failed: " + errorText(sendErr));
            }
            continue;
        }

        // connected
        if (re & (POLLERR | POLLNVAL)) {
            const int err = socketError(s.fd);
            const std::string why = err ? errorText(err) : std::string("socket error");
            d.closeTcp(s);
            sender.onTcpClosed(ch, why);
            continue;
        }
        if (re & kPollOut) {
            int err = 0;
            if (!d.drain(s, err)) {
                d.closeTcp(s);
                sender.onTcpClosed(ch, "send failed: " + errorText(err));
                continue;
            }
        }
        if (re & (kPollIn | POLLHUP)) {
            uint8_t buf[16384];
            for (;;) {
                const auto n = ::recv(s.fd, reinterpret_cast<char*>(buf), buflen_t(sizeof(buf)), 0);
                if (n > 0) {
                    const uint32_t gen = s.gen;
                    sender.onTcpData(ch, std::span<const uint8_t>(buf, size_t(n)));
                    if (s.fd != e.fd || s.gen != gen) break;   // the sender closed it
                    continue;
                }
                if (n == 0) {                                  // peer FIN
                    d.closeTcp(s);
                    sender.onTcpClosed(ch, std::string());
                    break;
                }
                const int err = lastError();
                if (wouldBlock(err)) break;
                d.closeTcp(s);
                sender.onTcpClosed(ch, errorText(err));
                break;
            }
        }
    }

    // 6. timers.
    sender.tick();
}

} // namespace fxchain
