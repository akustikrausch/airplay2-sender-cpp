// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// net_compat.h -- the thin POSIX/Winsock shim the poll adapter sits on.
// ----------------------------------------------------------------------------
// included ONLY by poll_transport.cpp. it hides the handful of differences
// between BSD sockets and Winsock behind POSIX-shaped names so the adapter
// body stays one code path. nothing Qt, nothing public.

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #pragma comment(lib, "Ws2_32.lib")
  using socket_t = SOCKET;
  using poll_nfds_t = ULONG;
  inline constexpr socket_t INVALID_SOCK = INVALID_SOCKET;
  inline int  sock_close(socket_t s)           { return closesocket(s); }
  inline int  sock_set_nonblocking(socket_t s) { u_long m = 1; return ioctlsocket(s, FIONBIO, &m); }
  inline int  sock_errno()                     { return WSAGetLastError(); }
  inline bool err_would_block(int e)           { return e == WSAEWOULDBLOCK; }
  inline bool err_in_progress(int e)           { return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS; }
  inline int  sock_poll(WSAPOLLFD* fds, poll_nfds_t n, int ms) { return WSAPoll(fds, n, ms); }
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <poll.h>
  #include <fcntl.h>
  #include <unistd.h>
  #include <errno.h>
  using socket_t = int;
  using poll_nfds_t = nfds_t;
  inline constexpr socket_t INVALID_SOCK = -1;
  inline int  sock_close(socket_t s)           { return ::close(s); }
  inline int  sock_set_nonblocking(socket_t s) { int f = ::fcntl(s, F_GETFL, 0); return ::fcntl(s, F_SETFL, f | O_NONBLOCK); }
  inline int  sock_errno()                     { return errno; }
  inline bool err_would_block(int e)           { return e == EAGAIN || e == EWOULDBLOCK; }
  inline bool err_in_progress(int e)           { return e == EINPROGRESS || e == EAGAIN || e == EWOULDBLOCK; }
  inline int  sock_poll(pollfd* fds, poll_nfds_t n, int ms) { return ::poll(fds, n, ms); }
#endif

#include <cstdint>
#include <ctime>

// monotonic milliseconds (the timer wheel's clock; never wall time).
inline uint64_t now_ms() {
#ifdef _WIN32
    static LARGE_INTEGER freq = [] { LARGE_INTEGER f; QueryPerformanceFrequency(&f); return f; }();
    LARGE_INTEGER cnt; QueryPerformanceCounter(&cnt);
    return uint64_t(cnt.QuadPart) * 1000ULL / uint64_t(freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return uint64_t(ts.tv_sec) * 1000ULL + uint64_t(ts.tv_nsec) / 1000000ULL;
#endif
}
