// SPDX-License-Identifier: Apache-2.0
//
// qt_transport.cpp -- ITransport on top of Qt sockets/timers (optional).
//
// thin delegation: each handle owns a QTcpSocket / QUdpSocket / QTimer whose
// Qt signals are wired to the ITransport callbacks. no Q_OBJECT here, the
// adapter never emits signals of its own, it only connects existing ones to
// lambdas (with the socket as the connection context so a deleted socket
// auto-disconnects). single-threaded on the Qt event-loop thread.

#include "qt_transport.h"

#include <QAbstractSocket>
#include <QByteArray>
#include <QEventLoop>
#include <QHostAddress>
#include <QString>
#include <QTcpSocket>
#include <QTimer>
#include <QUdpSocket>

#include <memory>
#include <unordered_map>

namespace fxchain {

struct QtTransport::Impl {
    struct Tcp {
        std::unique_ptr<QTcpSocket>      sock;
        std::function<void(bool)>        onConnected;
        std::function<void()>            onReadable;
        std::function<void()>            onDisconnected;
        std::function<void(std::string)> onError;
        bool connectedFired = false;
    };
    struct Udp {
        std::unique_ptr<QUdpSocket> sock;
        std::function<void()>       onReadable;
    };
    struct Tim {
        std::unique_ptr<QTimer> timer;
    };

    std::unordered_map<int, Tcp> tcp;
    std::unordered_map<int, Udp> udp;
    std::unordered_map<int, Tim> tim;
    int       nextHandle = 1;
    QEventLoop loop;

    Tcp* findTcp(int h) { auto it = tcp.find(h); return it == tcp.end() ? nullptr : &it->second; }
    Udp* findUdp(int h) { auto it = udp.find(h); return it == udp.end() ? nullptr : &it->second; }
    Tim* findTim(int h) { auto it = tim.find(h); return it == tim.end() ? nullptr : &it->second; }
};

QtTransport::QtTransport() : d_(std::make_unique<Impl>()) {}
QtTransport::~QtTransport() = default;

// ── TCP ──────────────────────────────────────────────────────────────

SockHandle QtTransport::tcpConnect(const std::string& host, uint16_t port) {
    const int h = d_->nextHandle++;
    Impl::Tcp& e = d_->tcp[h];
    e.sock = std::make_unique<QTcpSocket>();
    QTcpSocket* s = e.sock.get();

    QObject::connect(s, &QTcpSocket::connected, s, [this, h] {
        if (auto* t = d_->findTcp(h)) {
            t->connectedFired = true;
            if (t->onConnected) t->onConnected(true);
        }
    });
    QObject::connect(s, &QTcpSocket::readyRead, s, [this, h] {
        if (auto* t = d_->findTcp(h)) if (t->onReadable) t->onReadable();
    });
    QObject::connect(s, &QTcpSocket::disconnected, s, [this, h] {
        if (auto* t = d_->findTcp(h)) if (t->onDisconnected) t->onDisconnected();
    });
    QObject::connect(s, &QAbstractSocket::errorOccurred, s,
                     [this, h](QAbstractSocket::SocketError) {
        auto* t = d_->findTcp(h);
        if (!t || !t->sock) return;
        // a failure before the connect completes is a connect failure; after
        // it, a live-session error (mirrors the two original Qt handlers).
        if (!t->connectedFired
            && t->sock->state() != QAbstractSocket::ConnectedState) {
            if (t->onConnected) t->onConnected(false);
        } else if (t->onError) {
            t->onError(t->sock->errorString().toStdString());
        }
    });

    s->setSocketOption(QAbstractSocket::LowDelayOption, 1);   // TCP_NODELAY
    s->connectToHost(QString::fromStdString(host), port);
    return h;
}

void QtTransport::onTcpConnected(SockHandle h, std::function<void(bool)> cb) {
    if (auto* t = d_->findTcp(h)) t->onConnected = std::move(cb);
}
void QtTransport::onTcpReadable(SockHandle h, std::function<void()> cb) {
    if (auto* t = d_->findTcp(h)) t->onReadable = std::move(cb);
}
void QtTransport::onTcpDisconnected(SockHandle h, std::function<void()> cb) {
    if (auto* t = d_->findTcp(h)) t->onDisconnected = std::move(cb);
}
void QtTransport::onTcpError(SockHandle h, std::function<void(std::string)> cb) {
    if (auto* t = d_->findTcp(h)) t->onError = std::move(cb);
}

int QtTransport::tcpSend(SockHandle h, std::span<const uint8_t> data) {
    auto* t = d_->findTcp(h);
    if (!t || !t->sock) return -1;
    const qint64 n = t->sock->write(reinterpret_cast<const char*>(data.data()),
                                    qint64(data.size()));
    return n < 0 ? -1 : int(n);
}

int QtTransport::tcpRecv(SockHandle h, std::span<uint8_t> buf) {
    auto* t = d_->findTcp(h);
    if (!t || !t->sock) return -1;
    const qint64 n = t->sock->read(reinterpret_cast<char*>(buf.data()),
                                   qint64(buf.size()));
    return n < 0 ? -1 : int(n);   // EOF arrives via the disconnected signal
}

void QtTransport::tcpDisconnect(SockHandle h) {
    auto* t = d_->findTcp(h);
    if (!t || !t->sock) { d_->tcp.erase(h); return; }
    // flush queued bytes (the final TEARDOWN) then half-close, matching the
    // old flush + waitForBytesWritten + disconnectFromHost in stop().
    t->sock->flush();
    t->sock->disconnectFromHost();
    if (t->sock->state() != QAbstractSocket::UnconnectedState)
        t->sock->waitForDisconnected(300);
    d_->tcp.erase(h);
}

void QtTransport::tcpClose(SockHandle h) {
    auto* t = d_->findTcp(h);
    if (!t) return;
    if (t->sock) t->sock->abort();
    d_->tcp.erase(h);
}

SockAddr QtTransport::tcpLocalAddr(SockHandle h) {
    SockAddr out;
    auto* t = d_->findTcp(h);
    if (t && t->sock) {
        out.ip   = t->sock->localAddress().toString().toStdString();
        out.port = t->sock->localPort();
    }
    return out;
}

// ── UDP ──────────────────────────────────────────────────────────────

SockHandle QtTransport::udpBind(uint16_t port_hint) {
    const int h = d_->nextHandle++;
    Impl::Udp& e = d_->udp[h];
    e.sock = std::make_unique<QUdpSocket>();
    if (!e.sock->bind(QHostAddress::AnyIPv4, port_hint)) {
        d_->udp.erase(h);
        return kInvalidSock;
    }
    QUdpSocket* s = e.sock.get();
    QObject::connect(s, &QUdpSocket::readyRead, s, [this, h] {
        if (auto* u = d_->findUdp(h)) if (u->onReadable) u->onReadable();
    });
    return h;
}

uint16_t QtTransport::udpLocalPort(SockHandle h) {
    auto* u = d_->findUdp(h);
    return (u && u->sock) ? u->sock->localPort() : 0;
}

int QtTransport::udpSendTo(SockHandle h, std::span<const uint8_t> data,
                           const SockAddr& dest) {
    auto* u = d_->findUdp(h);
    if (!u || !u->sock) return -1;
    const qint64 n = u->sock->writeDatagram(
        reinterpret_cast<const char*>(data.data()), qint64(data.size()),
        QHostAddress(QString::fromStdString(dest.ip)), dest.port);
    return n < 0 ? -1 : int(n);
}

int QtTransport::udpRecvFrom(SockHandle h, std::span<uint8_t> buf,
                             SockAddr& src_out) {
    auto* u = d_->findUdp(h);
    if (!u || !u->sock) return -1;
    if (!u->sock->hasPendingDatagrams()) return 0;
    QHostAddress from;
    quint16 fromPort = 0;
    const qint64 n = u->sock->readDatagram(
        reinterpret_cast<char*>(buf.data()), qint64(buf.size()),
        &from, &fromPort);
    if (n < 0) return -1;
    src_out.ip   = from.toString().toStdString();
    src_out.port = fromPort;
    return int(n);
}

void QtTransport::onUdpReadable(SockHandle h, std::function<void()> cb) {
    if (auto* u = d_->findUdp(h)) u->onReadable = std::move(cb);
}

void QtTransport::udpClose(SockHandle h) {
    d_->udp.erase(h);
}

// ── timers ────────────────────────────────────────────────────────────

TimerHandle QtTransport::createTimer(int ms, bool repeating,
                                     std::function<void()> fn) {
    const int h = d_->nextHandle++;
    Impl::Tim& e = d_->tim[h];
    e.timer = std::make_unique<QTimer>();
    e.timer->setInterval(ms);
    e.timer->setSingleShot(!repeating);
    if (repeating) e.timer->setTimerType(Qt::PreciseTimer);  // the 8 ms pacer wants precision
    QTimer* t = e.timer.get();
    QObject::connect(t, &QTimer::timeout, t, [fn = std::move(fn)] { if (fn) fn(); });
    return h;
}
void QtTransport::startTimer(TimerHandle h) {
    if (auto* t = d_->findTim(h)) t->timer->start();
}
void QtTransport::stopTimer(TimerHandle h) {
    if (auto* t = d_->findTim(h)) t->timer->stop();
}
void QtTransport::setTimerInterval(TimerHandle h, int ms) {
    if (auto* t = d_->findTim(h)) t->timer->setInterval(ms);
}
void QtTransport::destroyTimer(TimerHandle h) {
    d_->tim.erase(h);
}

// ── run loop ──────────────────────────────────────────────────────────

void QtTransport::runLoop() { d_->loop.exec(); }
void QtTransport::stopLoop() { d_->loop.quit(); }

} // namespace fxchain
