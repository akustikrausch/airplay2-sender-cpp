// SPDX-License-Identifier: Apache-2.0
//
// raop_qt_host.cpp -- RaopIo on top of QTcpSocket / QUdpSocket / QTimer.
//
// thin delegation: each slot owns one Qt socket whose signals call straight
// into the sender's on*() methods. signals are disconnected before a socket
// is dropped, so a late signal can never reach a slot that was recycled.
// single-threaded on the Qt event-loop thread, like the sender itself.
//
// NOTE: this file is only compiled with -DAIRPLAY_BUILD_QT_HOST=ON and is not
// covered by the project's CI (which has no Qt). verify it inside the Qt
// application that uses it.

#include "raop_qt_host.h"
#include "raop_sender.h"

#include <QAbstractSocket>
#include <QByteArray>
#include <QHostAddress>
#include <QObject>
#include <QString>
#include <QTcpSocket>
#include <QTimer>
#include <QUdpSocket>

#include <array>

namespace fxchain {

namespace {

// an ipv4 endpoint as the sender wants it; a v4-mapped v6 address
// ("::ffff:a.b.c.d") is folded back to its dotted quad.
RaopEndpoint endpointOf(const QHostAddress& a, quint16 port) {
    bool ok = false;
    const quint32 ip4 = a.toIPv4Address(&ok);
    const QHostAddress v4 = ok ? QHostAddress(ip4) : a;
    return RaopEndpoint{v4.toString().toStdString(), port};
}

std::span<const uint8_t> spanOf(const QByteArray& b) {
    return std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(b.constData()), size_t(b.size()));
}

} // namespace

struct RaopQtHost::Impl {
    struct Tcp {
        QTcpSocket* sock = nullptr;
        bool connected = false;
    };
    struct Udp {
        QUdpSocket* sock = nullptr;
    };
    std::array<Tcp, 2> tcp;
    std::array<Udp, 3> udp;
    RaopSender* sender = nullptr;
    QTimer ticker;

    Tcp& t(RaopTcp ch) { return tcp[size_t(ch)]; }
    Udp& u(RaopUdp s)  { return udp[size_t(s)]; }

    void dropTcp(Tcp& s, bool now = false) {
        if (!s.sock) return;
        QObject::disconnect(s.sock, nullptr, nullptr, nullptr);
        s.sock->abort();
        if (now) delete s.sock; else s.sock->deleteLater();
        s.sock = nullptr;
        s.connected = false;
    }
    void dropUdp(Udp& s, bool now = false) {
        if (!s.sock) return;
        QObject::disconnect(s.sock, nullptr, nullptr, nullptr);
        s.sock->close();
        if (now) delete s.sock; else s.sock->deleteLater();
        s.sock = nullptr;
    }
};

RaopQtHost::RaopQtHost() : d_(std::make_unique<Impl>()) {
    d_->ticker.setTimerType(Qt::PreciseTimer);
    QObject::connect(&d_->ticker, &QTimer::timeout, &d_->ticker, [this] {
        if (!d_->sender) return;
        d_->sender->tick();
        d_->ticker.setInterval(d_->sender->active() ? 4 : 50);
    });
}

RaopQtHost::~RaopQtHost() {
    release();
    for (auto& s : d_->tcp) d_->dropTcp(s, true);
    for (auto& s : d_->udp) d_->dropUdp(s, true);
}

void RaopQtHost::drive(RaopSender& sender) {
    d_->sender = &sender;
    d_->ticker.start(4);
}

void RaopQtHost::release() {
    d_->ticker.stop();
    d_->sender = nullptr;
}

// -- RaopIo: tcp -------------------------------------------------------

void RaopQtHost::tcpConnect(RaopTcp ch, const std::string& host, uint16_t port) {
    Impl::Tcp& slot = d_->t(ch);
    d_->dropTcp(slot);
    auto* s = new QTcpSocket();
    slot.sock = s;
    s->setSocketOption(QAbstractSocket::LowDelayOption, 1);   // TCP_NODELAY

    QObject::connect(s, &QTcpSocket::connected, s, [this, ch] {
        Impl::Tcp& t = d_->t(ch);
        if (!t.sock || !d_->sender) return;
        t.connected = true;
        d_->sender->onTcpConnected(ch,
            endpointOf(t.sock->localAddress(), t.sock->localPort()),
            endpointOf(t.sock->peerAddress(), t.sock->peerPort()));
    });
    QObject::connect(s, &QTcpSocket::readyRead, s, [this, ch] {
        Impl::Tcp& t = d_->t(ch);
        if (!t.sock || !d_->sender) return;
        const QByteArray data = t.sock->readAll();
        if (!data.isEmpty()) d_->sender->onTcpData(ch, spanOf(data));
    });
    QObject::connect(s, &QAbstractSocket::errorOccurred, s, [this, ch](QAbstractSocket::SocketError err) {
        Impl::Tcp& t = d_->t(ch);
        if (!t.sock || !d_->sender) return;
        const std::string why = t.sock->errorString().toStdString();
        if (!t.connected) {
            d_->dropTcp(t);
            d_->sender->onTcpConnectFailed(ch, why);
            return;
        }
        // a peer FIN arrives as RemoteHostClosedError followed by disconnected():
        // let disconnected() report it as a clean close. anything else is an error.
        if (err == QAbstractSocket::RemoteHostClosedError) return;
        d_->dropTcp(t);
        d_->sender->onTcpClosed(ch, why);
    });
    QObject::connect(s, &QTcpSocket::disconnected, s, [this, ch] {
        Impl::Tcp& t = d_->t(ch);
        if (!t.sock || !d_->sender) return;
        d_->dropTcp(t);
        d_->sender->onTcpClosed(ch, std::string());
    });

    s->connectToHost(QString::fromStdString(host), port);
}

void RaopQtHost::tcpSend(RaopTcp ch, std::span<const uint8_t> bytes) {
    Impl::Tcp& t = d_->t(ch);
    if (!t.sock || bytes.empty()) return;
    t.sock->write(reinterpret_cast<const char*>(bytes.data()), qint64(bytes.size()));
}

void RaopQtHost::tcpClose(RaopTcp ch, bool flush) {
    Impl::Tcp& t = d_->t(ch);
    if (!t.sock) return;
    if (flush && t.connected) {
        // the old flush + waitForBytesWritten + disconnectFromHost + waitForDisconnected(300)
        QObject::disconnect(t.sock, nullptr, nullptr, nullptr);
        t.sock->flush();
        t.sock->waitForBytesWritten(500);
        t.sock->disconnectFromHost();
        if (t.sock->state() != QAbstractSocket::UnconnectedState)
            t.sock->waitForDisconnected(300);
    }
    d_->dropTcp(t);
}

// -- RaopIo: udp -------------------------------------------------------

uint16_t RaopQtHost::udpBind(RaopUdp which) {
    Impl::Udp& u = d_->u(which);
    d_->dropUdp(u);
    auto* s = new QUdpSocket();
    if (!s->bind(QHostAddress::AnyIPv4, 0)) {
        delete s;
        return 0;
    }
    u.sock = s;
    QObject::connect(s, &QUdpSocket::readyRead, s, [this, which] {
        Impl::Udp& slot = d_->u(which);
        while (slot.sock && d_->sender && slot.sock->hasPendingDatagrams()) {
            QByteArray dg;
            dg.resize(int(slot.sock->pendingDatagramSize()));
            QHostAddress from;
            quint16 port = 0;
            const qint64 n = slot.sock->readDatagram(dg.data(), dg.size(), &from, &port);
            if (n < 0) break;
            dg.resize(int(n));
            d_->sender->onUdpDatagram(which, spanOf(dg), endpointOf(from, port));
        }
    });
    return s->localPort();
}

void RaopQtHost::udpSend(RaopUdp which, const RaopEndpoint& to, std::span<const uint8_t> bytes) {
    Impl::Udp& u = d_->u(which);
    if (!u.sock) return;
    u.sock->writeDatagram(reinterpret_cast<const char*>(bytes.data()), qint64(bytes.size()),
                          QHostAddress(QString::fromStdString(to.ip)), to.port);
}

void RaopQtHost::udpClose(RaopUdp which) {
    d_->dropUdp(d_->u(which));
}

} // namespace fxchain
