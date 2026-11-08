#include "TransparentProxyProbe.hpp"

#include "TransparentProxyProbeProtocol.hpp"

#include <QElapsedTimer>
#include <QHostAddress>
#include <QNetworkInterface>
#include <QNetworkProxy>
#include <QTcpSocket>

#include <Security/SecRandom.h>
#include <string.h>

namespace interceptor {

bool verifyTransparentProxyProbe(const TransparentProxyProbeTarget &target,
                                 const QByteArray &secret, int timeoutMs, QString *error) {
    if (error)
        error->clear();
    const auto fail = [error](const QString &reason) {
        if (error)
            *error = reason;
        return false;
    };
    if (secret.size() != 32 || timeoutMs < 1 || timeoutMs > 3000 || target.listenerPort < 1 ||
        target.listenerPort > 65535 || target.upstreamPort < 1 || target.upstreamPort > 65535 ||
        target.interfaceName.isEmpty() || target.interfaceName.size() > 32 ||
        target.interfaceName.contains('\n') || target.interfaceName.contains('\r') ||
        target.interfaceName.contains(QChar::Null) ||
        QHostAddress(target.clientIp).protocol() != QAbstractSocket::IPv4Protocol ||
        QHostAddress(target.upstreamIp).protocol() != QAbstractSocket::IPv4Protocol)
        return fail(QStringLiteral("invalid_probe_target"));
    const QHostAddress listenerAddress(target.listenAddress);
    const auto iface = QNetworkInterface::interfaceFromName(target.interfaceName);
    bool ownsAddress = false;
    for (const auto &entry : iface.addressEntries())
        if (entry.ip() == listenerAddress)
            ownsAddress = true;
    if (!iface.isValid() || !iface.flags().testFlag(QNetworkInterface::IsUp) ||
        !iface.flags().testFlag(QNetworkInterface::IsRunning) ||
        iface.flags().testFlag(QNetworkInterface::IsLoopBack) || !ownsAddress ||
        listenerAddress.protocol() != QAbstractSocket::IPv4Protocol || listenerAddress.isNull() ||
        listenerAddress.isLoopback() || listenerAddress.isMulticast() ||
        listenerAddress == QHostAddress::Broadcast ||
        listenerAddress.toString() != target.listenAddress ||
        target.listenAddress == target.clientIp || target.listenAddress == target.upstreamIp ||
        (listenerAddress.toIPv4Address() & 0xffff0000U) == 0xa9fe0000U)
        return fail(QStringLiteral("invalid_probe_listener_address"));
    QByteArray nonce(32, Qt::Uninitialized);
    if (SecRandomCopyBytes(kSecRandomDefault, static_cast<size_t>(nonce.size()), nonce.data()) !=
        errSecSuccess)
        return fail(QStringLiteral("probe_nonce_unavailable"));
    const QByteArray expected = transparentProbeMac(target, nonce, secret);
    QTcpSocket socket;
    socket.setProxy(QNetworkProxy::NoProxy);
    QElapsedTimer elapsed;
    elapsed.start();
    if (!socket.bind(listenerAddress, 0))
        return fail(QStringLiteral("probe_bind_failed"));
    socket.connectToHost(listenerAddress, static_cast<quint16>(target.listenerPort));
    if (!socket.waitForConnected(timeoutMs))
        return fail(QStringLiteral("probe_connect_failed"));
    const QByteArray request = QByteArray("GET ") + transparentProbePrefix + nonce.toHex() +
                               " HTTP/1.1\r\nHost: " + target.listenAddress.toLatin1() +
                               "\r\nConnection: close\r\n\r\n";
    if (socket.write(request) != request.size())
        return fail(QStringLiteral("probe_write_failed"));
    QByteArray response;
    while (elapsed.elapsed() < timeoutMs && response.size() <= 1024) {
        const int remaining = timeoutMs - static_cast<int>(elapsed.elapsed());
        if (!socket.waitForReadyRead(remaining))
            break;
        response += socket.readAll();
        if (response.contains("\r\n\r\n") && response.endsWith(expected))
            break;
    }
    if (response.size() > 1024 || !response.startsWith("HTTP/1.1 200 "))
        return fail(QStringLiteral("probe_response_invalid"));
    const int separator = response.indexOf("\r\n\r\n");
    if (separator < 0)
        return fail(QStringLiteral("probe_response_incomplete"));
    const QByteArray body = response.mid(separator + 4);
    if (body.size() != expected.size() ||
        timingsafe_bcmp(body.constData(), expected.constData(),
                        static_cast<size_t>(expected.size())) != 0)
        return fail(QStringLiteral("probe_authentication_failed"));
    return true;
}

} // namespace interceptor
