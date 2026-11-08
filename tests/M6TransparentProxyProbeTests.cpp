#include "proxy/ProxyServer.hpp"
#include "proxy/TransparentProxyProbe.hpp"
#include "proxy/TransparentProxyProbeProtocol.hpp"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QNetworkInterface>
#include <QNetworkProxy>
#include <QTcpServer>
#include <QTcpSocket>
#include <QThread>
#include <QtTest>

#include <atomic>
#include <thread>

using namespace interceptor;

class M6TransparentProxyProbeTests final : public QObject {
    Q_OBJECT

    ProxyServer proxy_;
    TransparentProxyProbeTarget target_;
    QByteArray secret_;

    static std::optional<QPair<QString, QString>> activeInterfaceName() {
        for (const auto &networkInterface : QNetworkInterface::allInterfaces()) {
            const auto flags = networkInterface.flags();
            if (!flags.testFlag(QNetworkInterface::IsUp) ||
                !flags.testFlag(QNetworkInterface::IsRunning) ||
                flags.testFlag(QNetworkInterface::IsLoopBack))
                continue;
            for (const auto &entry : networkInterface.addressEntries())
                if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol &&
                    !entry.ip().isLoopback())
                    return QPair<QString, QString>{networkInterface.name(), entry.ip().toString()};
        }
        return std::nullopt;
    }

    static bool loopbackListenerAvailable() {
        QTcpServer server;
        const bool available = server.listen(QHostAddress::LocalHost, 0);
        server.close();
        return available;
    }

    static bool verifyOffOwnerThread(const TransparentProxyProbeTarget &target,
                                     const QByteArray &secret, int timeoutMs, QString *error) {
        std::atomic_bool done{false};
        bool result = false;
        QString workerError;
        std::thread worker([&] {
            result = verifyTransparentProxyProbe(target, secret, timeoutMs, &workerError);
            done.store(true, std::memory_order_release);
        });
        while (!done.load(std::memory_order_acquire)) {
            QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
            QThread::msleep(1);
        }
        worker.join();
        if (error)
            *error = workerError;
        return result;
    }

    QByteArray exchange(quint16 port, const QByteArray &request) {
        QTcpSocket socket;
        socket.setProxy(QNetworkProxy::NoProxy);
        if (!socket.bind(QHostAddress(target_.listenAddress)))
            return {};
        socket.connectToHost(QHostAddress(target_.listenAddress), port);
        if (!socket.waitForConnected(1000))
            return {};
        if (socket.write(request) != request.size() || !socket.waitForBytesWritten(1000))
            return {};
        QByteArray response;
        while (socket.waitForReadyRead(1000))
            response += socket.readAll();
        response += socket.readAll();
        return response;
    }

    static QByteArray getRequest(const QByteArray &path) {
        return QByteArray("GET ") + path +
               " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    }

    static QByteArray statusLine(const QByteArray &response) {
        return response.left(response.indexOf("\r\n"));
    }

  private slots:
    void init() {
        const auto interfaceName = activeInterfaceName();
        if (!interfaceName)
            QSKIP("Transparent listener requires an up, running non-loopback interface");
        if (!loopbackListenerAvailable())
            QSKIP("This environment does not permit local loopback listeners");

        SessionConfig config{interfaceName->first, "192.0.2.10", "192.0.2.30", 18081,
                             {"/api/generate"},    false};
        ProxyOptions options;
        options.transparentRedirect = true;
        options.listenAddress = interfaceName->second;
        options.allowedClientIp = config.clientIp;
        QVERIFY2(proxy_.start(config, options), "Could not start synthetic transparent proxy");
        const auto secret = proxy_.transparentProbeSecret();
        QVERIFY(secret.has_value());
        QCOMPARE(secret->size(), 32);
        secret_ = *secret;
        target_ = {config.interfaceName, config.clientIp, config.serverIp, config.serverPort,
                   static_cast<int>(proxy_.listenPort())};
        target_.listenAddress = interfaceName->second;
    }

    void cleanup() { proxy_.stop(); }

    void verifierAcceptsValidChallengeAndBindsEveryTupleField() {
        QString error;
        QVERIFY2(verifyOffOwnerThread(target_, secret_, 1000, &error), qPrintable(error));
        QVERIFY(error.isEmpty());

        const auto rejectTuple = [&](TransparentProxyProbeTarget wrong) {
            QString failure;
            QVERIFY(!verifyOffOwnerThread(wrong, secret_, 500, &failure));
            QVERIFY(!failure.isEmpty());
        };

        auto wrongInterface = target_;
        wrongInterface.interfaceName += QStringLiteral("_wrong");
        rejectTuple(wrongInterface);

        auto wrongClient = target_;
        wrongClient.clientIp = QStringLiteral("192.0.2.11");
        rejectTuple(wrongClient);

        auto wrongUpstream = target_;
        wrongUpstream.upstreamIp = QStringLiteral("192.0.2.31");
        rejectTuple(wrongUpstream);

        auto wrongUpstreamPort = target_;
        wrongUpstreamPort.upstreamPort = 18082;
        rejectTuple(wrongUpstreamPort);

        auto wrongAddress = target_;
        wrongAddress.listenAddress = QStringLiteral("127.0.0.1");
        rejectTuple(wrongAddress);

        auto invalidListenerPort = target_;
        invalidListenerPort.listenerPort = 0;
        rejectTuple(invalidListenerPort);

        QByteArray wrongSecret = secret_;
        wrongSecret[0] = static_cast<char>(wrongSecret[0] ^ 0x01);
        QString wrongSecretError;
        QVERIFY(!verifyOffOwnerThread(target_, wrongSecret, 500, &wrongSecretError));
        QCOMPARE(wrongSecretError, QStringLiteral("probe_authentication_failed"));
    }

    void verifierRejectsDifferentListeningPort() {
        QTcpServer occupied;
        QVERIFY(occupied.listen(QHostAddress(target_.listenAddress), 0));
        auto wrongPort = target_;
        wrongPort.listenerPort = static_cast<int>(occupied.serverPort());
        QString error;
        QVERIFY(!verifyOffOwnerThread(wrongPort, secret_, 100, &error));
        QVERIFY(!error.isEmpty());
    }

    void verifierFailsClosedOnOversizedAndDelayedResponses() {
        QTcpServer oversized;
        QVERIFY(oversized.listen(QHostAddress(target_.listenAddress), 0));
        connect(&oversized, &QTcpServer::newConnection, &oversized, [&oversized] {
            auto *socket = oversized.nextPendingConnection();
            connect(socket, &QTcpSocket::readyRead, socket, [socket] {
                (void)socket->readAll();
                QByteArray response("HTTP/1.1 200 OK\r\nContent-Length: 2000\r\n"
                                    "Connection: close\r\n\r\n");
                response += QByteArray(2000, 'x');
                socket->write(response);
                socket->disconnectFromHost();
            });
        });
        auto oversizedTarget = target_;
        oversizedTarget.listenerPort = static_cast<int>(oversized.serverPort());
        QString error;
        QVERIFY(!verifyOffOwnerThread(oversizedTarget, secret_, 500, &error));
        QVERIFY(!error.isEmpty());

        QTcpServer delayed;
        QVERIFY(delayed.listen(QHostAddress(target_.listenAddress), 0));
        connect(&delayed, &QTcpServer::newConnection, &delayed, [&delayed] {
            auto *socket = delayed.nextPendingConnection();
            connect(socket, &QTcpSocket::readyRead, socket, [socket] { (void)socket->readAll(); });
        });
        auto delayedTarget = target_;
        delayedTarget.listenerPort = static_cast<int>(delayed.serverPort());
        QElapsedTimer elapsed;
        elapsed.start();
        QVERIFY(!verifyOffOwnerThread(delayedTarget, secret_, 100, &error));
        QVERIFY(elapsed.elapsed() < 1000);
        QVERIFY(!error.isEmpty());
    }

    void verifierRejectsStoppedListener() {
        const auto oldTarget = target_;
        const auto oldSecret = secret_;
        proxy_.stop();
        QVERIFY(!proxy_.transparentProbeSecret().has_value());
        QString error;
        QVERIFY(!verifyOffOwnerThread(oldTarget, oldSecret, 200, &error));
        QVERIFY(!error.isEmpty());
    }

    void selectedLanEndpointAcceptsOnlyExactProbePathWithoutQuery() {
        QByteArray nonce(32, 'a');
        const QByteArray exactPath = QByteArray(transparentProbePrefix) + nonce.toHex();
        const QByteArray validResponse =
            exchange(static_cast<quint16>(target_.listenerPort), getRequest(exactPath));
        QVERIFY2(statusLine(validResponse).startsWith("HTTP/1.1 200 "), validResponse.constData());

        const QByteArray withQuery =
            exchange(static_cast<quint16>(target_.listenerPort), getRequest(exactPath + "?x=1"));
        QVERIFY(statusLine(withQuery).startsWith("HTTP/1.1 403 "));

        const QByteArray wrongLength = exchange(static_cast<quint16>(target_.listenerPort),
                                                getRequest(exactPath.left(exactPath.size() - 1)));
        QVERIFY(statusLine(wrongLength).startsWith("HTTP/1.1 403 "));

        QByteArray nonHex = QByteArray(transparentProbePrefix) + QByteArray(64, 'g');
        const QByteArray malformedNonce =
            exchange(static_cast<quint16>(target_.listenerPort), getRequest(nonHex));
        QVERIFY(statusLine(malformedNonce).startsWith("HTTP/1.1 400 "));

        const QByteArray postRequest = QByteArray("POST ") + exactPath +
                                       " HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n"
                                       "Connection: close\r\n\r\n";
        const QByteArray wrongMethod =
            exchange(static_cast<quint16>(target_.listenerPort), postRequest);
        QVERIFY(statusLine(wrongMethod).startsWith("HTTP/1.1 403 "));

        const QByteArray ordinaryLocalRequest =
            exchange(static_cast<quint16>(target_.listenerPort), getRequest("/api/generate"));
        QVERIFY(statusLine(ordinaryLocalRequest).startsWith("HTTP/1.1 403 "));
    }
};

QTEST_GUILESS_MAIN(M6TransparentProxyProbeTests)
#include "M6TransparentProxyProbeTests.moc"
