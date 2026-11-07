#include "core/SessionConfig.hpp"
#include "network/NetworkSession.hpp"
#include "proxy/ProxyServer.hpp"

#include <QHostAddress>
#include <QNetworkInterface>
#include <QTcpServer>
#include <QtTest>

using namespace interceptor;

class M6TransparentProxyReadinessTests final : public QObject {
    Q_OBJECT

    static std::optional<QString> activeInterfaceName() {
        for (const auto &networkInterface : QNetworkInterface::allInterfaces()) {
            const auto flags = networkInterface.flags();
            if (!flags.testFlag(QNetworkInterface::IsUp) ||
                !flags.testFlag(QNetworkInterface::IsRunning) ||
                flags.testFlag(QNetworkInterface::IsLoopBack))
                continue;
            for (const auto &entry : networkInterface.addressEntries())
                if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol &&
                    !entry.ip().isLoopback())
                    return networkInterface.name();
        }
        return std::nullopt;
    }
    static bool loopbackListenerAvailable() {
        QTcpServer server;
        const bool available = server.listen(QHostAddress::LocalHost, 0);
        server.close();
        return available;
    }
    static SessionConfig config(const QString &interfaceName) {
        return {interfaceName, "192.0.2.10", "192.0.2.30", 18081, {"/api/generate", "/api/chat"},
                false};
    }
    static NetworkFacts factsFor(const SessionConfig &session) {
        NetworkFacts facts;
        facts.interfaceName = session.interfaceName;
        facts.researchIp = "192.0.2.20";
        facts.researchMac = "02:00:00:00:00:20";
        facts.clientMac = "02:00:00:00:00:10";
        facts.serverMac = "02:00:00:00:00:30";
        facts.interfaceUp = facts.sameLink = facts.anchorAttached = facts.authorized = true;
        // The overload must populate these from the ProxyServer readiness evidence.
        facts.proxyReady = false;
        return facts;
    }

  private slots:
    void snapshotUsesActualBoundListenerAndConfiguredUpstream() {
        const auto interfaceName = activeInterfaceName();
        if (!interfaceName)
            QSKIP("An up/running interface is required for transparent proxy readiness");
        if (!loopbackListenerAvailable())
            QSKIP("This environment does not permit local loopback listeners");

        const auto session = config(*interfaceName);
        ProxyOptions options;
        options.transparentRedirect = true;
        options.allowedClientIp = session.clientIp;
        ProxyServer proxy;
        QVERIFY(proxy.start(session, options));
        const auto readiness = proxy.transparentReadiness();
        QVERIFY(readiness.has_value());
        QVERIFY(proxy.isTransparentReadinessCurrent(*readiness));

        QString error;
        const auto snapshot = SessionSnapshot::create(
            session, factsFor(session), *readiness, QStringLiteral("proxy-ready-session"), &error);
        QVERIFY2(snapshot.has_value(), qPrintable(error));
        QVERIFY(snapshot->facts().proxyReady);
        QCOMPARE(snapshot->facts().proxyServerIp, session.serverIp);
        QCOMPARE(snapshot->facts().proxyServerPort, session.serverPort);
        QCOMPARE(snapshot->facts().proxyListenPort, proxy.listenPort());
        QCOMPARE(snapshot->proxyPort(), static_cast<int>(proxy.listenPort()));
        QVERIFY(snapshot->pfRules().contains(
            QStringLiteral("rdr on \"%1\" inet proto tcp from %2 to %3 port %4 -> 127.0.0.1 "
                           "port %5")
                .arg(session.interfaceName, session.clientIp, session.serverIp,
                     QString::number(session.serverPort), QString::number(proxy.listenPort()))));

        proxy.stop();
        QVERIFY(!proxy.transparentReadiness().has_value());
        QVERIFY(!proxy.isTransparentReadinessCurrent(*readiness));
    }

    void snapshotRejectsReadinessForDifferentClientOrUpstream() {
        const auto interfaceName = activeInterfaceName();
        if (!interfaceName)
            QSKIP("An up/running interface is required for transparent proxy readiness");
        if (!loopbackListenerAvailable())
            QSKIP("This environment does not permit local loopback listeners");

        const auto original = config(*interfaceName);
        ProxyOptions options;
        options.transparentRedirect = true;
        options.allowedClientIp = original.clientIp;
        ProxyServer proxy;
        QVERIFY(proxy.start(original, options));
        const auto readiness = proxy.transparentReadiness();
        QVERIFY(readiness.has_value());

        auto wrongClient = original;
        wrongClient.clientIp = "192.0.2.11";
        QString error;
        QVERIFY(!SessionSnapshot::create(wrongClient, factsFor(wrongClient), *readiness,
                                         QStringLiteral("wrong-client"), &error));
        QVERIFY(!error.isEmpty());

        auto wrongUpstream = original;
        wrongUpstream.serverPort = 18082;
        QVERIFY(!SessionSnapshot::create(wrongUpstream, factsFor(wrongUpstream), *readiness,
                                         QStringLiteral("wrong-upstream"), &error));
        QVERIFY(!error.isEmpty());

        auto wrongInterface = original;
        wrongInterface.interfaceName = QStringLiteral("different_interface");
        QVERIFY(!SessionSnapshot::create(wrongInterface, factsFor(wrongInterface), *readiness,
                                         QStringLiteral("wrong-interface"), &error));
        QVERIFY(!error.isEmpty());

        proxy.stop();
        QVERIFY(!proxy.transparentReadiness().has_value());
    }

    void noReadinessExistsBeforeStartOrAfterStop() {
        ProxyServer proxy;
        QVERIFY(!proxy.transparentReadiness().has_value());
        proxy.stop();
        QVERIFY(!proxy.transparentReadiness().has_value());

        const auto session = config(QStringLiteral("synthetic0"));
        QVERIFY(!SessionSnapshot::create(session, factsFor(session), 0,
                                         QStringLiteral("without-listener")));
    }
};

QTEST_GUILESS_MAIN(M6TransparentProxyReadinessTests)
#include "M6TransparentProxyReadinessTests.moc"
