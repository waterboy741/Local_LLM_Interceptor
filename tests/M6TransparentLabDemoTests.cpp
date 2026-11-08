#include "core/SessionConfig.hpp"
#include "gui/MainWindow.hpp"
#include "network/NetworkSession.hpp"
#include "proxy/ProxyServer.hpp"
#include "session/SessionController.hpp"

#include <QCheckBox>
#include <QComboBox>
#include <QHostAddress>
#include <QLineEdit>
#include <QListWidget>
#include <QNetworkInterface>
#include <QPushButton>
#include <QRegularExpression>
#include <QSpinBox>
#include <QTabWidget>
#include <QTcpServer>
#include <QTcpSocket>
#include <QtTest>

using namespace interceptor;

namespace {
std::optional<QPair<QString, QString>> activeNonLoopbackInterface() {
    for (const auto &networkInterface : QNetworkInterface::allInterfaces()) {
        const auto flags = networkInterface.flags();
        if (!flags.testFlag(QNetworkInterface::IsUp) ||
            !flags.testFlag(QNetworkInterface::IsRunning) ||
            flags.testFlag(QNetworkInterface::IsLoopBack))
            continue;
        for (const auto &entry : networkInterface.addressEntries())
            if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol && !entry.ip().isLoopback())
                return QPair<QString, QString>{networkInterface.name(), entry.ip().toString()};
    }
    return std::nullopt;
}

SessionConfig demoConfig(const QString &interfaceName) {
    QString address;
    for (const auto &entry : QNetworkInterface::interfaceFromName(interfaceName).addressEntries())
        if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol && !entry.ip().isLoopback()) {
            address = entry.ip().toString();
            break;
        }
    const quint32 research = QHostAddress(address).toIPv4Address();
    const quint32 base = research & 0xffff0000U;
    const QString client = QHostAddress(base | ((research & 0xffffU) == 10 ? 11U : 10U)).toString();
    const QString server = QHostAddress(base | ((research & 0xffffU) == 30 ? 31U : 30U)).toString();
    return {interfaceName, client, server, 18081, {"/api/generate", "/api/chat"}, false};
}

bool loopbackListenerAvailable() {
    QTcpServer server;
    const bool available = server.listen(QHostAddress::LocalHost, 0);
    server.close();
    return available;
}

NetworkFacts syntheticFacts(const SessionConfig &config) {
    NetworkFacts facts;
    facts.prefixLength = 16;
    facts.interfaceName = config.interfaceName;
    for (const auto &entry :
         QNetworkInterface::interfaceFromName(config.interfaceName).addressEntries())
        if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol && !entry.ip().isLoopback()) {
            facts.researchIp = entry.ip().toString();
            break;
        }
    facts.researchMac = QStringLiteral("02:00:00:00:00:20");
    facts.clientMac = QStringLiteral("02:00:00:00:00:10");
    facts.serverMac = QStringLiteral("02:00:00:00:00:30");
    facts.interfaceUp = true;
    facts.sameLink = true;
    facts.anchorAttached = true;
    facts.authorized = true;
    return facts;
}
} // namespace

class M6TransparentLabDemoTests final : public QObject {
    Q_OBJECT

  private slots:
    void guiOmitsTransparentDemoControlsButKeepsRequestsAndModify() {
        SessionController controller;
        MainWindow window(&controller);
        auto *tabs = window.findChild<QTabWidget *>();
        QVERIFY(tabs);
        QVERIFY(!window.findChild<QPushButton *>("startTransparentDemoButton"));
        QVERIFY(!window.findChild<QPushButton *>("stopTransparentDemoButton"));
        QVERIFY(!window.findChild<QLineEdit *>("transparentDemoStatus"));
        QVERIFY(!window.findChild<QCheckBox *>("localDeviceInput"));
        QCOMPARE(tabs->tabText(1), QStringLiteral("Requests"));
        QCOMPARE(tabs->tabText(2), QStringLiteral("Modify settings"));
        QVERIFY(window.findChild<QListWidget *>("observedRequests"));
        QVERIFY(window.findChild<QComboBox *>("interceptionModeInput"));
    }

    void pfRulesUseBoundListenerPortAndExactClientTuple() {
        const auto interfaceName = activeNonLoopbackInterface();
        if (!interfaceName)
            QSKIP("An active non-loopback IPv4 interface is required by transparent listener "
                  "validation");
        if (!loopbackListenerAvailable())
            QSKIP("This environment does not permit local loopback listeners");

        const auto config = demoConfig(interfaceName->first);
        ProxyOptions options;
        options.transparentRedirect = true;
        options.listenAddress = interfaceName->second;
        options.allowedClientIp = config.clientIp;
        options.listenPort = 0;
        options.timeoutMs = 120000;

        ProxyServer proxy;
        QVERIFY2(proxy.start(config, options),
                 "Could not start synthetic LAN transparent listener");
        const auto readiness = proxy.transparentReadiness();
        QVERIFY(readiness.has_value());
        QVERIFY(proxy.isTransparentReadinessCurrent(*readiness));
        QCOMPARE(readiness->listenAddress(), interfaceName->second);
        QCOMPARE(readiness->allowedClientIp(), config.clientIp);
        QCOMPARE(readiness->upstreamServerIp(), config.serverIp);
        QCOMPARE(readiness->upstreamServerPort(), config.serverPort);
        QVERIFY(readiness->listenerPort() > 0);

        QString error;
        const auto snapshot = SessionSnapshot::create(config, syntheticFacts(config), *readiness,
                                                      QStringLiteral("lab-demo-test"), &error);
        QVERIFY2(snapshot.has_value(), qPrintable(error));
        const auto expected =
            QStringLiteral("rdr on \"%1\" inet proto tcp from %4 to %5 "
                           "port 18081 -> %3 port %2\n"
                           "pass in quick on \"%1\" inet proto tcp from %4 to "
                           "%3 port %2 flags S/SA keep state label \"llm_lab-demo-test\"\n"
                           "pass out quick on \"%1\" inet proto tcp from %3 to "
                           "%5 port 18081 flags S/SA keep state label "
                           "\"llm_lab-demo-test\"\n")
                .arg(interfaceName->first, QString::number(readiness->listenerPort()),
                     interfaceName->second, config.clientIp, config.serverIp);
        QCOMPARE(snapshot->proxyPort(), readiness->listenerPort());
        QCOMPARE(snapshot->facts().proxyListenPort, readiness->listenerPort());
        QCOMPARE(snapshot->pfRules(), expected);
        QCOMPARE(snapshot->pfRules().count(QStringLiteral("pass in quick")), 1);
        QVERIFY(!snapshot->pfRules().contains(QStringLiteral("inet from 192.0.2.10 to ")));
        QVERIFY(!snapshot->pfRules().contains(QStringLiteral("inet from 192.0.2.30 to ")));
        QVERIFY(!snapshot->pfRules().contains(QStringLiteral("from any")));
        QVERIFY(!snapshot->pfRules().contains(QStringLiteral("flush")));

        proxy.stop();
        QVERIFY(!proxy.transparentReadiness().has_value());
        QTcpSocket socket;
        socket.connectToHost(QHostAddress(interfaceName->second),
                             static_cast<quint16>(readiness->listenerPort()));
        if (socket.waitForConnected(250)) {
            socket.write(
                "GET /api/generate HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            socket.waitForBytesWritten(250);
            QVERIFY(!socket.waitForReadyRead(250));
        }
    }
};

QTEST_MAIN(M6TransparentLabDemoTests)
#include "M6TransparentLabDemoTests.moc"
