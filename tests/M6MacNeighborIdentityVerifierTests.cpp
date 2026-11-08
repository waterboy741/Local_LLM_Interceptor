#include "proxy/MacNeighborIdentityVerifier.hpp"

#include <QMap>
#include <QtTest>

#include <utility>

using namespace interceptor;

class MacNeighborFakeRunner final : public NetworkCommandRunner {
  public:
    NetworkQueryOutput output{NetworkCommandStatus::Completed,
                              0,
                              QByteArrayLiteral("? (192.0.2.10) at 2:0:0:0:0:10 on en0\n"),
                              {}};
    QVector<NetworkQuery> queries;
    QString lastInterface;
    QString lastAddress;
    int lastTimeout = 0;
    qsizetype lastLimit = 0;
    int calls = 0;

    NetworkQueryOutput query(NetworkQuery query, const QString &interfaceName, const QString &ipv4,
                             int timeoutMs, qsizetype outputLimitBytes) override {
        ++calls;
        queries.append(query);
        lastInterface = interfaceName;
        lastAddress = ipv4;
        lastTimeout = timeoutMs;
        lastLimit = outputLimitBytes;
        return output;
    }
};

class MacNeighborStatefulRunner final : public NetworkCommandRunner {
  public:
    int clientNeighborCalls = 0;
    QStringList calls;

    NetworkQueryOutput query(NetworkQuery query, const QString &, const QString &ipv4, int,
                             qsizetype) override {
        calls.append(QStringLiteral("%1:%2").arg(static_cast<int>(query)).arg(ipv4));
        switch (query) {
        case NetworkQuery::ClientRoute:
            return {NetworkCommandStatus::Completed,
                    0,
                    QByteArrayLiteral("route to: 192.0.2.10\ndestination: 192.0.2.0\n"
                                      "mask: 255.255.255.0\ngateway: link#1\ninterface: en0\n"
                                      "flags: <UP,DONE,STATIC>\n"),
                    {}};
        case NetworkQuery::ServerRoute:
            return {NetworkCommandStatus::Completed,
                    0,
                    QByteArrayLiteral("route to: 192.0.2.30\ndestination: 192.0.2.0\n"
                                      "mask: 255.255.255.0\ngateway: link#1\ninterface: en0\n"
                                      "flags: <UP,DONE,STATIC>\n"),
                    {}};
        case NetworkQuery::ClientNeighbor:
            ++clientNeighborCalls;
            if (ipv4 == QStringLiteral("192.0.2.10")) {
                const QByteArray mac = clientNeighborCalls >= 2
                                           ? QByteArrayLiteral("02:00:00:00:00:99")
                                           : QByteArrayLiteral("02:00:00:00:00:10");
                return {NetworkCommandStatus::Completed,
                        0,
                        QByteArrayLiteral("? (192.0.2.10) at ") + mac +
                            QByteArrayLiteral(" on en0\n"),
                        {}};
            }
            return {NetworkCommandStatus::Completed,
                    0,
                    QByteArrayLiteral("? (192.0.2.30) at 02:00:00:00:00:30 on en0\n"),
                    {}};
        case NetworkQuery::ServerNeighbor:
            return {NetworkCommandStatus::Completed,
                    0,
                    QByteArrayLiteral("? (192.0.2.30) at 02:00:00:00:00:30 on en0\n"),
                    {}};
        }
        return {};
    }
};

class MacNeighborGateLabProbe final : public LabProbe {
  public:
    InterfaceFacts interfaceFacts(const QString &) override {
        return {
            true, true, QStringLiteral("02:00:00:00:00:20"), {{QStringLiteral("192.0.2.20"), 24}}};
    }
    TcpProbeResult connectTcp(const QString &, const QString &, const QString &, int,
                              int) override {
        return TcpProbeResult::Reachable;
    }
};

class MacNeighborGatePfRunner final : public PfCommandRunner {
  public:
    PfQueryOutput query(PfQuery query, const QString &, int, qsizetype) override {
        switch (query) {
        case PfQuery::Status:
            return {PfCommandStatus::Completed, 0, QByteArrayLiteral("Status: Enabled\n")};
        case PfQuery::MainFilterRules:
            return {PfCommandStatus::Completed, 0,
                    QByteArrayLiteral("@0 anchor \"llm_interceptor/*\" all\n")};
        case PfQuery::MainTranslationRules:
            return {PfCommandStatus::Completed, 0,
                    QByteArrayLiteral("@0 rdr-anchor \"llm_interceptor/*\" all\n")};
        default:
            return {};
        }
    }
};

class MacNeighborGateListener final : public TransparentListenerVerifier {
  public:
    int calls = 0;
    bool verify(const TransparentProxyProbeTarget &, const QByteArray &, int) override {
        ++calls;
        return true;
    }
};

class M6MacNeighborIdentityVerifierTests final : public QObject {
    Q_OBJECT

    static SessionSnapshot snapshot() {
        SessionConfig config{"en0", "192.0.2.10", "192.0.2.30", 18081, {"/api/generate"}, false};
        NetworkFacts facts;
        facts.interfaceName = config.interfaceName;
        facts.researchIp = "192.0.2.20";
        facts.researchMac = "02:00:00:00:00:20";
        facts.clientMac = "02:00:00:00:00:10";
        facts.serverMac = "02:00:00:00:00:30";
        facts.proxyServerIp = config.serverIp;
        facts.proxyServerPort = config.serverPort;
        facts.proxyListenPort = 11434;
        facts.prefixLength = 24;
        facts.interfaceUp = facts.sameLink = facts.anchorAttached = facts.proxyReady =
            facts.authorized = true;
        const auto created =
            SessionSnapshot::create(config, facts, 11434, QStringLiteral("mac-neighbor-test"));
        if (!created)
            qFatal("Could not create synthetic MAC-neighbor snapshot");
        return *created;
    }

  private slots:
    void observesExactSelectedInterfaceAndCanonicalizesUnicastMac() {
        MacNeighborFakeRunner runner;
        MacNeighborIdentityVerifier verifier(runner);
        const auto observed = verifier.observe(QStringLiteral("en0"), QStringLiteral("192.0.2.10"));
        QVERIFY(observed.has_value());
        QVERIFY(observed->resolved);
        QCOMPARE(observed->interfaceName, QStringLiteral("en0"));
        QCOMPARE(observed->ipv4, QStringLiteral("192.0.2.10"));
        QCOMPARE(observed->mac, QStringLiteral("02:00:00:00:00:10"));
        QCOMPARE(runner.calls, 1);
        QCOMPARE(runner.queries, QVector<NetworkQuery>{NetworkQuery::ClientNeighbor});
        QCOMPARE(runner.lastInterface, QStringLiteral("en0"));
        QCOMPARE(runner.lastAddress, QStringLiteral("192.0.2.10"));
        QCOMPARE(runner.lastTimeout, MacNeighborIdentityVerifier::timeoutMs);
        QCOMPARE(runner.lastLimit, MacNeighborIdentityVerifier::maximumOutputBytes);

        runner.output.standardOutput =
            QByteArrayLiteral("? (192.0.2.10) at AA:BB:CC:DD:EE:F0 on en0 ifscope [ethernet]\n");
        const auto scoped = verifier.observe(QStringLiteral("en0"), QStringLiteral("192.0.2.10"));
        QVERIFY(scoped.has_value());
        QCOMPARE(scoped->mac, QStringLiteral("aa:bb:cc:dd:ee:f0"));

        runner.output.standardOutput =
            QByteArrayLiteral("ollama-host (192.0.2.10) at 2:0:0:0:0:10 on en0\n");
        const auto namedHost =
            verifier.observe(QStringLiteral("en0"), QStringLiteral("192.0.2.10"));
        QVERIFY(namedHost.has_value());
        QCOMPARE(namedHost->mac, QStringLiteral("02:00:00:00:00:10"));
    }

    void rejectsWrongInputAndWrongObservedInterfaceOrAddress() {
        MacNeighborFakeRunner runner;
        MacNeighborIdentityVerifier verifier(runner);
        for (const auto &[interfaceName, ipv4] :
             {std::pair{QStringLiteral("en0;whoami"), QStringLiteral("192.0.2.10")},
              std::pair{QStringLiteral("en0"), QStringLiteral("127.0.0.1")},
              std::pair{QStringLiteral("en0"), QStringLiteral("192.0.2.010")},
              std::pair{QStringLiteral("en0"), QStringLiteral("224.0.0.1")},
              std::pair{QStringLiteral("en0"), QStringLiteral("0.0.0.0")},
              std::pair{QStringLiteral("en0"), QStringLiteral("255.255.255.255")},
              std::pair{QStringLiteral("en0"), QStringLiteral("169.254.1.1")},
              std::pair{QStringLiteral("en0"), QStringLiteral("240.1.2.3")}}) {
            QVERIFY(!verifier.observe(interfaceName, ipv4).has_value());
            QVERIFY2(runner.calls == 0, qPrintable(ipv4));
        }

        runner.output.standardOutput =
            QByteArrayLiteral("? (192.0.2.10) at 02:00:00:00:00:10 on en1\n");
        QVERIFY(!verifier.observe(QStringLiteral("en0"), QStringLiteral("192.0.2.10")));
        runner.output.standardOutput =
            QByteArrayLiteral("? (192.0.2.11) at 02:00:00:00:00:10 on en0\n");
        QVERIFY(!verifier.observe(QStringLiteral("en0"), QStringLiteral("192.0.2.10")));
        QCOMPARE(runner.calls, 2);
    }

    void rejectsMalformedAmbiguousOrUnresolvedNeighborRows() {
        MacNeighborFakeRunner runner;
        MacNeighborIdentityVerifier verifier(runner);
        const QList<QByteArray> malformed = {
            {},
            QByteArrayLiteral("? (192.0.2.10) at 02:00:00:00:00:10 on en0\n"
                              "? (192.0.2.10) at 02:00:00:00:00:10 on en0\n"),
            QByteArrayLiteral("? (192.0.2.10) at 0200.0000.0010 on en0\n"),
            QByteArrayLiteral("? (192.0.2.10) at 02:00:00:00:00:10:11 on en0\n"),
            QByteArrayLiteral("? (192.0.2.10) at 02:00:00:00:00:10 extra on en0\n"),
            QByteArrayLiteral("? (192.0.2.10) at 02:00:00:00:00:10 on en0\n\n"),
            QByteArrayLiteral("? (192.0.2.10) at 02:00:00:00:00:10 on en0\0hidden"),
            QByteArrayLiteral("? (192.0.2.10) at 01:00:00:00:00:10 on en0\n"),
            QByteArrayLiteral("? (192.0.2.10) at 00:00:00:00:00:00 on en0\n"),
        };
        for (const auto &line : malformed) {
            runner.output = {NetworkCommandStatus::Completed, 0, line, {}};
            QVERIFY(!verifier.observe(QStringLiteral("en0"), QStringLiteral("192.0.2.10")));
        }

        runner.output = {NetworkCommandStatus::NoEntry, 0, {}, {}};
        QVERIFY(!verifier.observe(QStringLiteral("en0"), QStringLiteral("192.0.2.10")));
        runner.output = {NetworkCommandStatus::Completed,
                         1,
                         QByteArrayLiteral("? (192.0.2.10) at 02:00:00:00:00:10 on en0\n"),
                         {}};
        QVERIFY(!verifier.observe(QStringLiteral("en0"), QStringLiteral("192.0.2.10")));
        runner.output = {NetworkCommandStatus::Completed, 0,
                         QByteArrayLiteral("? (192.0.2.10) at 02:00:00:00:00:10 on en0\n"),
                         QByteArrayLiteral("warning")};
        QVERIFY(!verifier.observe(QStringLiteral("en0"), QStringLiteral("192.0.2.10")));
        runner.output = {NetworkCommandStatus::OutputLimitExceeded, -1, {}, {}};
        QVERIFY(!verifier.observe(QStringLiteral("en0"), QStringLiteral("192.0.2.10")));
        runner.output = {NetworkCommandStatus::TimedOut, -1, {}, {}};
        QVERIFY(!verifier.observe(QStringLiteral("en0"), QStringLiteral("192.0.2.10")));
        runner.output = {NetworkCommandStatus::Completed,
                         0,
                         QByteArray(MacNeighborIdentityVerifier::maximumOutputBytes + 1, 'x'),
                         {}};
        QVERIFY(!verifier.observe(QStringLiteral("en0"), QStringLiteral("192.0.2.10")));
    }

    void exposesStaleValidMacForExactSnapshotComparisonBeforeMutation() {
        MacNeighborStatefulRunner network;
        MacNeighborIdentityVerifier verifier(network);
        MacNeighborGateLabProbe lab;
        MacNeighborGatePfRunner pf;
        MacNeighborGateListener listener;
        auto snapshotValue = snapshot();

        const auto result = HelperPreMutationGate::verify(snapshotValue, QByteArray(32, 'p'), lab,
                                                          network, pf, verifier, listener);
        QVERIFY(!result.ready);
        QCOMPARE(result.statusCode, QStringLiteral("neighbor_identity_mismatch"));
        QVERIFY(network.calls.contains(QStringLiteral("2:192.0.2.10")));
        QCOMPARE(listener.calls, 0);
        QVERIFY(!network.calls.contains(QStringLiteral("0:192.0.2.30")));
    }
};

QTEST_GUILESS_MAIN(M6MacNeighborIdentityVerifierTests)
#include "M6MacNeighborIdentityVerifierTests.moc"
