#include "proxy/HelperPreMutationGate.hpp"

#include <QMap>
#include <QtTest>

using namespace interceptor;

class PreMutationFakeLabProbe final : public LabProbe {
  public:
    InterfaceFacts facts{
        true, true, QStringLiteral("02:00:00:00:00:20"), {{QStringLiteral("192.0.2.20"), 24}}};
    TcpProbeResult tcpResult = TcpProbeResult::Reachable;
    QStringList *calls = nullptr;

    InterfaceFacts interfaceFacts(const QString &name) override {
        if (calls)
            calls->append(QStringLiteral("interface:") + name);
        return facts;
    }
    TcpProbeResult connectTcp(const QString &interfaceName, const QString &sourceIpv4,
                              const QString &serverIp, int serverPort, int timeoutMs) override {
        if (calls)
            calls->append(QStringLiteral("tcp:%1:%2:%3:%4:%5")
                              .arg(interfaceName, sourceIpv4, serverIp)
                              .arg(serverPort)
                              .arg(timeoutMs));
        return tcpResult;
    }
};

class PreMutationFakeNetworkRunner final : public NetworkCommandRunner {
  public:
    QMap<int, NetworkQueryOutput> outputs;
    QStringList *calls = nullptr;

    NetworkQueryOutput query(NetworkQuery query, const QString &interfaceName, const QString &ipv4,
                             int timeoutMs, qsizetype outputLimitBytes) override {
        Q_UNUSED(timeoutMs);
        Q_UNUSED(outputLimitBytes);
        if (calls)
            calls->append(QStringLiteral("route:%1:%2:%3")
                              .arg(static_cast<int>(query))
                              .arg(interfaceName, ipv4));
        return outputs.value(static_cast<int>(query));
    }

    static QByteArray route(const QString &address, const QString &gateway,
                            const QString &interfaceName = QStringLiteral("synthetic0")) {
        return QStringLiteral("route to: %1\ndestination: 192.0.2.0\nmask: 255.255.255.0\n"
                              "gateway: %2\ninterface: %3\nflags: <UP,DONE,STATIC>\n")
            .arg(address, gateway, interfaceName)
            .toUtf8();
    }
    static QByteArray neighbor(const QString &address, const QString &mac,
                               const QString &interfaceName = QStringLiteral("synthetic0")) {
        return QStringLiteral("? (%1) at %2 on %3 ifscope [ethernet]\n")
            .arg(address, mac, interfaceName)
            .toUtf8();
    }
    void setSuccess() {
        outputs.insert(static_cast<int>(NetworkQuery::ClientRoute),
                       {NetworkCommandStatus::Completed, 0,
                        route(QStringLiteral("192.0.2.10"), QStringLiteral("link#1"))});
        outputs.insert(static_cast<int>(NetworkQuery::ServerRoute),
                       {NetworkCommandStatus::Completed, 0,
                        route(QStringLiteral("192.0.2.30"), QStringLiteral("link#1"))});
        outputs.insert(
            static_cast<int>(NetworkQuery::ClientNeighbor),
            {NetworkCommandStatus::Completed, 0,
             neighbor(QStringLiteral("192.0.2.10"), QStringLiteral("02:00:00:00:00:10"))});
        outputs.insert(
            static_cast<int>(NetworkQuery::ServerNeighbor),
            {NetworkCommandStatus::Completed, 0,
             neighbor(QStringLiteral("192.0.2.30"), QStringLiteral("02:00:00:00:00:30"))});
    }
};

class PreMutationFakePfRunner final : public PfCommandRunner {
  public:
    QStringList *calls = nullptr;
    bool enabled = true;
    bool filterAttachment = true;
    bool translationAttachment = true;

    PfQueryOutput query(PfQuery query, const QString &, int, qsizetype) override {
        if (calls)
            calls->append(QStringLiteral("pf:%1").arg(static_cast<int>(query)));
        switch (query) {
        case PfQuery::Status:
            return {PfCommandStatus::Completed, 0,
                    enabled ? QByteArrayLiteral("Status: Enabled\n")
                            : QByteArrayLiteral("Status: Disabled\n")};
        case PfQuery::MainFilterRules:
            return {PfCommandStatus::Completed, 0,
                    filterAttachment ? QByteArrayLiteral("@0 anchor \"llm_interceptor/*\" all\n")
                                     : QByteArrayLiteral("@0 pass all\n")};
        case PfQuery::MainTranslationRules:
            return {PfCommandStatus::Completed, 0,
                    translationAttachment
                        ? QByteArrayLiteral("@0 rdr-anchor \"llm_interceptor/*\" all\n")
                        : QByteArrayLiteral("@0 pass all\n")};
        default:
            return {};
        }
    }
};

class PreMutationFakeNeighborVerifier final : public NeighborIdentityVerifier {
  public:
    QString clientMac = QStringLiteral("02:00:00:00:00:10");
    QString serverMac = QStringLiteral("02:00:00:00:00:30");
    bool resolved = true;
    QStringList *calls = nullptr;

    std::optional<ObservedNeighborIdentity> observe(const QString &interfaceName,
                                                    const QString &ipv4) override {
        if (calls)
            calls->append(QStringLiteral("neighbor:") + ipv4);
        const auto mac = ipv4 == QStringLiteral("192.0.2.10") ? clientMac : serverMac;
        return ObservedNeighborIdentity{interfaceName, ipv4, mac, resolved};
    }
};

class PreMutationFakeListenerVerifier final : public TransparentListenerVerifier {
  public:
    bool result = true;
    TransparentProxyProbeTarget observedTarget;
    QByteArray observedSecret;
    int calls = 0;
    QStringList *callOrder = nullptr;

    bool verify(const TransparentProxyProbeTarget &target, const QByteArray &secret,
                int timeoutMs) override {
        ++calls;
        observedTarget = target;
        observedSecret = secret;
        if (callOrder)
            callOrder->append(QStringLiteral("listener:%1").arg(timeoutMs));
        return result;
    }
};

class M6HelperPreMutationGateTests final : public QObject {
    Q_OBJECT

    static SessionSnapshot makeSnapshot() {
        SessionConfig config{"synthetic0", "192.0.2.10",      "192.0.2.30",
                             18081,        {"/api/generate"}, false};
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
        const auto snapshot =
            SessionSnapshot::create(config, facts, 11434, QStringLiteral("pre-mutation-test"));
        if (!snapshot)
            qFatal("Could not create synthetic helper pre-mutation snapshot");
        return *snapshot;
    }

    struct Fakes {
        QStringList calls;
        PreMutationFakeLabProbe lab;
        PreMutationFakeNetworkRunner network;
        PreMutationFakePfRunner pf;
        PreMutationFakeNeighborVerifier neighbors;
        PreMutationFakeListenerVerifier listener;

        Fakes() {
            lab.calls = &calls;
            network.calls = &calls;
            pf.calls = &calls;
            neighbors.calls = &calls;
            listener.callOrder = &calls;
            network.setSuccess();
        }
    };

    static HelperPreMutationResult verify(Fakes &fakes,
                                          const QByteArray &secret = QByteArray(32, 'p')) {
        return HelperPreMutationGate::verify(makeSnapshot(), secret, fakes.lab, fakes.network,
                                             fakes.pf, fakes.neighbors, fakes.listener);
    }

    static bool containsPrefix(const QStringList &calls, const QString &prefix) {
        return std::any_of(calls.cbegin(), calls.cend(),
                           [&prefix](const QString &call) { return call.startsWith(prefix); });
    }

  private slots:
    void passesOnlyAfterFreshNetworkPfNeighborAndListenerChecks() {
        Fakes fakes;
        const auto result = verify(fakes);
        QVERIFY(result.ready);
        QCOMPARE(result.statusCode, QStringLiteral("ready"));
        QCOMPARE(fakes.listener.calls, 1);
        QCOMPARE(fakes.listener.observedSecret, QByteArray(32, 'p'));
        QCOMPARE(fakes.listener.observedTarget.interfaceName, QStringLiteral("synthetic0"));
        QCOMPARE(fakes.listener.observedTarget.clientIp, QStringLiteral("192.0.2.10"));
        QCOMPARE(fakes.listener.observedTarget.upstreamIp, QStringLiteral("192.0.2.30"));
        QCOMPARE(fakes.listener.observedTarget.upstreamPort, 18081);
        QCOMPARE(fakes.listener.observedTarget.listenerPort, 11434);
        QCOMPARE(fakes.calls.last(), QStringLiteral("listener:1000"));
        QVERIFY(containsPrefix(fakes.calls,
                               QStringLiteral("tcp:synthetic0:192.0.2.20:192.0.2.30:18081:")));
    }

    void rejectsInvalidSecretBeforeAnyObservation() {
        Fakes fakes;
        const auto result = verify(fakes, QByteArray(31, 'p'));
        QVERIFY(!result.ready);
        QCOMPARE(result.statusCode, QStringLiteral("snapshot_or_probe_secret_invalid"));
        QVERIFY(fakes.calls.isEmpty());
    }

    void rejectsChangedInterfaceIdentityOrAddressBeforeRouteChecks() {
        {
            Fakes fakes;
            fakes.lab.facts.macAddress = QStringLiteral("02:00:00:00:00:99");
            const auto result = verify(fakes);
            QVERIFY(!result.ready);
            QCOMPARE(result.statusCode, QStringLiteral("research_interface_identity_mismatch"));
            QCOMPARE(fakes.calls, QStringList{QStringLiteral("interface:synthetic0")});
        }
        {
            Fakes fakes;
            fakes.lab.facts.ipv4Addresses[0].ipv4 = QStringLiteral("192.0.2.21");
            const auto result = verify(fakes);
            QVERIFY(!result.ready);
            QCOMPARE(result.statusCode, QStringLiteral("research_interface_address_mismatch"));
            QCOMPARE(fakes.calls, QStringList{QStringLiteral("interface:synthetic0")});
        }
    }

    void rejectsUnverifiedRoutesOrChangedNeighborMacBeforeUpstreamOrPf() {
        {
            Fakes fakes;
            fakes.network.outputs[static_cast<int>(NetworkQuery::ClientRoute)].standardOutput =
                PreMutationFakeNetworkRunner::route(QStringLiteral("192.0.2.10"),
                                                    QStringLiteral("192.0.2.1"));
            const auto result = verify(fakes);
            QVERIFY(!result.ready);
            QCOMPARE(result.statusCode, QStringLiteral("route_or_neighbor_not_verified"));
            QCOMPARE(fakes.listener.calls, 0);
            QVERIFY(!containsPrefix(fakes.calls, QStringLiteral("tcp:")));
            QVERIFY(!containsPrefix(fakes.calls, QStringLiteral("pf:")));
        }
        {
            Fakes fakes;
            fakes.neighbors.serverMac = QStringLiteral("02:00:00:00:00:99");
            const auto result = verify(fakes);
            QVERIFY(!result.ready);
            QCOMPARE(result.statusCode, QStringLiteral("neighbor_identity_mismatch"));
            QCOMPARE(fakes.calls[fakes.calls.size() - 2], QStringLiteral("neighbor:192.0.2.10"));
            QCOMPARE(fakes.calls.last(), QStringLiteral("neighbor:192.0.2.30"));
            QVERIFY(!containsPrefix(fakes.calls, QStringLiteral("tcp:")));
            QVERIFY(!containsPrefix(fakes.calls, QStringLiteral("pf:")));
            QCOMPARE(fakes.listener.calls, 0);
        }
    }

    void rejectsUnreachableUpstreamOrUnreadyPfBeforeListenerProbe() {
        {
            Fakes fakes;
            fakes.lab.tcpResult = TcpProbeResult::TimedOut;
            const auto result = verify(fakes);
            QVERIFY(!result.ready);
            QCOMPARE(result.statusCode, QStringLiteral("upstream_not_reachable"));
            QVERIFY(!containsPrefix(fakes.calls, QStringLiteral("pf:")));
            QCOMPARE(fakes.listener.calls, 0);
        }
        {
            Fakes fakes;
            fakes.pf.filterAttachment = false;
            const auto result = verify(fakes);
            QVERIFY(!result.ready);
            QCOMPARE(result.statusCode, QStringLiteral("pf_attachment_not_ready"));
            QVERIFY(containsPrefix(fakes.calls, QStringLiteral("pf:")));
            QCOMPARE(fakes.calls.last(), QStringLiteral("pf:1"));
            QCOMPARE(fakes.listener.calls, 0);
        }
    }

    void rejectsListenerMismatchOnlyAfterAllIndependentChecks() {
        Fakes fakes;
        fakes.listener.result = false;
        const auto result = verify(fakes);
        QVERIFY(!result.ready);
        QCOMPARE(result.statusCode, QStringLiteral("transparent_listener_not_verified"));
        QCOMPARE(fakes.listener.calls, 1);
        QCOMPARE(fakes.calls.last(), QStringLiteral("listener:1000"));
        QVERIFY(containsPrefix(fakes.calls, QStringLiteral("tcp:")));
        QVERIFY(containsPrefix(fakes.calls, QStringLiteral("pf:")));
        QCOMPARE(fakes.calls[fakes.calls.size() - 2], QStringLiteral("pf:2"));
    }
};

QTEST_GUILESS_MAIN(M6HelperPreMutationGateTests)
#include "M6HelperPreMutationGateTests.moc"
