#include "network/ArpCodec.hpp"
#include "network/ArpNeighborAdapter.hpp"

#include <QtTest>
#include <algorithm>

using namespace interceptor;

namespace {
class RecordingPacketIo final : public ArpPacketIo {
  public:
    struct Write {
        QString interfaceName;
        QByteArray frame;
    };

    QList<Write> writes;
    int failAt = -1;

    bool sendFrame(const QString &interfaceName, const QByteArray &frame) override {
        writes.append({interfaceName, frame});
        return writes.size() != failAt;
    }
};

SessionSnapshot makeSnapshot() {
    SessionConfig config{"synthetic0", "192.0.2.10", "192.0.2.30", 18081, {"/api/generate"}, false};
    NetworkFacts facts;
    facts.interfaceName = "synthetic0";
    facts.researchIp = "192.0.2.20";
    facts.researchMac = "02:00:00:00:00:20";
    facts.clientMac = "02:00:00:00:00:10";
    facts.serverMac = "02:00:00:00:00:30";
    facts.proxyServerIp = "192.0.2.30";
    facts.proxyServerPort = 18081;
    facts.proxyListenPort = 11434;
    facts.interfaceUp = facts.sameLink = facts.anchorAttached = facts.proxyReady =
        facts.authorized = true;
    auto snapshot = SessionSnapshot::create(config, facts, 11434, "offline-arp-test");
    if (!snapshot)
        qFatal("Cannot construct synthetic ARP snapshot");
    return *snapshot;
}

void verifyPairFrames(const QList<RecordingPacketIo::Write> &writes, const QString &interfaceName,
                      const QList<QByteArray> &expectedFrames, const QStringList &expectedTargetIps,
                      const QStringList &expectedTargetMacs, const QStringList &expectedSenderIps,
                      const QStringList &expectedSenderMacs) {
    QCOMPARE(writes.size(), 2);
    QCOMPARE(expectedFrames.size(), 2);
    for (qsizetype i = 0; i < writes.size(); ++i) {
        QCOMPARE(writes[i].interfaceName, interfaceName);
        QCOMPARE(writes[i].frame, expectedFrames[i]);
        QCOMPARE(writes[i].frame.size(), 60);
        const auto packet = ArpCodec::parse(writes[i].frame);
        QVERIFY(packet.has_value());
        QCOMPARE(packet->operation, quint16(2));
        QCOMPARE(packet->targetIp, expectedTargetIps[i]);
        QCOMPARE(packet->targetMac, QByteArray::fromHex(expectedTargetMacs[i].toLatin1()));
        QCOMPARE(packet->senderIp, expectedSenderIps[i]);
        QCOMPARE(packet->senderMac, QByteArray::fromHex(expectedSenderMacs[i].toLatin1()));
    }
}
} // namespace

class M6ArpNeighborAdapterTests : public QObject {
    Q_OBJECT
  private slots:
    void sendsOnlySnapshotScopedRedirectionFrames() {
        const auto snapshot = makeSnapshot();
        RecordingPacketIo io;
        ArpNeighborAdapter adapter(io);

        const auto result = adapter.sendRedirection(snapshot);

        QVERIFY(result.success());
        QCOMPARE(result.status, ArpSendStatus::Completed);
        QCOMPARE(result.attemptedFrames, 2);
        QCOMPARE(result.completedFrames, 2);
        QVERIFY(result.mayHaveApplied());
        verifyPairFrames(io.writes, snapshot.facts().interfaceName, snapshot.redirectionFrames(),
                         {"192.0.2.10", "192.0.2.30"}, {"020000000010", "020000000030"},
                         {"192.0.2.30", "192.0.2.10"}, {"020000000020", "020000000020"});
    }

    void sendsOnlySnapshotScopedRestorationFrames() {
        const auto snapshot = makeSnapshot();
        RecordingPacketIo io;
        ArpNeighborAdapter adapter(io);

        const auto result = adapter.sendRestoration(snapshot);

        QVERIFY(result.success());
        QCOMPARE(result.attemptedFrames, 2);
        QCOMPARE(result.completedFrames, 2);
        QVERIFY(result.mayHaveApplied());
        verifyPairFrames(io.writes, snapshot.facts().interfaceName, snapshot.restorationFrames(),
                         {"192.0.2.10", "192.0.2.30"}, {"020000000010", "020000000030"},
                         {"192.0.2.30", "192.0.2.10"}, {"020000000030", "020000000010"});
    }

    void stopsAfterPossiblyPartialFirstFrameFailure() {
        const auto snapshot = makeSnapshot();
        RecordingPacketIo io;
        io.failAt = 1;
        ArpNeighborAdapter adapter(io);

        const auto result = adapter.sendRedirection(snapshot);

        QCOMPARE(result.status, ArpSendStatus::WriteFailed);
        QCOMPARE(result.attemptedFrames, 1);
        QCOMPARE(result.completedFrames, 0);
        QVERIFY(result.mayHaveApplied());
        QCOMPARE(io.writes.size(), 1);
        QCOMPARE(io.writes.front().interfaceName, snapshot.facts().interfaceName);
        QCOMPARE(io.writes.front().frame, snapshot.redirectionFrames().front());
    }

    void stopsAfterSecondFrameFailureAndRetryResendsWholeRestorationPair() {
        const auto snapshot = makeSnapshot();
        RecordingPacketIo io;
        io.failAt = 2;
        ArpNeighborAdapter adapter(io);

        const auto failed = adapter.sendRestoration(snapshot);

        QCOMPARE(failed.status, ArpSendStatus::WriteFailed);
        QCOMPARE(failed.attemptedFrames, 2);
        QCOMPARE(failed.completedFrames, 1);
        QVERIFY(failed.mayHaveApplied());
        QCOMPARE(io.writes.size(), 2);
        QCOMPARE(io.writes[0].frame, snapshot.restorationFrames()[0]);
        QCOMPARE(io.writes[1].frame, snapshot.restorationFrames()[1]);
        QVERIFY(std::all_of(io.writes.cbegin(), io.writes.cend(), [&](const auto &write) {
            return write.interfaceName == snapshot.facts().interfaceName;
        }));

        io.writes.clear();
        io.failAt = -1;
        const auto retried = adapter.sendRestoration(snapshot);
        QVERIFY(retried.success());
        QCOMPARE(retried.attemptedFrames, 2);
        QCOMPARE(retried.completedFrames, 2);
        verifyPairFrames(io.writes, snapshot.facts().interfaceName, snapshot.restorationFrames(),
                         {"192.0.2.10", "192.0.2.30"}, {"020000000010", "020000000030"},
                         {"192.0.2.30", "192.0.2.10"}, {"020000000030", "020000000010"});
    }
};

QTEST_GUILESS_MAIN(M6ArpNeighborAdapterTests)
#include "M6ArpNeighborAdapterTests.moc"
