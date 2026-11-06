#include "network/ArpBpfReadinessCli.hpp"
#include "network/ArpCodec.hpp"
#include "network/MacBpfArpPacketIo.hpp"

#include <QJsonDocument>
#include <QJsonObject>
#include <QtTest>

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <sys/ioctl.h>

using namespace interceptor;

namespace {
class FakeBpfSystemCalls final : public BpfSystemCalls {
  public:
    struct IoctlCall {
        unsigned long request;
        QByteArray interfaceName;
        int value = -1;
    };

    QList<QString> openedPaths;
    QList<int> openFlags;
    QList<IoctlCall> ioctlCalls;
    QList<int> closedDescriptors;
    QList<QByteArray> writtenFrames;
    int descriptorsBeforeSuccess = 0;
    int descriptorToReturn = 42;
    int forcedOpenError = 0;
    int linkType = DLT_EN10MB;
    int headerCompleteReadback = 1;
    unsigned long failingIoctl = 0;
    int closeResult = 0;
    qint64 writeResult = -2;

    int openDevice(const QString &path, int flags, int &errorNumber) override {
        openedPaths.append(path);
        openFlags.append(flags);
        if (forcedOpenError != 0) {
            errorNumber = forcedOpenError;
            return -1;
        }
        if (openedPaths.size() <= descriptorsBeforeSuccess) {
            errorNumber = openedPaths.size() % 2 ? EBUSY : ENOENT;
            return -1;
        }
        errorNumber = 0;
        return descriptorToReturn;
    }

    int ioctlDevice(int descriptor, unsigned long request, void *argument) override {
        Q_UNUSED(descriptor);
        IoctlCall call{request};
        if (request == BIOCSETIF) {
            const auto *interfaceRequest = static_cast<const struct ifreq *>(argument);
            call.interfaceName =
                QByteArray(interfaceRequest->ifr_name,
                           static_cast<qsizetype>(strnlen(interfaceRequest->ifr_name, IFNAMSIZ)));
        } else if (request == BIOCGDLT) {
            *static_cast<u_int *>(argument) = static_cast<u_int>(linkType);
            call.value = linkType;
        } else if (request == BIOCSHDRCMPLT) {
            call.value = *static_cast<u_int *>(argument);
        } else if (request == BIOCGHDRCMPLT) {
            *static_cast<u_int *>(argument) = static_cast<u_int>(headerCompleteReadback);
            call.value = headerCompleteReadback;
        }
        ioctlCalls.append(call);
        return request == failingIoctl ? -1 : 0;
    }

    qint64 writeDevice(int descriptor, const char *data, qsizetype size) override {
        Q_UNUSED(descriptor);
        writtenFrames.append(QByteArray(data, size));
        return writeResult == -2 ? size : writeResult;
    }

    int closeDevice(int descriptor) override {
        closedDescriptors.append(descriptor);
        return closeResult;
    }
};

SessionSnapshot makeSnapshot(const QString &interfaceName = "en0") {
    SessionConfig config{interfaceName, "192.0.2.10",      "192.0.2.30",
                         18081,         {"/api/generate"}, false};
    NetworkFacts facts;
    facts.interfaceName = interfaceName;
    facts.researchIp = "192.0.2.20";
    facts.researchMac = "02:00:00:00:00:20";
    facts.clientMac = "02:00:00:00:00:10";
    facts.serverMac = "02:00:00:00:00:30";
    facts.proxyServerIp = "192.0.2.30";
    facts.proxyServerPort = 18081;
    facts.proxyListenPort = 11434;
    facts.interfaceUp = facts.sameLink = facts.anchorAttached = facts.proxyReady =
        facts.authorized = true;
    auto snapshot = SessionSnapshot::create(config, facts, 11434, "offline-bpf-test");
    if (!snapshot)
        qFatal("Cannot construct synthetic ARP snapshot");
    return *snapshot;
}

ArpLabProbePlan makeProbePlan() {
    ArpLabProbeInputs inputs;
    inputs.selectedInterfaceName = "en0";
    inputs.observedInterfaceName = "en0";
    inputs.researchIp = "192.0.2.20";
    inputs.clientIp = "192.0.2.11";
    inputs.serverIp = "192.0.2.31";
    inputs.researchMac = "02:00:00:00:00:20";
    inputs.clientMac = "02:00:00:00:00:11";
    inputs.serverMac = "02:00:00:00:00:31";
    const auto plan = ArpLabProbePlan::create(inputs);
    if (!plan)
        qFatal("Cannot construct synthetic ARP-only probe plan");
    return *plan;
}

QByteArray validReplyFrame(const SessionSnapshot &snapshot) {
    const auto frame = snapshot.redirectionFrames().front();
    if (frame.size() != MacBpfArpPacketIo::arpFrameSize)
        qFatal("Cannot construct synthetic ARP reply");
    return frame;
}

QByteArray validUnplannedReply() {
    return ArpCodec::encode({QByteArray::fromHex("020000000020"),
                             QByteArray::fromHex("020000000044"),
                             QByteArray::fromHex("020000000020"),
                             QByteArray::fromHex("020000000044"), "192.0.2.44", "192.0.2.20", 2});
}
} // namespace

class M6MacBpfArpPacketIoTests : public QObject {
    Q_OBJECT
  private slots:
    void scansAtMostTheBoundedBpfDeviceRange() {
        const auto snapshot = makeSnapshot();
        FakeBpfSystemCalls calls;
        calls.descriptorsBeforeSuccess = MacBpfArpPacketIo::maximumDeviceIndex + 1;

        MacBpfArpPacketIo writer(snapshot, calls);

        QVERIFY(!writer.isReady());
        QCOMPARE(writer.status(), BpfArpWriterStatus::OpenFailed);
        QCOMPARE(calls.openedPaths.size(), MacBpfArpPacketIo::maximumDeviceIndex + 1);
        QCOMPARE(calls.openedPaths.first(), QString("/dev/bpf0"));
        QCOMPARE(calls.openedPaths.last(), QString("/dev/bpf255"));
        QVERIFY(calls.ioctlCalls.isEmpty());
        QVERIFY(calls.closedDescriptors.isEmpty());
    }

    void opensFirstAvailableDeviceAndBindsSelectedInterface() {
        const auto snapshot = makeSnapshot();
        FakeBpfSystemCalls calls;
        calls.descriptorsBeforeSuccess = 2;

        MacBpfArpPacketIo writer(snapshot, calls);

        QVERIFY(writer.isReady());
        QCOMPARE(writer.status(), BpfArpWriterStatus::Ready);
        QCOMPARE(writer.interfaceName(), QString("en0"));
        QCOMPARE(calls.openedPaths, QList<QString>({"/dev/bpf0", "/dev/bpf1", "/dev/bpf2"}));
        QCOMPARE(calls.ioctlCalls.size(), 4);
        QCOMPARE(calls.ioctlCalls[0].request, static_cast<unsigned long>(BIOCSETIF));
        QCOMPARE(calls.ioctlCalls[0].interfaceName, QByteArray("en0"));
        QCOMPARE(calls.ioctlCalls[1].request, static_cast<unsigned long>(BIOCGDLT));
        QCOMPARE(calls.ioctlCalls[2].request, static_cast<unsigned long>(BIOCSHDRCMPLT));
        QCOMPARE(calls.ioctlCalls[2].value, 1);
        QCOMPARE(calls.ioctlCalls[3].request, static_cast<unsigned long>(BIOCGHDRCMPLT));
        QCOMPARE(calls.ioctlCalls[3].value, 1);
        QVERIFY(calls.openedPaths.first().startsWith("/dev/bpf"));
        for (const auto flags : calls.openFlags) {
            QVERIFY(flags & O_RDWR);
            QVERIFY(flags & O_CLOEXEC);
            QVERIFY(flags & O_NONBLOCK);
        }
        QVERIFY(writer.close());
        QCOMPARE(calls.closedDescriptors, QList<int>({42}));
    }

    void rejectsNonEthernetDltAndClosesDescriptor() {
        const auto snapshot = makeSnapshot();
        FakeBpfSystemCalls calls;
        calls.linkType = 12;

        MacBpfArpPacketIo writer(snapshot, calls);

        QVERIFY(!writer.isReady());
        QCOMPARE(writer.status(), BpfArpWriterStatus::UnsupportedLinkType);
        QCOMPARE(calls.ioctlCalls.size(), 2);
        QCOMPARE(calls.closedDescriptors, QList<int>({42}));
        QVERIFY(calls.writtenFrames.isEmpty());
    }

    void closesDescriptorOnEachSetupFailure() {
        const QList<unsigned long> failureRequests{BIOCSETIF, BIOCGDLT, BIOCSHDRCMPLT,
                                                   BIOCGHDRCMPLT};
        const QList<BpfArpWriterStatus> expectedStatuses{
            BpfArpWriterStatus::AttachFailed, BpfArpWriterStatus::UnsupportedLinkType,
            BpfArpWriterStatus::HeaderCompleteFailed, BpfArpWriterStatus::HeaderCompleteFailed};

        for (qsizetype i = 0; i < failureRequests.size(); ++i) {
            const auto snapshot = makeSnapshot();
            FakeBpfSystemCalls calls;
            calls.failingIoctl = failureRequests[i];
            MacBpfArpPacketIo writer(snapshot, calls);
            QVERIFY(!writer.isReady());
            QCOMPARE(writer.status(), expectedStatuses[i]);
            QCOMPARE(calls.closedDescriptors, QList<int>({42}));
            QVERIFY(calls.writtenFrames.isEmpty());
        }

        FakeBpfSystemCalls badReadback;
        badReadback.headerCompleteReadback = 0;
        const auto snapshot = makeSnapshot();
        MacBpfArpPacketIo writer(snapshot, badReadback);
        QVERIFY(!writer.isReady());
        QCOMPARE(writer.status(), BpfArpWriterStatus::HeaderCompleteFailed);
        QCOMPARE(badReadback.closedDescriptors, QList<int>({42}));
    }

    void refusesInvalidInterfaceWithoutOpeningDevice() {
        const auto snapshot = makeSnapshot("abcdefghijklmnop");
        FakeBpfSystemCalls calls;

        MacBpfArpPacketIo writer(snapshot, calls);

        QVERIFY(!writer.isReady());
        QCOMPARE(writer.status(), BpfArpWriterStatus::InvalidInterface);
        QVERIFY(calls.openedPaths.isEmpty());
        QVERIFY(calls.ioctlCalls.isEmpty());
    }

    void rejectsWrongInterfaceAndMalformedOrNonExactFramesBeforeWrite() {
        const auto snapshot = makeSnapshot();
        FakeBpfSystemCalls calls;
        MacBpfArpPacketIo writer(snapshot, calls);
        QVERIFY(writer.isReady());
        const auto valid = validReplyFrame(snapshot);

        QVERIFY(!writer.sendFrame("en1", valid));
        QCOMPARE(writer.status(), BpfArpWriterStatus::InterfaceMismatch);
        QVERIFY(!writer.sendFrame("en0", valid.left(59)));
        QCOMPARE(writer.status(), BpfArpWriterStatus::InvalidFrame);
        QVERIFY(!writer.sendFrame("en0", valid + '\0'));
        QCOMPARE(writer.status(), BpfArpWriterStatus::InvalidFrame);
        QVERIFY(!writer.sendFrame("en0", QByteArray(60, '\0')));
        QCOMPARE(writer.status(), BpfArpWriterStatus::InvalidFrame);
        const auto request = ArpCodec::encode(
            {QByteArray::fromHex("020000000020"), QByteArray::fromHex("020000000010"),
             QByteArray::fromHex("020000000020"), QByteArray::fromHex("020000000010"), "192.0.2.30",
             "192.0.2.10", 1});
        QCOMPARE(request.size(), MacBpfArpPacketIo::arpFrameSize);
        QVERIFY(!writer.sendFrame("en0", request));
        QCOMPARE(writer.status(), BpfArpWriterStatus::InvalidFrame);
        QVERIFY(calls.writtenFrames.isEmpty());
    }

    void rejectsAValidArpReplyOutsideTheSnapshotPair() {
        const auto snapshot = makeSnapshot();
        FakeBpfSystemCalls calls;
        MacBpfArpPacketIo writer(snapshot, calls);
        QVERIFY(writer.isReady());
        const auto outOfPair = ArpCodec::encode(
            {QByteArray::fromHex("020000000020"), QByteArray::fromHex("020000000077"),
             QByteArray::fromHex("020000000020"), QByteArray::fromHex("020000000077"), "192.0.2.77",
             "192.0.2.20", 2});
        QCOMPARE(outOfPair.size(), MacBpfArpPacketIo::arpFrameSize);
        QVERIFY(ArpCodec::parse(outOfPair).has_value());

        QVERIFY(!writer.sendFrame("en0", outOfPair));

        QCOMPARE(writer.status(), BpfArpWriterStatus::InvalidFrame);
        QVERIFY(calls.writtenFrames.isEmpty());
    }

    void probeWriterAllowsOnlyItsTwoPlannedFrames() {
        const auto plan = makeProbePlan();
        FakeBpfSystemCalls calls;
        MacBpfArpPacketIo writer(plan, calls);
        QVERIFY(writer.isReady());
        QCOMPARE(plan.allowedFrames().size(), 2);

        for (const auto &frame : plan.allowedFrames())
            QVERIFY(writer.sendFrame(plan.interfaceName(), frame));
        QCOMPARE(calls.writtenFrames, plan.allowedFrames());

        const auto unrelatedValidReply = ArpCodec::encode(
            {QByteArray::fromHex("020000000020"), QByteArray::fromHex("020000000044"),
             QByteArray::fromHex("020000000020"), QByteArray::fromHex("020000000044"), "192.0.2.44",
             "192.0.2.20", 2});
        QCOMPARE(unrelatedValidReply.size(), MacBpfArpPacketIo::arpFrameSize);
        QVERIFY(ArpCodec::parse(unrelatedValidReply).has_value());
        QVERIFY(!writer.sendFrame(plan.interfaceName(), unrelatedValidReply));
        QCOMPARE(writer.status(), BpfArpWriterStatus::InvalidFrame);
        QCOMPARE(calls.writtenFrames, plan.allowedFrames());
    }

    void snapshotWriterRetainsItsExistingFourFrameAllowlist() {
        const auto snapshot = makeSnapshot();
        FakeBpfSystemCalls calls;
        MacBpfArpPacketIo writer(snapshot, calls);
        QVERIFY(writer.isReady());
        auto expectedFrames = snapshot.redirectionFrames();
        expectedFrames.append(snapshot.restorationFrames());
        QCOMPARE(expectedFrames.size(), 4);

        for (const auto &frame : expectedFrames)
            QVERIFY(writer.sendFrame(snapshot.facts().interfaceName, frame));
        QCOMPARE(calls.writtenFrames, expectedFrames);

        QVERIFY(!writer.sendFrame(snapshot.facts().interfaceName, validUnplannedReply()));
        QCOMPARE(writer.status(), BpfArpWriterStatus::InvalidFrame);
        QCOMPARE(calls.writtenFrames, expectedFrames);
    }

    void shortAndErrorWritesFailOnceAndRemainUncertain() {
        const auto snapshot = makeSnapshot();
        const auto frame = validReplyFrame(snapshot);
        for (const qint64 writeResult : {qint64(17), qint64(-1)}) {
            FakeBpfSystemCalls calls;
            calls.writeResult = writeResult;
            MacBpfArpPacketIo writer(snapshot, calls);
            QVERIFY(writer.isReady());

            QVERIFY(!writer.sendFrame("en0", frame));

            QCOMPARE(writer.status(), BpfArpWriterStatus::WriteFailed);
            QVERIFY(writer.lastWriteMayHaveApplied());
            QCOMPARE(calls.writtenFrames, QList<QByteArray>({frame}));
            QVERIFY(writer.close());
            QCOMPARE(calls.closedDescriptors, QList<int>({42}));
        }
    }

    void completeWriteAndCloseDoNotUseNativeDeviceCalls() {
        const auto snapshot = makeSnapshot();
        FakeBpfSystemCalls calls;
        MacBpfArpPacketIo writer(snapshot, calls);
        const auto frame = validReplyFrame(snapshot);

        QVERIFY(writer.sendFrame("en0", frame));

        QCOMPARE(writer.status(), BpfArpWriterStatus::Ready);
        QVERIFY(writer.lastWriteMayHaveApplied());
        QCOMPARE(calls.writtenFrames, QList<QByteArray>({frame}));
        QVERIFY(writer.close());
        QVERIFY(!writer.isReady());
        QVERIFY(writer.close());
        QCOMPARE(calls.closedDescriptors, QList<int>({42}));
    }

    void reportsCloseFailureWithoutRetryingTheDescriptor() {
        const auto snapshot = makeSnapshot();
        FakeBpfSystemCalls calls;
        calls.closeResult = -1;
        MacBpfArpPacketIo writer(snapshot, calls);
        QVERIFY(writer.isReady());

        QVERIFY(!writer.close());

        QVERIFY(!writer.isReady());
        QCOMPARE(writer.status(), BpfArpWriterStatus::CloseFailed);
        QVERIFY(!writer.close());
        QCOMPARE(calls.closedDescriptors, QList<int>({42}));
    }

    void preservesCloseFailureWhenSetupFailureAlsoNeedsCleanup() {
        const auto snapshot = makeSnapshot();
        FakeBpfSystemCalls calls;
        calls.failingIoctl = BIOCSETIF;
        calls.closeResult = -1;

        MacBpfArpPacketIo writer(snapshot, calls);

        QVERIFY(!writer.isReady());
        QCOMPARE(writer.status(), BpfArpWriterStatus::CloseFailed);
        QCOMPARE(calls.closedDescriptors, QList<int>({42}));
        QVERIFY(!writer.close());
        QCOMPARE(calls.closedDescriptors, QList<int>({42}));
    }

    void openOnlyReadinessSucceedsAndAlwaysClosesWithoutWriting() {
        FakeBpfSystemCalls calls;

        const auto result = MacBpfArpPacketIo::probeReadiness("en0", calls);

        QVERIFY(result.ready());
        QCOMPARE(result.status, BpfArpWriterStatus::Ready);
        QVERIFY(result.deviceOpened);
        QVERIFY(result.interfaceBound);
        QVERIFY(result.ethernetLink);
        QVERIFY(result.headerComplete);
        QVERIFY(result.closeConfirmed);
        QCOMPARE(calls.closedDescriptors, QList<int>({42}));
        QVERIFY(calls.writtenFrames.isEmpty());
    }

    void openOnlyReadinessRejectsInvalidInterfaceBeforeOpen() {
        FakeBpfSystemCalls calls;

        const auto result = MacBpfArpPacketIo::probeReadiness("../en0", calls);

        QVERIFY(!result.ready());
        QCOMPARE(result.status, BpfArpWriterStatus::InvalidInterface);
        QVERIFY(!result.deviceOpened);
        QVERIFY(calls.openedPaths.isEmpty());
        QVERIFY(calls.ioctlCalls.isEmpty());
        QVERIFY(calls.closedDescriptors.isEmpty());
        QVERIFY(calls.writtenFrames.isEmpty());
    }

    void openOnlyReadinessReportsPermissionFailureWithoutCleanupOrWrite() {
        FakeBpfSystemCalls calls;
        calls.forcedOpenError = EACCES;

        const auto result = MacBpfArpPacketIo::probeReadiness("en0", calls);

        QVERIFY(!result.ready());
        QCOMPARE(result.status, BpfArpWriterStatus::OpenFailed);
        QVERIFY(!result.deviceOpened);
        QVERIFY(!result.interfaceBound);
        QVERIFY(!result.closeConfirmed);
        QCOMPARE(calls.openedPaths, QList<QString>({"/dev/bpf0"}));
        QVERIFY(calls.ioctlCalls.isEmpty());
        QVERIFY(calls.closedDescriptors.isEmpty());
        QVERIFY(calls.writtenFrames.isEmpty());
    }

    void openOnlyReadinessClosesAfterBindDltAndHeaderFailures() {
        struct SetupFailure {
            unsigned long request;
            int linkType;
            int headerReadback;
            BpfArpWriterStatus status;
        };
        const QList<SetupFailure> failures{
            {BIOCSETIF, DLT_EN10MB, 1, BpfArpWriterStatus::AttachFailed},
            {BIOCGDLT, DLT_EN10MB, 1, BpfArpWriterStatus::UnsupportedLinkType},
            {0, 12, 1, BpfArpWriterStatus::UnsupportedLinkType},
            {BIOCSHDRCMPLT, DLT_EN10MB, 1, BpfArpWriterStatus::HeaderCompleteFailed},
            {BIOCGHDRCMPLT, DLT_EN10MB, 1, BpfArpWriterStatus::HeaderCompleteFailed},
            {0, DLT_EN10MB, 0, BpfArpWriterStatus::HeaderCompleteFailed}};

        for (const auto &failure : failures) {
            FakeBpfSystemCalls calls;
            calls.failingIoctl = failure.request;
            calls.linkType = failure.linkType;
            calls.headerCompleteReadback = failure.headerReadback;

            const auto result = MacBpfArpPacketIo::probeReadiness("en0", calls);

            QVERIFY(!result.ready());
            QCOMPARE(result.status, failure.status);
            QVERIFY(result.deviceOpened);
            QVERIFY(result.closeConfirmed);
            QCOMPARE(calls.closedDescriptors, QList<int>({42}));
            QVERIFY(calls.writtenFrames.isEmpty());
        }
    }

    void openOnlyReadinessReportsCloseFailureWithoutWriting() {
        FakeBpfSystemCalls calls;
        calls.closeResult = -1;

        const auto result = MacBpfArpPacketIo::probeReadiness("en0", calls);

        QVERIFY(!result.ready());
        QCOMPARE(result.status, BpfArpWriterStatus::CloseFailed);
        QVERIFY(result.deviceOpened);
        QVERIFY(result.interfaceBound);
        QVERIFY(result.ethernetLink);
        QVERIFY(result.headerComplete);
        QVERIFY(!result.closeConfirmed);
        QCOMPARE(calls.closedDescriptors, QList<int>({42}));
        QVERIFY(calls.writtenFrames.isEmpty());
    }

    void cliInvalidArgumentsNeverOpenDevice() {
        const QList<QStringList> invalidArguments{{"arp_bpf_readiness"},
                                                  {"arp_bpf_readiness", "--bogus"},
                                                  {"arp_bpf_readiness", "--interface"}};
        for (const auto &arguments : invalidArguments) {
            FakeBpfSystemCalls calls;

            const auto result = ArpBpfReadinessCli::run(arguments, calls);

            QCOMPARE(result.exitCode, 2);
            QVERIFY(result.standardOutput.isEmpty());
            QVERIFY(!result.standardError.isEmpty());
            QVERIFY(calls.openedPaths.isEmpty());
            QVERIFY(calls.ioctlCalls.isEmpty());
            QVERIFY(calls.writtenFrames.isEmpty());
        }

        FakeBpfSystemCalls invalidInterfaceCalls;
        const auto invalidInterface = ArpBpfReadinessCli::run(
            {"arp_bpf_readiness", "--interface", "../en0"}, invalidInterfaceCalls);
        QCOMPARE(invalidInterface.exitCode, 1);
        QVERIFY(invalidInterface.standardOutput.contains("invalid_interface"));
        QVERIFY(invalidInterfaceCalls.openedPaths.isEmpty());
        QVERIFY(invalidInterfaceCalls.ioctlCalls.isEmpty());
        QVERIFY(invalidInterfaceCalls.writtenFrames.isEmpty());
    }

    void cliHelpVersionUnknownAndDuplicateArgumentsNeverOpenDevice() {
        const QList<QPair<QStringList, int>> cases{
            {{"arp_bpf_readiness", "--help"}, 0},
            {{"arp_bpf_readiness", "--version"}, 0},
            {{"arp_bpf_readiness", "--interface", "en0", "--interface", "en1"}, 2},
            {{"arp_bpf_readiness", "--unknown"}, 2}};
        for (const auto &testCase : cases) {
            FakeBpfSystemCalls calls;

            const auto result = ArpBpfReadinessCli::run(testCase.first, calls);

            QCOMPARE(result.exitCode, testCase.second);
            QVERIFY(calls.openedPaths.isEmpty());
            QVERIFY(calls.ioctlCalls.isEmpty());
            QVERIFY(calls.writtenFrames.isEmpty());
        }
    }

    void cliSuccessReturnsSanitizedOpenOnlyJsonWithoutWriting() {
        FakeBpfSystemCalls calls;

        const auto result =
            ArpBpfReadinessCli::run({"arp_bpf_readiness", "--interface", "en0"}, calls);

        QCOMPARE(result.exitCode, 0);
        QVERIFY(result.standardError.isEmpty());
        QJsonParseError parseError;
        const auto document = QJsonDocument::fromJson(result.standardOutput.toUtf8(), &parseError);
        QCOMPARE(parseError.error, QJsonParseError::NoError);
        QVERIFY(document.isObject());
        const auto object = document.object();
        QCOMPARE(object.value("status").toString(), QString("ready"));
        QVERIFY(object.value("device_opened").toBool());
        QVERIFY(object.value("interface_bound").toBool());
        QVERIFY(object.value("ethernet_link").toBool());
        QVERIFY(object.value("header_complete").toBool());
        QVERIFY(object.value("close_confirmed").toBool());
        QCOMPARE(object.value("traffic_sent").toBool(), false);
        QCOMPARE(object.size(), 7);
        QVERIFY(!result.standardOutput.contains("en0"));
        QVERIFY(!result.standardOutput.contains("192."));
        QVERIFY(!result.standardOutput.contains("02:00"));
        QVERIFY(!result.standardOutput.contains("/dev/bpf"));
        QVERIFY(!result.standardOutput.contains("errno"));
        QCOMPARE(calls.closedDescriptors, QList<int>({42}));
        QVERIFY(calls.writtenFrames.isEmpty());
    }
};

QTEST_GUILESS_MAIN(M6MacBpfArpPacketIoTests)
#include "M6MacBpfArpPacketIoTests.moc"
