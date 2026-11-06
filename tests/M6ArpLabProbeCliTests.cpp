#include "network/ArpCodec.hpp"
#include "network/ArpLabProbeCli.hpp"

#include <QJsonDocument>
#include <QJsonObject>
#include <QtTest>

#include <cerrno>
#include <cstring>
#include <functional>
#include <net/bpf.h>
#include <net/if.h>
#include <sys/ioctl.h>

using namespace interceptor;

namespace {
const QString kResearchIp = "192.0.2.20";
const QString kClientIp = "192.0.2.11";
const QString kServerIp = "192.0.2.31";
const QString kResearchMac = "02:00:00:00:00:20";
const QString kClientMac = "02:00:00:00:00:11";
const QString kServerMac = "02:00:00:00:00:31";

class FakeBpfSystemCalls final : public BpfSystemCalls {
  public:
    QStringList openedPaths;
    QList<unsigned long> ioctls;
    QList<QByteArray> writtenFrames;
    QList<int> closedDescriptors;
    int descriptor = 51;
    int linkType = DLT_EN10MB;
    int headerCompleteReadback = 1;
    int failIoctl = 0;
    int failWriteAt = -1;
    qint64 failedWriteResult = -1;
    int closeResult = 0;

    int openDevice(const QString &path, int, int &errorNumber) override {
        openedPaths.append(path);
        errorNumber = 0;
        return descriptor;
    }

    int ioctlDevice(int fd, unsigned long request, void *argument) override {
        Q_UNUSED(fd);
        ioctls.append(request);
        if (request == BIOCSETIF) {
            const auto *ifreq = static_cast<const struct ifreq *>(argument);
            const auto name = QByteArray(
                ifreq->ifr_name, static_cast<qsizetype>(strnlen(ifreq->ifr_name, IFNAMSIZ)));
            if (name != QByteArray("en0"))
                return -1;
        } else if (request == BIOCGDLT) {
            *static_cast<u_int *>(argument) = static_cast<u_int>(linkType);
        } else if (request == BIOCGHDRCMPLT) {
            *static_cast<u_int *>(argument) = static_cast<u_int>(headerCompleteReadback);
        }
        return request == static_cast<unsigned long>(failIoctl) ? -1 : 0;
    }

    qint64 writeDevice(int fd, const char *data, qsizetype size) override {
        Q_UNUSED(fd);
        writtenFrames.append(QByteArray(data, size));
        if (writtenFrames.size() == failWriteAt)
            return failedWriteResult;
        return size;
    }

    int closeDevice(int fd) override {
        closedDescriptors.append(fd);
        return closeResult;
    }
};

class FakeWaiter final : public ArpProbeWaiter {
  public:
    bool interruptedInitially = false;
    bool interruptedAfterWait = false;
    ArpProbeWaitOutcome outcome = ArpProbeWaitOutcome::Elapsed;
    QList<int> waits;

    bool interrupted() const override { return interruptedInitially || interruptedAfterWait; }
    ArpProbeWaitOutcome waitFor(int durationMs) override {
        waits.append(durationMs);
        interruptedAfterWait = outcome == ArpProbeWaitOutcome::Interrupted;
        return outcome;
    }
};

class FakeInterfaceInspector final : public ArpProbeInterfaceInspector {
  public:
    ArpProbeInterfaceEvidence evidence{true, true, true, "en0", kResearchMac, {{kResearchIp, 24}}};
    QStringList inspectedInterfaces;

    ArpProbeInterfaceEvidence inspect(const QString &interfaceName) override {
        inspectedInterfaces.append(interfaceName);
        return evidence;
    }
};

QStringList validArguments() {
    return {"arp_arp_probe",
            "--interface",
            "en0",
            "--research-ip",
            kResearchIp,
            "--research-mac",
            kResearchMac,
            "--client-ip",
            kClientIp,
            "--client-mac",
            kClientMac,
            "--server-ip",
            kServerIp,
            "--server-mac",
            kServerMac,
            "--prefix-length",
            "24",
            "--duration-ms",
            "1250",
            "--confirm-one-client-arp-probe"};
}

QJsonObject parseOutput(const ArpLabProbeCliResult &result) {
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(result.standardOutput.toUtf8(), &error);
    if (error.error != QJsonParseError::NoError || !document.isObject())
        qFatal("Probe CLI did not return valid JSON output");
    return document.object();
}

void verifyNoSensitiveOutput(const QString &output) {
    for (const auto &secret : {QString("en0"), kResearchIp, kClientIp, kServerIp, kResearchMac,
                               kClientMac, kServerMac, QString("/dev/bpf"), QString("errno")})
        QVERIFY(!output.contains(secret));
}
} // namespace

class M6ArpLabProbeCliTests : public QObject {
    Q_OBJECT
  private slots:
    void rejectsUnexpectedPositionalArgumentsBeforeOpeningBpf() {
        auto arguments = validArguments();
        arguments.append("198.51.100.77");
        FakeBpfSystemCalls calls;
        FakeWaiter waiter;
        FakeInterfaceInspector inspector;

        const auto result = ArpLabProbeCli::run(arguments, calls, waiter, inspector);

        QCOMPARE(result.exitCode, 2);
        QVERIFY(result.standardOutput.isEmpty());
        QVERIFY(!result.standardError.isEmpty());
        QVERIFY(calls.openedPaths.isEmpty());
        QVERIFY(calls.writtenFrames.isEmpty());
    }

    void timeoutSendsOnlyRedirectThenCorrectionAndSanitizedResult() {
        FakeBpfSystemCalls calls;
        FakeWaiter waiter;
        FakeInterfaceInspector inspector;

        const auto result = ArpLabProbeCli::run(validArguments(), calls, waiter, inspector);

        QCOMPARE(result.exitCode, 0);
        const auto json = parseOutput(result);
        QCOMPARE(json.value("status").toString(),
                 QString("corrective_frame_write_accepted_after_timeout"));
        QVERIFY(json.value("redirect_write_attempted").toBool());
        QVERIFY(json.value("redirect_write_accepted").toBool());
        QVERIFY(json.value("corrective_write_attempted").toBool());
        QVERIFY(json.value("corrective_write_accepted").toBool());
        QVERIFY(json.value("descriptor_close_confirmed").toBool());
        QCOMPARE(json.value("peer_cache_change_verified").toBool(), false);
        QCOMPARE(calls.writtenFrames.size(), 2);
        QCOMPARE(calls.writtenFrames[0].size(), 60);
        QCOMPARE(calls.writtenFrames[1].size(), 60);
        const auto redirect = ArpCodec::parse(calls.writtenFrames[0]);
        const auto correction = ArpCodec::parse(calls.writtenFrames[1]);
        QVERIFY(redirect.has_value());
        QVERIFY(correction.has_value());
        QCOMPARE(redirect->senderIp, kServerIp);
        QCOMPARE(redirect->targetIp, kClientIp);
        QCOMPARE(redirect->senderMac, QByteArray::fromHex("020000000020"));
        QCOMPARE(correction->senderIp, kServerIp);
        QCOMPARE(correction->targetIp, kClientIp);
        QCOMPARE(correction->senderMac, QByteArray::fromHex("020000000031"));
        QCOMPARE(waiter.waits, QList<int>({1250}));
        QCOMPARE(calls.closedDescriptors, QList<int>({51}));
        QCOMPARE(inspector.inspectedInterfaces, QStringList({"en0"}));
        verifyNoSensitiveOutput(result.standardOutput);
    }

    void validationMismatchDoesNotOpenBpf() {
        const QList<std::function<void(ArpProbeInterfaceEvidence &)>> invalidEvidence{
            [](auto &evidence) { evidence.found = false; },
            [](auto &evidence) { evidence.up = false; },
            [](auto &evidence) { evidence.running = false; },
            [](auto &evidence) { evidence.interfaceName = "en1"; },
            [](auto &evidence) { evidence.macAddress = "02:00:00:00:00:99"; },
            [](auto &evidence) { evidence.ipv4Addresses.clear(); },
            [](auto &evidence) { evidence.ipv4Addresses[0].prefixLength = 25; }};

        for (const auto &mutate : invalidEvidence) {
            FakeBpfSystemCalls calls;
            FakeWaiter waiter;
            FakeInterfaceInspector inspector;
            mutate(inspector.evidence);

            const auto result = ArpLabProbeCli::run(validArguments(), calls, waiter, inspector);

            QCOMPARE(result.exitCode, 2);
            QCOMPARE(parseOutput(result).value("status").toString(),
                     QString("interface_preflight_failed"));
            QVERIFY(calls.openedPaths.isEmpty());
            QVERIFY(calls.ioctls.isEmpty());
            QVERIFY(calls.writtenFrames.isEmpty());
            QVERIFY(calls.closedDescriptors.isEmpty());
            verifyNoSensitiveOutput(result.standardOutput);
        }
    }

    void malformedPlanAndPreexistingSignalDoNotOpenBpf() {
        auto invalidArgs = validArguments();
        invalidArgs[invalidArgs.indexOf(kClientIp)] = "192.0.2.255";
        FakeBpfSystemCalls invalidCalls;
        FakeWaiter invalidWaiter;
        FakeInterfaceInspector invalidInspector;
        const auto invalidResult =
            ArpLabProbeCli::run(invalidArgs, invalidCalls, invalidWaiter, invalidInspector);
        QCOMPARE(invalidResult.exitCode, 2);
        QCOMPARE(parseOutput(invalidResult).value("status").toString(),
                 QString("invalid_probe_plan"));
        QVERIFY(invalidCalls.openedPaths.isEmpty());
        QVERIFY(invalidCalls.writtenFrames.isEmpty());

        auto invalidDurationArgs = validArguments();
        invalidDurationArgs[invalidDurationArgs.indexOf("1250")] = "5001";
        FakeBpfSystemCalls durationCalls;
        FakeWaiter durationWaiter;
        FakeInterfaceInspector durationInspector;
        const auto durationResult = ArpLabProbeCli::run(invalidDurationArgs, durationCalls,
                                                        durationWaiter, durationInspector);
        QCOMPARE(durationResult.exitCode, 2);
        QVERIFY(durationCalls.openedPaths.isEmpty());
        QVERIFY(durationCalls.writtenFrames.isEmpty());

        FakeBpfSystemCalls signalCalls;
        FakeWaiter signalWaiter;
        signalWaiter.interruptedInitially = true;
        FakeInterfaceInspector signalInspector;
        const auto signalResult =
            ArpLabProbeCli::run(validArguments(), signalCalls, signalWaiter, signalInspector);
        QCOMPARE(parseOutput(signalResult).value("status").toString(),
                 QString("interrupted_before_redirect"));
        QVERIFY(signalCalls.openedPaths.isEmpty());
        QVERIFY(signalCalls.writtenFrames.isEmpty());
    }

    void interruptedWaitRestoresAndPartialRedirectFailureStillCorrects() {
        FakeBpfSystemCalls signalCalls;
        FakeWaiter signalWaiter;
        signalWaiter.outcome = ArpProbeWaitOutcome::Interrupted;
        FakeInterfaceInspector signalInspector;
        const auto signalResult =
            ArpLabProbeCli::run(validArguments(), signalCalls, signalWaiter, signalInspector);
        QCOMPARE(signalResult.exitCode, 130);
        QCOMPARE(parseOutput(signalResult).value("status").toString(),
                 QString("corrective_frame_write_accepted_after_signal"));
        QCOMPARE(signalCalls.writtenFrames.size(), 2);
        QCOMPARE(signalWaiter.waits, QList<int>({1250}));

        FakeBpfSystemCalls partialCalls;
        partialCalls.failWriteAt = 1;
        partialCalls.failedWriteResult = 22;
        FakeWaiter partialWaiter;
        FakeInterfaceInspector partialInspector;
        const auto partialResult =
            ArpLabProbeCli::run(validArguments(), partialCalls, partialWaiter, partialInspector);
        QCOMPARE(partialResult.exitCode, 1);
        QCOMPARE(parseOutput(partialResult).value("status").toString(),
                 QString("redirect_write_uncertain_corrective_write_accepted"));
        QCOMPARE(partialCalls.writtenFrames.size(), 2);
        QCOMPARE(partialWaiter.waits.size(), 0);
        QCOMPARE(partialCalls.writtenFrames[1].size(), 60);
        QVERIFY(parseOutput(partialResult).value("corrective_write_accepted").toBool());
    }

    void failedCorrectionIsReportedWithoutSendingAnyAdditionalFrames() {
        FakeBpfSystemCalls calls;
        calls.failWriteAt = 2;
        FakeWaiter waiter;
        FakeInterfaceInspector inspector;

        const auto result = ArpLabProbeCli::run(validArguments(), calls, waiter, inspector);

        QCOMPARE(result.exitCode, 1);
        QCOMPARE(parseOutput(result).value("status").toString(), QString("cleanup_uncertain"));
        QCOMPARE(calls.writtenFrames.size(), 2);
        QVERIFY(parseOutput(result).value("redirect_write_accepted").toBool());
        QVERIFY(!parseOutput(result).value("corrective_write_accepted").toBool());
        QVERIFY(calls.writtenFrames[0] != calls.writtenFrames[1]);
    }

    void missingUnknownAndDuplicateOptionsNeverOpenDevice() {
        auto missing = validArguments();
        const auto serverMacIndex = missing.indexOf("--server-mac");
        missing.removeAt(serverMacIndex + 1);
        missing.removeAt(serverMacIndex);

        auto unknown = validArguments();
        unknown.append("--unknown-option");

        auto positional = validArguments();
        positional.append("unexpected-token");

        auto duplicate = validArguments();
        duplicate.append("--interface=en0");

        for (const auto &arguments : {missing, unknown, duplicate, positional}) {
            FakeBpfSystemCalls calls;
            FakeWaiter waiter;
            FakeInterfaceInspector inspector;

            const auto result = ArpLabProbeCli::run(arguments, calls, waiter, inspector);

            QCOMPARE(result.exitCode, 2);
            QVERIFY(result.standardOutput.isEmpty());
            QVERIFY(!result.standardError.isEmpty());
            QVERIFY(calls.openedPaths.isEmpty());
            QVERIFY(calls.ioctls.isEmpty());
            QVERIFY(calls.writtenFrames.isEmpty());
            QVERIFY(calls.closedDescriptors.isEmpty());
            verifyNoSensitiveOutput(result.standardError);
        }
    }
};

QTEST_GUILESS_MAIN(M6ArpLabProbeCliTests)
#include "M6ArpLabProbeCliTests.moc"
