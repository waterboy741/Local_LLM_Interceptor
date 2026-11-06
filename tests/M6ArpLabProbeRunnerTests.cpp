#include "network/ArpLabProbeRunner.hpp"

#include <QtTest>

#include <stdexcept>

using namespace interceptor;

namespace {
ArpLabProbePlan makePlan() {
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
        qFatal("Cannot construct synthetic ARP probe plan");
    return *plan;
}

class FakePacketIo final : public ArpPacketIo {
  public:
    struct Write {
        QString interfaceName;
        QByteArray frame;
    };
    QList<Write> writes;
    int failAt = -1;
    int throwAt = -1;

    bool sendFrame(const QString &interfaceName, const QByteArray &frame) override {
        writes.append({interfaceName, frame});
        if (writes.size() == throwAt)
            throw std::runtime_error("fake packet writer failure");
        return writes.size() != failAt;
    }
};

class FakeWaiter final : public ArpProbeWaiter {
  public:
    bool interruptedInitially = false;
    bool interruptedAfterWait = false;
    bool throwOnWait = false;
    bool throwOnInterruptedAfterWait = false;
    ArpProbeWaitOutcome outcome = ArpProbeWaitOutcome::Elapsed;
    mutable int interruptedChecks = 0;
    bool waitCalled = false;
    QList<int> waits;

    bool interrupted() const override {
        ++interruptedChecks;
        if (throwOnInterruptedAfterWait && waitCalled)
            throw std::runtime_error("fake signal query failure");
        return interruptedInitially || interruptedAfterWait;
    }
    ArpProbeWaitOutcome waitFor(int durationMs) override {
        waits.append(durationMs);
        waitCalled = true;
        if (throwOnWait)
            throw std::runtime_error("fake wait failure");
        interruptedAfterWait = outcome == ArpProbeWaitOutcome::Interrupted;
        return outcome;
    }
};

void verifyTwoPlannedWrites(const FakePacketIo &io, const ArpLabProbePlan &plan) {
    QCOMPARE(io.writes.size(), 2);
    QCOMPARE(io.writes[0].interfaceName, plan.interfaceName());
    QCOMPARE(io.writes[0].frame, plan.redirectionFrame());
    QCOMPARE(io.writes[1].interfaceName, plan.interfaceName());
    QCOMPARE(io.writes[1].frame, plan.restorationFrame());
}
} // namespace

class M6ArpLabProbeRunnerTests : public QObject {
    Q_OBJECT
  private slots:
    void redirectsOnceThenCorrectsAfterTimeout() {
        const auto plan = makePlan();
        FakePacketIo io;
        FakeWaiter waiter;

        const auto result = ArpLabProbeRunner::run(plan, io, waiter, 1750);

        QCOMPARE(result.status, ArpLabProbeStatus::CorrectionWriteAcceptedAfterTimeout);
        QVERIFY(result.writeSequenceComplete());
        QVERIFY(result.redirectAttempted);
        QVERIFY(result.redirectWriteAccepted);
        QVERIFY(result.restorationAttempted);
        QVERIFY(result.restorationWriteAccepted);
        QVERIFY(!result.interrupted);
        QCOMPARE(waiter.waits, QList<int>({1750}));
        verifyTwoPlannedWrites(io, plan);
    }

    void signalDuringWaitStillSendsOneCorrection() {
        const auto plan = makePlan();
        FakePacketIo io;
        FakeWaiter waiter;
        waiter.outcome = ArpProbeWaitOutcome::Interrupted;

        const auto result = ArpLabProbeRunner::run(plan, io, waiter, 5000);

        QCOMPARE(result.status, ArpLabProbeStatus::CorrectionWriteAcceptedAfterSignal);
        QVERIFY(result.writeSequenceComplete());
        QVERIFY(result.interrupted);
        QCOMPARE(waiter.waits, QList<int>({5000}));
        verifyTwoPlannedWrites(io, plan);
    }

    void preexistingSignalPreventsRedirectAndWait() {
        const auto plan = makePlan();
        FakePacketIo io;
        FakeWaiter waiter;
        waiter.interruptedInitially = true;

        const auto result = ArpLabProbeRunner::run(plan, io, waiter, 1000);

        QCOMPARE(result.status, ArpLabProbeStatus::InterruptedBeforeRedirect);
        QVERIFY(result.interrupted);
        QVERIFY(!result.redirectAttempted);
        QVERIFY(!result.restorationAttempted);
        QVERIFY(waiter.waits.isEmpty());
        QVERIFY(io.writes.isEmpty());
    }

    void invalidDurationHasNoPacketOrWaitSideEffects() {
        const auto plan = makePlan();
        for (const int duration : {0, -1, ArpLabProbeRunner::maximumDurationMs + 1}) {
            FakePacketIo io;
            FakeWaiter waiter;

            const auto result = ArpLabProbeRunner::run(plan, io, waiter, duration);

            QCOMPARE(result.status, ArpLabProbeStatus::InvalidDuration);
            QVERIFY(!result.redirectAttempted);
            QVERIFY(!result.restorationAttempted);
            QVERIFY(waiter.waits.isEmpty());
            QVERIFY(io.writes.isEmpty());
        }
    }

    void uncertainRedirectWriteTriggersImmediateCorrectionWithoutRetry() {
        const auto plan = makePlan();
        FakePacketIo io;
        io.failAt = 1;
        FakeWaiter waiter;

        const auto result = ArpLabProbeRunner::run(plan, io, waiter, 5000);

        QCOMPARE(result.status, ArpLabProbeStatus::RedirectWriteUncertainCorrectionAccepted);
        QVERIFY(result.writeSequenceComplete());
        QVERIFY(result.redirectAttempted);
        QVERIFY(!result.redirectWriteAccepted);
        QVERIFY(result.restorationAttempted);
        QVERIFY(result.restorationWriteAccepted);
        QVERIFY(waiter.waits.isEmpty());
        verifyTwoPlannedWrites(io, plan);
    }

    void failedCorrectionLeavesCleanupUncertainWithoutMoreTraffic() {
        const auto plan = makePlan();
        FakePacketIo io;
        io.failAt = 2;
        FakeWaiter waiter;

        const auto result = ArpLabProbeRunner::run(plan, io, waiter, 50);

        QCOMPARE(result.status, ArpLabProbeStatus::CleanupUncertain);
        QVERIFY(!result.writeSequenceComplete());
        QVERIFY(result.redirectWriteAccepted);
        QVERIFY(result.restorationAttempted);
        QVERIFY(!result.restorationWriteAccepted);
        QCOMPARE(waiter.waits, QList<int>({50}));
        verifyTwoPlannedWrites(io, plan);
    }

    void thrownRedirectWriterStillGetsOneCorrectionAttempt() {
        const auto plan = makePlan();
        FakePacketIo io;
        io.throwAt = 1;
        FakeWaiter waiter;

        const auto result = ArpLabProbeRunner::run(plan, io, waiter, 1000);

        QCOMPARE(result.status, ArpLabProbeStatus::RedirectWriteUncertainCorrectionAccepted);
        QVERIFY(!result.redirectWriteAccepted);
        QVERIFY(result.restorationAttempted);
        QVERIFY(result.restorationWriteAccepted);
        QVERIFY(waiter.waits.isEmpty());
        verifyTwoPlannedWrites(io, plan);
    }

    void waiterFailureAfterRedirectStillAttemptsCorrectionAndReportsUncertain() {
        const auto plan = makePlan();
        FakePacketIo io;
        FakeWaiter waiter;
        waiter.throwOnWait = true;

        const auto result = ArpLabProbeRunner::run(plan, io, waiter, 1000);

        QCOMPARE(result.status, ArpLabProbeStatus::CleanupUncertain);
        QVERIFY(result.redirectWriteAccepted);
        QVERIFY(result.restorationAttempted);
        QVERIFY(result.restorationWriteAccepted);
        QCOMPARE(waiter.waits, QList<int>({1000}));
        verifyTwoPlannedWrites(io, plan);
    }

    void signalQueryFailureAfterRedirectStillAttemptsCorrection() {
        const auto plan = makePlan();
        FakePacketIo io;
        FakeWaiter waiter;
        waiter.throwOnInterruptedAfterWait = true;

        const auto result = ArpLabProbeRunner::run(plan, io, waiter, 750);

        QCOMPARE(result.status, ArpLabProbeStatus::CleanupUncertain);
        QVERIFY(result.redirectWriteAccepted);
        QVERIFY(result.restorationAttempted);
        QVERIFY(result.restorationWriteAccepted);
        QCOMPARE(waiter.waits, QList<int>({750}));
        verifyTwoPlannedWrites(io, plan);
    }
};

QTEST_GUILESS_MAIN(M6ArpLabProbeRunnerTests)
#include "M6ArpLabProbeRunnerTests.moc"
