#include "network/InstalledSessionControl.hpp"

#include <QtTest>

#include <algorithm>
#include <vector>

namespace interceptor {

namespace {

// Deterministic offline backend: records the exact call order and every controllable outcome.
class FakeCoreBackend final : public InstalledSessionControlBackend {
  public:
    QStringList calls;
    bool isRoot = true;
    bool verificationSucceeds = true;
    bool starts = true;
    int stopAttemptsUntilClean = 0; // >0: the first N stops report not cleaned

    bool effectiveRoot() override {
        calls << QStringLiteral("root");
        return isRoot;
    }
    bool freshListenerVerification(const InstalledSessionTuple &tuple,
                                   const std::vector<unsigned char> &secret) override {
        calls << QStringLiteral("verify:%1:%2:%3:%4:%5:%6")
                     .arg(QString::fromStdString(tuple.interfaceName),
                          QString::fromStdString(tuple.clientIpv4),
                          QString::fromStdString(tuple.upstreamIpv4),
                          QString::fromStdString(tuple.listenAddress))
                     .arg(tuple.upstreamPort)
                     .arg(tuple.listenerPort);
        lastSecret = secret;
        return verificationSucceeds;
    }
    bool startOwnedOperations(const InstalledSessionTuple &, std::string *error) override {
        calls << QStringLiteral("start");
        if (!starts && error)
            *error = "scoped_backend_unavailable";
        return starts;
    }
    void heartbeatOwnedOperations() override { calls << QStringLiteral("heartbeat"); }
    bool stopOwnedOperations(bool *cleaned, std::string *error) override {
        calls << QStringLiteral("stop");
        const bool cleanedNow = stopAttemptsUntilClean <= 0;
        if (stopAttemptsUntilClean > 0)
            --stopAttemptsUntilClean;
        if (cleaned)
            *cleaned = cleanedNow;
        if (!cleanedNow && error)
            *error = "anchor_cleanup_failed";
        return cleanedNow;
    }

    std::vector<unsigned char> lastSecret;
};

XpcControlRequest startRequest() {
    XpcControlRequest request;
    request.operation = XpcControlOperation::Start;
    request.sessionInterface = "en0";
    request.sessionClientIpv4 = "192.0.2.10";
    request.sessionUpstreamIpv4 = "192.0.2.30";
    request.sessionListenAddress = "192.0.2.20";
    request.sessionUpstreamPort = 18081;
    request.sessionListenerPort = 11434;
    request.probeSecret = std::vector<unsigned char>(32, 'q');
    return request;
}
XpcControlRequest sessionRequest(XpcControlOperation operation, const std::string &sessionId,
                                 const std::vector<unsigned char> &capability) {
    XpcControlRequest request;
    request.operation = operation;
    request.sessionId = sessionId;
    request.sessionCapability = capability;
    return request;
}

} // namespace

class M6InstalledSessionControlCoreTests final : public QObject {
    Q_OBJECT

  private:
    int64_t clockMs = 1000;

    void freshCore(FakeCoreBackend &backend, InstalledSessionControlCore **core) {
        *core = new InstalledSessionControlCore(backend, [this] { return clockMs; });
    }

    static void compareReplyReason(const XpcSessionControlReply &reply, const char *reason) {
        QCOMPARE(reply.reason, std::string(reason));
    }
    static void compareReplyState(const XpcSessionControlReply &reply, const char *state) {
        QCOMPARE(reply.state, std::string(state));
    }

  private slots:
    void readyCoreRejectsSessionBoundCommandsAndUnsupportedOperations() {
        FakeCoreBackend backend;
        InstalledSessionControlCore core(backend, [this] { return clockMs; });
        QCOMPARE(core.state(), xpcSessionControlStateReady);
        QVERIFY(!core.sessionActive());

        const auto heartbeat = core.handleControlRequest(sessionRequest(
            XpcControlOperation::Heartbeat, "session", std::vector<unsigned char>(32, 'a')));
        QVERIFY(!heartbeat.ok);
        compareReplyReason(heartbeat, "session_binding_mismatch");
        compareReplyState(heartbeat, "ready");

        const auto stop = core.handleControlRequest(sessionRequest(
            XpcControlOperation::Stop, "session", std::vector<unsigned char>(32, 'a')));
        QVERIFY(!stop.ok);
        compareReplyReason(stop, "session_binding_mismatch");

        for (const XpcControlOperation operation :
             {XpcControlOperation::Probe, XpcControlOperation::Status,
              XpcControlOperation::Invalid}) {
            XpcControlRequest request;
            request.operation = operation;
            const auto rejected = core.handleControlRequest(request);
            QVERIFY(!rejected.ok);
            compareReplyReason(rejected, "operation_unsupported");
            compareReplyState(rejected, "ready");
        }
    }

    void nonRootOrUnverifiedStartsFailClosedBeforeOperations() {
        {
            FakeCoreBackend backend;
            backend.isRoot = false;
            InstalledSessionControlCore core(backend, [this] { return clockMs; });
            const auto rejected = core.handleControlRequest(startRequest());
            QVERIFY(!rejected.ok);
            compareReplyReason(rejected, "session_start_unavailable");
            compareReplyState(rejected, "ready");
            // Nothing but the root check ran: no verification, no operations.
            QCOMPARE(backend.calls, QStringList{QStringLiteral("root")});
        }
        {
            FakeCoreBackend backend;
            backend.verificationSucceeds = false;
            InstalledSessionControlCore core(backend, [this] { return clockMs; });
            const auto rejected = core.handleControlRequest(startRequest());
            QVERIFY(!rejected.ok);
            QCOMPARE(backend.lastSecret.size(), std::size_t(32));
            QVERIFY(backend.calls.contains(QStringLiteral("root")));
            QVERIFY(!backend.calls.contains(QStringLiteral("start")));
        }
    }

    void freshListenerVerificationRunsOnlyAfterEffectiveRootAndBeforeOperations() {
        for (const QString &backendError :
             {QStringLiteral("scoped_backend_unavailable"), QString()}) {
            FakeCoreBackend backend;
            backend.starts = backendError.isEmpty();
            InstalledSessionControlCore core(backend, [this] { return clockMs; });
            const auto reply = core.handleControlRequest(startRequest());
            // The fixed order: root -> fresh verification -> start owned operations.
            const QStringList expectedCalls = {
                QStringLiteral("root"),
                QStringLiteral("verify:en0:192.0.2.10:192.0.2.30:192.0.2.20:18081:11434"),
                QStringLiteral("start")};
            QCOMPARE(backend.calls, expectedCalls);
            if (!backendError.isEmpty()) {
                QVERIFY(!reply.ok);
                compareReplyReason(reply, "session_start_failed");
                compareReplyState(reply, "ready");
                QVERIFY(reply.sessionCapability.empty());
                QVERIFY(reply.sessionId.empty());
                QVERIFY(!core.sessionActive());
                QCOMPARE(core.state(), xpcSessionControlStateReady);
            }
        }
    }

    void acceptedStartDeliversCapabilityOnceAndEchoesStateActive() {
        FakeCoreBackend backend;
        InstalledSessionControlCore core(backend, [this] { return clockMs; });
        const auto reply = core.handleControlRequest(startRequest());
        QVERIFY(reply.ok);
        compareReplyState(reply, "active");
        QVERIFY(reply.reason.empty());
        QVERIFY(reply.sessionId.size() == 16);
        for (const char character : reply.sessionId)
            QVERIFY((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f'));
        QVERIFY(reply.sessionCapability.size() == std::size_t(32));
        QCOMPARE(core.state(), xpcSessionControlStateActive);
        QVERIFY(core.sessionActive());

        // One session per process: a second Start is a replay and never re-delivers.
        const auto duplicate = core.handleControlRequest(startRequest());
        QVERIFY(!duplicate.ok);
        compareReplyReason(duplicate, "duplicate_start");
        compareReplyState(duplicate, "active");
        QVERIFY(duplicate.sessionCapability.empty());
        QVERIFY(duplicate.sessionId.empty());

        // The delivered capability is the only session authority for heartbeat.
        const auto heartbeat = core.handleControlRequest(sessionRequest(
            XpcControlOperation::Heartbeat, reply.sessionId, reply.sessionCapability));
        QVERIFY(heartbeat.ok);
        QVERIFY(heartbeat.sessionCapability.empty());
        QCOMPARE(QByteArray::fromStdString(heartbeat.sessionId),
                 QByteArray::fromStdString(reply.sessionId));
        compareReplyState(heartbeat, "active");
        QVERIFY(backend.calls.contains(QStringLiteral("heartbeat")));
    }

    void sessionCommandsRequireTheExactCapabilityBinding() {
        FakeCoreBackend backend;
        InstalledSessionControlCore core(backend, [this] { return clockMs; });
        const auto start = core.handleControlRequest(startRequest());
        QVERIFY(start.ok);
        const std::vector<unsigned char> wrong(32, 'z');

        const auto wrongId = core.handleControlRequest(sessionRequest(
            XpcControlOperation::Heartbeat, "not-the-session", start.sessionCapability));
        QVERIFY(!wrongId.ok);
        compareReplyReason(wrongId, "session_binding_mismatch");
        compareReplyState(wrongId, "active");

        const auto wrongCapability =
            core.handleControlRequest(sessionRequest(XpcControlOperation::Heartbeat,
                                                     start.sessionId, wrong));
        QVERIFY(!wrongCapability.ok);
        compareReplyReason(wrongCapability, "session_binding_mismatch");

        const auto shortCapability =
            core.handleControlRequest(sessionRequest(XpcControlOperation::Heartbeat,
                                                     start.sessionId, {}));
        QVERIFY(!shortCapability.ok);
        compareReplyReason(shortCapability, "session_binding_mismatch");
    }

    void heartbeatRejectsRegressedClockReadings() {
        FakeCoreBackend backend;
        InstalledSessionControlCore core(backend, [this] { return clockMs; });
        const auto start = core.handleControlRequest(startRequest());
        QVERIFY(start.ok);

        clockMs = 999; // a regressed session clock is never heartbeat authority
        const auto regressed = core.handleControlRequest(sessionRequest(
            XpcControlOperation::Heartbeat, start.sessionId, start.sessionCapability));
        QVERIFY(!regressed.ok);
        compareReplyReason(regressed, "heartbeat_rejected");
        compareReplyState(regressed, "active");

        clockMs = 2000;
        const auto accepted = core.handleControlRequest(sessionRequest(
            XpcControlOperation::Heartbeat, start.sessionId, start.sessionCapability));
        QVERIFY(accepted.ok);
    }

    void watchdogTickStopsStaleSessionsAndKeepsRecentOnes() {
        FakeCoreBackend backend;
        InstalledSessionControlCore core(backend, [this] { return clockMs; });
        const auto start = core.handleControlRequest(startRequest());
        QVERIFY(start.ok);

        // Fresh heartbeats hold the session across many ticks.
        for (int tick = 0; tick < 3; ++tick) {
            clockMs += 1000;
            QVERIFY(core.watchdogTick());
            QVERIFY(core.sessionActive());
        }

        // A heartbeat gap beyond the timeout is stopped by the owner-loop watchdog; with a
        // clean backend the state is stopped and the capability is revoked.
        clockMs += InstalledSessionControlCore::watchdogTimeoutMs + 1;
        QVERIFY(!core.watchdogTick());
        QCOMPARE(core.state(), xpcSessionControlStateStopped);
        QVERIFY(backend.calls.count(QStringLiteral("stop")) == 1);
        const auto lateHeartbeat = core.handleControlRequest(sessionRequest(
            XpcControlOperation::Heartbeat, start.sessionId, start.sessionCapability));
        QVERIFY(!lateHeartbeat.ok);
        compareReplyReason(lateHeartbeat, "session_binding_mismatch");
        compareReplyState(lateHeartbeat, "stopped");

        // The watchdog is one-shot after the stop: later ticks report nothing to stop.
        QVERIFY(core.watchdogTick());
    }

    void watchdogTickRetainsCleanupWhenBackendCannotClean() {
        FakeCoreBackend backend;
        backend.stopAttemptsUntilClean = 10;
        InstalledSessionControlCore core(backend, [this] { return clockMs; });
        const auto start = core.handleControlRequest(startRequest());
        QVERIFY(start.ok);
        clockMs += InstalledSessionControlCore::watchdogTimeoutMs + 1;
        QVERIFY(!core.watchdogTick());
        QCOMPARE(core.state(), xpcSessionControlStateCleanupPending);
        QVERIFY(core.sessionActive() == false);

        // A late heartbeat arrives but is rejected while cleanup is pending; it never resumes.
        const auto lateHeartbeat = core.handleControlRequest(sessionRequest(
            XpcControlOperation::Heartbeat, start.sessionId, start.sessionCapability));
        QVERIFY(!lateHeartbeat.ok);
        compareReplyReason(lateHeartbeat, "heartbeat_rejected");
        compareReplyState(lateHeartbeat, "cleanup_pending");

        // A bound Stop retry re-drives cleanup and reports the verified transition.
        QVERIFY(core.watchdogTick()); // pending cleanup: ticks are no-ops
        const auto firstRetry = core.handleControlRequest(
            sessionRequest(XpcControlOperation::Stop, start.sessionId, start.sessionCapability));
        QVERIFY(!firstRetry.ok); // first retry still not clean (stopAttemptsUntilClean was 10)
        compareReplyState(firstRetry, "cleanup_pending");
        backend.stopAttemptsUntilClean = 0;
        const auto verified = core.handleControlRequest(
            sessionRequest(XpcControlOperation::Stop, start.sessionId, start.sessionCapability));
        QVERIFY(verified.ok);
        compareReplyState(verified, "stopped");
        QVERIFY(verified.sessionCapability.empty());
        QCOMPARE(core.state(), xpcSessionControlStateStopped);
    }

    void stopRetryReDrivesCleanupUntilVerifiedIdle() {
        FakeCoreBackend backend;
        backend.stopAttemptsUntilClean = 1;
        InstalledSessionControlCore core(backend, [this] { return clockMs; });
        const auto start = core.handleControlRequest(startRequest());
        QVERIFY(start.ok);

        const auto firstStop = core.handleControlRequest(
            sessionRequest(XpcControlOperation::Stop, start.sessionId, start.sessionCapability));
        QVERIFY(!firstStop.ok);
        compareReplyReason(firstStop, "cleanup_pending");
        compareReplyState(firstStop, "cleanup_pending");

        // While cleanup is pending a replayed Start cannot create a second session.
        const auto duplicate = core.handleControlRequest(startRequest());
        QVERIFY(!duplicate.ok);
        compareReplyReason(duplicate, "duplicate_start");

        const auto verified = core.handleControlRequest(
            sessionRequest(XpcControlOperation::Stop, start.sessionId, start.sessionCapability));
        QVERIFY(verified.ok);
        verifyStateStoppedAndTerminal(core, start.sessionId, start.sessionCapability);
    }

    void cleanStopIsTerminalForTheProcess() {
        FakeCoreBackend backend;
        InstalledSessionControlCore core(backend, [this] { return clockMs; });
        const auto start = core.handleControlRequest(startRequest());
        QVERIFY(start.ok);
        const auto stop = core.handleControlRequest(
            sessionRequest(XpcControlOperation::Stop, start.sessionId, start.sessionCapability));
        QVERIFY(stop.ok);
        verifyStateStoppedAndTerminal(core, start.sessionId, start.sessionCapability);
    }

  private:
    void verifyStateStoppedAndTerminal(InstalledSessionControlCore &core,
                                        const std::string &sessionId,
                                        const std::vector<unsigned char> &capability) {
        QCOMPARE(core.state(), xpcSessionControlStateStopped);
        // Stop replays fail binding: the capability was revoked with the verified stop.
        const auto replay = core.handleControlRequest(
            sessionRequest(XpcControlOperation::Stop, sessionId, capability));
        QVERIFY(!replay.ok);
        compareReplyReason(replay, "session_binding_mismatch");
        compareReplyState(replay, "stopped");
        // One session per process: a late Start never restarts operations.
        const auto lateStart = core.handleControlRequest(startRequest());
        QVERIFY(!lateStart.ok);
        compareReplyReason(lateStart, "lifecycle_stopped");
        compareReplyState(lateStart, "stopped");
    }
};

} // namespace interceptor

QTEST_GUILESS_MAIN(interceptor::M6InstalledSessionControlCoreTests)
#include "M6InstalledSessionControlCoreTests.moc"
