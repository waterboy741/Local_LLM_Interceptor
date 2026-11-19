#include "network/HelperLifecycleRuntime.hpp"
#include "network/HostSessionLease.hpp"
#include "network/PfAnchorOperations.hpp"
#include "network/PfRecoveryJournal.hpp"
#include "network/TrustedBootstrapHandoff.hpp"
#include "network/UnixPeerCredentials.hpp"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QTemporaryDir>
#include <QtTest>

#include <cstring>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

using namespace interceptor;

namespace {

class LifecycleFakeBackend final : public SystemOperations {
  public:
    QStringList calls;
    bool leaseAcquisitionSucceeds = true;
    bool sessionLeaseReleaseSucceeds = true;

    std::optional<int> readSetting(NetworkSetting setting) override {
        calls << (setting == NetworkSetting::Forwarding ? "read-forwarding" : "read-redirects");
        return setting == NetworkSetting::Forwarding ? 1 : 1;
    }
    SettingChange compareAndSetSetting(NetworkSetting, int, int) override {
        calls << "setting-change";
        return SettingChange::Unchanged;
    }
    std::optional<QString> acquireSessionLease(const SessionSnapshot &) override {
        calls << "acquire-session-lease";
        return leaseAcquisitionSucceeds ? std::optional<QString>(QStringLiteral("session-lease"))
                                        : std::nullopt;
    }
    bool releaseSessionLease(const QString &token) override {
        calls << "release-session-lease:" + token;
        return sessionLeaseReleaseSucceeds;
    }
    std::optional<QString> acquirePfReference() override {
        calls << "acquire-pf-reference";
        return QStringLiteral("synthetic-pf-token");
    }
    bool releasePfReference(const QString &token) override {
        calls << "release-pf-reference:" + token;
        return true;
    }
    bool installAnchor(const SessionSnapshot &) override {
        calls << "install-anchor";
        return true;
    }
    bool removeAnchor(const SessionSnapshot &) override {
        calls << "remove-anchor";
        return true;
    }
    bool clearOwnedState(const SessionSnapshot &) override {
        calls << "clear-owned-state";
        return true;
    }
    bool beginArp(const SessionSnapshot &) override {
        calls << "begin-arp";
        return true;
    }
    bool endArp(const SessionSnapshot &) override {
        calls << "end-arp";
        return true;
    }
    bool restoreNeighbors(const SessionSnapshot &) override {
        calls << "restore-neighbors";
        return true;
    }
    bool interfaceAvailable(const SessionSnapshot &) override {
        calls << "interface-available";
        return true;
    }
    bool retainRecovery(const SessionSnapshot &, const OwnershipJournal &) override {
        calls << "retain-recovery";
        return true;
    }
};

class LifecycleFakeAuthorization final : public PfAnchorAuthorization {
  public:
    bool effectiveUserIsRoot() override { return true; }
    bool pfEnabled() override { return true; }
    bool verifySessionLease(const SessionSnapshot &, const QString &) override { return true; }
    bool verifyActiveAttachment(const SessionSnapshot &) override { return true; }
    bool verifyAnchorOwnership(const SessionSnapshot &, const QString &,
                               PfAnchorOperation) override {
        return true;
    }
};

class LifecycleFakePfRunner final : public PfAnchorCommandRunner {
  public:
    QStringList calls;
    PfAnchorCommandResult execute(const PfAnchorCommand &command, int, qsizetype) override {
        calls << (command.operation() == PfAnchorOperation::Install ? QStringLiteral("install")
                                                                     : QStringLiteral("remove"));
        return {PfAnchorCommandStatus::Completed, 0, true, true};
    }
};

class LifecycleFakeCleanupVerifier final : public PfAnchorCleanupVerifier {
  public:
    PfAnchorCleanupVerification verifyOwnedAnchorEmpty(const SessionSnapshot &) override {
        return PfAnchorCleanupVerification::Empty;
    }
};

class LifecycleFakeBootstrapAuthenticator final : public BootstrapPeerAuthenticator {
  public:
    bool authenticate(int, const QByteArray &) override { return true; }
};

class LifecyclePrivateDirectory {
  public:
    LifecyclePrivateDirectory() : directory_(QStringLiteral("/tmp/m6-lifecycle-XXXXXX")) {
        if (!directory_.isValid())
            return;
        const QByteArray path = directory_.path().toLocal8Bit();
        if (::chmod(path.constData(), 0700) != 0)
            return;
        descriptor_ = ::open(path.constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    }
    ~LifecyclePrivateDirectory() {
        if (descriptor_ >= 0)
            ::close(descriptor_);
    }
    bool valid() const { return directory_.isValid() && descriptor_ >= 0; }
    int fd() const { return descriptor_; }

  private:
    QTemporaryDir directory_;
    int descriptor_ = -1;
};

struct LifecycleDependencies {
    LifecycleFakeBackend backend;
    LifecycleFakeAuthorization authorization;
    LifecycleFakePfRunner runner;
    PfAnchorOperations operations{authorization, runner};
    LifecycleFakeCleanupVerifier cleanupVerifier;
    PfRecoveryJournal recoveryJournal;
    PfAnchorRecoveryCoordinator coordinator{operations, recoveryJournal, cleanupVerifier};

    explicit LifecycleDependencies(int directoryFd)
        : recoveryJournal(PfRecoveryJournal::open(directoryFd)) {}
};

// Injectable-seam harness mirroring the runtime fixture: every startup-order boundary, the
// monotonic clock, and journal/readiness outcomes are fake-backed and deterministic.
struct LifecycleHarness {
    LifecyclePrivateDirectory directory;
    std::unique_ptr<LifecycleDependencies> deps;
    VerifiedPeer controlPeer;
    std::optional<TrustedBootstrapHandoff> pendingHandoff;
    QStringList stepOrder;
    bool handoffReceiverFails = false;
    QString handoffError;
    bool journalRecoverySucceeds = true;
    bool listenerReadinessSucceeds = true;
    bool factoryReturnsNull = false;
    bool clockFails = false;
    qint64 clockMs = 100;
    QByteArray observedSecret;
    QElapsedTimer *realClock = nullptr;

    bool valid() const { return directory.valid() && deps && deps->recoveryJournal.valid(); }

    static SessionConfig sessionConfig() {
        return {"synthetic0", "192.0.2.10", "192.0.2.30", 18081, {"/api/generate", "/api/chat"},
                false};
    }
    static NetworkFacts facts() {
        NetworkFacts value;
        value.interfaceName = "synthetic0";
        value.researchIp = "192.0.2.20";
        value.researchMac = "02:00:00:00:00:20";
        value.clientMac = "02:00:00:00:00:10";
        value.serverMac = "02:00:00:00:00:30";
        value.proxyServerIp = "192.0.2.30";
        value.proxyServerPort = 18081;
        value.proxyListenPort = 11434;
        value.interfaceUp = value.sameLink = value.anchorAttached = value.proxyReady =
            value.authorized = true;
        return value;
    }
    static std::optional<SessionSnapshot>
    makeSnapshot(const QString &sessionId = QStringLiteral("lifecycle-session")) {
        return SessionSnapshot::create(sessionConfig(), facts(), 11434, sessionId);
    }
    static VerifiedPeer kernelPeer() {
        int sockets[2] = {-1, -1};
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
            qFatal("Cannot create synthetic lifecycle peer socket pair");
        const auto peer = verifiedPeerForUnixSocket(sockets[0]);
        ::close(sockets[0]);
        ::close(sockets[1]);
        if (!peer)
            qFatal("Cannot verify synthetic lifecycle peer");
        return *peer;
    }
    // A mismatching but authenticated-on-the-transport peer: same kernel uid, different identity.
    static VerifiedPeer mismatchedPeer() {
        VerifiedPeer peer;
        peer.uid = kernelPeer().uid;
        peer.auditIdentity = QByteArrayLiteral("other-audited-identity");
        peer.transportAuthenticated = true;
        return peer;
    }
    static VerifiedPeer unauthenticatedPeer() {
        VerifiedPeer peer;
        peer.uid = kernelPeer().uid;
        peer.auditIdentity = QByteArrayLiteral("unverified");
        peer.transportAuthenticated = false;
        return peer;
    }
    static std::optional<TrustedBootstrapHandoff>
    transferSnapshot(const SessionSnapshot &snapshot, const QByteArray &secret) {
        int sockets[2] = {-1, -1};
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
            return std::nullopt;
        LifecycleFakeBootstrapAuthenticator writerAuthenticator, receiverAuthenticator;
        QString writeError;
        bool written = false;
        std::thread writer([&] {
            written = writeBootstrapHandoff(sockets[0], writerAuthenticator,
                                            QByteArrayLiteral("helper-code"), snapshot, secret,
                                            &writeError);
        });
        QString receiveError;
        auto handoff = receiveTrustedBootstrapHandoff(sockets[1], receiverAuthenticator,
                                                      QByteArrayLiteral("gui-code"), &receiveError);
        writer.join();
        ::close(sockets[0]);
        ::close(sockets[1]);
        if (!written)
            qFatal("Cannot write synthetic lifecycle handoff: %s", qPrintable(writeError));
        if (!handoff)
            qFatal("Cannot receive synthetic lifecycle handoff: %s", qPrintable(receiveError));
        return handoff;
    }

    explicit LifecycleHarness()
        : controlPeer(kernelPeer()), pendingHandoff(transferSnapshot(*makeSnapshot(),
                                                                     QByteArray(32, 'q'))) {
        if (directory.valid())
            deps = std::make_unique<LifecycleDependencies>(directory.fd());
    }

    HelperLifecycleRuntime::Seams seams() {
        HelperLifecycleRuntime::Seams value;
        value.handoffReceiver = [this](QString *error) -> std::optional<HelperLifecycleHandoff> {
            stepOrder << QStringLiteral("handoff");
            if (handoffReceiverFails || !pendingHandoff) {
                if (error)
                    *error = handoffError;
                return std::nullopt;
            }
            HelperLifecycleHandoff result{std::move(*pendingHandoff), controlPeer};
            pendingHandoff.reset();
            return result;
        };
        value.journalRecovery = [this](QString *detail) {
            stepOrder << QStringLiteral("journal");
            if (journalRecoverySucceeds)
                return true;
            if (detail)
                *detail = QStringLiteral("release_needed_reference_unresolved");
            return false;
        };
        value.listenerReadiness = [this](QString *detail) {
            stepOrder << QStringLiteral("readiness");
            if (listenerReadinessSucceeds)
                return true;
            if (detail)
                *detail = QStringLiteral("listener_probe_unconfirmed");
            return false;
        };
        value.operationsFactory =
            [this](const HostSessionLease &lease, const SessionSnapshot &,
                   const QByteArray &secret) -> std::unique_ptr<PfAnchorRecoverySystemOperations> {
            stepOrder << QStringLiteral("factory");
            observedSecret = secret;
            if (factoryReturnsNull || !lease.acquired() || !lease.descriptorHasCloseOnExec())
                return {};
            return std::make_unique<PfAnchorRecoverySystemOperations>(deps->backend, lease,
                                                                     deps->coordinator);
        };
        value.monotonicClock = [this]() -> qint64 {
            if (clockFails)
                return -1;
            if (realClock)
                return realClock->elapsed();
            return clockMs;
        };
        return value;
    }

    std::unique_ptr<HelperLifecycleRuntime> makeRuntime(QString *error = nullptr) {
        return HelperLifecycleRuntime::create(directory.fd(), seams(), error);
    }
    std::unique_ptr<HelperLifecycleRuntime> makeReadyRuntime(QString *error = nullptr) {
        auto runtime = makeRuntime(error);
        if (!runtime)
            return {};
        if (!runtime->initialize(error))
            return {};
        return runtime;
    }

    static XpcControlRequest startRequest() {
        XpcControlRequest request;
        request.operation = XpcControlOperation::Start;
        return request;
    }
    static XpcControlRequest sessionRequest(XpcControlOperation operation,
                                            const std::string &sessionId,
                                            const std::vector<unsigned char> &capability) {
        XpcControlRequest request;
        request.operation = operation;
        request.sessionId = sessionId;
        request.sessionCapability = capability;
        return request;
    }
};

#define QCOMPARE_PHASE(actual, expected)                                                           \
    do {                                                                                           \
        QCOMPARE(actual, expected);                                                                \
    } while (false)

} // namespace

namespace interceptor {

class M6HelperLifecycleRuntimeTests final : public QObject {
    Q_OBJECT

  private slots:
    void createRequiresTrustedDescriptorAndEverySeam() {
        QString error;
        auto noDescriptor = HelperLifecycleRuntime::create(-1, LifecycleHarness().seams(), &error);
        QVERIFY(!noDescriptor);
        QCOMPARE(error, QStringLiteral("trusted_directory_descriptor_required"));

        LifecycleHarness harness;
        QVERIFY(harness.valid());
        HelperLifecycleRuntime::Seams missing = harness.seams();
        missing.handoffReceiver = {};
        QString missingError;
        auto created = HelperLifecycleRuntime::create(harness.directory.fd(), missing, &missingError);
        QVERIFY(!created);
        QCOMPARE(missingError, QStringLiteral("lifecycle_seams_required"));
    }

    void uninitializedRuntimeRejectsEveryControlRequest() {
        LifecycleHarness harness;
        QVERIFY(harness.valid());
        QString error;
        auto runtime = harness.makeRuntime(&error);
        QVERIFY2(runtime, qPrintable(error));
        QCOMPARE_PHASE(runtime->phase(), HelperLifecyclePhase::NotInitialized);
        QCOMPARE(runtime->sessionId(), QString());
        QVERIFY(!runtime->watchdogRunning());
        QCOMPARE(runtime->sessionState(), NetworkSession::State::CleanupPending);
        QVERIFY(runtime->snapshot() == nullptr);

        const auto startRejected =
            runtime->handleControlRequest(harness.controlPeer, LifecycleHarness::startRequest());
        QCOMPARE(startRejected.ok, false);
        QCOMPARE(QByteArray::fromStdString(startRejected.state),
                 QByteArrayLiteral("uninitialized"));
        QCOMPARE(QByteArray::fromStdString(startRejected.reason),
                 QByteArrayLiteral("lifecycle_not_initialized"));

        const auto heartbeatRejected = runtime->handleControlRequest(
            harness.controlPeer,
            LifecycleHarness::sessionRequest(XpcControlOperation::Heartbeat, "id",
                                              std::vector<unsigned char>(32, 'a')));
        QVERIFY(!heartbeatRejected.ok);
        QCOMPARE(QByteArray::fromStdString(heartbeatRejected.reason),
                 QByteArrayLiteral("lifecycle_not_initialized"));

        const auto stopRejected = runtime->handleControlRequest(
            harness.controlPeer,
            LifecycleHarness::sessionRequest(XpcControlOperation::Stop, "id",
                                              std::vector<unsigned char>(32, 'a')));
        QVERIFY(!stopRejected.ok);
        QCOMPARE(QByteArray::fromStdString(stopRejected.reason),
                 QByteArrayLiteral("lifecycle_not_initialized"));
    }

    void initializeRunsTheFixedStartupOrderWithAuthenticatedHandoffFirst() {
        LifecycleHarness harness;
        QVERIFY(harness.valid());
        const auto snapshot = LifecycleHarness::makeSnapshot();
        QVERIFY(snapshot.has_value());

        QString error;
        auto runtime = harness.makeRuntime(&error);
        QVERIFY2(runtime, qPrintable(error));
        QVERIFY(runtime->initialize(&error));
        QVERIFY(error.isEmpty());

        // Fixed order: authenticated handoff -> frozen snapshot + operations assembly ->
        // journal recovery -> fresh listener readiness. Nothing runs before the earlier step.
        const QStringList expectedStartupOrder = {
            QStringLiteral("handoff"), QStringLiteral("factory"), QStringLiteral("journal"),
            QStringLiteral("readiness")};
        QCOMPARE(harness.stepOrder, expectedStartupOrder);
        QCOMPARE_PHASE(runtime->phase(), HelperLifecyclePhase::Ready);
        QVERIFY(runtime->phaseDetail().isEmpty());
        QVERIFY(runtime->snapshot() != nullptr);
        QCOMPARE(runtime->snapshot()->sessionId(), snapshot->sessionId());
        QCOMPARE(runtime->sessionId(), QString());
        QVERIFY(runtime->watchdogRunning() == false);
        // The one-time probe secret crossed to the operations assembly exactly once.
        QCOMPARE(harness.observedSecret, QByteArray(32, 'q'));
        // The lease, journals, and directory inode are exclusively owned while ready.
        auto heldLease = HostSessionLease::acquire(harness.directory.fd());
        QVERIFY(!heldLease.acquired());
        QCOMPARE(heldLease.status(), HostSessionLeaseStatus::AlreadyHeld);
        // Adoption itself never runs a network operation.
        QVERIFY(harness.deps->backend.calls.isEmpty());

        // Initialize is one-shot per process.
        QVERIFY(!runtime->initialize(&error));
        QCOMPARE(error, QStringLiteral("lifecycle_already_initialized"));
        QCOMPARE_PHASE(runtime->phase(), HelperLifecyclePhase::Ready);

        // Before any Start, every session-bound command fails binding.
        const auto heartbeat = runtime->handleControlRequest(
            harness.controlPeer,
            LifecycleHarness::sessionRequest(XpcControlOperation::Heartbeat, "id",
                                             std::vector<unsigned char>(32, 'a')));
        QVERIFY(!heartbeat.ok);
        QCOMPARE(QByteArray::fromStdString(heartbeat.state), QByteArrayLiteral("ready"));
        QCOMPARE(QByteArray::fromStdString(heartbeat.reason),
                 QByteArrayLiteral("session_binding_mismatch"));
    }

    void handoffFailureReportsInitializationFailedAndNeverComposesOperations() {
        LifecycleHarness harness;
        QVERIFY(harness.valid());
        harness.handoffReceiverFails = true;
        harness.handoffError = QStringLiteral("authenticated handoff rejected");
        QString error;
        auto runtime = harness.makeRuntime(&error);
        QVERIFY2(runtime, qPrintable(error));
        QVERIFY(!runtime->initialize(&error));
        QCOMPARE(error, QStringLiteral("authenticated handoff rejected"));
        QCOMPARE_PHASE(runtime->phase(), HelperLifecyclePhase::InitializationFailed);
        QCOMPARE(harness.stepOrder, QStringList{QStringLiteral("handoff")});
        QVERIFY(runtime->snapshot() == nullptr);

        const auto rejected =
            runtime->handleControlRequest(harness.controlPeer, LifecycleHarness::startRequest());
        QVERIFY(!rejected.ok);
        QCOMPARE(QByteArray::fromStdString(rejected.state), QByteArrayLiteral("init_failed"));
        QCOMPARE(QByteArray::fromStdString(rejected.reason),
                 QByteArrayLiteral("lifecycle_not_ready"));
        QVERIFY(runtime->watchdogRunning() == false);
    }

    void handoffFailureDetailIsTruncatedToTheBoundedLength() {
        LifecycleHarness harness;
        QVERIFY(harness.valid());
        harness.handoffReceiverFails = true;
        harness.handoffError = QString(300, 'h');
        QString error;
        auto runtime = harness.makeRuntime(&error);
        QVERIFY2(runtime, qPrintable(error));
        QVERIFY(!runtime->initialize(&error));
        QCOMPARE_PHASE(runtime->phase(), HelperLifecyclePhase::InitializationFailed);
        QVERIFY(runtime->phaseDetail().size() <= 256);
        QCOMPARE(runtime->phaseDetail().size(), 256);
    }

    void operationsFactoryFailureBlocksEveryLaterStep() {
        LifecycleHarness harness;
        QVERIFY(harness.valid());
        harness.factoryReturnsNull = true;
        QString error;
        auto runtime = harness.makeRuntime(&error);
        QVERIFY2(runtime, qPrintable(error));
        QVERIFY(!runtime->initialize(&error));
        QCOMPARE(error, QStringLiteral("helper_operations_unavailable"));
        QCOMPARE_PHASE(runtime->phase(), HelperLifecyclePhase::InitializationFailed);
        const QStringList afterFactoryOnly = {QStringLiteral("handoff"),
                                        QStringLiteral("factory")};
        QCOMPARE(harness.stepOrder, afterFactoryOnly);
        QVERIFY(runtime->snapshot() == nullptr);
        QVERIFY(harness.deps->backend.calls.isEmpty());
        // A failed assembly never retained a lease or obligation.
        auto available = HostSessionLease::acquire(harness.directory.fd());
        QVERIFY(available.acquired());
    }

    void pendingJournalRecoveryBlocksReadinessFailClosedAndRetainsTheLease() {
        LifecycleHarness harness;
        QVERIFY(harness.valid());
        harness.journalRecoverySucceeds = false;
        QString error;
        auto runtime = harness.makeRuntime(&error);
        QVERIFY2(runtime, qPrintable(error));
        QVERIFY(!runtime->initialize(&error));
        QCOMPARE(error, QStringLiteral("journal_recovery_pending"));
        QCOMPARE_PHASE(runtime->phase(), HelperLifecyclePhase::RecoveryPending);
        QCOMPARE(runtime->phaseDetail(),
                 QStringLiteral("release_needed_reference_unresolved"));
        const QStringList afterJournal = {QStringLiteral("handoff"), QStringLiteral("factory"),
                                     QStringLiteral("journal")};
        QCOMPARE(harness.stepOrder, afterJournal);
        QVERIFY(runtime->watchdogRunning() == false);
        QVERIFY(runtime->snapshot() != nullptr); // the frozen snapshot stays frozen

        // Start is rejected and no operations are composed.
        const auto start =
            runtime->handleControlRequest(harness.controlPeer, LifecycleHarness::startRequest());
        QVERIFY(!start.ok);
        QCOMPARE(QByteArray::fromStdString(start.state),
                 QByteArrayLiteral("recovery_pending"));
        QCOMPARE(QByteArray::fromStdString(start.reason),
                 QByteArrayLiteral("lifecycle_recovery_pending"));
        QVERIFY(harness.deps->backend.calls.isEmpty());

        const auto heartbeat = runtime->handleControlRequest(
            harness.controlPeer,
            LifecycleHarness::sessionRequest(XpcControlOperation::Heartbeat, "id",
                                             std::vector<unsigned char>(32, 'a')));
        QVERIFY(!heartbeat.ok);
        QCOMPARE(QByteArray::fromStdString(heartbeat.reason),
                 QByteArrayLiteral("lifecycle_recovery_pending"));

        // The obligation is retained: the lease stays held while the process lives.
        auto heldLease = HostSessionLease::acquire(harness.directory.fd());
        QVERIFY(!heldLease.acquired());
        runtime.reset();
        auto released = HostSessionLease::acquire(harness.directory.fd());
        QVERIFY(released.acquired());
    }

    void restartWithPendingCleanupCannotReportReadyAboveUnresolvedObligations() {
        LifecycleHarness harness;
        QVERIFY(harness.valid());
        harness.journalRecoverySucceeds = false;
        QString error;
        auto firstRuntime = harness.makeRuntime(&error);
        QVERIFY2(firstRuntime, qPrintable(error));
        QVERIFY(!firstRuntime->initialize(nullptr));
        QCOMPARE_PHASE(firstRuntime->phase(), HelperLifecyclePhase::RecoveryPending);
        firstRuntime.reset();

        // Process restart with the obligation still pending: re-entry again reports
        // recovery_pending and rejects Start before any operations factory runs.
        harness.stepOrder.clear();
        harness.pendingHandoff.reset();
        auto restartHandoff =
            LifecycleHarness::transferSnapshot(*LifecycleHarness::makeSnapshot(), QByteArray(32, 'q'));
        harness.pendingHandoff.emplace(std::move(*restartHandoff));
        auto restartedRuntime = harness.makeRuntime(&error);
        QVERIFY2(restartedRuntime, qPrintable(error));
        QVERIFY(!restartedRuntime->initialize(nullptr));
        QCOMPARE_PHASE(restartedRuntime->phase(), HelperLifecyclePhase::RecoveryPending);
        const auto rejected = restartedRuntime->handleControlRequest(
            harness.controlPeer, LifecycleHarness::startRequest());
        QVERIFY(!rejected.ok);
        QCOMPARE(QByteArray::fromStdString(rejected.state),
                 QByteArrayLiteral("recovery_pending"));

        // Only an explicit reconciliation allows a later process to report ready.
        restartedRuntime.reset();
        harness.journalRecoverySucceeds = true;
        harness.stepOrder.clear();
        harness.pendingHandoff.reset();
        auto recoverHandoff =
            LifecycleHarness::transferSnapshot(*LifecycleHarness::makeSnapshot(), QByteArray(32, 'q'));
        harness.pendingHandoff.emplace(std::move(*recoverHandoff));
        auto recoveredRuntime = harness.makeReadyRuntime(&error);
        QVERIFY2(recoveredRuntime, qPrintable(error));
        QCOMPARE_PHASE(recoveredRuntime->phase(), HelperLifecyclePhase::Ready);
    }

    void listenerReadinessFailureReportsInitializationFailedAfterJournalRecovery() {
        LifecycleHarness harness;
        QVERIFY(harness.valid());
        harness.listenerReadinessSucceeds = false;
        QString error;
        auto runtime = harness.makeRuntime(&error);
        QVERIFY2(runtime, qPrintable(error));
        QVERIFY(!runtime->initialize(&error));
        QCOMPARE(error, QStringLiteral("listener_readiness_unconfirmed"));
        QCOMPARE_PHASE(runtime->phase(), HelperLifecyclePhase::InitializationFailed);
        QCOMPARE(runtime->phaseDetail(), QStringLiteral("listener_probe_unconfirmed"));
        const QStringList expectedStartupOrder2 = {
            QStringLiteral("handoff"), QStringLiteral("factory"), QStringLiteral("journal"),
            QStringLiteral("readiness")};
        QCOMPARE(harness.stepOrder, expectedStartupOrder2);
        // Historical snapshot readiness is never authority: the fresh probe decides.
        QVERIFY(runtime->snapshot() != nullptr);

        // Cleanup obligations acquired before the failure stay retained until destruction.
        auto heldLease = HostSessionLease::acquire(harness.directory.fd());
        QVERIFY(!heldLease.acquired());
        runtime.reset();
        auto released = HostSessionLease::acquire(harness.directory.fd());
        QVERIFY(released.acquired());
    }

    void initializeAndControlRequireTheOwnerThread() {
        LifecycleHarness harness;
        QVERIFY(harness.valid());
        QString error;
        auto runtime = harness.makeRuntime(&error);
        QVERIFY2(runtime, qPrintable(error));

        bool initialized = true;
        QString threadError;
        std::thread worker([&] { initialized = runtime->initialize(&threadError); });
        worker.join();
        QVERIFY(!initialized);
        QCOMPARE(threadError, QStringLiteral("lifecycle_owner_thread_required"));
        QCOMPARE_PHASE(runtime->phase(), HelperLifecyclePhase::NotInitialized);

        runtime->handleControlRequest( // no-op state-seeding on the owner thread
            harness.controlPeer, LifecycleHarness::startRequest());
        bool offThreadOk = false;
        XpcSessionControlReply offThreadReply;
        std::thread offThreadWorker([&] {
            offThreadReply =
                runtime->handleControlRequest(harness.controlPeer, LifecycleHarness::startRequest());
            offThreadOk = offThreadReply.ok;
        });
        offThreadWorker.join();
        QVERIFY(!offThreadOk);
        QCOMPARE(QByteArray::fromStdString(offThreadReply.reason),
                 QByteArrayLiteral("lifecycle_owner_thread_required"));
        QCOMPARE(QByteArray::fromStdString(offThreadReply.state),
                 QByteArrayLiteral("uninitialized"));

        // The owner thread afterwards still runs the unmodified startup order.
        QVERIFY(runtime->initialize(&error));
        QCOMPARE_PHASE(runtime->phase(), HelperLifecyclePhase::Ready);
    }

    void unauthenticatedOrMismatchedPeerIsRejectedWithoutStateChange() {
        LifecycleHarness harness;
        QVERIFY(harness.valid());
        QString error;
        auto runtime = harness.makeReadyRuntime(&error);
        QVERIFY2(runtime, qPrintable(error));

        const auto unauthenticated = runtime->handleControlRequest(
            LifecycleHarness::unauthenticatedPeer(), LifecycleHarness::startRequest());
        QVERIFY(!unauthenticated.ok);
        QCOMPARE(QByteArray::fromStdString(unauthenticated.reason),
                 QByteArrayLiteral("control_peer_mismatch"));
        QCOMPARE(QByteArray::fromStdString(unauthenticated.state), QByteArrayLiteral("ready"));

        const auto mismatched = runtime->handleControlRequest(LifecycleHarness::mismatchedPeer(),
                                                             LifecycleHarness::startRequest());
        QVERIFY(!mismatched.ok);
        QCOMPARE(QByteArray::fromStdString(mismatched.reason),
                 QByteArrayLiteral("control_peer_mismatch"));
        QCOMPARE(QByteArray::fromStdString(mismatched.state), QByteArrayLiteral("ready"));
        QVERIFY(harness.deps->backend.calls.isEmpty());
        QCOMPARE_PHASE(runtime->phase(), HelperLifecyclePhase::Ready);
    }

    void authenticatedStartVerifiesOperationsBeforeActiveAndReleasesCapabilityOnce() {
        LifecycleHarness harness;
        QVERIFY(harness.valid());
        QString error;
        auto runtime = harness.makeReadyRuntime(&error);
        QVERIFY2(runtime, qPrintable(error));

        auto reply =
            runtime->handleControlRequest(harness.controlPeer, LifecycleHarness::startRequest());
        QVERIFY2(reply.ok, QByteArray::fromStdString(reply.reason).constData());
        QCOMPARE(QByteArray::fromStdString(reply.state), QByteArrayLiteral("active"));
        QVERIFY(reply.reason.empty());
        QVERIFY(reply.sessionCapability.size() == xpcSessionControlCapabilityBytes);
        QCOMPARE(QString::fromStdString(reply.sessionId), runtime->sessionId());
        QCOMPARE(runtime->sessionId(), runtime->snapshot()->sessionId());
        QVERIFY(runtime->watchdogRunning());
        QVERIFY(harness.deps->runner.calls.contains(QStringLiteral("install")));
        QVERIFY(reply.sessionId.size() <= xpcSessionControlMaximumSessionIdBytes);

        // Duplicate Start never re-sends the capability and never restarts operations.
        const auto duplicate =
            runtime->handleControlRequest(harness.controlPeer, LifecycleHarness::startRequest());
        QVERIFY(!duplicate.ok);
        QCOMPARE(QByteArray::fromStdString(duplicate.reason),
                 QByteArrayLiteral("duplicate_start"));
        QCOMPARE(QByteArray::fromStdString(duplicate.state), QByteArrayLiteral("active"));
        QVERIFY(duplicate.sessionCapability.empty());
        QVERIFY(harness.deps->runner.calls.count(QStringLiteral("install")) == 1);

        // The released capability is authority for heartbeat and stop only.
        const auto heartbeat =
            runtime->handleControlRequest(harness.controlPeer,
                                          LifecycleHarness::sessionRequest(
                                              XpcControlOperation::Heartbeat, reply.sessionId,
                                              reply.sessionCapability));
        QVERIFY(heartbeat.ok);
        QCOMPARE(QByteArray::fromStdString(heartbeat.state), QByteArrayLiteral("active"));
        QVERIFY(heartbeat.sessionCapability.empty());
        QCOMPARE(QString::fromStdString(heartbeat.sessionId), runtime->sessionId());

        // The capability leaves its reply bytes with the caller: wipe after use.
        wipeXpcSessionControlReply(reply);
        QVERIFY(reply.sessionCapability.empty());
    }

    void startRejectsUnavailableClockAndKeepsTheEndpointReady() {
        LifecycleHarness harness;
        QVERIFY(harness.valid());
        QString error;
        auto runtime = harness.makeReadyRuntime(&error);
        QVERIFY2(runtime, qPrintable(error));
        harness.clockFails = true;

        const auto rejected =
            runtime->handleControlRequest(harness.controlPeer, LifecycleHarness::startRequest());
        QVERIFY(!rejected.ok);
        QCOMPARE(QByteArray::fromStdString(rejected.reason),
                 QByteArrayLiteral("clock_unavailable"));
        QCOMPARE(QByteArray::fromStdString(rejected.state), QByteArrayLiteral("ready"));
        QCOMPARE_PHASE(runtime->phase(), HelperLifecyclePhase::Ready);
        QVERIFY(harness.deps->backend.calls.isEmpty());

        harness.clockFails = false;
        const auto accepted =
            runtime->handleControlRequest(harness.controlPeer, LifecycleHarness::startRequest());
        QVERIFY(accepted.ok);
    }

    void failedSessionStartRetainsReadinessWithoutReportingActive() {
        LifecycleHarness harness;
        QVERIFY(harness.valid());
        harness.deps->backend.leaseAcquisitionSucceeds = false;
        QString error;
        auto runtime = harness.makeReadyRuntime(&error);
        QVERIFY2(runtime, qPrintable(error));

        const auto failed =
            runtime->handleControlRequest(harness.controlPeer, LifecycleHarness::startRequest());
        QVERIFY(!failed.ok);
        QCOMPARE(QByteArray::fromStdString(failed.reason),
                 QByteArrayLiteral("session_start_failed"));
        QVERIFY(failed.sessionCapability.empty());
        QCOMPARE(harness.deps->backend.calls,
                 QStringList{QStringLiteral("acquire-session-lease")});
        QCOMPARE(runtime->sessionState(), NetworkSession::State::Idle);
        QVERIFY(runtime->watchdogRunning() == false);
        // A one-shot host cannot bypass a failed start with a later Start.
        const auto retry =
            runtime->handleControlRequest(harness.controlPeer, LifecycleHarness::startRequest());
        QVERIFY(!retry.ok);
        QCOMPARE(QByteArray::fromStdString(retry.reason),
                 QByteArrayLiteral("session_start_failed"));
        QVERIFY(retry.sessionCapability.empty());
    }

    void boundSessionCommandsEnforceCapabilityAndSessionBinding() {
        LifecycleHarness harness;
        QVERIFY(harness.valid());
        QString error;
        auto runtime = harness.makeReadyRuntime(&error);
        QVERIFY2(runtime, qPrintable(error));
        auto start =
            runtime->handleControlRequest(harness.controlPeer, LifecycleHarness::startRequest());
        QVERIFY(start.ok);
        const std::vector<unsigned char> wrongCapability(32, 'z');

        // Session id alone is never authorization: a valid capability with another id fails.
        const auto wrongId = runtime->handleControlRequest(
            harness.controlPeer,
            LifecycleHarness::sessionRequest(XpcControlOperation::Heartbeat,
                                             "not-the-bound-session", start.sessionCapability));
        QVERIFY(!wrongId.ok);
        QCOMPARE(QByteArray::fromStdString(wrongId.reason),
                 QByteArrayLiteral("session_binding_mismatch"));
        QCOMPARE(QByteArray::fromStdString(wrongId.state), QByteArrayLiteral("active"));

        // A bound id with the wrong capability never reaches the dispatcher's authority.
        const auto wrongCapabilityReply = runtime->handleControlRequest(
            harness.controlPeer, LifecycleHarness::sessionRequest(XpcControlOperation::Heartbeat,
                                                                  start.sessionId, wrongCapability));
        QVERIFY(!wrongCapabilityReply.ok);
        QCOMPARE(QByteArray::fromStdString(wrongCapabilityReply.reason),
                 QByteArrayLiteral("heartbeat_rejected"));
        QCOMPARE(QByteArray::fromStdString(wrongCapabilityReply.state),
                 QByteArrayLiteral("active"));

        // A mismatched authenticated peer never binds to the session either.
        const auto mismatched = runtime->handleControlRequest(
            LifecycleHarness::mismatchedPeer(),
            LifecycleHarness::sessionRequest(XpcControlOperation::Heartbeat, start.sessionId,
                                             start.sessionCapability));
        QVERIFY(!mismatched.ok);
        QCOMPARE(QByteArray::fromStdString(mismatched.reason),
                 QByteArrayLiteral("control_peer_mismatch"));
        QCOMPARE(runtime->sessionState(), NetworkSession::State::Active);
        wipeXpcSessionControlReply(start);
    }

    void heartbeatWithRegressedClockIsRejectedByTheDispatcher() {
        LifecycleHarness harness;
        QVERIFY(harness.valid());
        QString error;
        auto runtime = harness.makeReadyRuntime(&error);
        QVERIFY2(runtime, qPrintable(error));
        harness.clockMs = 5000;
        auto start =
            runtime->handleControlRequest(harness.controlPeer, LifecycleHarness::startRequest());
        QVERIFY(start.ok);

        // The session clock is exclusively the helper's monotonic clock: a regressed reading
        // is rejected, never interpreted as a fresh heartbeat.
        harness.clockMs = 4000;
        const auto regressed = runtime->handleControlRequest(
            harness.controlPeer, LifecycleHarness::sessionRequest(XpcControlOperation::Heartbeat,
                                                                  start.sessionId,
                                                                  start.sessionCapability));
        QVERIFY(!regressed.ok);
        QCOMPARE(QByteArray::fromStdString(regressed.reason),
                 QByteArrayLiteral("heartbeat_rejected"));
        QCOMPARE(QByteArray::fromStdString(regressed.state), QByteArrayLiteral("active"));
        wipeXpcSessionControlReply(start);
    }

    void cleanStopRepliesVerifiedStoppedAndReplaysFailBinding() {
        LifecycleHarness harness;
        QVERIFY(harness.valid());
        QString error;
        auto runtime = harness.makeReadyRuntime(&error);
        QVERIFY2(runtime, qPrintable(error));
        auto start =
            runtime->handleControlRequest(harness.controlPeer, LifecycleHarness::startRequest());
        QVERIFY(start.ok);

        const auto stop = runtime->handleControlRequest(
            harness.controlPeer, LifecycleHarness::sessionRequest(XpcControlOperation::Stop,
                                                                  start.sessionId,
                                                                  start.sessionCapability));
        QVERIFY(stop.ok);
        QCOMPARE(QByteArray::fromStdString(stop.state), QByteArrayLiteral("stopped"));
        QVERIFY(stop.sessionCapability.empty());
        QVERIFY(runtime->watchdogRunning() == false);
        QVERIFY(harness.deps->runner.calls.contains(QStringLiteral("remove")));
        QVERIFY(harness.deps->backend.calls.contains(
            QStringLiteral("release-session-lease:session-lease")));

        // The capability is spent by a verified stop: replays fail binding, not cleanup.
        const auto stopReplay = runtime->handleControlRequest(
            harness.controlPeer, LifecycleHarness::sessionRequest(XpcControlOperation::Stop,
                                                                  start.sessionId,
                                                                  start.sessionCapability));
        QVERIFY(!stopReplay.ok);
        QCOMPARE(QByteArray::fromStdString(stopReplay.reason),
                 QByteArrayLiteral("session_binding_mismatch"));
        QCOMPARE(QByteArray::fromStdString(stopReplay.state), QByteArrayLiteral("stopped"));

        const auto heartbeatReplay = runtime->handleControlRequest(
            harness.controlPeer,
            LifecycleHarness::sessionRequest(XpcControlOperation::Heartbeat, start.sessionId,
                                             start.sessionCapability));
        QVERIFY(!heartbeatReplay.ok);
        QCOMPARE(QByteArray::fromStdString(heartbeatReplay.reason),
                 QByteArrayLiteral("session_binding_mismatch"));

        // One session per process: a post-stop Start is terminal and never restarts operations.
        const auto restarted =
            runtime->handleControlRequest(harness.controlPeer, LifecycleHarness::startRequest());
        QVERIFY(!restarted.ok);
        QCOMPARE(QByteArray::fromStdString(restarted.reason),
                 QByteArrayLiteral("lifecycle_stopped"));
        QCOMPARE(QByteArray::fromStdString(restarted.state), QByteArrayLiteral("stopped"));
        QVERIFY(harness.deps->runner.calls.count(QStringLiteral("install")) == 1);
        wipeXpcSessionControlReply(start);
    }

    void stopRetryReDrivesCleanupUntilVerifiedIdle() {
        LifecycleHarness harness;
        QVERIFY(harness.valid());
        harness.deps->backend.sessionLeaseReleaseSucceeds = false;
        QString error;
        auto runtime = harness.makeReadyRuntime(&error);
        QVERIFY2(runtime, qPrintable(error));
        auto start =
            runtime->handleControlRequest(harness.controlPeer, LifecycleHarness::startRequest());
        QVERIFY(start.ok);

        const auto firstStop = runtime->handleControlRequest(
            harness.controlPeer, LifecycleHarness::sessionRequest(XpcControlOperation::Stop,
                                                                  start.sessionId,
                                                                  start.sessionCapability));
        QVERIFY(!firstStop.ok);
        QCOMPARE(QByteArray::fromStdString(firstStop.reason),
                 QByteArrayLiteral("cleanup_pending"));
        QCOMPARE(QByteArray::fromStdString(firstStop.state),
                 QByteArrayLiteral("cleanup_pending"));
        QCOMPARE(runtime->sessionState(), NetworkSession::State::CleanupPending);
        QVERIFY(runtime->watchdogRunning() == false);

        // Heartbeats while cleanup is pending are rejected and never resume the session.
        const auto pendingHeartbeat = runtime->handleControlRequest(
            harness.controlPeer, LifecycleHarness::sessionRequest(XpcControlOperation::Heartbeat,
                                                                  start.sessionId,
                                                                  start.sessionCapability));
        QVERIFY(!pendingHeartbeat.ok);
        QCOMPARE(QByteArray::fromStdString(pendingHeartbeat.reason),
                 QByteArrayLiteral("heartbeat_rejected"));
        QCOMPARE(QByteArray::fromStdString(pendingHeartbeat.state),
                 QByteArrayLiteral("cleanup_pending"));
        QCOMPARE(runtime->sessionState(), NetworkSession::State::CleanupPending);

        // A bound retry re-drives cleanup and fails again while the obligation is real.
        const auto secondStop = runtime->handleControlRequest(
            harness.controlPeer, LifecycleHarness::sessionRequest(XpcControlOperation::Stop,
                                                                  start.sessionId,
                                                                  start.sessionCapability));
        QVERIFY(!secondStop.ok);
        QCOMPARE(QByteArray::fromStdString(secondStop.reason),
                 QByteArrayLiteral("cleanup_pending"));
        QCOMPARE(runtime->sessionState(), NetworkSession::State::CleanupPending);

        // Only a verified transition to Idle proves cleanup and answers ok=true.
        harness.deps->backend.sessionLeaseReleaseSucceeds = true;
        const auto verifiedStop = runtime->handleControlRequest(
            harness.controlPeer, LifecycleHarness::sessionRequest(XpcControlOperation::Stop,
                                                                  start.sessionId,
                                                                  start.sessionCapability));
        QVERIFY(verifiedStop.ok);
        QCOMPARE(QByteArray::fromStdString(verifiedStop.state), QByteArrayLiteral("stopped"));
        QVERIFY(harness.deps->backend.calls.contains(
            QStringLiteral("release-session-lease:session-lease")));
        QVERIFY(harness.deps->backend.calls.count(
                    QStringLiteral("release-session-lease:session-lease")) >= 2);

        const auto duplicateStart =
            runtime->handleControlRequest(harness.controlPeer, LifecycleHarness::startRequest());
        QVERIFY(!duplicateStart.ok);
        QCOMPARE(QByteArray::fromStdString(duplicateStart.reason),
                 QByteArrayLiteral("lifecycle_stopped"));
        wipeXpcSessionControlReply(start);
    }

    void lostClientWatchdogStopsTheSessionOnTheOwnerLoop() {
        LifecycleHarness harness;
        QVERIFY(harness.valid());
        QString error;
        auto runtime = harness.makeReadyRuntime(&error);
        QVERIFY2(runtime, qPrintable(error));
        QElapsedTimer realClock;
        realClock.start();
        harness.realClock = &realClock;
        auto start =
            runtime->handleControlRequest(harness.controlPeer, LifecycleHarness::startRequest());
        QVERIFY(start.ok);
        QCOMPARE(runtime->watchdogRunning(), true);
        // Deterministic bounded wait: no fixed sleep; the watchdog timeout proves the stop.
        const qint64 waitLimitMs = NetworkSession::watchdogTimeoutMs * 2;
        while (runtime->sessionState() == NetworkSession::State::Active &&
               realClock.elapsed() < waitLimitMs)
            QCoreApplication::processEvents(QEventLoop::AllEvents, 100);
        QCOMPARE(runtime->sessionState(), NetworkSession::State::Idle);
        QVERIFY(runtime->watchdogRunning() == false);
        QVERIFY(harness.deps->runner.calls.contains(QStringLiteral("remove")));
        QVERIFY(harness.deps->backend.calls.contains(
            QStringLiteral("release-session-lease:session-lease")));

        // The orphaned control handle is binding-mismatched after the watchdog stop.
        const auto heartbeat = runtime->handleControlRequest(
            harness.controlPeer, LifecycleHarness::sessionRequest(XpcControlOperation::Heartbeat,
                                                                  start.sessionId,
                                                                  start.sessionCapability));
        QVERIFY(!heartbeat.ok);
        QCOMPARE(QByteArray::fromStdString(heartbeat.state), QByteArrayLiteral("stopped"));
        QCOMPARE(QByteArray::fromStdString(heartbeat.reason),
                 QByteArrayLiteral("session_binding_mismatch"));
        wipeXpcSessionControlReply(start);
    }

    void readOnlyOperationsAreNeverAnsweredByTheLifecycleRuntime() {
        LifecycleHarness harness;
        QVERIFY(harness.valid());
        QString error;
        auto runtime = harness.makeReadyRuntime(&error);
        QVERIFY2(runtime, qPrintable(error));

        for (const XpcControlOperation operation :
             {XpcControlOperation::Probe, XpcControlOperation::Status,
              XpcControlOperation::Invalid}) {
            XpcControlRequest request;
            request.operation = operation;
            const auto reply = runtime->handleControlRequest(harness.controlPeer, request);
            QVERIFY(!reply.ok);
            QCOMPARE(QByteArray::fromStdString(reply.reason),
                     QByteArrayLiteral("operation_unsupported"));
            QVERIFY(reply.sessionCapability.empty());
            QVERIFY(reply.sessionId.empty());
        }
        QCOMPARE_PHASE(runtime->phase(), HelperLifecyclePhase::Ready);
    }
};

} // namespace interceptor

QTEST_GUILESS_MAIN(interceptor::M6HelperLifecycleRuntimeTests)
#include "M6HelperLifecycleRuntimeTests.moc"
