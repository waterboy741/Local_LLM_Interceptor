#include "network/LeasedHelperHost.hpp"
#include "network/PfAnchorOperations.hpp"
#include "network/PfRecoveryJournal.hpp"
#include "network/UnixPeerCredentials.hpp"

#include <QCoreApplication>
#include <QEvent>
#include <QTemporaryDir>
#include <QtTest>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

using namespace interceptor;

class HelperHostFakeBackend final : public SystemOperations {
  public:
    QStringList calls;
    bool leaseAcquisitionSucceeds = true;
    bool sessionLeaseReleaseSucceeds = true;
    int forwarding = 0;
    int redirects = 1;

    std::optional<int> readSetting(NetworkSetting setting) override {
        calls << (setting == NetworkSetting::Forwarding ? "read-forwarding" : "read-redirects");
        return setting == NetworkSetting::Forwarding ? forwarding : redirects;
    }
    SettingChange compareAndSetSetting(NetworkSetting setting, int expected, int desired) override {
        calls << (setting == NetworkSetting::Forwarding ? "forwarding-change" : "redirect-change");
        auto &value = setting == NetworkSetting::Forwarding ? forwarding : redirects;
        if (value == desired)
            return SettingChange::Unchanged;
        if (value != expected)
            return SettingChange::Conflict;
        value = desired;
        return SettingChange::Applied;
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
        calls << "direct-install-anchor";
        return true;
    }
    bool removeAnchor(const SessionSnapshot &) override {
        calls << "direct-remove-anchor";
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

class HelperHostFakeAuthorization final : public PfAnchorAuthorization {
  public:
    QStringList calls;
    bool root = true;
    bool enabled = true;
    bool leaseValid = true;
    bool attachmentValid = true;
    bool ownershipValid = true;

    bool effectiveUserIsRoot() override {
        calls << "root";
        return root;
    }
    bool pfEnabled() override {
        calls << "pf-enabled";
        return enabled;
    }
    bool verifySessionLease(const SessionSnapshot &, const QString &) override {
        calls << "session-lease";
        return leaseValid;
    }
    bool verifyActiveAttachment(const SessionSnapshot &) override {
        calls << "attachment";
        return attachmentValid;
    }
    bool verifyAnchorOwnership(const SessionSnapshot &, const QString &,
                               PfAnchorOperation) override {
        calls << "anchor-ownership";
        return ownershipValid;
    }
};

class HelperHostFakePfRunner final : public PfAnchorCommandRunner {
  public:
    QStringList calls;

    PfAnchorCommandResult execute(const PfAnchorCommand &command, int timeoutMs,
                                  qsizetype outputLimit) override {
        calls << (command.operation() == PfAnchorOperation::Install ? "install" : "remove");
        if (timeoutMs != PfAnchorOperations::commandTimeoutMs ||
            outputLimit != PfAnchorOperations::maximumOutputBytes)
            return {PfAnchorCommandStatus::Failed, -1, false, true};
        return {PfAnchorCommandStatus::Completed, 0, true, true};
    }
};

class HelperHostFakeCleanupVerifier final : public PfAnchorCleanupVerifier {
  public:
    int calls = 0;

    PfAnchorCleanupVerification verifyOwnedAnchorEmpty(const SessionSnapshot &) override {
        ++calls;
        return PfAnchorCleanupVerification::Empty;
    }
};

class HelperHostPrivateDirectory {
  public:
    HelperHostPrivateDirectory() {
        if (!directory_.isValid())
            return;
        const QByteArray path = directory_.path().toLocal8Bit();
        if (::chmod(path.constData(), 0700) != 0)
            return;
        descriptor_ = ::open(path.constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    }
    ~HelperHostPrivateDirectory() {
        if (descriptor_ >= 0)
            ::close(descriptor_);
    }
    bool valid() const { return directory_.isValid() && descriptor_ >= 0; }
    int fd() const { return descriptor_; }

  private:
    QTemporaryDir directory_;
    int descriptor_ = -1;
};

namespace interceptor {

class M6LeasedHelperHostTests final : public QObject {
    Q_OBJECT

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
    static std::optional<SessionSnapshot> makeSnapshot(const QString &sessionId,
                                                       QString *error = nullptr) {
        auto cfg = sessionConfig();
        return SessionSnapshot::create(cfg, facts(), 11434, sessionId, error);
    }
    static TransparentProxyReadiness readiness(bool *current) {
        TransparentProxyReadiness value(QStringLiteral("synthetic0"), QStringLiteral("127.0.0.1"),
                                        QStringLiteral("192.0.2.10"), QStringLiteral("192.0.2.30"),
                                        11434, 18081);
        value.currentCheck_ = [current] { return *current; };
        return value;
    }
    static VerifiedPeer kernelPeer() {
        int sockets[2] = {-1, -1};
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
            qFatal("Cannot create synthetic bootstrap peer socket pair");
        const auto peer = verifiedPeerForUnixSocket(sockets[0]);
        ::close(sockets[0]);
        ::close(sockets[1]);
        if (!peer)
            qFatal("Cannot verify synthetic bootstrap peer");
        return *peer;
    }
    static LeasedHelperHost::OperationsFactory
    operationsFactory(HelperHostFakeBackend &backend, PfAnchorRecoveryCoordinator &coordinator) {
        return [&backend, &coordinator](const HostSessionLease &lease, const SessionSnapshot &) {
            if (!lease.acquired() || !lease.descriptorHasCloseOnExec())
                return std::unique_ptr<PfAnchorRecoverySystemOperations>{};
            return std::make_unique<PfAnchorRecoverySystemOperations>(backend, lease, coordinator);
        };
    }
    static QByteArray wireCommand(quint8 command, const QByteArray &capability,
                                  const QString &anchor) {
        const QByteArray anchorBytes = anchor.toUtf8();
        QByteArray payload;
        payload.append(char(1));
        payload.append(static_cast<char>(command));
        payload.append(static_cast<char>(capability.size()));
        payload += capability;
        payload.append(static_cast<char>(anchorBytes.size()));
        payload += anchorBytes;
        const auto length = static_cast<quint32>(payload.size());
        QByteArray frame;
        frame.append(static_cast<char>((length >> 24) & 0xff));
        frame.append(static_cast<char>((length >> 16) & 0xff));
        frame.append(static_cast<char>((length >> 8) & 0xff));
        frame.append(static_cast<char>(length & 0xff));
        frame += payload;
        return frame;
    }
    static void writeAll(int fd, const QByteArray &bytes) {
        qsizetype offset = 0;
        while (offset < bytes.size()) {
            const auto count =
                ::write(fd, bytes.constData() + offset, static_cast<size_t>(bytes.size() - offset));
            if (count <= 0)
                qFatal("Cannot write synthetic helper command");
            offset += static_cast<qsizetype>(count);
        }
    }
    static bool dispatchWire(LeasedHelperHost &host, const QByteArray &wire, QByteArray *response,
                             bool *fileDescriptorsRemainOpen, QString *error = nullptr) {
        int sockets[2] = {-1, -1};
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
            qFatal("Cannot create synthetic command socket pair");
        writeAll(sockets[1], wire);
        if (::shutdown(sockets[1], SHUT_WR) != 0)
            qFatal("Cannot half-close synthetic command socket");
        const bool accepted = host.dispatchOne(sockets[0], error);
        char byte = 0;
        response->clear();
        if (::recv(sockets[1], &byte, 1, MSG_DONTWAIT) == 1)
            response->append(byte);
        *fileDescriptorsRemainOpen =
            ::fcntl(sockets[0], F_GETFD) >= 0 && ::fcntl(sockets[1], F_GETFD) >= 0;
        ::close(sockets[0]);
        ::close(sockets[1]);
        return accepted;
    }

    struct Dependencies {
        HelperHostFakeBackend backend;
        HelperHostFakeAuthorization authorization;
        HelperHostFakePfRunner runner;
        PfAnchorOperations operations{authorization, runner};
        HelperHostFakeCleanupVerifier cleanupVerifier;
        PfRecoveryJournal recoveryJournal;
        PfAnchorRecoveryCoordinator coordinator{operations, recoveryJournal, cleanupVerifier};

        explicit Dependencies(int directoryFd)
            : recoveryJournal(PfRecoveryJournal::open(directoryFd)) {}
    };

  private slots:
    void invalidPeerReadinessFactoryOrSnapshotCannotReachOperations() {
        HelperHostPrivateDirectory directory;
        QVERIFY(directory.valid());
        Dependencies deps(directory.fd());
        QVERIFY(deps.recoveryJournal.valid());
        int factoryCalls = 0;
        const auto factory = [&factoryCalls, &deps](const HostSessionLease &lease,
                                                    const SessionSnapshot &snapshot) {
            ++factoryCalls;
            return M6LeasedHelperHostTests::operationsFactory(deps.backend,
                                                              deps.coordinator)(lease, snapshot);
        };

        VerifiedPeer invalidPeer;
        QString error;
        bool current = true;
        auto proxyReadiness = readiness(&current);
        auto noPeer = LeasedHelperHost::create(
            directory.fd(), sessionConfig(), facts(), proxyReadiness, invalidPeer, factory,
            [] { return qint64(10); }, &error);
        QVERIFY(!noPeer);
        QCOMPARE(error, QStringLiteral("trusted_bootstrap_peer_required"));
        QCOMPARE(factoryCalls, 0);
        QVERIFY(deps.backend.calls.isEmpty());

        const auto peer = kernelPeer();
        current = false;
        auto notReady = LeasedHelperHost::create(
            directory.fd(), sessionConfig(), facts(), proxyReadiness, peer, factory,
            [] { return qint64(10); }, &error);
        QVERIFY(!notReady);
        QCOMPARE(error, QStringLiteral("transparent_proxy_not_current"));
        QCOMPARE(factoryCalls, 0);
        auto leaseCanBeReacquired = HostSessionLease::acquire(directory.fd());
        QVERIFY(leaseCanBeReacquired.acquired());
        QCOMPARE(leaseCanBeReacquired.release(), HostSessionLeaseStatus::Released);

        current = true;
        auto wrongConfig = sessionConfig();
        wrongConfig.clientIp = QStringLiteral("192.0.2.11");
        auto mismatch = LeasedHelperHost::create(
            directory.fd(), wrongConfig, facts(), proxyReadiness, peer, factory,
            [] { return qint64(10); }, &error);
        QVERIFY(!mismatch);
        QVERIFY(!error.isEmpty());
        QCOMPARE(factoryCalls, 0);
        auto leaseAfterMismatch = HostSessionLease::acquire(directory.fd());
        QVERIFY(leaseAfterMismatch.acquired());
        QCOMPARE(leaseAfterMismatch.release(), HostSessionLeaseStatus::Released);

        const auto noOperations = [](const HostSessionLease &, const SessionSnapshot &) {
            return std::unique_ptr<PfAnchorRecoverySystemOperations>{};
        };
        auto unavailable = LeasedHelperHost::create(
            directory.fd(), sessionConfig(), facts(), proxyReadiness, peer, noOperations,
            [] { return qint64(10); }, &error);
        QVERIFY(!unavailable);
        QCOMPARE(error, QStringLiteral("helper_operations_unavailable"));
        auto leaseAfterFactoryFailure = HostSessionLease::acquire(directory.fd());
        QVERIFY(leaseAfterFactoryFailure.acquired());
    }

    void bootstrapStartCredentialsHeartbeatStopAndLeaseLifetime() {
        HelperHostPrivateDirectory directory;
        QVERIFY(directory.valid());
        Dependencies deps(directory.fd());
        QVERIFY(deps.recoveryJournal.valid());
        const auto peer = kernelPeer();
        bool current = true;
        qint64 clockValue = 100;
        auto proxyReadiness = readiness(&current);

        QString error;
        auto created = LeasedHelperHost::create(
            directory.fd(), sessionConfig(), facts(), proxyReadiness, peer,
            operationsFactory(deps.backend, deps.coordinator),
            [&clockValue] { return clockValue++; }, &error);
        QVERIFY2(created, qPrintable(error));
        auto *host = created.get();
        QVERIFY(!host->watchdogRunning());
        const auto preStartState = host->state();
        QCOMPARE(preStartState, NetworkSession::State::Idle);
        QVERIFY(!host->takeCredentials().has_value());
        const bool started = host->start(&error);
        QVERIFY2(started, qPrintable(QStringLiteral("%1; backend=%2 auth=%3 runner=%4")
                                         .arg(error, deps.backend.calls.join(','),
                                              deps.authorization.calls.join(','),
                                              deps.runner.calls.join(','))));
        QVERIFY(error.isEmpty());
        QCOMPARE(host->state(), NetworkSession::State::Active);
        QVERIFY(host->watchdogRunning());
        QVERIFY(proxyReadiness.isCurrent());
        QVERIFY(deps.backend.calls.contains(QStringLiteral("acquire-session-lease")));
        QVERIFY(deps.runner.calls.contains(QStringLiteral("install")));

        auto credentials = host->takeCredentials();
        QVERIFY(credentials.has_value());
        QCOMPARE(credentials->sessionId(), host->snapshot().sessionId());
        QCOMPARE(credentials->capability().size(), 32);
        QVERIFY(!host->takeCredentials().has_value());

        QByteArray reply;
        bool descriptorsOpen = false;
        const auto heartbeat = wireCommand(1, credentials->capability(), host->snapshot().anchor());
        QVERIFY(dispatchWire(*host, heartbeat, &reply, &descriptorsOpen, &error));
        QVERIFY(descriptorsOpen);
        QCOMPARE(reply, QByteArray(1, char(1)));
        QCOMPARE(error, QString());
        QCOMPARE(host->state(), NetworkSession::State::Active);

        const auto stop = wireCommand(2, credentials->capability(), host->snapshot().anchor());
        QVERIFY(dispatchWire(*host, stop, &reply, &descriptorsOpen, &error));
        QVERIFY(descriptorsOpen);
        QCOMPARE(reply, QByteArray(1, char(1)));
        QCOMPARE(host->state(), NetworkSession::State::Idle);
        QVERIFY(!host->watchdogRunning());
        QVERIFY(deps.backend.calls.contains(QStringLiteral("end-arp")));
        QVERIFY(deps.backend.calls.contains(QStringLiteral("restore-neighbors")));
        QVERIFY(deps.runner.calls.contains(QStringLiteral("remove")));
        QVERIFY(deps.cleanupVerifier.calls > 0);
        QVERIFY(deps.backend.calls.contains(QStringLiteral("release-session-lease:session-lease")));
        QCOMPARE(deps.recoveryJournal.read().status, PfRecoveryJournalStatus::JournalMissing);
        QVERIFY(host->stop(&error));
        QVERIFY(!host->takeCredentials().has_value());

        auto stillHeld = HostSessionLease::acquire(directory.fd());
        QVERIFY(!stillHeld.acquired());
        QCOMPARE(stillHeld.status(), HostSessionLeaseStatus::AlreadyHeld);
        created.reset();
        auto availableAfterDestruction = HostSessionLease::acquire(directory.fd());
        QVERIFY(availableAfterDestruction.acquired());
    }

    void readinessBecomingStaleBeforeStartPreventsActivation() {
        HelperHostPrivateDirectory directory;
        QVERIFY(directory.valid());
        Dependencies deps(directory.fd());
        QVERIFY(deps.recoveryJournal.valid());
        const auto peer = kernelPeer();
        bool current = true;
        auto proxyReadiness = readiness(&current);
        QString error;
        auto created = LeasedHelperHost::create(
            directory.fd(), sessionConfig(), facts(), proxyReadiness, peer,
            operationsFactory(deps.backend, deps.coordinator), [] { return qint64(100); }, &error);
        QVERIFY(created);
        current = false;
        QVERIFY(!created->start(&error));
        QCOMPARE(error, QStringLiteral("transparent_proxy_not_current"));
        QCOMPARE(created->state(), NetworkSession::State::Idle);
        QVERIFY(deps.backend.calls.isEmpty());
        QVERIFY(!created->takeCredentials().has_value());
        QVERIFY(!created->start(&error)); // one-shot bootstrap cannot bypass a failed recheck
        created.reset();
        auto leaseAfterDestroy = HostSessionLease::acquire(directory.fd());
        QVERIFY(leaseAfterDestroy.acquired());
    }

    void failedSessionStartLeavesNoNetworkEffectsAndReleasesLeaseOnHostDestroy() {
        HelperHostPrivateDirectory directory;
        QVERIFY(directory.valid());
        Dependencies deps(directory.fd());
        QVERIFY(deps.recoveryJournal.valid());
        deps.backend.leaseAcquisitionSucceeds = false;
        const auto peer = kernelPeer();
        bool current = true;
        auto proxyReadiness = readiness(&current);
        QString error;
        auto host = LeasedHelperHost::create(
            directory.fd(), sessionConfig(), facts(), proxyReadiness, peer,
            operationsFactory(deps.backend, deps.coordinator), [] { return qint64(100); }, &error);
        QVERIFY2(host, qPrintable(error));

        QVERIFY(!host->start(&error));
        QCOMPARE(error, QStringLiteral("helper_session_start_failed"));
        QCOMPARE(host->state(), NetworkSession::State::Idle);
        QCOMPARE(deps.backend.calls, QStringList{QStringLiteral("acquire-session-lease")});
        QVERIFY(deps.authorization.calls.isEmpty());
        QVERIFY(deps.runner.calls.isEmpty());
        QCOMPARE(deps.recoveryJournal.read().status, PfRecoveryJournalStatus::JournalMissing);

        auto anotherLease = HostSessionLease::acquire(directory.fd());
        QVERIFY(!anotherLease.acquired()); // host lock outlives failed session start
        host.reset();
        auto leaseAfterDestroy = HostSessionLease::acquire(directory.fd());
        QVERIFY(leaseAfterDestroy.acquired());
    }

    void staleReadinessAfterStartStopsBeforeHeartbeatDispatch() {
        HelperHostPrivateDirectory directory;
        QVERIFY(directory.valid());
        Dependencies deps(directory.fd());
        QVERIFY(deps.recoveryJournal.valid());
        const auto peer = kernelPeer();
        bool current = true;
        auto proxyReadiness = readiness(&current);
        QString error;
        auto host = LeasedHelperHost::create(
            directory.fd(), sessionConfig(), facts(), proxyReadiness, peer,
            operationsFactory(deps.backend, deps.coordinator), [] { return qint64(100); }, &error);
        QVERIFY2(host, qPrintable(error));
        QVERIFY2(host->start(&error), qPrintable(error));
        auto credentials = host->takeCredentials();
        QVERIFY(credentials.has_value());

        current = false;
        QByteArray reply;
        bool descriptorsOpen = false;
        const auto heartbeat = wireCommand(1, credentials->capability(), host->snapshot().anchor());
        QVERIFY(!dispatchWire(*host, heartbeat, &reply, &descriptorsOpen, &error));
        QVERIFY(descriptorsOpen);
        QCOMPARE(reply, QByteArray());
        QCOMPARE(error, QStringLiteral("transparent_proxy_not_current"));
        QCOMPARE(host->state(), NetworkSession::State::Idle);
        QVERIFY(!host->watchdogRunning());
        QVERIFY(deps.backend.calls.contains(QStringLiteral("release-session-lease:session-lease")));
        QVERIFY(deps.runner.calls.contains(QStringLiteral("remove")));
    }

    void activeHostDestructionAttemptsCleanupBeforeLeaseRelease() {
        HelperHostPrivateDirectory directory;
        QVERIFY(directory.valid());
        Dependencies deps(directory.fd());
        QVERIFY(deps.recoveryJournal.valid());
        const auto peer = kernelPeer();
        bool current = true;
        auto proxyReadiness = readiness(&current);
        QString error;
        auto host = LeasedHelperHost::create(
            directory.fd(), sessionConfig(), facts(), proxyReadiness, peer,
            operationsFactory(deps.backend, deps.coordinator), [] { return qint64(100); }, &error);
        QVERIFY2(host, qPrintable(error));
        QVERIFY2(host->start(&error), qPrintable(error));
        QVERIFY(host->watchdogRunning());
        host.reset();

        QVERIFY(deps.backend.calls.contains(QStringLiteral("end-arp")));
        QVERIFY(deps.backend.calls.contains(QStringLiteral("restore-neighbors")));
        QVERIFY(deps.runner.calls.contains(QStringLiteral("remove")));
        QVERIFY(deps.backend.calls.contains(QStringLiteral("release-session-lease:session-lease")));
        QCOMPARE(deps.recoveryJournal.read().status, PfRecoveryJournalStatus::JournalMissing);
        auto lease = HostSessionLease::acquire(directory.fd());
        QVERIFY(lease.acquired());
    }

    void ownerThreadIsRequiredForHostControlMethods() {
        HelperHostPrivateDirectory directory;
        QVERIFY(directory.valid());
        Dependencies deps(directory.fd());
        QVERIFY(deps.recoveryJournal.valid());
        const auto peer = kernelPeer();
        bool current = true;
        auto proxyReadiness = readiness(&current);
        QString createError;
        auto host = LeasedHelperHost::create(
            directory.fd(), sessionConfig(), facts(), proxyReadiness, peer,
            operationsFactory(deps.backend, deps.coordinator), [] { return qint64(100); },
            &createError);
        QVERIFY2(host, qPrintable(createError));

        bool started = true;
        QString startError;
        std::thread worker([&] { started = host->start(&startError); });
        worker.join();

        QVERIFY(!started);
        QCOMPARE(startError, QStringLiteral("helper_owner_thread_required"));
        QCOMPARE(host->state(), NetworkSession::State::Idle);
        QVERIFY(!host->watchdogRunning());
        QVERIFY(deps.backend.calls.isEmpty());
        host.reset();
    }

    void crossThreadDestructionDefersCleanupToOwnerThread() {
        HelperHostPrivateDirectory directory;
        QVERIFY(directory.valid());
        Dependencies deps(directory.fd());
        QVERIFY(deps.recoveryJournal.valid());
        const auto peer = kernelPeer();
        bool current = true;
        auto proxyReadiness = readiness(&current);
        QString error;
        auto host = LeasedHelperHost::create(
            directory.fd(), sessionConfig(), facts(), proxyReadiness, peer,
            operationsFactory(deps.backend, deps.coordinator), [] { return qint64(100); }, &error);
        QVERIFY2(host, qPrintable(error));
        QVERIFY(host->start(&error));

        std::thread worker([owned = std::move(host)]() mutable { owned.reset(); });
        worker.join();
        QVERIFY(!host);
        QVERIFY(!deps.backend.calls.contains(QStringLiteral("end-arp")));
        auto beforeOwnerCleanup = HostSessionLease::acquire(directory.fd());
        QVERIFY(!beforeOwnerCleanup.acquired());

        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        QCoreApplication::processEvents();
        QVERIFY(deps.backend.calls.contains(QStringLiteral("end-arp")));
        QVERIFY(deps.backend.calls.contains(QStringLiteral("restore-neighbors")));
        QVERIFY(deps.backend.calls.contains(QStringLiteral("release-session-lease:session-lease")));
        QCOMPARE(deps.recoveryJournal.read().status, PfRecoveryJournalStatus::JournalMissing);
        auto afterOwnerCleanup = HostSessionLease::acquire(directory.fd());
        QVERIFY(afterOwnerCleanup.acquired());
    }
};

} // namespace interceptor

QTEST_GUILESS_MAIN(interceptor::M6LeasedHelperHostTests)
#include "M6LeasedHelperHostTests.moc"
