#include "network/LeasedHelperHost.hpp"
#include "network/LeasedUnixHelperCommandListener.hpp"
#include "network/PfAnchorOperations.hpp"
#include "network/PfRecoveryJournal.hpp"
#include "network/UnixPeerCredentials.hpp"

#include <QCoreApplication>
#include <QDir>
#include <QEvent>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QtTest>

#include <cstring>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
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
    HelperHostPrivateDirectory() : directory_(QStringLiteral("/tmp/m6-helper-XXXXXX")) {
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
    QString path() const { return directory_.path(); }

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
    static int connectUnixSocket(const QString &path) {
        const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
            return -1;
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        const QByteArray encoded = QFile::encodeName(path);
        if (encoded.size() >= static_cast<qsizetype>(sizeof(address.sun_path))) {
            ::close(fd);
            return -1;
        }
        std::memcpy(address.sun_path, encoded.constData(), static_cast<size_t>(encoded.size()));
        address.sun_path[encoded.size()] = '\0';
        if (::connect(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
            ::close(fd);
            return -1;
        }
        return fd;
    }
    static bool pathnameUnixSocketsAvailable(const QString &directory) {
        const QString probePath = directory + QStringLiteral("/.m6_unix_bind_probe");
        const QByteArray encoded = QFile::encodeName(probePath);
        const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
            return false;
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        if (encoded.size() >= static_cast<qsizetype>(sizeof(address.sun_path))) {
            ::close(fd);
            return false;
        }
        std::memcpy(address.sun_path, encoded.constData(), static_cast<size_t>(encoded.size()));
        address.sun_path[encoded.size()] = '\0';
        const bool bound =
            ::bind(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == 0;
        if (bound)
            (void)::unlink(encoded.constData());
        ::close(fd);
        return bound;
    }
    static QByteArray listenerTransaction(LeasedUnixHelperCommandListener &listener,
                                          const QString &path, const QByteArray &wire,
                                          HelperListenerServeResult *served) {
        const int client = connectUnixSocket(path);
        if (client < 0)
            return {};
        writeAll(client, wire);
        if (::shutdown(client, SHUT_WR) != 0) {
            ::close(client);
            return {};
        }
        *served = listener.serveOne(100);
        QByteArray response;
        char buffer[8];
        ssize_t count = 0;
        while ((count = ::read(client, buffer, sizeof(buffer))) > 0)
            response.append(buffer, static_cast<qsizetype>(count));
        ::close(client);
        return response;
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

    void unixListenerRequiresActiveHostAndMatchingDirectory() {
        HelperHostPrivateDirectory directory;
        QVERIFY(directory.valid());
        Dependencies deps(directory.fd());
        QVERIFY(deps.recoveryJournal.valid());
        bool current = true;
        auto proxyReadiness = readiness(&current);
        QString error;
        auto host = LeasedHelperHost::create(
            directory.fd(), sessionConfig(), facts(), proxyReadiness, kernelPeer(),
            operationsFactory(deps.backend, deps.coordinator), [] { return qint64(100); }, &error);
        QVERIFY2(host, qPrintable(error));
        const QString path = directory.path() + QLatin1Char('/') +
                             QString::fromLatin1(LeasedUnixHelperCommandListener::socketBasename);
        auto inactive =
            LeasedUnixHelperCommandListener::create(path, directory.fd(), *host, &error);
        QVERIFY(!inactive);
        QCOMPARE(error, QStringLiteral("active_helper_host_required"));
        QVERIFY(!QFileInfo::exists(path));

        QVERIFY(host->start(&error));
        QTemporaryDir other;
        QVERIFY(other.isValid());
        QVERIFY(::chmod(QFile::encodeName(other.path()).constData(), 0700) == 0);
        const int otherFd =
            ::open(QFile::encodeName(other.path()).constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        QVERIFY(otherFd >= 0);
        auto wrongParent = LeasedUnixHelperCommandListener::create(path, otherFd, *host, &error);
        ::close(otherFd);
        QVERIFY(!wrongParent);
        QCOMPARE(error, QStringLiteral("socket_parent_directory_mismatch"));
        QVERIFY(!QFileInfo::exists(path));
        QCOMPARE(host->state(), NetworkSession::State::Idle);
        QVERIFY(deps.backend.calls.contains(QStringLiteral("release-session-lease:session-lease")));
    }

    void unixListenerHandlesHeartbeatAndStopWithPrivateSocketAndCleanup() {
        HelperHostPrivateDirectory directory;
        QVERIFY(directory.valid());
        if (!pathnameUnixSocketsAvailable(directory.path()))
            QSKIP("AF_UNIX pathname bind is unavailable in this environment");
        Dependencies deps(directory.fd());
        QVERIFY(deps.recoveryJournal.valid());
        bool current = true;
        auto proxyReadiness = readiness(&current);
        QString error;
        auto host = LeasedHelperHost::create(
            directory.fd(), sessionConfig(), facts(), proxyReadiness, kernelPeer(),
            operationsFactory(deps.backend, deps.coordinator), [] { return qint64(100); }, &error);
        QVERIFY2(host, qPrintable(error));
        QVERIFY2(host->start(&error), qPrintable(error));
        auto credentials = host->takeCredentials();
        QVERIFY(credentials.has_value());

        const QString path = directory.path() + QLatin1Char('/') +
                             QString::fromLatin1(LeasedUnixHelperCommandListener::socketBasename);
        auto listener =
            LeasedUnixHelperCommandListener::create(path, directory.fd(), *host, &error);
        QVERIFY2(listener, qPrintable(error));
        struct stat socketInfo{};
        QVERIFY(::lstat(QFile::encodeName(path).constData(), &socketInfo) == 0);
        QVERIFY(S_ISSOCK(socketInfo.st_mode));
        QCOMPARE(socketInfo.st_uid, ::geteuid());
        QCOMPARE(socketInfo.st_mode & 07777, mode_t(0600));

        HelperListenerServeResult served;
        auto heartbeat = wireCommand(1, credentials->capability(), host->snapshot().anchor());
        QCOMPARE(listenerTransaction(*listener, path, heartbeat, &served), QByteArray(1, char(1)));
        QCOMPARE(served.status, HelperListenerServeStatus::RequestHandled);
        QCOMPARE(host->state(), NetworkSession::State::Active);
        auto stop = wireCommand(2, credentials->capability(), host->snapshot().anchor());
        QVERIFY(::chmod(QFile::encodeName(path).constData(), 0644) == 0);
        deps.backend.sessionLeaseReleaseSucceeds = false;
        QCOMPARE(listenerTransaction(*listener, path, stop, &served), QByteArray(1, char(0)));
        QCOMPARE(served.status, HelperListenerServeStatus::RequestRejected);
        QCOMPARE(host->state(), NetworkSession::State::CleanupPending);
        QVERIFY(listener->isListening());
        QVERIFY(QFileInfo::exists(path));

        deps.backend.sessionLeaseReleaseSucceeds = true;
        QCOMPARE(listenerTransaction(*listener, path, stop, &served), QByteArray(1, char(1)));
        QCOMPARE(served.status, HelperListenerServeStatus::RequestHandled);
        QCOMPARE(host->state(), NetworkSession::State::Idle);
        QVERIFY(!listener->isListening());
        QVERIFY(listener->serveOne(0).status == HelperListenerServeStatus::ListenerUnavailable);
        QVERIFY(!QFileInfo::exists(path));

        listener.reset();
        QVERIFY(::lstat(QFile::encodeName(path).constData(), &socketInfo) != 0);
    }

    void unixListenerRejectsMalformedAndUnauthorizedThenServesNextClient() {
        HelperHostPrivateDirectory directory;
        QVERIFY(directory.valid());
        if (!pathnameUnixSocketsAvailable(directory.path()))
            QSKIP("AF_UNIX pathname bind is unavailable in this environment");
        Dependencies deps(directory.fd());
        QVERIFY(deps.recoveryJournal.valid());
        bool current = true;
        auto proxyReadiness = readiness(&current);
        QString error;
        auto host = LeasedHelperHost::create(
            directory.fd(), sessionConfig(), facts(), proxyReadiness, kernelPeer(),
            operationsFactory(deps.backend, deps.coordinator), [] { return qint64(100); }, &error);
        QVERIFY(host);
        QVERIFY(host->start(&error));
        auto credentials = host->takeCredentials();
        QVERIFY(credentials.has_value());
        const QString path = directory.path() + QLatin1Char('/') +
                             QString::fromLatin1(LeasedUnixHelperCommandListener::socketBasename);
        auto listener =
            LeasedUnixHelperCommandListener::create(path, directory.fd(), *host, &error);
        QVERIFY2(listener, qPrintable(error));
        HelperListenerServeResult served;

        QCOMPARE(listenerTransaction(*listener, path, QByteArray::fromHex("00000000"), &served),
                 QByteArray(1, char(0)));
        QCOMPARE(served.status, HelperListenerServeStatus::RequestRejected);
        QByteArray wrongCapability = credentials->capability();
        wrongCapability[0] = static_cast<char>(wrongCapability[0] ^ 0x01);
        auto unauthorized = wireCommand(1, wrongCapability, host->snapshot().anchor());
        QCOMPARE(listenerTransaction(*listener, path, unauthorized, &served),
                 QByteArray(1, char(0)));
        QCOMPARE(served.status, HelperListenerServeStatus::RequestRejected);

        auto heartbeat = wireCommand(1, credentials->capability(), host->snapshot().anchor());
        QCOMPARE(listenerTransaction(*listener, path, heartbeat, &served), QByteArray(1, char(1)));
        QCOMPARE(served.status, HelperListenerServeStatus::RequestHandled);
    }

    void unixListenerBoundsWaitsRejectsWrongThreadAndProtectsReplacedPath() {
        HelperHostPrivateDirectory directory;
        QVERIFY(directory.valid());
        if (!pathnameUnixSocketsAvailable(directory.path()))
            QSKIP("AF_UNIX pathname bind is unavailable in this environment");
        Dependencies deps(directory.fd());
        QVERIFY(deps.recoveryJournal.valid());
        bool current = true;
        auto proxyReadiness = readiness(&current);
        QString error;
        auto host = LeasedHelperHost::create(
            directory.fd(), sessionConfig(), facts(), proxyReadiness, kernelPeer(),
            operationsFactory(deps.backend, deps.coordinator), [] { return qint64(100); }, &error);
        QVERIFY(host);
        QVERIFY(host->start(&error));
        const QString path = directory.path() + QLatin1Char('/') +
                             QString::fromLatin1(LeasedUnixHelperCommandListener::socketBasename);
        auto listener =
            LeasedUnixHelperCommandListener::create(path, directory.fd(), *host, &error);
        QVERIFY2(listener, qPrintable(error));
        QCOMPARE(listener->serveOne(20).status, HelperListenerServeStatus::TimedOut);
        QCOMPARE(listener->serveOne(1001).status, HelperListenerServeStatus::Failed);
        HelperListenerServeStatus threadResult = HelperListenerServeStatus::RequestHandled;
        std::thread worker([&] { threadResult = listener->serveOne(0).status; });
        worker.join();
        QCOMPARE(threadResult, HelperListenerServeStatus::Failed);
        QVERIFY(listener->isListening());

        const QByteArray nativePath = QFile::encodeName(path);
        QVERIFY(::unlink(nativePath.constData()) == 0);
        const int replacement =
            ::open(nativePath.constData(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        QVERIFY(replacement >= 0);
        ::close(replacement);
        listener.reset();
        struct stat info{};
        QVERIFY(::lstat(nativePath.constData(), &info) == 0);
        QVERIFY(S_ISREG(info.st_mode));
    }

    void unixListenerPreservesExistingPathAndAcceptsCanonicalParentAlias() {
        HelperHostPrivateDirectory directory;
        QVERIFY(directory.valid());
        if (!pathnameUnixSocketsAvailable(directory.path()))
            QSKIP("AF_UNIX pathname bind is unavailable in this environment");
        Dependencies deps(directory.fd());
        QVERIFY(deps.recoveryJournal.valid());
        bool current = true;
        auto proxyReadiness = readiness(&current);
        QString error;
        auto host = LeasedHelperHost::create(
            directory.fd(), sessionConfig(), facts(), proxyReadiness, kernelPeer(),
            operationsFactory(deps.backend, deps.coordinator), [] { return qint64(100); }, &error);
        QVERIFY(host);
        QVERIFY(host->start(&error));
        const QString path = directory.path() + QLatin1Char('/') +
                             QString::fromLatin1(LeasedUnixHelperCommandListener::socketBasename);
        const QByteArray nativePath = QFile::encodeName(path);
        const QByteArray alias = QFile::encodeName(directory.path() + QStringLiteral("-alias"));
        QVERIFY(::symlink(QFile::encodeName(directory.path()).constData(), alias.constData()) == 0);
        auto listener = LeasedUnixHelperCommandListener::create(
            QString::fromLocal8Bit(alias + '/' + LeasedUnixHelperCommandListener::socketBasename),
            directory.fd(), *host, &error);
        QVERIFY2(listener, qPrintable(error));
        QCOMPARE(listener->socketPath(),
                 QDir(directory.path()).canonicalPath() + QLatin1Char('/') +
                     QString::fromLatin1(LeasedUnixHelperCommandListener::socketBasename));
        listener.reset();
        QVERIFY(::access(nativePath.constData(), F_OK) != 0);
        QVERIFY(::unlink(alias.constData()) == 0);

        const int existing =
            ::open(nativePath.constData(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        QVERIFY(existing >= 0);
        QCOMPARE(::write(existing, "x", 1), ssize_t(1));
        ::close(existing);
        auto collision =
            LeasedUnixHelperCommandListener::create(path, directory.fd(), *host, &error);
        QVERIFY(!collision);
        QCOMPARE(error, QStringLiteral("socket_path_already_exists"));
        QCOMPARE(host->state(), NetworkSession::State::Idle);
        QVERIFY(deps.backend.calls.contains(QStringLiteral("release-session-lease:session-lease")));
        const int preserved = ::open(nativePath.constData(), O_RDONLY | O_CLOEXEC);
        QVERIFY(preserved >= 0);
        char preservedByte = 0;
        QCOMPARE(::read(preserved, &preservedByte, 1), ssize_t(1));
        QCOMPARE(preservedByte, 'x');
        ::close(preserved);
    }
};

} // namespace interceptor

QTEST_GUILESS_MAIN(interceptor::M6LeasedHelperHostTests)
#include "M6LeasedHelperHostTests.moc"
