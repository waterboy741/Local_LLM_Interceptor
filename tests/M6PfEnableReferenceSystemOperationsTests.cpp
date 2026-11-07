#include "network/PfAnchorRecoverySystemOperations.hpp"

#include <QTemporaryDir>
#include <QtTest>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace interceptor;

class EnableLifecycleBackend final : public SystemOperations {
  public:
    QStringList *events = nullptr;
    QStringList calls;
    std::optional<QString> sessionLease = QStringLiteral("new-session-lease");
    int forwarding = 0;
    int redirects = 1;

    std::optional<int> readSetting(NetworkSetting setting) override {
        calls << "read-setting";
        return setting == NetworkSetting::Forwarding ? forwarding : redirects;
    }
    SettingChange compareAndSetSetting(NetworkSetting setting, int expected, int desired) override {
        calls << "compare-setting";
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
        if (events)
            events->append("backend.acquire-session-lease");
        return sessionLease;
    }
    bool releaseSessionLease(const QString &) override {
        calls << "release-session-lease";
        return true;
    }
    std::optional<QString> acquirePfReference() override {
        calls << "direct-acquire-pf-reference";
        return QStringLiteral("must-not-be-used");
    }
    bool releasePfReference(const QString &) override {
        calls << "direct-release-pf-reference";
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
        calls << "clear-state";
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

class EnableLifecyclePfRunner final : public PfEnableReferenceCommandRunner {
  public:
    struct Call {
        PfEnableReferenceOperation operation;
        QString program;
        QStringList arguments;
        int timeoutMs;
        qsizetype outputLimit;
    };
    QStringList *events = nullptr;
    QVector<Call> calls;
    QVector<PfEnableReferenceCommandResult> results;

    PfEnableReferenceCommandResult execute(const PfEnableReferenceCommand &command, int timeoutMs,
                                           qsizetype outputLimit) override {
        calls.append(
            {command.operation(), command.program(), command.arguments(), timeoutMs, outputLimit});
        if (events)
            events->append(command.operation() == PfEnableReferenceOperation::Acquire
                               ? QStringLiteral("pf.acquire")
                               : QStringLiteral("pf.release:%1").arg(command.arguments().last()));
        if (results.isEmpty())
            return {PfEnableReferenceCommandStatus::Completed, 0, true, true,
                    QByteArrayLiteral("Token : 88\n")};
        const auto result = results.front();
        results.pop_front();
        return result;
    }
};

class EnableLifecycleVerifier final : public PfEnableReferenceTokenVerifier {
  public:
    QStringList *events = nullptr;
    QVector<PfEnableReferenceTokenState> states;
    QVector<quint64> tokens;

    PfEnableReferenceTokenState verifyToken(quint64 token) override {
        tokens.append(token);
        if (events)
            events->append(QStringLiteral("verify:%1").arg(token));
        if (states.isEmpty())
            return PfEnableReferenceTokenState::Absent;
        const auto result = states.front();
        states.pop_front();
        return result;
    }
};

class EnableLifecycleAnchorAuthorization final : public PfAnchorAuthorization {
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

class EnableLifecycleAnchorRunner final : public PfAnchorCommandRunner {
  public:
    PfAnchorCommandResult execute(const PfAnchorCommand &, int, qsizetype) override {
        return {PfAnchorCommandStatus::Completed, 0, true, true};
    }
};

class EnableLifecycleAnchorVerifier final : public PfAnchorCleanupVerifier {
  public:
    PfAnchorCleanupVerification verifyOwnedAnchorEmpty(const SessionSnapshot &) override {
        return PfAnchorCleanupVerification::Empty;
    }
};

class PrivateEnableLifecycleDirectory {
  public:
    PrivateEnableLifecycleDirectory() {
        if (!directory_.isValid())
            return;
        const QByteArray path = directory_.path().toLocal8Bit();
        if (::chmod(path.constData(), 0700) != 0)
            return;
        descriptor_ = ::open(path.constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    }
    ~PrivateEnableLifecycleDirectory() {
        if (descriptor_ >= 0)
            ::close(descriptor_);
    }
    bool valid() const { return directory_.isValid() && descriptor_ >= 0; }
    int fd() const { return descriptor_; }

  private:
    QTemporaryDir directory_;
    int descriptor_ = -1;
};

class M6PfEnableReferenceSystemOperationsTests final : public QObject {
    Q_OBJECT

    static SessionSnapshot snapshot(const QString &sessionId) {
        SessionConfig config{"synthetic0", "192.0.2.10",      "192.0.2.30",
                             18081,        {"/api/generate"}, false};
        NetworkFacts facts;
        facts.interfaceName = "synthetic0";
        facts.researchIp = "192.0.2.20";
        facts.researchMac = "02:00:00:00:00:20";
        facts.clientMac = "02:00:00:00:00:10";
        facts.serverMac = "02:00:00:00:00:30";
        facts.proxyServerIp = config.serverIp;
        facts.proxyServerPort = config.serverPort;
        facts.proxyListenPort = 11434;
        facts.interfaceUp = facts.sameLink = facts.anchorAttached = facts.proxyReady =
            facts.authorized = true;
        const auto result = SessionSnapshot::create(config, facts, 11434, sessionId);
        if (!result)
            qFatal("Cannot construct synthetic enable-reference snapshot");
        return *result;
    }

  private slots:
    void startupRecoveryPrecedesNewLeaseThenNewReferenceUsesExactToken() {
        PrivateEnableLifecycleDirectory directory;
        QVERIFY(directory.valid());
        auto hostLease = HostSessionLease::acquire(directory.fd());
        QVERIFY(hostLease.acquired());
        auto anchorJournal = PfRecoveryJournal::open(directory.fd());
        QVERIFY(anchorJournal.valid());
        auto enableJournal = PfEnableReferenceJournal::open(directory.fd());
        QVERIFY(enableJournal.valid());
        QCOMPARE(enableJournal.persistAcquirePending("previous-session"),
                 PfEnableReferenceJournalStatus::Persisted);
        QCOMPARE(enableJournal.persistCapturedToken("previous-session", 77),
                 PfEnableReferenceJournalStatus::Persisted);
        QCOMPARE(enableJournal.markReleasePending("previous-session", 77),
                 PfEnableReferenceJournalStatus::Persisted);

        QStringList events;
        EnableLifecycleBackend backend;
        backend.events = &events;
        EnableLifecyclePfRunner startupRunner;
        startupRunner.events = &events;
        startupRunner.results.append({PfEnableReferenceCommandStatus::Completed, 0, true, true,
                                      QByteArrayLiteral("released\n")});
        EnableLifecycleVerifier startupVerifier;
        startupVerifier.events = &events;
        startupVerifier.states = {PfEnableReferenceTokenState::Absent,
                                  PfEnableReferenceTokenState::Absent};
        PfEnableReferenceOwner startupOwner(startupRunner);
        PfEnableReferenceRecoveryCoordinator startupCoordinator(startupOwner, enableJournal,
                                                                startupVerifier);

        EnableLifecyclePfRunner activeRunner;
        activeRunner.events = &events;
        activeRunner.results.append({PfEnableReferenceCommandStatus::Completed, 0, true, true,
                                     QByteArrayLiteral("Token : 88\n")});
        activeRunner.results.append({PfEnableReferenceCommandStatus::Completed, 0, true, true,
                                     QByteArrayLiteral("released\n")});
        EnableLifecycleVerifier activeVerifier;
        activeVerifier.events = &events;
        activeVerifier.states = {PfEnableReferenceTokenState::Absent};
        PfEnableReferenceOwner activeOwner(activeRunner);
        PfEnableReferenceRecoveryCoordinator activeCoordinator(activeOwner, enableJournal,
                                                               activeVerifier);

        EnableLifecycleAnchorAuthorization anchorAuthorization;
        EnableLifecycleAnchorRunner anchorRunner;
        PfAnchorOperations anchorOperations(anchorAuthorization, anchorRunner);
        EnableLifecycleAnchorVerifier anchorVerifier;
        PfAnchorRecoveryCoordinator anchorCoordinator(anchorOperations, anchorJournal,
                                                      anchorVerifier);
        PfAnchorRecoverySystemOperations decorated(backend, hostLease, anchorCoordinator,
                                                   &activeCoordinator, &startupCoordinator);

        const auto currentSession = snapshot("current-session");
        const auto sessionToken = decorated.acquireSessionLease(currentSession);
        QVERIFY(sessionToken.has_value());
        QCOMPARE(*sessionToken, QStringLiteral("new-session-lease"));
        const int startupVerificationIndex = events.indexOf(QStringLiteral("verify:77"));
        const int leaseAcquireIndex =
            events.indexOf(QStringLiteral("backend.acquire-session-lease"));
        QVERIFY(startupVerificationIndex >= 0);
        QVERIFY(leaseAcquireIndex > startupVerificationIndex);
        QCOMPARE(enableJournal.read().status, PfEnableReferenceJournalStatus::Missing);
        QVERIFY(!decorated.installAnchor(currentSession)); // no captured PF token yet
        QCOMPARE(anchorJournal.read().status, PfRecoveryJournalStatus::JournalMissing);

        const auto pfToken = decorated.acquirePfReference();
        QVERIFY(pfToken.has_value());
        QCOMPARE(*pfToken, QStringLiteral("88"));
        QVERIFY(!decorated.acquirePfReference()); // one reference per active session
        QCOMPARE(activeRunner.calls.size(), 1);
        QVERIFY(decorated.installAnchor(currentSession));
        QVERIFY(!decorated.releasePfReference(*pfToken)); // install alone does not prove cleanup
        QCOMPARE(activeRunner.calls.size(), 1);
        QVERIFY(!decorated.releaseSessionLease(*sessionToken));
        const auto callCount = activeRunner.calls.size();
        QVERIFY(!decorated.releasePfReference(QStringLiteral("89")));
        QCOMPARE(activeRunner.calls.size(), callCount);
        QVERIFY(!backend.calls.contains(QStringLiteral("direct-acquire-pf-reference")));
        QVERIFY(!backend.calls.contains(QStringLiteral("direct-release-pf-reference")));

        QVERIFY(decorated.removeAnchor(currentSession));
        QVERIFY(decorated.installAnchor(currentSession)); // a new install invalidates cleanup proof
        QVERIFY(!decorated.releasePfReference(*pfToken));
        QCOMPARE(activeRunner.calls.size(), callCount);
        QVERIFY(decorated.removeAnchor(currentSession));
        QVERIFY(decorated.releasePfReference(*pfToken));
        QVERIFY(decorated.releaseSessionLease(*sessionToken));
        QCOMPARE(enableJournal.read().status, PfEnableReferenceJournalStatus::Missing);
        QCOMPARE(startupVerifier.tokens, QVector<quint64>({77, 77}));
        QCOMPARE(activeVerifier.tokens, QVector<quint64>({88}));

        QVERIFY(startupRunner.calls.isEmpty()); // verified absent, so no startup -X is needed
        QCOMPARE(activeRunner.calls.size(), 2);
        QCOMPARE(activeRunner.calls[0].arguments, (QStringList{"-E"}));
        QCOMPARE(activeRunner.calls[1].arguments, (QStringList{"-X", "88"}));
        for (const auto &call : activeRunner.calls)
            QVERIFY(!call.arguments.contains("-d"));
    }

    void unknownRecoveryRecordBlocksNewLeaseBeforeBackendAndCurrentPfCommands() {
        PrivateEnableLifecycleDirectory directory;
        QVERIFY(directory.valid());
        auto hostLease = HostSessionLease::acquire(directory.fd());
        QVERIFY(hostLease.acquired());
        auto anchorJournal = PfRecoveryJournal::open(directory.fd());
        QVERIFY(anchorJournal.valid());
        auto enableJournal = PfEnableReferenceJournal::open(directory.fd());
        QVERIFY(enableJournal.valid());
        QCOMPARE(enableJournal.persistAcquirePending("orphan-session"),
                 PfEnableReferenceJournalStatus::Persisted);

        EnableLifecycleBackend backend;
        EnableLifecyclePfRunner startupRunner;
        EnableLifecycleVerifier startupVerifier;
        PfEnableReferenceOwner startupOwner(startupRunner);
        PfEnableReferenceRecoveryCoordinator startupCoordinator(startupOwner, enableJournal,
                                                                startupVerifier);
        EnableLifecyclePfRunner activeRunner;
        EnableLifecycleVerifier activeVerifier;
        PfEnableReferenceOwner activeOwner(activeRunner);
        PfEnableReferenceRecoveryCoordinator activeCoordinator(activeOwner, enableJournal,
                                                               activeVerifier);
        EnableLifecycleAnchorAuthorization anchorAuthorization;
        EnableLifecycleAnchorRunner anchorRunner;
        PfAnchorOperations anchorOperations(anchorAuthorization, anchorRunner);
        EnableLifecycleAnchorVerifier anchorVerifier;
        PfAnchorRecoveryCoordinator anchorCoordinator(anchorOperations, anchorJournal,
                                                      anchorVerifier);
        PfAnchorRecoverySystemOperations decorated(backend, hostLease, anchorCoordinator,
                                                   &activeCoordinator, &startupCoordinator);

        QVERIFY(!decorated.acquireSessionLease(snapshot("new-session")));
        QVERIFY(backend.calls.isEmpty());
        QVERIFY(startupRunner.calls.isEmpty()); // unknown token must not be released speculatively
        QVERIFY(activeRunner.calls.isEmpty());
        QCOMPARE(enableJournal.read().status, PfEnableReferenceJournalStatus::Present);
    }

    void releaseNeededRecordBlocksStartupUntilAnchorCleanupIsProven() {
        PrivateEnableLifecycleDirectory directory;
        QVERIFY(directory.valid());
        auto hostLease = HostSessionLease::acquire(directory.fd());
        QVERIFY(hostLease.acquired());
        auto anchorJournal = PfRecoveryJournal::open(directory.fd());
        QVERIFY(anchorJournal.valid());
        auto enableJournal = PfEnableReferenceJournal::open(directory.fd());
        QVERIFY(enableJournal.valid());
        QCOMPARE(enableJournal.persistAcquirePending("previous-session"),
                 PfEnableReferenceJournalStatus::Persisted);
        QCOMPARE(enableJournal.persistCapturedToken("previous-session", 77),
                 PfEnableReferenceJournalStatus::Persisted);

        EnableLifecycleBackend backend;
        EnableLifecyclePfRunner startupRunner;
        EnableLifecycleVerifier startupVerifier;
        PfEnableReferenceOwner startupOwner(startupRunner);
        PfEnableReferenceRecoveryCoordinator startupCoordinator(startupOwner, enableJournal,
                                                                startupVerifier);
        EnableLifecyclePfRunner activeRunner;
        EnableLifecycleVerifier activeVerifier;
        PfEnableReferenceOwner activeOwner(activeRunner);
        PfEnableReferenceRecoveryCoordinator activeCoordinator(activeOwner, enableJournal,
                                                               activeVerifier);
        EnableLifecycleAnchorAuthorization anchorAuthorization;
        EnableLifecycleAnchorRunner anchorRunner;
        PfAnchorOperations anchorOperations(anchorAuthorization, anchorRunner);
        EnableLifecycleAnchorVerifier anchorVerifier;
        PfAnchorRecoveryCoordinator anchorCoordinator(anchorOperations, anchorJournal,
                                                      anchorVerifier);
        PfAnchorRecoverySystemOperations decorated(backend, hostLease, anchorCoordinator,
                                                   &activeCoordinator, &startupCoordinator);

        QVERIFY(!decorated.acquireSessionLease(snapshot("new-session")));
        QVERIFY(backend.calls.isEmpty());
        QVERIFY(startupRunner.calls.isEmpty()); // no -X before anchor cleanup is proven
        QVERIFY(activeRunner.calls.isEmpty());
        QVERIFY(startupVerifier.tokens.isEmpty()); // phase is blocked before token verification
        QCOMPARE(enableJournal.read().status, PfEnableReferenceJournalStatus::Present);
        QCOMPARE(enableJournal.read().record->phase, PfEnableReferenceJournalPhase::ReleaseNeeded);
    }

    void uncertainActiveAcquireRetainsJournalAndPreventsLeaseRelease() {
        PrivateEnableLifecycleDirectory directory;
        QVERIFY(directory.valid());
        auto hostLease = HostSessionLease::acquire(directory.fd());
        QVERIFY(hostLease.acquired());
        auto anchorJournal = PfRecoveryJournal::open(directory.fd());
        QVERIFY(anchorJournal.valid());
        auto enableJournal = PfEnableReferenceJournal::open(directory.fd());
        QVERIFY(enableJournal.valid());

        EnableLifecycleBackend backend;
        EnableLifecyclePfRunner activeRunner;
        activeRunner.results.append({PfEnableReferenceCommandStatus::TimedOut, -1, true, true, {}});
        EnableLifecycleVerifier activeVerifier;
        PfEnableReferenceOwner activeOwner(activeRunner);
        PfEnableReferenceRecoveryCoordinator activeCoordinator(activeOwner, enableJournal,
                                                               activeVerifier);
        EnableLifecycleAnchorAuthorization anchorAuthorization;
        EnableLifecycleAnchorRunner anchorRunner;
        PfAnchorOperations anchorOperations(anchorAuthorization, anchorRunner);
        EnableLifecycleAnchorVerifier anchorVerifier;
        PfAnchorRecoveryCoordinator anchorCoordinator(anchorOperations, anchorJournal,
                                                      anchorVerifier);
        PfAnchorRecoverySystemOperations decorated(backend, hostLease, anchorCoordinator,
                                                   &activeCoordinator);

        const auto token = decorated.acquireSessionLease(snapshot("uncertain-session"));
        QVERIFY(token.has_value());
        QVERIFY(!decorated.acquirePfReference());
        QVERIFY(!decorated.releaseSessionLease(*token));
        QVERIFY(!decorated.installAnchor(snapshot("uncertain-session")));
        QCOMPARE(anchorJournal.read().status, PfRecoveryJournalStatus::JournalMissing);
        QVERIFY(!decorated.acquirePfReference()); // pending recovery cannot issue another -E
        QCOMPARE(activeRunner.calls.size(), 1);
        QCOMPARE(activeRunner.calls.front().arguments, (QStringList{"-E"}));
        QCOMPARE(backend.calls, QStringList{QStringLiteral("acquire-session-lease")});
        const auto record = enableJournal.read();
        QCOMPARE(record.status, PfEnableReferenceJournalStatus::Present);
        QVERIFY(record.record.has_value());
        QCOMPARE(record.record->sessionId, QStringLiteral("uncertain-session"));
        QCOMPARE(record.record->phase, PfEnableReferenceJournalPhase::AcquireUncertain);
    }

    void uncertainReleaseRetainsTokenSpecificRecoveryObligation() {
        PrivateEnableLifecycleDirectory directory;
        QVERIFY(directory.valid());
        auto hostLease = HostSessionLease::acquire(directory.fd());
        QVERIFY(hostLease.acquired());
        auto anchorJournal = PfRecoveryJournal::open(directory.fd());
        QVERIFY(anchorJournal.valid());
        auto enableJournal = PfEnableReferenceJournal::open(directory.fd());
        QVERIFY(enableJournal.valid());

        EnableLifecycleBackend backend;
        EnableLifecyclePfRunner activeRunner;
        activeRunner.results.append({PfEnableReferenceCommandStatus::Completed, 0, true, true,
                                     QByteArrayLiteral("Token : 91\n")});
        activeRunner.results.append({PfEnableReferenceCommandStatus::TimedOut, -1, true, true, {}});
        EnableLifecycleVerifier activeVerifier;
        PfEnableReferenceOwner activeOwner(activeRunner);
        PfEnableReferenceRecoveryCoordinator activeCoordinator(activeOwner, enableJournal,
                                                               activeVerifier);
        EnableLifecycleAnchorAuthorization anchorAuthorization;
        EnableLifecycleAnchorRunner anchorRunner;
        PfAnchorOperations anchorOperations(anchorAuthorization, anchorRunner);
        EnableLifecycleAnchorVerifier anchorVerifier;
        PfAnchorRecoveryCoordinator anchorCoordinator(anchorOperations, anchorJournal,
                                                      anchorVerifier);
        PfAnchorRecoverySystemOperations decorated(backend, hostLease, anchorCoordinator,
                                                   &activeCoordinator);

        const auto sessionToken = decorated.acquireSessionLease(snapshot("release-pending"));
        QVERIFY(sessionToken.has_value());
        const auto pfToken = decorated.acquirePfReference();
        QVERIFY(pfToken.has_value());
        QCOMPARE(*pfToken, QStringLiteral("91"));
        QVERIFY(!decorated.releasePfReference(*pfToken)); // anchor cleanup must happen first
        QCOMPARE(activeRunner.calls.size(), 1);
        QVERIFY(decorated.installAnchor(snapshot("release-pending")));
        QVERIFY(!decorated.releasePfReference(*pfToken)); // install is not a cleanup receipt
        QCOMPARE(activeRunner.calls.size(), 1);
        QVERIFY(decorated.removeAnchor(snapshot("release-pending")));
        QVERIFY(!decorated.releasePfReference(*pfToken));
        QVERIFY(!decorated.releaseSessionLease(*sessionToken));
        QCOMPARE(activeRunner.calls.size(), 2);
        QCOMPARE(activeRunner.calls[0].arguments, (QStringList{"-E"}));
        QCOMPARE(activeRunner.calls[1].arguments, (QStringList{"-X", "91"}));
        const auto record = enableJournal.read();
        QCOMPARE(record.status, PfEnableReferenceJournalStatus::Present);
        QVERIFY(record.record.has_value());
        QCOMPARE(record.record->phase, PfEnableReferenceJournalPhase::ReleasePending);
        QCOMPARE(record.record->token, std::optional<quint64>(91));
        for (const auto &call : activeRunner.calls)
            QVERIFY(!call.arguments.contains("-d"));
        QVERIFY(!backend.calls.contains(QStringLiteral("direct-release-pf-reference")));
    }

    void sharedStartupAndActiveCoordinatorIsRejected() {
        PrivateEnableLifecycleDirectory directory;
        QVERIFY(directory.valid());
        auto hostLease = HostSessionLease::acquire(directory.fd());
        QVERIFY(hostLease.acquired());
        auto anchorJournal = PfRecoveryJournal::open(directory.fd());
        auto enableJournal = PfEnableReferenceJournal::open(directory.fd());
        QVERIFY(anchorJournal.valid());
        QVERIFY(enableJournal.valid());
        EnableLifecycleBackend backend;
        EnableLifecyclePfRunner runner;
        EnableLifecycleVerifier verifier;
        PfEnableReferenceOwner owner(runner);
        PfEnableReferenceRecoveryCoordinator sharedCoordinator(owner, enableJournal, verifier);
        EnableLifecycleAnchorAuthorization anchorAuthorization;
        EnableLifecycleAnchorRunner anchorRunner;
        PfAnchorOperations anchorOperations(anchorAuthorization, anchorRunner);
        EnableLifecycleAnchorVerifier anchorVerifier;
        PfAnchorRecoveryCoordinator anchorCoordinator(anchorOperations, anchorJournal,
                                                      anchorVerifier);
        PfAnchorRecoverySystemOperations decorated(backend, hostLease, anchorCoordinator,
                                                   &sharedCoordinator, &sharedCoordinator);

        QVERIFY(!decorated.acquireSessionLease(snapshot("same-coordinator")));
        QVERIFY(backend.calls.isEmpty());
        QVERIFY(runner.calls.isEmpty());
    }

    void separateStartupAndActiveJournalsFailClosed() {
        PrivateEnableLifecycleDirectory directory;
        QVERIFY(directory.valid());
        auto hostLease = HostSessionLease::acquire(directory.fd());
        QVERIFY(hostLease.acquired());
        auto anchorJournal = PfRecoveryJournal::open(directory.fd());
        auto startupJournal = PfEnableReferenceJournal::open(directory.fd());
        auto activeJournal = PfEnableReferenceJournal::open(directory.fd());
        QVERIFY(anchorJournal.valid());
        QVERIFY(startupJournal.valid());
        QVERIFY(activeJournal.valid());
        EnableLifecycleBackend backend;
        EnableLifecyclePfRunner startupRunner;
        EnableLifecycleVerifier startupVerifier;
        PfEnableReferenceOwner startupOwner(startupRunner);
        PfEnableReferenceRecoveryCoordinator startupCoordinator(startupOwner, startupJournal,
                                                                startupVerifier);
        EnableLifecyclePfRunner activeRunner;
        EnableLifecycleVerifier activeVerifier;
        PfEnableReferenceOwner activeOwner(activeRunner);
        PfEnableReferenceRecoveryCoordinator activeCoordinator(activeOwner, activeJournal,
                                                               activeVerifier);
        EnableLifecycleAnchorAuthorization anchorAuthorization;
        EnableLifecycleAnchorRunner anchorRunner;
        PfAnchorOperations anchorOperations(anchorAuthorization, anchorRunner);
        EnableLifecycleAnchorVerifier anchorVerifier;
        PfAnchorRecoveryCoordinator anchorCoordinator(anchorOperations, anchorJournal,
                                                      anchorVerifier);
        PfAnchorRecoverySystemOperations decorated(backend, hostLease, anchorCoordinator,
                                                   &activeCoordinator, &startupCoordinator);

        QVERIFY(!decorated.acquireSessionLease(snapshot("split-journal")));
        QVERIFY(backend.calls.isEmpty());
        QVERIFY(startupRunner.calls.isEmpty());
        QVERIFY(activeRunner.calls.isEmpty());
    }

    void sharedStartupAndActiveOwnerIsRejected() {
        PrivateEnableLifecycleDirectory directory;
        QVERIFY(directory.valid());
        auto hostLease = HostSessionLease::acquire(directory.fd());
        QVERIFY(hostLease.acquired());
        auto anchorJournal = PfRecoveryJournal::open(directory.fd());
        auto enableJournal = PfEnableReferenceJournal::open(directory.fd());
        QVERIFY(anchorJournal.valid());
        QVERIFY(enableJournal.valid());
        EnableLifecycleBackend backend;
        EnableLifecyclePfRunner runner;
        EnableLifecycleVerifier startupVerifier;
        EnableLifecycleVerifier activeVerifier;
        PfEnableReferenceOwner sharedOwner(runner);
        PfEnableReferenceRecoveryCoordinator startupCoordinator(sharedOwner, enableJournal,
                                                                startupVerifier);
        PfEnableReferenceRecoveryCoordinator activeCoordinator(sharedOwner, enableJournal,
                                                               activeVerifier);
        EnableLifecycleAnchorAuthorization anchorAuthorization;
        EnableLifecycleAnchorRunner anchorRunner;
        PfAnchorOperations anchorOperations(anchorAuthorization, anchorRunner);
        EnableLifecycleAnchorVerifier anchorVerifier;
        PfAnchorRecoveryCoordinator anchorCoordinator(anchorOperations, anchorJournal,
                                                      anchorVerifier);
        PfAnchorRecoverySystemOperations decorated(backend, hostLease, anchorCoordinator,
                                                   &activeCoordinator, &startupCoordinator);

        QVERIFY(!decorated.acquireSessionLease(snapshot("shared-owner")));
        QVERIFY(backend.calls.isEmpty());
        QVERIFY(runner.calls.isEmpty());
    }
};

QTEST_GUILESS_MAIN(M6PfEnableReferenceSystemOperationsTests)
#include "M6PfEnableReferenceSystemOperationsTests.moc"
