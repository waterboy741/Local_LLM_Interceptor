#include "network/PfAnchorRecoverySystemOperations.hpp"

#include <QTemporaryDir>
#include <QtTest>

#include <fcntl.h>
#include <memory>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

using namespace interceptor;

class RecoverySystemFakeBackend final : public SystemOperations {
  public:
    QStringList calls;
    QString leaseToken = QStringLiteral("synthetic-session-lease");
    bool releaseLeaseSucceeds = true;
    int forwarding = 0;
    int redirects = 1;

    std::optional<int> readSetting(NetworkSetting setting) override {
        calls << (setting == NetworkSetting::Forwarding ? "read-forwarding" : "read-redirects");
        return setting == NetworkSetting::Forwarding ? forwarding : redirects;
    }
    SettingChange compareAndSetSetting(NetworkSetting setting, int expected, int desired) override {
        calls << "compare-and-set";
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
        return leaseToken;
    }
    bool releaseSessionLease(const QString &token) override {
        calls << "release-session-lease:" + token;
        return releaseLeaseSucceeds;
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

class RecoverySystemFakeAuthorization final : public PfAnchorAuthorization {
  public:
    QStringList calls;
    QString observedLease;
    QString observedAnchor;
    PfAnchorOperation observedOperation = PfAnchorOperation::Install;
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
    bool verifySessionLease(const SessionSnapshot &, const QString &token) override {
        calls << "lease";
        observedLease = token;
        return leaseValid;
    }
    bool verifyActiveAttachment(const SessionSnapshot &) override {
        calls << "attachment";
        return attachmentValid;
    }
    bool verifyAnchorOwnership(const SessionSnapshot &snapshot, const QString &token,
                               PfAnchorOperation operation) override {
        calls << "ownership";
        observedLease = token;
        observedAnchor = snapshot.anchor();
        observedOperation = operation;
        return ownershipValid;
    }
};

class RecoverySystemFakeRunner final : public PfAnchorCommandRunner {
  public:
    QVector<PfAnchorCommandResult> results;
    QVector<PfAnchorOperation> operations;
    QStringList anchors;
    QStringList leaseTokens;

    PfAnchorCommandResult execute(const PfAnchorCommand &command, int, qsizetype) override {
        operations.append(command.operation());
        anchors.append(command.anchor());
        if (results.isEmpty())
            return {PfAnchorCommandStatus::Completed, 0, true, true};
        const auto result = results.front();
        results.pop_front();
        return result;
    }
};

class RecoverySystemFakeVerifier final : public PfAnchorCleanupVerifier {
  public:
    PfAnchorCleanupVerification next = PfAnchorCleanupVerification::Empty;
    int calls = 0;

    PfAnchorCleanupVerification verifyOwnedAnchorEmpty(const SessionSnapshot &) override {
        ++calls;
        return next;
    }
};

class PrivateRecoverySystemDirectory {
  public:
    PrivateRecoverySystemDirectory() {
        if (!directory_.isValid())
            return;
        const QByteArray path = directory_.path().toLocal8Bit();
        if (::chmod(path.constData(), 0700) != 0)
            return;
        descriptor_ = ::open(path.constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    }
    ~PrivateRecoverySystemDirectory() {
        if (descriptor_ >= 0)
            ::close(descriptor_);
    }
    bool valid() const { return directory_.isValid() && descriptor_ >= 0; }
    int fd() const { return descriptor_; }

  private:
    QTemporaryDir directory_;
    int descriptor_ = -1;
};

class M6PfAnchorRecoverySystemOperationsTests final : public QObject {
    Q_OBJECT

    static SessionSnapshot snapshot(const QString &sessionId = QStringLiteral("recovery-system"),
                                    const QString &serverIp = QStringLiteral("192.0.2.30")) {
        SessionConfig config{"synthetic0", "192.0.2.10", serverIp, 18081, {"/api/generate"}, false};
        NetworkFacts facts;
        facts.interfaceName = "synthetic0";
        facts.researchIp = "192.0.2.20";
        facts.researchMac = "02:00:00:00:00:20";
        facts.clientMac = "02:00:00:00:00:10";
        facts.serverMac = "02:00:00:00:00:30";
        facts.proxyServerIp = serverIp;
        facts.proxyServerPort = config.serverPort;
        facts.proxyListenPort = 11434;
        facts.interfaceUp = facts.sameLink = facts.anchorAttached = facts.proxyReady =
            facts.authorized = true;
        const auto result = SessionSnapshot::create(config, facts, 11434, sessionId);
        if (!result)
            qFatal("Cannot construct synthetic PF recovery system snapshot");
        return *result;
    }

    struct Harness {
        PrivateRecoverySystemDirectory directory;
        HostSessionLease lease;
        PfRecoveryJournal journal;
        RecoverySystemFakeBackend backend;
        RecoverySystemFakeAuthorization authorization;
        RecoverySystemFakeRunner runner;
        PfAnchorOperations operations{authorization, runner};
        RecoverySystemFakeVerifier verifier;
        PfAnchorRecoveryCoordinator coordinator{operations, journal, verifier};
        std::unique_ptr<PfAnchorRecoverySystemOperations> decorated;

        Harness()
            : lease(HostSessionLease::acquire(directory.fd())),
              journal(PfRecoveryJournal::open(directory.fd())) {
            if (lease.acquired() && journal.valid())
                decorated =
                    std::make_unique<PfAnchorRecoverySystemOperations>(backend, lease, coordinator);
        }
    };

  private slots:
    void unheldHostLeaseBlocksEveryOperationBeforeBackendOrPf() {
        RecoverySystemFakeBackend backend;
        auto unheldLease = HostSessionLease::acquire(-1);
        PrivateRecoverySystemDirectory directory;
        QVERIFY(directory.valid());
        auto journal = PfRecoveryJournal::open(directory.fd());
        QVERIFY(journal.valid());
        RecoverySystemFakeAuthorization authorization;
        RecoverySystemFakeRunner runner;
        PfAnchorOperations operations(authorization, runner);
        RecoverySystemFakeVerifier verifier;
        PfAnchorRecoveryCoordinator coordinator(operations, journal, verifier);
        PfAnchorRecoverySystemOperations decorated(backend, unheldLease, coordinator);
        const auto session = snapshot();
        OwnershipJournal ownership;

        QVERIFY(!decorated.readSetting(NetworkSetting::Forwarding));
        QCOMPARE(decorated.compareAndSetSetting(NetworkSetting::Forwarding, 0, 1),
                 SettingChange::Failed);
        QVERIFY(!decorated.acquireSessionLease(session));
        QVERIFY(!decorated.releaseSessionLease("anything"));
        QVERIFY(!decorated.acquirePfReference());
        QVERIFY(!decorated.releasePfReference("pf-token"));
        QVERIFY(!decorated.installAnchor(session));
        QVERIFY(!decorated.removeAnchor(session));
        QVERIFY(!decorated.clearOwnedState(session));
        QVERIFY(!decorated.beginArp(session));
        QVERIFY(!decorated.endArp(session));
        QVERIFY(!decorated.restoreNeighbors(session));
        QVERIFY(!decorated.interfaceAvailable(session));
        QVERIFY(!decorated.retainRecovery(session, ownership));

        QVERIFY(backend.calls.isEmpty());
        QVERIFY(authorization.calls.isEmpty());
        QVERIFY(runner.operations.isEmpty());
        QCOMPARE(verifier.calls, 0);
        QCOMPARE(journal.read().status, PfRecoveryJournalStatus::JournalMissing);
    }

    void acquiredLeaseBindsExactSnapshotAndRoutesInstallCleanupThroughCoordinator() {
        Harness harness;
        QVERIFY(harness.directory.valid());
        QVERIFY(harness.lease.acquired());
        QVERIFY(harness.journal.valid());
        QVERIFY(harness.decorated);
        const auto session = snapshot();

        const auto token = harness.decorated->acquireSessionLease(session);
        QVERIFY(token.has_value());
        QCOMPARE(*token, harness.backend.leaseToken);
        QVERIFY(!harness.decorated->acquireSessionLease(session)); // no duplicate acquisition
        QVERIFY(!harness.decorated->interfaceAvailable(snapshot("different-session")));
        QVERIFY(!harness.decorated->installAnchor(snapshot("different-session")));
        const auto alteredSnapshot = snapshot(session.sessionId(), QStringLiteral("192.0.2.40"));
        QVERIFY(!harness.decorated->interfaceAvailable(alteredSnapshot));
        QVERIFY(!harness.decorated->installAnchor(alteredSnapshot));
        QVERIFY(harness.runner.operations.isEmpty());
        QVERIFY(harness.backend.calls.contains("acquire-session-lease"));

        QVERIFY(harness.decorated->installAnchor(session));
        QCOMPARE(harness.runner.operations, QVector<PfAnchorOperation>{PfAnchorOperation::Install});
        QCOMPARE(harness.runner.anchors, QStringList{session.anchor()});
        QCOMPARE(harness.authorization.observedLease, *token);
        QCOMPARE(harness.authorization.observedAnchor, session.anchor());
        QCOMPARE(harness.authorization.observedOperation, PfAnchorOperation::Install);
        const auto pending = harness.journal.read();
        QCOMPARE(pending.status, PfRecoveryJournalStatus::JournalPresent);
        QVERIFY(pending.record.has_value());
        QCOMPARE(pending.record->sessionId, session.sessionId());

        QVERIFY(harness.decorated->removeAnchor(session));
        QCOMPARE(
            harness.runner.operations,
            (QVector<PfAnchorOperation>{PfAnchorOperation::Install, PfAnchorOperation::RemoveNat,
                                        PfAnchorOperation::RemoveRules}));
        QCOMPARE(harness.verifier.calls, 1);
        QCOMPARE(harness.authorization.observedLease, *token);
        QCOMPARE(harness.authorization.observedOperation, PfAnchorOperation::RemoveRules);
        QCOMPARE(harness.journal.read().status, PfRecoveryJournalStatus::JournalMissing);
    }

    void failedInstallAndCleanupRetainJournalAndLeaseTokenUntilReleaseSucceeds() {
        Harness harness;
        QVERIFY(harness.directory.valid());
        QVERIFY(harness.decorated);
        QVERIFY(harness.decorated->acquireSessionLease(snapshot()));
        const auto session = snapshot();

        harness.runner.results.append({PfAnchorCommandStatus::TimedOut, -1, true, true});
        harness.runner.results.append({PfAnchorCommandStatus::Failed, -1, true, true});
        QVERIFY(!harness.decorated->installAnchor(session));
        QCOMPARE(harness.journal.read().status, PfRecoveryJournalStatus::JournalPresent);
        QVERIFY(!harness.decorated->removeAnchor(session));
        QCOMPARE(harness.journal.read().status, PfRecoveryJournalStatus::JournalPresent);
        QCOMPARE(harness.verifier.calls, 0);
        QCOMPARE(harness.authorization.observedLease, harness.backend.leaseToken);

        harness.backend.releaseLeaseSucceeds = false;
        QVERIFY(!harness.decorated->releaseSessionLease(harness.backend.leaseToken));
        QVERIFY(harness.decorated->readSetting(NetworkSetting::Forwarding));
        QCOMPARE(harness.backend.calls.last(),
                 QStringLiteral("read-forwarding")); // token remains active after failed release
        QVERIFY(harness.decorated->removeAnchor(session)); // retained token still authorizes retry
        QCOMPARE(harness.journal.read().status, PfRecoveryJournalStatus::JournalMissing);
        harness.backend.releaseLeaseSucceeds = true;
        QVERIFY(harness.decorated->releaseSessionLease(harness.backend.leaseToken));
        QVERIFY(!harness.decorated->readSetting(NetworkSetting::Forwarding));
        QCOMPARE(harness.journal.read().status, PfRecoveryJournalStatus::JournalMissing);
    }

    void wrongThreadCannotReachBackendOrPfRunner() {
        Harness harness;
        QVERIFY(harness.directory.valid());
        QVERIFY(harness.decorated);
        QVERIFY(harness.decorated->acquireSessionLease(snapshot()));

        std::optional<int> setting;
        bool available = true;
        std::thread worker([&] {
            setting = harness.decorated->readSetting(NetworkSetting::Forwarding);
            available = harness.decorated->interfaceAvailable(snapshot());
        });
        worker.join();

        QVERIFY(!setting);
        QVERIFY(!available);
        QCOMPARE(harness.backend.calls.size(), 1);
        QCOMPARE(harness.backend.calls.front(), QStringLiteral("acquire-session-lease"));
        QVERIFY(harness.authorization.calls.isEmpty());
        QVERIFY(harness.runner.operations.isEmpty());
    }
};

QTEST_GUILESS_MAIN(M6PfAnchorRecoverySystemOperationsTests)
#include "M6PfAnchorRecoverySystemOperationsTests.moc"
