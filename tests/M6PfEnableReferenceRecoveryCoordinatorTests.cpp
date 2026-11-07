#include "network/PfEnableReferenceRecoveryCoordinator.hpp"

#include <QTemporaryDir>
#include <QtTest>

#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace interceptor;

namespace {
class PrivateJournalDirectory {
  public:
    PrivateJournalDirectory() {
        if (!directory_.isValid())
            return;
        if (::chmod(directory_.path().toLocal8Bit().constData(), 0700) != 0)
            return;
        fd_ =
            ::open(directory_.path().toLocal8Bit().constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    }
    ~PrivateJournalDirectory() {
        if (fd_ >= 0)
            ::close(fd_);
    }
    bool valid() const { return directory_.isValid() && fd_ >= 0; }
    int fd() const { return fd_; }

  private:
    QTemporaryDir directory_;
    int fd_ = -1;
};

class TraceJournalFileOps final : public PfEnableReferenceJournalFileOps {
  public:
    QStringList &events;
    int failSyncFileCall = -1;
    int failSyncDirectoryCall = -1;
    int syncFileCalls = 0;
    int syncDirectoryCalls = 0;

    explicit TraceJournalFileOps(QStringList &trace) : events(trace) {}

    int syncFile(int fd) override {
        events << "sync-file";
        ++syncFileCalls;
        if (syncFileCalls == failSyncFileCall) {
            errno = EIO;
            return -1;
        }
        return ::fsync(fd);
    }
    int syncDirectory(int fd) override {
        events << "sync-directory";
        ++syncDirectoryCalls;
        if (syncDirectoryCalls == failSyncDirectoryCall) {
            errno = EIO;
            return -1;
        }
        return ::fsync(fd);
    }
    int renameAt(int oldDirFd, const char *oldName, int newDirFd, const char *newName) override {
        events << "rename";
        return ::renameat(oldDirFd, oldName, newDirFd, newName);
    }
    int unlinkAt(int dirFd, const char *name) override {
        events << "unlink";
        return ::unlinkat(dirFd, name, 0);
    }
};

class TracePfRunner final : public PfEnableReferenceCommandRunner {
  public:
    struct Call {
        QStringList arguments;
        PfEnableReferenceOperation operation;
    };
    QStringList &events;
    QList<PfEnableReferenceCommandResult> results;
    QVector<Call> calls;

    explicit TracePfRunner(QStringList &trace) : events(trace) {}

    PfEnableReferenceCommandResult execute(const PfEnableReferenceCommand &command, int,
                                           qsizetype) override {
        const auto arguments = command.arguments();
        calls.append({arguments, command.operation()});
        const auto result =
            results.isEmpty() ? PfEnableReferenceCommandResult{} : results.takeFirst();
        if (result.started)
            events << (command.operation() == PfEnableReferenceOperation::Acquire ? "-E" : "-X");
        return result;
    }
};

class TraceTokenVerifier final : public PfEnableReferenceTokenVerifier {
  public:
    QStringList &events;
    PfEnableReferenceTokenState state = PfEnableReferenceTokenState::Absent;
    QVector<quint64> tokens;

    explicit TraceTokenVerifier(QStringList &trace) : events(trace) {}
    PfEnableReferenceTokenState verifyToken(quint64 token) override {
        events << "verify-token";
        tokens.append(token);
        return state;
    }
};

PfEnableReferenceCommandResult acquireResult(QByteArray output = "Token : 73\n") {
    return {PfEnableReferenceCommandStatus::Completed, 0, true, true, std::move(output)};
}

PfEnableReferenceCommandResult releaseResult() {
    return {PfEnableReferenceCommandStatus::Completed, 0, true, true, {}};
}

qsizetype indexOf(const QStringList &events, const QString &event, qsizetype start = 0) {
    for (qsizetype index = start; index < events.size(); ++index)
        if (events[index] == event)
            return index;
    return -1;
}
} // namespace

class M6PfEnableReferenceRecoveryCoordinatorTests : public QObject {
    Q_OBJECT

  private slots:
    void durableAcquirePendingPrecedesEnableCommandAndTokenPersistence() {
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        QStringList events;
        TraceJournalFileOps fileOps(events);
        auto journal = PfEnableReferenceJournal::open(directory.fd(), &fileOps);
        TracePfRunner runner(events);
        runner.results.append(acquireResult());
        TraceTokenVerifier verifier(events);
        PfEnableReferenceOwner owner(runner);
        PfEnableReferenceRecoveryCoordinator coordinator(owner, journal, verifier);

        const auto result = coordinator.acquire("session-a");

        QVERIFY(result.success);
        QCOMPARE(result.statusCode, QString("acquired_token_durable"));
        QCOMPARE(runner.calls.size(), 1);
        QCOMPARE(runner.calls.first().arguments, QStringList{"-E"});
        const auto enableAt = indexOf(events, "-E");
        QVERIFY(enableAt >= 3);
        QCOMPARE(events[enableAt - 1], QString("sync-directory"));
        const auto tokenPersistSync = indexOf(events, "sync-file", enableAt + 1);
        QVERIFY(tokenPersistSync > enableAt);
        const auto read = journal.read();
        QCOMPARE(read.record->phase, PfEnableReferenceJournalPhase::ReleaseNeeded);
        QCOMPARE(*read.record->token, quint64(73));
    }

    void noEnableCommandRunsWhenPendingJournalCannotBeDurablyWritten() {
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        QStringList events;
        TraceJournalFileOps fileOps(events);
        fileOps.failSyncFileCall = 1;
        auto journal = PfEnableReferenceJournal::open(directory.fd(), &fileOps);
        TracePfRunner runner(events);
        runner.results.append(acquireResult());
        TraceTokenVerifier verifier(events);
        PfEnableReferenceOwner owner(runner);
        PfEnableReferenceRecoveryCoordinator coordinator(owner, journal, verifier);

        const auto result = coordinator.acquire("session-a");

        QVERIFY(!result.success);
        QCOMPARE(result.statusCode, QString("acquire_journal_not_durable"));
        QVERIFY(runner.calls.isEmpty());
        QCOMPARE(journal.read().status, PfEnableReferenceJournalStatus::Missing);
    }

    void capturedTokenPersistenceFailureLeavesCleanupPendingAndNeverClaimsSuccess() {
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        QStringList events;
        TraceJournalFileOps fileOps(events);
        fileOps.failSyncFileCall = 2;
        auto journal = PfEnableReferenceJournal::open(directory.fd(), &fileOps);
        TracePfRunner runner(events);
        runner.results.append(acquireResult());
        TraceTokenVerifier verifier(events);
        PfEnableReferenceOwner owner(runner);
        PfEnableReferenceRecoveryCoordinator coordinator(owner, journal, verifier);

        const auto result = coordinator.acquire("session-a");

        QVERIFY(!result.success);
        QVERIFY(result.cleanupPending);
        QCOMPARE(result.statusCode, QString("acquired_token_journal_uncertain"));
        QCOMPARE(runner.calls.size(), 1);
        QCOMPARE(journal.read().record->phase, PfEnableReferenceJournalPhase::AcquirePending);
        const auto release = coordinator.release("session-a");
        QVERIFY(!release.success);
        QVERIFY(release.cleanupPending);
        QCOMPARE(release.statusCode, QString("release_not_owned_by_coordinator"));
        QVERIFY(indexOf(events, "-X") < 0);
        QCOMPARE(coordinator.acquire("session-a").statusCode, QString("acquire_already_called"));
        QCOMPARE(runner.calls.size(), 1);
    }

    void ambiguousAcquireIsPersistedAsUncertainAndCannotRelease() {
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        QStringList events;
        TraceJournalFileOps fileOps(events);
        auto journal = PfEnableReferenceJournal::open(directory.fd(), &fileOps);
        TracePfRunner runner(events);
        runner.results.append(
            {PfEnableReferenceCommandStatus::TimedOut, -1, true, false, "untrusted child output"});
        TraceTokenVerifier verifier(events);
        PfEnableReferenceOwner owner(runner);
        PfEnableReferenceRecoveryCoordinator coordinator(owner, journal, verifier);

        const auto acquired = coordinator.acquire("session-a");
        QVERIFY(!acquired.success);
        QVERIFY(acquired.cleanupPending);
        QCOMPARE(acquired.statusCode, QString("acquire_uncertain"));
        QCOMPARE(journal.read().record->phase, PfEnableReferenceJournalPhase::AcquireUncertain);

        const auto released = coordinator.release("session-a");
        QVERIFY(!released.success);
        QVERIFY(released.cleanupPending);
        QCOMPARE(released.statusCode, QString("release_not_owned_by_coordinator"));
        QCOMPARE(runner.calls.size(), 1);
        QVERIFY(indexOf(events, "-X") < 0);
    }

    void provenNeverStartedAcquireClearsPendingOnlyAfterDirectorySync() {
        for (const bool failClearSync : {false, true}) {
            PrivateJournalDirectory directory;
            QVERIFY(directory.valid());
            QStringList events;
            TraceJournalFileOps fileOps(events);
            auto journal = PfEnableReferenceJournal::open(directory.fd(), &fileOps);
            TracePfRunner runner(events);
            runner.results.append({PfEnableReferenceCommandStatus::Failed, -1, false, true, {}});
            TraceTokenVerifier verifier(events);
            PfEnableReferenceOwner owner(runner);
            PfEnableReferenceRecoveryCoordinator coordinator(owner, journal, verifier);
            if (failClearSync)
                fileOps.failSyncDirectoryCall = 2;

            const auto result = coordinator.acquire("session-a");

            QVERIFY(!result.success);
            QVERIFY(result.cleanupPending == failClearSync);
            QCOMPARE(result.statusCode, failClearSync
                                            ? QString("acquire_not_started_journal_uncertain")
                                            : QString("acquire_not_started"));
            QCOMPARE(runner.calls.size(), 1);
            QCOMPARE(runner.calls.first().arguments, QStringList{"-E"});
            QCOMPARE(indexOf(events, "-E"), qsizetype(-1));
            QVERIFY(indexOf(events, "-X") < 0);
            QCOMPARE(journal.read().status, PfEnableReferenceJournalStatus::Missing);
        }
    }

    void releaseCommandWaitsForDurableReleasePendingAndIsOneShot() {
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        QStringList events;
        TraceJournalFileOps fileOps(events);
        auto journal = PfEnableReferenceJournal::open(directory.fd(), &fileOps);
        TracePfRunner runner(events);
        runner.results.append(acquireResult());
        runner.results.append(releaseResult());
        TraceTokenVerifier verifier(events);
        verifier.state = PfEnableReferenceTokenState::Active;
        PfEnableReferenceOwner owner(runner);
        PfEnableReferenceRecoveryCoordinator coordinator(owner, journal, verifier);
        QVERIFY(coordinator.acquire("session-a").success);

        const auto firstRelease = coordinator.release("session-a");
        QVERIFY(!firstRelease.success);
        QVERIFY(firstRelease.cleanupPending);
        QCOMPARE(firstRelease.journalStatus, PfEnableReferenceJournalStatus::TokenStillActive);
        QCOMPARE(runner.calls.size(), 2);
        QCOMPARE(runner.calls.last().arguments, (QStringList{"-X", "73"}));
        const auto releaseAt = indexOf(events, "-X");
        QVERIFY(releaseAt > 0);
        QCOMPARE(events[releaseAt - 1], QString("sync-directory"));

        verifier.state = PfEnableReferenceTokenState::Unknown;
        const auto unknown = coordinator.release("session-a");
        QVERIFY(!unknown.success);
        QCOMPARE(unknown.journalStatus, PfEnableReferenceJournalStatus::VerificationUnknown);
        QCOMPARE(runner.calls.size(), 2);

        verifier.state = PfEnableReferenceTokenState::Absent;
        const auto clear = coordinator.release("session-a");
        QVERIFY(clear.success);
        QCOMPARE(clear.statusCode, QString("reference_released_and_verified"));
        QCOMPARE(runner.calls.size(), 2);
        QCOMPARE(verifier.tokens, QVector<quint64>({73, 73, 73}));
        QCOMPARE(journal.read().status, PfEnableReferenceJournalStatus::Missing);
    }

    void releasePendingPersistenceFailurePreventsReleaseCommand() {
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        QStringList events;
        TraceJournalFileOps fileOps(events);
        auto journal = PfEnableReferenceJournal::open(directory.fd(), &fileOps);
        TracePfRunner runner(events);
        runner.results.append(acquireResult());
        runner.results.append(releaseResult());
        TraceTokenVerifier verifier(events);
        PfEnableReferenceOwner owner(runner);
        PfEnableReferenceRecoveryCoordinator coordinator(owner, journal, verifier);
        QVERIFY(coordinator.acquire("session-a").success);
        fileOps.failSyncFileCall = fileOps.syncFileCalls + 1;

        const auto result = coordinator.release("session-a");

        QVERIFY(!result.success);
        QVERIFY(result.cleanupPending);
        QCOMPARE(result.statusCode, QString("release_pending_not_durable"));
        QCOMPARE(runner.calls.size(), 1);
        QVERIFY(indexOf(events, "-X") < 0);
        QCOMPARE(journal.read().record->phase, PfEnableReferenceJournalPhase::ReleaseNeeded);
    }

    void releasePendingDirectorySyncUncertaintyNeverRetriesReleaseCommand() {
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        QStringList events;
        TraceJournalFileOps fileOps(events);
        auto journal = PfEnableReferenceJournal::open(directory.fd(), &fileOps);
        TracePfRunner runner(events);
        runner.results.append(acquireResult());
        runner.results.append(releaseResult());
        TraceTokenVerifier verifier(events);
        PfEnableReferenceOwner owner(runner);
        PfEnableReferenceRecoveryCoordinator coordinator(owner, journal, verifier);
        QVERIFY(coordinator.acquire("session-a").success);
        fileOps.failSyncDirectoryCall = fileOps.syncDirectoryCalls + 1;

        const auto first = coordinator.release("session-a");
        QVERIFY(!first.success);
        QVERIFY(first.cleanupPending);
        QCOMPARE(first.statusCode, QString("release_pending_not_durable"));
        QCOMPARE(journal.read().record->phase, PfEnableReferenceJournalPhase::ReleasePending);
        QVERIFY(indexOf(events, "-X") < 0);

        const auto second = coordinator.release("session-a");
        QVERIFY(!second.success);
        QVERIFY(second.cleanupPending);
        QCOMPARE(runner.calls.size(), 1);
        QVERIFY(indexOf(events, "-X") < 0);
        QCOMPARE(journal.read().record->phase, PfEnableReferenceJournalPhase::ReleasePending);
    }

    void uncertainReleaseCommandIsNeverIssuedTwice() {
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        QStringList events;
        TraceJournalFileOps fileOps(events);
        auto journal = PfEnableReferenceJournal::open(directory.fd(), &fileOps);
        TracePfRunner runner(events);
        runner.results.append(acquireResult());
        runner.results.append({PfEnableReferenceCommandStatus::TimedOut, -1, true, false, {}});
        TraceTokenVerifier verifier(events);
        PfEnableReferenceOwner owner(runner);
        PfEnableReferenceRecoveryCoordinator coordinator(owner, journal, verifier);
        QVERIFY(coordinator.acquire("session-a").success);

        const auto first = coordinator.release("session-a");
        QVERIFY(!first.success);
        QVERIFY(first.cleanupPending);
        QCOMPARE(first.statusCode, QString("release_uncertain_timed_out"));
        QCOMPARE(journal.read().record->phase, PfEnableReferenceJournalPhase::ReleasePending);
        QCOMPARE(runner.calls.size(), 2);

        const auto second = coordinator.release("session-a");
        QVERIFY(!second.success);
        QVERIFY(second.cleanupPending);
        QCOMPARE(runner.calls.size(), 2);
        QCOMPARE(runner.calls.last().arguments, (QStringList{"-X", "73"}));
    }
};

QTEST_GUILESS_MAIN(M6PfEnableReferenceRecoveryCoordinatorTests)
#include "M6PfEnableReferenceRecoveryCoordinatorTests.moc"
