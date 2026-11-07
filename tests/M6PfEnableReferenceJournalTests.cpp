#include "network/PfEnableReferenceJournal.hpp"

#include <QTemporaryDir>
#include <QtTest>

#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>

using namespace interceptor;

namespace {
constexpr char journalName[] = "llm_interceptor.pf-enable.journal";

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

class FakeJournalFileOps final : public PfEnableReferenceJournalFileOps {
  public:
    int failSyncFileCall = -1;
    int failSyncDirectoryCall = -1;
    int failRenameCall = -1;
    int syncFileCalls = 0;
    int syncDirectoryCalls = 0;
    int renameCalls = 0;
    int unlinkCalls = 0;

    int syncFile(int fd) override {
        ++syncFileCalls;
        return syncFileCalls == failSyncFileCall ? fail() : ::fsync(fd);
    }
    int syncDirectory(int fd) override {
        ++syncDirectoryCalls;
        return syncDirectoryCalls == failSyncDirectoryCall ? fail() : ::fsync(fd);
    }
    int renameAt(int oldDirFd, const char *oldName, int newDirFd, const char *newName) override {
        ++renameCalls;
        return renameCalls == failRenameCall ? fail()
                                             : ::renameat(oldDirFd, oldName, newDirFd, newName);
    }
    int unlinkAt(int dirFd, const char *name) override {
        ++unlinkCalls;
        return ::unlinkat(dirFd, name, 0);
    }

  private:
    static int fail() {
        errno = EIO;
        return -1;
    }
};

class FakeTokenVerifier final : public PfEnableReferenceTokenVerifier {
  public:
    PfEnableReferenceTokenState next = PfEnableReferenceTokenState::Unknown;
    QVector<quint64> tokens;

    PfEnableReferenceTokenState verifyToken(quint64 token) override {
        tokens.append(token);
        return next;
    }
};

class FakeEnableCommandRunner final : public PfEnableReferenceCommandRunner {
  public:
    QList<PfEnableReferenceCommandResult> results;

    PfEnableReferenceCommandResult execute(const PfEnableReferenceCommand &, int,
                                           qsizetype) override {
        return results.isEmpty() ? PfEnableReferenceCommandResult{} : results.takeFirst();
    }
};

PfEnableReferenceReleaseReceipt releaseReceiptFor(quint64 token) {
    FakeEnableCommandRunner runner;
    runner.results.append({PfEnableReferenceCommandStatus::Completed, 0, true, true,
                           QByteArray("Token : ") + QByteArray::number(token) + '\n'});
    runner.results.append({PfEnableReferenceCommandStatus::Completed, 0, true, true, {}});
    PfEnableReferenceOwner owner(runner);
    if (!owner.acquire().success)
        qFatal("Fake PF reference acquire failed");
    const auto result = owner.release();
    if (!result.releaseReceipt)
        qFatal("Fake PF reference release did not produce a receipt");
    return *result.releaseReceipt;
}

QByteArray readJournal(int directoryFd) {
    const int fd = ::openat(directoryFd, journalName, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return {};
    QByteArray bytes(1024, Qt::Uninitialized);
    const auto count = ::read(fd, bytes.data(), static_cast<size_t>(bytes.size()));
    ::close(fd);
    if (count < 0)
        return {};
    bytes.resize(static_cast<qsizetype>(count));
    return bytes;
}
} // namespace

class M6PfEnableReferenceJournalTests : public QObject {
    Q_OBJECT

  private slots:
    void persistsBeforeAcquireAndRecoversCapturedTokenAndReleasePhases() {
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        auto journal = PfEnableReferenceJournal::open(directory.fd());
        QVERIFY(journal.valid());
        QCOMPARE(journal.read().status, PfEnableReferenceJournalStatus::Missing);

        QCOMPARE(journal.persistAcquirePending("session-a"),
                 PfEnableReferenceJournalStatus::Persisted);
        auto pending = PfEnableReferenceJournal::open(directory.fd()).read();
        QCOMPARE(pending.status, PfEnableReferenceJournalStatus::Present);
        QVERIFY(pending.record.has_value());
        QCOMPARE(pending.record->sessionId, QString("session-a"));
        QCOMPARE(pending.record->phase, PfEnableReferenceJournalPhase::AcquirePending);
        QVERIFY(!pending.record->token.has_value());

        QCOMPARE(journal.persistCapturedToken("session-a", 12345),
                 PfEnableReferenceJournalStatus::Persisted);
        auto tokenCaptured = journal.read();
        QCOMPARE(tokenCaptured.status, PfEnableReferenceJournalStatus::Present);
        QVERIFY(tokenCaptured.record->token.has_value());
        QCOMPARE(*tokenCaptured.record->token, quint64(12345));
        QCOMPARE(tokenCaptured.record->phase, PfEnableReferenceJournalPhase::ReleaseNeeded);

        QCOMPARE(journal.markReleasePending("session-a", 12345),
                 PfEnableReferenceJournalStatus::Persisted);
        QCOMPARE(journal.markReleasePending("session-a", 12345),
                 PfEnableReferenceJournalStatus::InvalidTransition);
        const auto releasePending = PfEnableReferenceJournal::open(directory.fd()).read();
        QCOMPARE(releasePending.record->phase, PfEnableReferenceJournalPhase::ReleasePending);
        QCOMPARE(*releasePending.record->token, quint64(12345));
        QVERIFY(readJournal(directory.fd()).contains("token=12345"));
    }

    void unknownAcquireBlocksNewOwnerAndCannotBeCleared() {
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        auto journal = PfEnableReferenceJournal::open(directory.fd());
        QCOMPARE(journal.persistAcquirePending("session-a"),
                 PfEnableReferenceJournalStatus::Persisted);
        QCOMPARE(journal.markAcquisitionUncertain("session-a"),
                 PfEnableReferenceJournalStatus::Persisted);
        QCOMPARE(journal.persistAcquirePending("session-b"),
                 PfEnableReferenceJournalStatus::OwnerConflict);
        const auto read = journal.read();
        QCOMPARE(read.record->phase, PfEnableReferenceJournalPhase::AcquireUncertain);
        QVERIFY(!read.record->token.has_value());

        FakeTokenVerifier verifier;
        verifier.next = PfEnableReferenceTokenState::Absent;
        const auto receipt = releaseReceiptFor(12345);
        QCOMPARE(journal.clearAfterVerifiedRelease("session-a", receipt, verifier),
                 PfEnableReferenceJournalStatus::OwnerConflict);
        QVERIFY(verifier.tokens.isEmpty());
        QCOMPARE(journal.read().status, PfEnableReferenceJournalStatus::Present);
    }

    void uncertainAcquireWithTokenStaysRecoveryOnlyAndCannotClear() {
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        auto journal = PfEnableReferenceJournal::open(directory.fd());
        QCOMPARE(journal.persistAcquirePending("session-a"),
                 PfEnableReferenceJournalStatus::Persisted);
        QCOMPARE(journal.markAcquisitionUncertain("session-a", 12345),
                 PfEnableReferenceJournalStatus::Persisted);
        auto read = journal.read();
        QCOMPARE(read.record->phase, PfEnableReferenceJournalPhase::AcquireUncertainWithToken);
        QCOMPARE(*read.record->token, quint64(12345));
        QCOMPARE(journal.persistCapturedToken("session-a", 12345),
                 PfEnableReferenceJournalStatus::InvalidTransition);
        QCOMPARE(journal.markReleasePending("session-a", 12345),
                 PfEnableReferenceJournalStatus::InvalidTransition);
        FakeTokenVerifier verifier;
        verifier.next = PfEnableReferenceTokenState::Absent;
        const auto receipt = releaseReceiptFor(12345);
        QCOMPARE(journal.clearAfterVerifiedRelease("session-a", receipt, verifier),
                 PfEnableReferenceJournalStatus::InvalidTransition);
        QVERIFY(verifier.tokens.isEmpty());
        read = journal.read();
        QCOMPARE(read.record->phase, PfEnableReferenceJournalPhase::AcquireUncertainWithToken);
    }

    void clearRequiresExactOwnerTokenReleasePendingAndAbsentEvidence() {
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        auto journal = PfEnableReferenceJournal::open(directory.fd());
        QCOMPARE(journal.persistAcquirePending("session-a"),
                 PfEnableReferenceJournalStatus::Persisted);
        QCOMPARE(journal.persistCapturedToken("session-a", 12345),
                 PfEnableReferenceJournalStatus::Persisted);
        QCOMPARE(journal.markReleasePending("session-a", 12345),
                 PfEnableReferenceJournalStatus::Persisted);

        FakeTokenVerifier verifier;
        const auto receipt = releaseReceiptFor(12345);
        const auto mismatchedReceipt = releaseReceiptFor(54321);
        verifier.next = PfEnableReferenceTokenState::Active;
        QCOMPARE(journal.clearAfterVerifiedRelease("session-a", receipt, verifier),
                 PfEnableReferenceJournalStatus::TokenStillActive);
        QCOMPARE(verifier.tokens, QVector<quint64>{12345});
        verifier.next = PfEnableReferenceTokenState::Unknown;
        QCOMPARE(journal.clearAfterVerifiedRelease("session-a", receipt, verifier),
                 PfEnableReferenceJournalStatus::VerificationUnknown);
        QCOMPARE(journal.clearAfterVerifiedRelease("session-b", receipt, verifier),
                 PfEnableReferenceJournalStatus::OwnerConflict);
        QCOMPARE(journal.clearAfterVerifiedRelease("session-a", mismatchedReceipt, verifier),
                 PfEnableReferenceJournalStatus::OwnerConflict);
        QCOMPARE(verifier.tokens.size(), 2);

        verifier.next = PfEnableReferenceTokenState::Absent;
        QCOMPARE(journal.clearAfterVerifiedRelease("session-a", receipt, verifier),
                 PfEnableReferenceJournalStatus::Cleared);
        QCOMPARE(journal.read().status, PfEnableReferenceJournalStatus::Missing);
    }

    void fileAndDirectorySyncFailuresStayVisibleAndNeverClaimPersisted() {
        {
            PrivateJournalDirectory directory;
            QVERIFY(directory.valid());
            FakeJournalFileOps ops;
            ops.failSyncFileCall = 1;
            auto journal = PfEnableReferenceJournal::open(directory.fd(), &ops);

            QCOMPARE(journal.persistAcquirePending("session-a"),
                     PfEnableReferenceJournalStatus::IoFailed);
            QCOMPARE(journal.read().status, PfEnableReferenceJournalStatus::Missing);
            QCOMPARE(ops.syncFileCalls, 1);
            QCOMPARE(ops.syncDirectoryCalls, 0);
        }
        {
            PrivateJournalDirectory directory;
            QVERIFY(directory.valid());
            FakeJournalFileOps ops;
            ops.failSyncDirectoryCall = 1;
            auto journal = PfEnableReferenceJournal::open(directory.fd(), &ops);

            QCOMPARE(journal.persistAcquirePending("session-a"),
                     PfEnableReferenceJournalStatus::DurabilityUncertain);
            QCOMPARE(journal.read().status, PfEnableReferenceJournalStatus::Present);
            QCOMPARE(ops.syncFileCalls, 1);
            QCOMPARE(ops.syncDirectoryCalls, 1);
        }
        {
            PrivateJournalDirectory directory;
            QVERIFY(directory.valid());
            FakeJournalFileOps ops;
            ops.failRenameCall = 1;
            auto journal = PfEnableReferenceJournal::open(directory.fd(), &ops);

            QCOMPARE(journal.persistAcquirePending("session-a"),
                     PfEnableReferenceJournalStatus::IoFailed);
            QCOMPARE(journal.read().status, PfEnableReferenceJournalStatus::Missing);
            QCOMPARE(ops.renameCalls, 1);
        }
    }

    void unsafeSymlinkAndHardLinkedJournalFilesAreRejected() {
        {
            PrivateJournalDirectory directory;
            QVERIFY(directory.valid());
            QVERIFY(::symlinkat("target", directory.fd(), journalName) == 0);
            auto journal = PfEnableReferenceJournal::open(directory.fd());
            QCOMPARE(journal.read().status, PfEnableReferenceJournalStatus::UnsafeFile);
        }
        {
            PrivateJournalDirectory directory;
            QVERIFY(directory.valid());
            auto journal = PfEnableReferenceJournal::open(directory.fd());
            QCOMPARE(journal.persistAcquirePending("session-a"),
                     PfEnableReferenceJournalStatus::Persisted);
            const QByteArray linkedName("linked-copy");
            QVERIFY(::linkat(directory.fd(), journalName, directory.fd(), linkedName.constData(),
                             0) == 0);
            QCOMPARE(journal.read().status, PfEnableReferenceJournalStatus::UnsafeFile);
        }
    }
};

QTEST_GUILESS_MAIN(M6PfEnableReferenceJournalTests)
#include "M6PfEnableReferenceJournalTests.moc"
